# Nginx Log Analysis

Applicativo Python per generare un report HTML con l'analisi degli access log del web server nginx.

Vincoli di base: nessuna CDN davanti al web server (quindi `$remote_addr` è l'IP reale del client), applicativo **multi-sito**, output un **report HTML statico autoconsistente a livello di dati** — nessuna richiesta di rete per navigarlo.

---

## 0. Architettura

### Pipeline a stadi

Ogni sottocomando è uno stadio **idempotente** che produce un artefatto proprio. Rilanciarlo non ricomincia da capo: ogni stadio tiene uno stato e salta ciò che non è cambiato.

| Comando | Legge | Scrive |
|---|---|---|
| `sites` | `config/sites/*.yaml` | elenco su stdout |
| `fetch --site D [--force]` | server via ssh | `logs/D/*.gz` + `logs/D/_manifest.json` |
| `parse --site D [--rebuild]` | archivio `.gz` | `data/D/events/ym=AAAA-MM/*.parquet`, `data/D/_parse_state.json`, `errors/D_unparsed.log` |
| `ipranges refresh\|show` | `config/bot_sources.yaml` | `cache/ip_ranges.parquet`, `cache/ip_sources/*.json` |
| `verify --site D [--no-dns]` | events + store range | `data/D/ip_verdict.parquet`, `cache/dns.sqlite` |
| `enrich --site D` | events + verdetti | `data/D/enriched/ym=AAAA-MM/part.parquet` |
| `gsc --site D` | API Search Console | `data/D/gsc.parquet` |
| `report --site D [--all\|--latest]` | enriched + gsc + `input/D/` | `output/log_analysis_<dominio>_<periodo>.html` |
| `run --site D` | tutti gli stadi in sequenza | tutti gli artefatti |

`run` accetta anche `--skip-fetch`. `report` e `run` accettano `--no-compress-payload` e `--inline-libs`.

Fallimenti non fatali: GSC assente o non raggiungibile fa proseguire la pipeline senza le colonne click/impression. Fallimento di `ipranges` in `run` **ferma** la pipeline: senza range ogni bot risulterebbe non verificato, che è peggio che fermarsi.

### Albero

```
main.py                 entry point, la logica sta in loganalyzer/cli.py
loganalyzer/            cli, config, logformat, fetch, parse, ipranges,
                        verify, classify, enrich, gsc, aggregate, report
config/  defaults.yaml, sites/<dominio>.yaml, bots.yaml,
         bot_sources.yaml, attack_patterns.yaml
logs/<dominio>/         archivio .gz + _manifest.json     (gitignore)
data/<dominio>/         events/, enriched/, gsc.parquet,
                        ip_verdict.parquet, _parse_state.json
cache/                  ip_ranges.parquet, ip_sources/, dns.sqlite
input/<dominio>/        input esterni opzionali (sitemap.xml, ...)
errors/                 <dominio>_unparsed.log
output/                 report HTML
```

### Stack obbligato

| Libreria | Perché |
|---|---|
| **Polars** + **pyarrow** | milioni di righe; il parsing è vettoriale, non riga per riga |
| **tzdata** | su Windows `zoneinfo` non ha il database IANA e Polars fallisce anche solo su `time_zone="UTC"` |
| **numpy** | indice dei range IPv4 con `searchsorted` vettorializzato |
| **dnspython** | rDNS forward-confirmed |
| **requests**, **PyYAML** | fonti degli IP range, configurazione |
| **google-api-python-client**, **google-auth** | Search Console |
| **ECharts 5.5.1**, **Tabulator 6.3.1** | front-end; versioni pinnate con hash SRI |

### Convenzioni

- `argparse` a sottocomandi; **logging su stderr**, stdout resta pulito (i comandi stampano solo il percorso dell'artefatto).
- Configurazione: `config/defaults.yaml` fuso in profondità sotto `config/sites/<dominio>.yaml`. Nessuna regola di classificazione nel codice Python: stanno nei YAML.
- Se servisse `.env`: `dotenv_values()`, mai `load_dotenv()` — in multi-sito inquina `os.environ` e il secondo sito eredita le variabili del primo.

---

## 1. Get data

Scaricare tutti gli access log di nginx via SSH e salvarli in `logs/<dominio>/`.

Percorso tipico sul server `/var/log/nginx/`, pattern per sito (es. `evemilano_access.log*`). **Non usare `*access.log*`**: intercetta anche i log degli altri vhost sullo stesso server.

Prima di scegliere l'architettura, misurare il volume reale:

```bash
du -sh /var/log/nginx/
ls -la /var/log/nginx/*access.log*
zcat -f /var/log/nginx/*access.log* | wc -l
```

### Un file remoto è identificato dal contenuto, non dal nome

È la decisione portante dello stadio. logrotate rinumera gli archivi a ogni giro e le serie compressa e non compressa si intrecciano: `evemilano_access.log.2` copre nov–dic 2025 mentre `.2.gz` copre giu–lug 2026. **Indicizzare per nome fa riscaricare tutto a ogni run e compone una timeline sbagliata.**

L'identità è il **fingerprint md5 dei primi 4096 byte**. Il manifest locale `logs/<dominio>/_manifest.json` mappa fingerprint → `{remote_name, local_file, bytes_ingested, plain_bytes, remote_is_gzip, remote_mtime, fetched_at}`.

`rotate 8` cancella lo storico sul server: **l'archivio locale è la fonte di verità**, non il server.

### Trasferimento

Niente `rsync`: non c'è su Windows e non vale una dipendenza. Bastano ssh e le coreutils remote.

- Manifest remoto: uno script `bash -s` passato su stdin che per ogni file emette `path, size, mtime, md5 dei primi N byte, flag gz`. Il **flag gz si ricava dai magic bytes** (`1f8b`), non dall'estensione: convivono archivi ruotati compressi e non compressi con la stessa numerazione, e il nome non dice la verità.
- File nuovo già compresso: `cat`, si copia tale e quale — ricomprimerlo produrrebbe un doppio strato gzip illeggibile con una `gzip.open()` normale. File in chiaro: `gzip -c`, che su 100 MB ne trasferisce una decina.
- File attivo cresciuto: `tail -c +<ingested+1> | gzip -c` e si **appende il risultato all'archivio locale come nuovo membro gzip**. I membri concatenati restano un gzip valido.
- Scrittura su file temporaneo e sostituzione atomica alla fine; la decompressione in streaming serve insieme a validare l'integrità e a calcolare `plain_bytes`.
- Archivio remoto compresso che cresce, o file più piccolo di quanto già in archivio (rotazione `copytruncate`): riscaricare per intero.
- I valori di `dir` e `pattern` finiscono in una shell remota: validarli con una allowlist di caratteri prima di interpolarli.

### La deduplica è per intervallo di byte, mai per riga

Due righe identiche — stesso IP, stesso secondo, stesso URL — possono essere entrambe legittime. Scartarne una perderebbe un dato vero. Si deduplica su (fingerprint, byte già acquisiti).

### Configurazione del sito

`config/sites/<dominio>.yaml`:

```yaml
domain: evemilano.com
ssh:      { host: evemilano }          # alias di ~/.ssh/config: utente e chiave arrivano da lì
logs:     { dir: /var/log/nginx, pattern: "evemilano_access.log*" }
log_format: '$remote_addr - $remote_user [$time_local] "$request" ...'
timezone: Europe/Rome
site:     { scheme: https, host: www.evemilano.com }
sections: { root_label, other_label, probe_label, known: [...], overrides: [...] }
notes:    { assets_logged: false, excluded_from_log: ["/analytics/"] }
gsc:      { enabled, site_url, token_path }
```

---

## 2. Analizzare

### Il parser si genera dalla stringa `log_format`

Il formato va letto dalla direttiva `log_format` di nginx (o dichiarato per sito) e **compilato in regex**, così lo stesso codice serve siti con formati diversi senza toccare Python. I nomi riservati `combined` e `common` si espandono nella stringa corrispondente.

Per ogni `$variabile` il tipo di campo si deduce dai delimitatori: fra virgolette, fra parentesi quadre, oppure nudo. I gruppi devono essere `(?P<nome>...)`: è l'unica sintassi accettata sia dal modulo `re` di Python sia dal motore regex Rust di Polars, e la stessa stringa serve entrambi. Variabile ripetuta = errore di configurazione.

### Variabili del formato `combined`

| Variabile | Descrizione | Esempio |
|---|---|---|
| `$remote_addr` | IP client (IPv4 o IPv6) | `216.40.75.12`, `2001:4860:7:1718::fe` |
| — | letterale `-` (placeholder ident) | `-` |
| `$remote_user` | utente HTTP Basic Auth | `-` |
| `[$time_local]` | timestamp locale, `%d/%b/%Y:%H:%M:%S %z` | `[01/Sep/2026:15:42:56 +0200]` |
| `"$request"` | metodo + URI (con query string) + protocollo | `"GET /blog/google-dorking/ HTTP/2.0"` |
| `$status` | codice HTTP | `200`, `301`, `403` |
| `$body_bytes_sent` | byte del body, esclusi gli header | `41278` |
| `"$http_referer"` | referer | `"https://www.google.com/"` oppure `"-"` |
| `"$http_user_agent"` | user agent | `"Mozilla/5.0 (compatible; Googlebot/2.1; ...)"` |

### Regole di parsing

- **L'escaping non è il problema che sembra.** Nei campi fra virgolette nginx sostituisce `"` con `\x22`, `\` con `\x5C` e ogni byte non stampabile con `\xNN`: dentro un campo quotato non compare mai una virgoletta vera e la regex non ha ambiguità da risolvere. **Il problema sono gli spazi**: `$request` può contenerne più di due (`"GET /a b c HTTP/1.1"`), ed è il motivo per cui spezzare la riga sugli spazi — con `awk` o con `split()` — disallinea i campi su una parte del traffico.
- **Scomporre `$request`** in metodo / target / protocollo, con l'URI greedy fino all'ultimo spazio, poi il target in `path` e `query`. Ciò che non si scompone **non è un errore di parsing**: sono handshake TLS arrivati sulla porta 80, scanner con protocolli propri, richieste troncate. Vanno tenute, marcate `request_malformed`, e la richiesta grezza conservata **solo per quelle righe** — tenerla per tutte raddoppierebbe il Parquet senza aggiungere nulla.
- Il `-` sentinella di nginx diventa un null vero.
- Nei Parquet i campi restano come li ha scritti nginx. La conversione `\xNN` → byte serve solo dove il valore leggibile conta davvero (report, file degli errori): per un handshake TLS la forma `\x16\x03\x01` dice più del byte grezzo corrispondente.
- **Righe non parsabili: mai scartarle in silenzio.** Vanno in `errors/<dominio>_unparsed.log`, con contatore e percentuale sul totale riportati nel report. Sopra l'1% il log avvisa che il `log_format` potrebbe non corrispondere.
- **Parsing vettoriale.** L'archivio si legge come singola colonna di testo — separatore NUL, che nginx non può emettere — e la regex si applica in blocco con `str.extract_groups()`, che gira nel motore Rust. Su 7,9 milioni di righe è un ordine di grandezza rispetto a un ciclo con `re.match`.

### Storage

Parquet zstd partizionato per mese: `data/<dominio>/events/ym=AAAA-MM/<archivio>.parquet`. Colonne: `ts, ip, method, path, query, protocol, status, bytes, referer, user_agent, request_malformed, request_raw`.

Lo stadio è idempotente **per archivio**: `_parse_state.json` ricorda i `plain_bytes` già parsati e salta gli archivi invariati. Quando l'archivio attivo cresce viene **riparsato per intero**: costa pochi secondi ed evita la contabilità degli offset, che sarebbe l'unico punto della pipeline capace di duplicare righe in silenzio. Prima di riscrivere, i Parquet di quell'archivio si cancellano.

### Timezone

Il timestamp si parsa con l'offset scritto nel log e si **conserva in UTC**. La conversione all'ora locale del sito avviene **una volta sola**, in aggregazione. Farla avanti e indietro è dove nascono gli off-by-one sul giorno, e un periodo lungo contiene sempre un cambio di ora legale.

---

## 3. IP range e verifica dell'identità

Uno user agent è una stringa che il client sceglie: chiunque può scriverci "Googlebot". L'unica prova di identità è l'indirizzo IP.

### Store globale dei range

Un unico Parquet condiviso fra tutti i siti — gli IP di Googlebot sono gli stessi ovunque — con schema `cidr, ip_version, source_id, source_url, owner, category, bots, trust, fetched_at, from_snapshot`.

Le fonti stanno in `config/bot_sources.yaml`, ognuna con `id, url, parser, owner, category, trust, bots`. Il download è parallelo; ogni fonte viene validata (CIDR interpretabili) **prima** di scrivere lo snapshot locale in `cache/ip_sources/<id>.json`: non ha senso conservare come fallback una risposta che non sappiamo interpretare. Se il download fallisce si usa lo snapshot e lo si dichiara; se nessuna fonte è disponibile lo store non viene riscritto.

**`trust` decide se una fonte può produrre un `VERIFIED`:**

| trust | Significato |
|---|---|
| `identity` | il prefisso appartiene a quel crawler: prova l'identità |
| `hint` | il prefisso dice solo dove è ospitato l'IP, non chi è |

Il file di AWS contiene diecimila prefissi che coprono l'intera nuvola: "questo IP è su AWS, quindi è ClaudeBot" non è un'inferenza valida. Chi arriva solo da lì non diventa mai `VERIFIED`.

**Tre parser** coprono tutte le fonti note:

- `google_prefixes` — `{"prefixes": [{"ipv4Prefix"|"ipv6Prefix": "..."}]}`. È lo schema di Google, Bing, OpenAI, Anthropic, Perplexity, Apple, DuckDuckGo e Ahrefs: di fatto uno standard per la verifica dei crawler.
- `aws_prefixes` — `{"prefixes":[{"ip_prefix"}], "ipv6_prefixes":[{"ipv6_prefix"}]}`.
- `plain_cidr` — lista nuda di stringhe CIDR.

**Fonti verificate raggiungibili (2026-09-01):**

| id | URL | trust |
|---|---|---|
| `google_common` `google_special` `google_user_triggered` `google_user_triggered_google` `google_user_triggered_agents` | `developers.google.com/static/crawling/ipranges/{common-crawlers,special-crawlers,user-triggered-fetchers,user-triggered-fetchers-google,user-triggered-agents}.json` | identity |
| `bing` | `bing.com/toolbox/bingbot.json` | identity |
| `openai_gptbot` `openai_searchbot` `openai_chatgpt_user` `openai_chatgpt_agents` `openai_chatgpt_connectors` | `openai.com/{gptbot,searchbot,chatgpt-user,chatgpt-agents,chatgpt-connectors}.json` | identity |
| `anthropic` | `claude.com/crawling/bots.json` — lista unica, non distingue ClaudeBot da Claude-User: la distinzione la fa lo user agent | identity |
| `perplexity_bot` `perplexity_user` | `perplexity.ai/{perplexitybot,perplexity-user}.json` | identity |
| `apple` | `search.developer.apple.com/applebot.json` | identity |
| `duckduckgo` | `duckduckgo.com/duckduckbot.json` | identity |
| `ahrefs` | `api.ahrefs.com/v3/public/crawler-ip-ranges` | identity |
| `aws` | `ip-ranges.amazonaws.com/ip-ranges.json` | **hint** |

Gli URL cambiano nel tempo: per questo stanno in configurazione e per questo esiste lo snapshot di fallback.

Senza range pubblicati: **Baidu** (`*.crawl.baidu.com`, `*.baidu.jp`) e **Yandex** (`*.yandex.ru/.net/.com`) si verificano solo per rDNS; **Semrush** e **Bytedance** non hanno né range né PTR affidabile e restano `UNVERIFIABLE`.

### Il verdetto è per coppia (IP, bot dichiarato)

Non per IP: lo stesso indirizzo può ospitare un bot legittimo e uno che ne usurpa il nome. L'artefatto è `data/<dominio>/ip_verdict.parquet` con `ip, bot_id, ip_status, ip_owner`.

**Due metodi, con precedenza esplicita:**

1. **Match sui range ufficiali** — rapido, nessuna query di rete. Vale solo se la fonte che copre l'IP è fra quelle dichiarate dalla regola **e** ha `trust: identity`.
2. **rDNS forward-confirmed** — PTR dell'IP → il nome deve terminare con un suffisso atteso → risolvendo quel nome (A/AAAA) si deve tornare all'IP di partenza. Il doppio passaggio è ciò che rende il metodo affidabile: un PTR si può dichiarare, ma non si può far risolvere `googlebot.com` a un IP altrui.

**In caso di discordanza prevale l'esito negativo.**

Il costo è più basso di quanto sembri: il rDNS serve **solo** alle coppie la cui regola ha `rdns_suffixes` e che il match sui range non ha già risolto. Su 386.383 IP distinti sono qualche decina di migliaia al primo giro, quasi zero dopo.

**Cache persistente** `cache/dns.sqlite` — `(ip PRIMARY KEY, ptr, forward_ok, error, checked_at)` — condivisa fra tutti i siti, con TTL. Conserva PTR ed esito della conferma in avanti, che non dipendono dal bot che si sta verificando. Senza cache si generano milioni di query. Scrittura a blocchi durante la risoluzione, non solo alla fine.

Supportare IPv6 sia nel rDNS sia nel match dei range.

**Un NXDOMAIN (o NoAnswer) sul PTR non è un errore di lookup.** È una risposta definitiva: quell'IP non ha reverse. I crawler che si verificano per rDNS ce l'hanno sempre, quindi l'identità dichiarata è falsa. Va classificato `SPOOFED`, non `DNS_ERROR`, e tenuto distinto da un timeout, dove semplicemente non si è saputo.

### Tabella decisionale

Una regola è *verificabile* se dichiara `ip_sources` oppure `rdns_suffixes`.

| Condizione | Esito |
|---|---|
| regola non verificabile, categoria `Browser` | `NOT_APPLICABLE` |
| regola non verificabile, altre categorie | `UNVERIFIABLE` |
| PTR con suffisso sbagliato, conferma in avanti fallita, oppure NXDOMAIN | `SPOOFED` |
| match su fonte `identity` dichiarata dalla regola, **oppure** rDNS forward-confirmed | `VERIFIED` |
| lookup non riuscita (timeout, errore di risoluzione) | `DNS_ERROR` |
| `--no-dns` su una regola che richiede rDNS | `UNVERIFIABLE` |
| nessuno dei precedenti | `SPOOFED` |

Indice dei range: i prefissi di una singola fonte sono disgiunti, quindi per ogni fonte basta una lista ordinata di intervalli. IPv4 come interi a 64 bit con `searchsorted` numpy, vettorializzato su tutti gli IP in un colpo solo; IPv6 con `bisect` su interi Python, che reggono nativamente i 128 bit.

---

## 4. Clustering

Attributi da assegnare a ciascuna richiesta.

### Agent

Categorie: `Browser`, `Search engine bot`, `AI bot`, `AI Agents bot`, `Python bot`, `General bot`.

Le sei categorie sono un punto di partenza; per un'analisi SEO la distinzione che conta è la **sottocategoria** dei bot AI, che separa tre comportamenti economicamente diversi:

| subcategory | Categoria | Cosa fa | Esempi |
|---|---|---|---|
| `training` | AI bot | il contenuto finisce in un dataset di addestramento | GPTBot, ClaudeBot, Google-Extended |
| `answer-index` | AI bot | il contenuto alimenta l'indice di un motore di risposta | OAI-SearchBot, PerplexityBot |
| `on-demand` | AI Agents bot | non crawla: va a prendere una pagina che un utente ha chiesto ora | ChatGPT-User, Claude-User, Perplexity-User |

Le regole stanno in `config/bots.yaml`, mai nel codice:

```yaml
case_insensitive: true
fallback_bot_hint: 'bot|crawl|spider|slurp|scrape|fetch|http-?client|libwww|...'
fallback_bot:      { name: "Bot non riconosciuto", category: General bot }
fallback_browser:  { name: "Browser (altro)",      category: Browser }
no_user_agent:     { name: "Senza user agent",     category: General bot }
rules:
  - id: chatgpt_user                  # univoco, validato al caricamento
    ua_regex: 'ChatGPT-User'
    name: ChatGPT-User
    category: AI Agents bot
    subcategory: on-demand
    verify: { ip_sources: [...], rdns_suffixes: [...] }   # assente => UNVERIFIABLE
```

**L'ordine del file è l'ordine di valutazione e il primo match vince.** Non è estetica: `Googlebot-Image` deve precedere `Googlebot`, `AhrefsSiteAudit` deve precedere `AhrefsBot`, i fetcher on-demand devono precedere i crawler di training (altrimenti ChatGPT-User finisce classificato GPTBot), Edge e Opera devono precedere Chrome, che deve precedere Safari.

Vincoli da imporre al caricamento, perché la v1 li aveva violati tutti in silenzio: `id` univoco, categoria fra le sei previste, regex compilabile, e avviso se `ip_sources` cita una fonte inesistente in `bot_sources.yaml`.

Due dettagli implementativi che cambiano i numeri:

- **La classificazione si applica agli user agent distinti, non alle righe** (530k stringhe contro 7,45M righe), e il risultato torna sulle righe con una join.
- La join dev'essere **`join_nulls=True`**: l'1,6% delle richieste non ha user agent, e senza quel flag quelle righe escono con categoria a null e spariscono da ogni conteggio per categoria.

I browser vanno collassati a famiglia senza versione: tenerli per versione rende la dimensione inutilizzabile.

### IP Verified

| Stato | Significato |
|---|---|
| `VERIFIED` | rDNS o IP range confermano l'identità dichiarata |
| `SPOOFED` | lo UA dichiara un bot noto ma l'IP non corrisponde |
| `UNVERIFIABLE` | nessuna lista né rDNS disponibile per quel bot |
| `DNS_ERROR` | lookup fallita per timeout o errore di risoluzione |
| `NOT_APPLICABLE` | traffico browser, verifica non pertinente |

Calcolo in §3. Le righe senza verdetto dopo la join ricadono su `UNVERIFIABLE`.

### Sezione — allowlist, mai il primo segmento grezzo

Preso alla lettera, il primo segmento dell'URI ha **oltre 35.000 valori distinti**, quasi tutti inventati da scanner: una dimensione con quella cardinalità non è pivotabile. La sezione si deriva quindi in quest'ordine:

1. richiesta con `probe_family` → etichetta `(probe)`;
2. `overrides` per sito (regex → etichetta, primo match vince);
3. primo segmento **se è nella allowlist `known`**;
4. path vuoto → `(root)`, tutto il resto → `(other)`.

### Tipo risorsa

Non è il rapporto "HTML contro asset" di un'analisi classica: se il vhost ha `access_log off` sugli asset, quelli non compaiono nei log e il rapporto non è calcolabile. Il valore `asset` resta previsto per i siti che li loggano. Tassonomia, primo match vince: `malformed`, `robots`, `sitemap`, `feed`, `api`, `asset`, `php-endpoint`, `data`, `HTML`.

### Sonde di scanner e attacco

Una quota rilevante delle richieste sono probe. Su un sito WordPress pubblico `wp-login.php` prende centinaia di migliaia di richieste, e fra le estensioni più richieste dopo `.php` compaiono `.env`, `.sql`, `.bak`, `.key`. Senza separarle, "top URI" e "crawl waste" finiscono dominate da URL che non esistono e non interessano a nessuno.

**Il traffico si tiene e si marca, non si esclude dal dataset**: è metà delle richieste e dice cose vere sul sito. Regole in `config/attack_patterns.yaml`, primo match vince:

```yaml
rules:
  - id: env_files
    family: "File .env"
    attack: true                     # false = rumore non ostile (wp-cron, invio commenti)
    path_regex: '(?i)\.env($|[^a-z])|...'
    exclude_path_regex: '...'        # opzionale
    methods: [POST]                  # opzionale
    statuses: [400, 403, 404, 500]   # opzionale
```

Due colonne, non una: **`probe_family`** (qualunque sonda → esclusa dalle viste SEO) e **`is_attack_probe`** (solo ciò che è ostile → sezione sicurezza). Servono entrambe perché non tutto ciò che va escluso dalle viste SEO è un attacco: `wp-cron.php` è un endpoint interno di WordPress, rumore ma non ostilità.

Il motore regex di Polars **non supporta i lookahead**: i pattern vanno scritti senza. Le varianti codificate degli scanner (`/.env%09`, `/.envrc`, `/%2f.env%2eexample`) si coprono cercando il token seguito da un carattere che non sia una lettera.

Famiglie da coprire: file `.env`, repository esposti (`.git`, `.svn`), file di configurazione, chiavi e credenziali, backup e dump, exploit PHP, appliance VPN/firewall, pannelli di amministrazione, CGI e injection, brute force e ricognizione su `wp-login.php`, XML-RPC, sonde su `wp-includes`/`wp-content`, enumerazione plugin, `wp-cron`, invio commenti, e come ultima rete le sonde PHP generiche (eseguibile fuori dai percorsi noti + status di errore).

### `is_ua_anomaly` — uno user agent da browser non basta a dire "browser"

Su 13 mesi il singolo user agent più frequente di evemilano.com è un Chrome su macOS con 2.026.397 richieste da 7.748 indirizzi: 261 richieste per IP, concentrate in due mesi. È uno scraper travestito e da solo vale il **27% del traffico**. Senza separarlo, qualunque rapporto fra traffico umano e automatico è falsato di oltre un quarto e qualunque confronto anno su anno è privo di senso.

Il segnale è la **concentrazione**: `hit >= anomaly.min_hits` **e** `hit/IP >= anomaly.min_hits_per_ip`, applicato **solo** a chi si dichiara `Browser` — un bot dichiarato che fa molte richieste da pochi IP è semplicemente un bot. Chrome vero su questo sito sta a 17 richieste per indirizzo.

La colonna non è filtrabile nel report: è una proprietà della stringa UA, e come tale va dichiarata.

### Altri attributi

`has_query` — presenza o assenza di query string, per l'analisi di crawl waste.

Il dataset arricchito si riscrive per intero a ogni run in `data/<dominio>/enriched/ym=AAAA-MM/part.parquet`.

---

## 5. Integrazione Google Search Console

Aggiungere **click** e **impression** per URL, sullo **stesso periodo coperto dai log**, così le due fonti sono confrontabili.

**Il server MCP `gsc` non è invocabile da uno script Python**: è un canale per l'assistente, non una libreria. Si parla direttamente con l'API `searchconsole/v1`, riusando un token OAuth esistente (scope `webmasters.readonly`) il cui percorso è configurabile per sito. Se il token è scaduto e rinnovabile si rinnova e si riscrive; il flusso OAuth interattivo non ha senso in una pipeline che gira senza nessuno davanti allo schermo.

Query `searchanalytics`: `dimensions: [page, date]`, `type: web`, `dataState: all`, paginata a 25.000 righe. Artefatto `data/<dominio>/gsc.parquet` con `page, path, date, clicks, impressions, position, unconsolidated`.

- **Il join avviene su path normalizzato**: si tolgono fragment e query string, si toglie schema+host, si garantisce lo slash iniziale. Click e impression sono per pagina, non per variante parametrica.
- **GSC consolida i dati con qualche giorno di ritardo.** Le righe negli ultimi `gsc.data_delay_days` giorni si marcano `unconsolidated`: il report deve segnalarlo, altrimenti si leggono come un crollo del traffico.
- **Le impression sono aggregate per pagina e risultano ~9% più alte del totale di proprietà mostrato dall'interfaccia.** Non è un errore: con la dimensione `page` l'API passa in modalità `byPage`, e due URL dello stesso sito nella stessa SERP contano due impression invece di una. Verificato riga per riga contro l'API. Il report deve dichiararlo, altrimenti il confronto con la schermata di Search Console sembra un bug.
- **Se le credenziali non sono disponibili, le colonne e le sezioni relative si nascondono senza bloccare la generazione del report.**

---

## 6. Report

Report HTML di **tutto il traffico**, non solo i bot. Un solo file, autoconsistente a livello di dati: i cubi pre-aggregati finiscono in un blocco dentro la pagina e tutto il filtraggio avviene nel browser senza altre richieste. IP non anonimizzati, sempre completi.

Nome file: `log_analysis_<dominio con . → _>_<AAAAMMGG>-<AAAAMMGG>.html`, dove il periodo è quello **coperto dai dati**, non la data di generazione. Es. `log_analysis_evemilano_com_20250803-20260901.html`.

### 6.1 Il payload è uno star schema, non un ipercubo

Con milioni di righe il dataset grezzo non può stare in una pagina web. La struttura che ci sta dentro:

- **categoria** e **sottocategoria** sono attributi del bot, non assi propri;
- **sezione** e **tipo risorsa** sono attributi dell'**URL**, presi al valore **modale** delle sue richieste e ri-joinati sulle righe prima di costruire i cubi.

Il valore modale non è un dettaglio estetico. Se i cubi tenessero sezione e tipo per riga, sotto un filtro di sezione il grafico temporale conterebbe le richieste con quella sezione e la tabella URL gli URL la cui sezione modale è quella, con i loro hit totali: **due numeri diversi per lo stesso filtro**. (In Polars `.first()` dentro un `group_by` restituisce un elemento arbitrario: serve `.mode().first()`.)

Ogni cubo è **colonnare**: array paralleli di interi, con i valori sostituiti dagli indici dei dizionari. Pesa circa un terzo di un array di oggetti con le chiavi ripetute.

### 6.2 I cubi

| Cubo | Assi | Misure | Perché così |
|---|---|---|---|
| `main` | giorno, bot, verifica, status, sonda, sezione, tipo | hit, byte | l'asse portante: regge i widget temporali e la classifica degli status |
| `url` | URL, bot, verifica, classe status, sonda, **mese** | hit, byte | la data a livello di URL esiste solo al mese: misurato, senza tempo 94k celle, per mese 387k, per giorno oltre due milioni |
| `attack` | giorno, famiglia, bot, verifica, classe, sezione, tipo | hit, `~ui` | solo le sonde; il flag sonda lì è costante |
| `hour_dow` | ora, giorno settimana, bot, verifica, classe, sonda, sezione, tipo | hit | senza la data per costruzione: aggiungerla lo trasformerebbe nella tabella dei fatti |
| `day_bot` | giorno, bot, sonda | `~ui` | esiste solo per gli IP unici, che nessun altro cubo può dare |
| `tops.{ua,ip,referer}` | chiave, giorno, categoria, verifica, classe, sonda | hit, `~ui` | user agent, IP e referer non sono assi di nessun cubo |

`tops` serializza un **pool** di `top_pool` chiavi candidate e il front-end ne ri-ordina `top_n` sotto filtro. Il limite va dichiarato in pagina: una chiave fuori dal pool globale non può risalire in classifica. Per gli user agent il bot è un **attributo della chiave**, non un asse: così il filtro "user agent" vale anche lì senza moltiplicare le celle.

Top URI e top status **non** hanno un cubo dedicato: si ricalcolano da `url` e `main`, quindi ordinano l'intero dizionario invece di 25 voci congelate.

### 6.3 Le misure di unicità non sono additive

**URL unici e IP unici.** Sommare gli unici giornalieri sovrastima di 2–5×: lo stesso IP torna il giorno dopo. Nel payload il loro nome **comincia per `~`**, e il prefisso è un contratto: il riduttore del front-end **solleva un errore** se qualcuno prova a sommare una colonna che comincia così. Le uniche riduzioni lecite sono il massimo giornaliero e il totale di periodo precalcolato; **dove non sono ricavabili la pagina mostra un trattino, mai un'approssimazione**, e dice perché.

### 6.4 Dizionario degli URL

Non tutti gli URL ci stanno. La selezione ha una **priorità non negoziabile su due punti**: un URL in sitemap o con click da Search Console non viene mai scartato, per quanto poco traffico abbia. Sono esattamente quelli su cui il report deve poter dire "nessun bot lo ha mai visto".

Ordine: `in_sitemap` → click GSC → impression GSC → hit da bot verificati → hit di errore → resto → sonde. Si tengono i primi `url_dict_size`.

Tre accortezze che tengono esatti i totali:

- **La coda scartata diventa due righe di raccolta, non una**: sonde e non-sonde separate. Il filtro sonde è attivo di default, e con un solo sink i totali della tabella divergerebbero da quelli dei cubi appena lo si tocca.
- **Gli URL che Google conosce ma che nei log non compaiono affatto vanno aggiunti a mano**, con zero richieste: la tabella nasce dai log e da sola non può contenerli. Su evemilano sono 75 URL con impression che in 13 mesi nessuno — Googlebot compreso — ha mai richiesto, ed è precisamente ciò che la sezione sulla freschezza del crawl deve mostrare.
- **Le richieste malformate non hanno un path.** Lasciarle a null le fa sparire da ogni join (null non è uguale a null, in SQL come in Polars) e il cubo per URL smette di tornare con quello principale. Serve una voce dichiarata, `(richiesta malformata)`.

Per lo stesso motivo gli **attributi ignoti hanno voci di dizionario vere** — `(mai nei log)`, `(aggregato)` — e non l'indice `-1`: in JavaScript `mask[-1]` è `undefined`, cioè falso, e quelle righe sparirebbero sempre in silenzio.

### 6.5 Budget e degradazione

Il peso si stima **prima** di serializzare. **La regola che non si viola mai: i totali restano esatti, la granularità no.** Ogni troncamento lascia una riga sink che conserva hit e byte, e **la degradazione si dichiara in pagina**.

Il payload porta tutti gli assi del filtro su ogni cubo, e per questo il tetto realistico è di **24 MB di JSON**, non 5. Il *file* resta piccolo perché il JSON si incorpora **gzip + base64** e si decomprime con `DecompressionStream('gzip')` al caricamento: questi interi comprimono ~7×, e senza compressione il file passerebbe da ~3 a ~19 MB. Le due leve per rientrare nel tetto sono `report.url_dict_size` (i cubi per URL scalano linearmente) e `report.top_pool`.

Ordine dei blocchi in fondo alla pagina: **payload → definizione del codice → avvio**. Il codice legge il payload alle prime righe, quindi l'ordine non è indifferente.

### 6.6 Il filtraggio incrociato ha limiti strutturali, e la pagina li dichiara

Con dati pre-aggregati un filtro agisce su un widget solo se la dimensione filtrata è un asse del cubo che lo alimenta, o un attributo di uno dei suoi assi. Alcune combinazioni non sono rappresentabili: "quanti hit ha preso l'URL X il 12 marzo" richiederebbe un cubo URL × giorno da milioni di celle.

Perciò **gli assi di ogni cubo viaggiano nel payload** (`meta.axes`) e ogni widget dichiara il cubo che lo alimenta: il front-end **deriva** l'avviso invece di averlo scritto a mano in ogni widget. Se una leva di budget togliesse un asse, l'avviso ricomparirebbe da solo. Tre forme distinte, che dicono cose diverse:

- ⚠ *filtri non applicati qui: …* — il cubo non ha quelle dimensioni;
- *intervallo arrotondato al mese* — applicato, ma a grana più grossa;
- *perimetro fisso: …* — il widget guarda per definizione un sottoinsieme (solo sonde, solo IP verificati, solo URL noti a Google). Non è un avviso, è una descrizione.

**Mostrare numeri non filtrati senza dirlo è l'unica cosa che questo report non deve fare.**

### 6.7 Autoverifica

`meta.selftest` porta una manciata di stati di filtro con hit e byte **calcolati in Polars riga per riga**. Al caricamento la pagina li fa girare nel proprio riduttore e li confronta. È l'unico controllo che attraversa il confine fra i due linguaggi: tutti gli altri ne verificano un lato solo, e un errore di codifica degli assi passerebbe inosservato proprio perché ogni lato è coerente con sé stesso. Se un numero non torna, **la pagina lo dice** invece di mostrare in silenzio un totale sbagliato.

### 6.8 Front-end

CSS e JS da cloud, con versione pinnata e hash SRI; `--inline-libs` li incorpora. Tabelle Tabulator, grafici ECharts.

- **Le colonne dei cubi diventano TypedArray una volta sola.** Le **misure vanno in `Float64Array`, mai in `Int32Array`**: la somma dei byte di un giorno per un bot supera i 2,1 miliardi e andrebbe in overflow silenzioso — nessun errore in console, solo totali sbagliati. Gli **indici** invece si dimensionano sulla cardinalità del dizionario (`Uint8`/`Uint16`/`Int32`): su 860.000 celle è la differenza fra ~10 e ~45 MB di heap.
- **Indice di offset sulla colonna di testa**, che è ordinata: trasforma il filtro su quell'asse in uno slice contiguo invece di una scansione con branch. Trascinare l'intervallo di date è il gesto più frequente della pagina.
- **Una passata di riduzione per cubo, non per widget.** Oltre a costare cinque volte tanto, riscansionare lo stesso cubo in widget diversi è il modo in cui due numeri che devono coincidere divergono.
- **I grafici seguono il fotogramma (`requestAnimationFrame`), le tabelle no** (debounce ~140 ms): ricostruire 12.000 righe di Tabulator costa più di tutte le riduzioni messe insieme, e mentre si trascina uno slider non serve a nessuno.
- **Aritmetica di calendario, mai di fuso.** `new Date('2025-08-03T00:00:00')` è mezzanotte locale, ma `toISOString()` la riporta in UTC: a est di Greenwich il giorno stampato è quello prima. Date sempre costruite e formattate dai componenti locali.
- Il **colore segue l'entità, mai la posizione in classifica**: l'indice del dizionario è stabile, quindi un filtro che riduce le serie non ridipinge quelle rimaste. Otto tinte categoriali in ordine fisso mai ciclato; i colori di stato riservati alla verifica degli IP e sempre accompagnati da icona ed etichetta; una sola scala per asse; tema chiaro/scuro; formattazione numerica italiana.

### 6.9 Sezioni della pagina

| Sezione | Contenuto | Perimetro |
|---|---|---|
| KPI | richieste, byte, IP unici, URL unici, quota sonde, quota UA anomali — **tutti reattivi al filtro** | `main` |
| Note | asset non loggati, path esclusi dal log, aggregazione GSC per pagina, UA anomali, degradazione, righe non parsate | — |
| Traffico nel tempo | crawl budget: aree impilate per categoria di agente, con zoom sull'asse | `main` |
| Identità dichiarata e verificata | barre impilate per bot con gli esiti della verifica | `main`, esclusi i `NOT_APPLICABLE` |
| Tabella pivot + grafico collegato | dimensione a scelta fra user agent, categoria, verifica, status; misure hit, quota, byte, IP unici | `main` |
| Status dei bot verificati | classi di status per bot: 4xx e 5xx qui sono crawl budget buttato via | solo `VERIFIED` |
| Tabella URL | sezione, tipo, hit, byte, IP unici, click e impression GSC, primo e ultimo hit, giorni dall'ultimo Googlebot verificato | `url` |
| Freschezza del crawl Googlebot | quanti URL **noti a Google** non ricevono una visita da oltre N giorni, e quante impression valgono | URL in sitemap o con impression; solo Googlebot verificato, totale di periodo |
| Copertura AI | URL **distinti** raggiunti da ciascun agente AI, con la sottocategoria nel tooltip | `url`, categorie da `report.ai_categories` |
| Distribuzione oraria | heatmap ora × giorno della settimana, ora locale del sito | `hour_dow` |
| Sonde e attacchi | famiglie di sonda nel tempo | solo traffico con `probe_family` |
| Classifiche | top URI, user agent, IP, referer, status; clic su una riga ne mostra l'andamento temporale | vedi 6.2 |

Due scelte della sezione sulla freschezza vanno rispettate. L'universo **non sono tutti gli URL osservati**: sui log di un sito pubblico la maggior parte dei percorsi se li inventano gli scanner e Googlebot non ha ragione di chiederli — contano gli URL che **Google conosce**. E la barra misura il **numero di URL**, non le impression: con le impression la fascia "entro 30 gg" ne vale milioni e schiaccia a zero proprio le fasce che la sezione deve far vedere.

Il rapporto **HTML vs asset per bot** va nascosto quando il sito non logga gli asset (`notes.assets_logged: false`): non è calcolabile, e una sezione vuota è peggio di una sezione assente.

### Filtri dinamici

Su: intervallo di date, sonde (escluse / incluse / solo), categoria agente, user agent, stato di verifica IP, classe di status, sezione, tipo risorsa. Cross-filtering: la selezione aggiorna tutti i widget, **entro i limiti dichiarati in 6.6**.

Le sonde sono **escluse di default**: è la vista SEO. Un contatore accanto a ogni gruppo dice cosa è selezionato senza dover risalire con lo scorrimento.

### Input esterni opzionali

In `input/<dominio>/`: `sitemap.xml` (anche più d'uno), export Screaming Frog, dati GSC. Se mancano, le sezioni che ne dipendono si nascondono senza generare errori.

---

## 7. Parametri da fissare

`config/defaults.yaml`, sovrascrivibili per sito.

| Chiave | Default | Nota |
|---|---|---|
| `report.googlebot_stale_days` | 30 | soglia iniziale della sezione freschezza |
| `report.json_budget_bytes` | 25165824 (24 MB) | il payload porta tutti gli assi su ogni cubo |
| `report.compress_payload` | true | gzip+base64; senza, il file passa da ~3 a ~19 MB |
| `report.top_n` | 25 | lunghezza delle classifiche |
| `report.top_pool` | 75 | chiavi candidate serializzate; 25 → 35k celle, 150 → 156k |
| `report.url_dict_size` | 12000 | i cubi per URL scalano linearmente |
| `report.ai_categories` | `[AI bot, AI Agents bot]` | quali categorie la sezione AI considera proprie |
| `report.window` | `all` | `all` (tutto l'archivio) oppure `latest` (solo il log più recente) |
| `report.compare_previous_period` | true | *dichiarato, widget non ancora implementato* |
| `dns.cache_ttl_days` | 30 | |
| `dns.timeout_seconds` | 3 | |
| `dns.max_workers` | 50 | |
| `dns.retries` | 2 | tentativi prima di dichiarare `DNS_ERROR` |
| `anomaly.min_hits` | 10000 | soglia di `is_ua_anomaly` |
| `anomaly.min_hits_per_ip` | 50 | Chrome vero sta a 17, lo scraper travestito a 261 |
| `gsc.data_delay_days` | 3 | giorni marcati non consolidati |
| `fetch.fingerprint_bytes` | 4096 | byte usati per l'identità di un file remoto |
| `fetch.ssh_timeout_seconds` | 600 | |

`--latest` stabilisce "più recente" **dal contenuto**, non dal nome del file: la numerazione della rotazione non è cronologica.

---

## 8. Punti chiusi e cosa resta aperto

Risolti misurando, non ipotizzando:

1. **Volume** — 7,9M righe / ~1 GB su 13 mesi, 386k IP distinti, 107k path, 530k user agent. Polars + Parquet bastano; DuckDB non serve.
2. **Quanti siti e server** — un file di configurazione per sito, con credenziali e formato di log propri. Store degli IP range e cache DNS condivisi fra tutti.
3. **Report cross-sito** — non necessario con un sito solo. Le pre-aggregazioni restano indicizzate per dominio, così aggiungerlo dopo non impone un rifacimento.

Previsto dallo spec ma **non implementato**, da tenere presente:

- **Tempo di risposta** — richiede `$request_time` o `$upstream_response_time` nel `log_format`; con `combined` il dato non esiste. La sezione va costruita solo se il formato del sito lo porta.
- **Confronto periodo su periodo** del crawl budget — parametro dichiarato, widget assente.
- **Orphan URL** in senso stretto (crawlati dai bot ma assenti in sitemap) — la sitemap alimenta la priorità di selezione degli URL e l'universo della sezione freschezza, ma non esiste una vista dedicata.
- **Crawl waste** è implementato come classi di status per bot verificato; `has_query` è calcolato ma non arriva nel report.
- **Stato dei filtri nell'URL** della pagina, per condividere una vista filtrata.
