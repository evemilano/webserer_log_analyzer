# logAnalyzer2 — analisi log nginx multi-sito con report HTML

> **Stato: implementato e verificato su evemilano.com.** Tutti e nove i blocchi della checklist in fondo sono chiusi, ognuno con il suo gate superato. La pipeline completa gira in ~65 s a caldo e produce un report da 3,45 MB su un tetto di 5.
>
> Documenti collegati: [`prompt.md`](prompt.md) (specifica), [`_requisiti.md`](_requisiti.md) (vincoli di base), [`CLAUDE.md`](CLAUDE.md) (comandi e insidie).

## Context

`logAnalyzer2/` conteneva solo `prompt.md` e `requisiti.md`. Va costruito da zero l'applicativo che lo spec descrive: scarico incrementale degli access log nginx via SSH, parsing, verifica identità dei bot, clustering, join con Google Search Console e report HTML statico autoconsistente.

Esiste un predecessore, `logAnalyzer/` (v1): una web-app Flask con upload manuale del file di log. Architettura diversa e non riusabile in blocco, ma contiene tre pezzi di sostanza da riprendere: lo schema data-driven di `bot_mappings.csv`, il fetch parallelo degli IP range di `files/ip_manager.py`, e la regex Combined di `files/log_parser.py`.

### Cosa è stato misurato sul server (e cosa cambia rispetto a `prompt.md`)

Il server è stato interrogato via `ssh evemilano` prima di progettare. Cinque risultati modificano lo spec:

1. **Volume: 7,9M righe, ~1 GB.** `evemilano_access.log*` = 7,4M righe; `searcus_access.log` = 412k. Copertura continua **ago-2025 → set-2026** (~395 giorni). 386.347 IP client unici, 107.406 path unici, 529.948 user agent distinti. Risponde al punto aperto §8.1: Polars + Parquet bastano, DuckDB non serve.

2. **La numerazione della rotazione non è cronologica.** logrotate gira su `size 100M` con `delaycompress`, e le due serie si intrecciano: `evemilano_access.log.2` copre nov–dic 2025 mentre `.2.gz` copre giu–lug 2026. Ordinare per nome file darebbe una timeline sbagliata. Inoltre `rotate 8` cancella lo storico: **l'archivio locale è la fonte di verità**, non il server.

3. **Gli asset non sono loggati.** Nel vhost `evemilano` le location `\.(css|js|eot|woff|ttf|jpg|jpeg|png|webp|gif|svg|ico|mp4|...)$` hanno `access_log off`. Verificato: 8 richieste asset su 122.000. La sezione **"Rapporto HTML vs asset per bot" di §6 non è calcolabile** e va sostituita; anche la dimensione "tipo risorsa" ha poco da dire.

4. **Il traffico di scanner/attacco domina.** `wp-login.php` 675k hit, `wp-cron.php` 454k, poi `/ssl-vpn`, `/global-protect`, `.env`, `/config`, `/vendor`. Il 38% delle richieste finisce su `.php`. Effetto collaterale importante: i primi segmenti URI distinti sono **35.239** — se la "sezione" è il primo segmento grezzo, la dimensione è inutilizzabile. Serve allowlist per sito + `(other)`.

5. **`combined`, non `timed_combined`.** Il vhost usa `access_log ... combined if=$loggable_request`, con `/analytics/` escluso dal log via `map`. Nessuna CDN davanti, quindi `$remote_addr` è l'IP reale (coerente con `requisiti.md`).

Altre due cose: un singolo UA `Chrome/151` fa il 23% del traffico del file corrente — quasi certamente uno scraper mascherato, meritevole di una sua analisi. E 2.616 righe su 122k hanno `$status` fuori posto: sono handshake TLS sulla porta 80 loggati come richiesta malformata, da isolare e non scartare.

### Decisioni prese

- **Scope**: solo `evemilano.com`, ma con architettura multi-sito predisposta — un file di config per sito.
- **GSC**: API diretta riusando il token OAuth esistente. Il server MCP `gsc` non è invocabile da uno script Python.
- **Scanner/attacco**: taggato per riga, filtrabile ed escludibile.
- **Finestra**: tutti i log presenti nell'archivio (`--all`, default) oppure solo il file più recente (`--latest`).

---

## Architettura

```
logAnalyzer2/
├── amb/                              # venv (convenzione del repo)
├── config/
│   ├── sites/evemilano.com.yaml      # un file per sito
│   ├── bots.yaml                     # UA → categoria/sottocategoria + strategia di verifica
│   ├── bot_sources.yaml              # sorgenti degli IP range
│   ├── attack_patterns.yaml          # regole is_attack_probe
│   └── defaults.yaml                 # i default di prompt.md §7
├── logs/<domain>/                    # archivio raw .gz + _manifest.json
├── data/<domain>/
│   ├── events/ym=YYYY-MM/*.parquet   # parsato
│   ├── enriched/ym=YYYY-MM/*.parquet # classificato + verificato + arricchito
│   └── gsc.parquet
├── cache/
│   ├── ip_ranges.parquet             # store globale CIDR → owner/bot/categoria/fonte/data
│   ├── ip_sources/*.json             # snapshot di fallback
│   └── dns.sqlite                    # IP → verdetto rDNS, TTL, condivisa tra siti
├── input/<domain>/                   # sitemap.xml, export Screaming Frog (opzionali)
├── errors/<domain>_unparsed.log
├── output/
├── credenziali/                      # token GSC (gitignored)
├── loganalyzer/                      # package
│   ├── cli.py fetch.py logformat.py parse.py ipranges.py verify.py
│   ├── classify.py enrich.py gsc.py aggregate.py report.py
│   └── templates/report.html
├── main.py
├── requirements.txt
└── CLAUDE.md
```

**Convenzioni ereditate dal repo** (verificate): venv `amb/`, `argparse` a sottocomandi, `logging.basicConfig(..., stream=sys.stderr)` per lasciare stdout pulito, `dotenv_values()` **mai** `load_dotenv()` (in un applicativo multi-sito `load_dotenv` inquina `os.environ` e il secondo sito eredita le variabili del primo — regola presa da `wpmanager_clienti/wpmanager/config.py`).

**YAML invece di `config.py`**: il repo non usa YAML da nessuna parte, ma `prompt.md` li nomina esplicitamente (`sites.yaml`, `bots.yaml`, `bot_sources.yaml`) e sono dati, non codice — le regole bot devono essere modificabili senza toccare Python. Deviazione consapevole dalla convenzione.

**Regola del `CLAUDE.md` di root**: i sottoprogetti sono repo separati. Il codice riusato da `logAnalyzer/` e da `evemilano_ai_manager/` va **copiato** dentro `logAnalyzer2/`, mai importato cross-cartella.

**Dipendenze** (`requirements.txt`, con versioni pinnate — la v1 non le aveva): `polars`, `pyarrow`, `dnspython`, `requests`, `PyYAML`, `python-dotenv`, `google-api-python-client`, `google-auth`, `google-auth-oauthlib`. Polars e pyarrow sono nuove per il repo, che oggi è pandas-only: la giustificazione è il parsing vettoriale di 7,9M righe.

### Pipeline

Sette stadi, ognuno idempotente e con un artefatto proprio. Sottocomandi CLI:

```
main.py fetch    --site evemilano.com
main.py parse    --site evemilano.com
main.py ipranges refresh
main.py verify   --site evemilano.com
main.py enrich   --site evemilano.com
main.py gsc      --site evemilano.com
main.py report   --site evemilano.com [--all | --latest]
main.py run      --site evemilano.com [--all | --latest]   # tutto in sequenza
```

---

## Dettaglio degli stadi

### 1. `fetch.py` — trasferimento incrementale senza rsync

`rsync` **non è installato** su Windows (verificato: assente sia da PATH sia da Git Bash) e la preferenza è per soluzioni zero-install. Si usa `ssh` + coreutils remoti, che ottengono lo stesso risultato con meno attrito:

- **Manifest remoto**: `stat -c '%s %Y'` + `head -c 4096 <f> | md5sum` per ogni file del glob. L'identità di un file è `(md5 dei primi 4 KB, dimensione)`.
- **La rinumerazione della rotazione non causa ri-download**: l'archivio è indicizzato per fingerprint, non per nome remoto.
- **File live cresciuto, stesso fingerprint** → scarica solo la coda: `ssh <host> "tail -c +$((offset+1)) '<f>' | gzip -c"`, appeso al `.gz` locale. I membri gzip concatenati sono un file gzip valido e `zcat` li legge in sequenza (verificato).
- **File nuovo** → `ssh <host> "gzip -c '<f>'"` in locale (compressione in transito).
- **Ledger** `logs/<domain>/_manifest.json`: fingerprint → `{remote_name, bytes_ingested, local_file, first_ts, last_ts}`.
- **Dedup esatto per (fingerprint, byte range)**, non per riga. Righe identiche possono essere legittime (stesso IP, stesso secondo, stesso URL): un dedup a livello di riga perderebbe dati veri.

### 2. `logformat.py` + `parse.py`

Il parser si **genera dalla stringa `log_format`** dichiarata in `config/sites/<domain>.yaml` (per evemilano: `combined`), così è riusabile su siti con formati diversi.

Costruzione della regex per token: `"$var"` → `"((?:[^"\\]|\\.)*)"`, `[$time_local]` → `\[([^\]]+)\]`, `$var` nudo → `(\S+)`. nginx escapa `"` in `\x22`, quindi non c'è ambiguità reale, ma la regex tollerante evita sorprese. Dopo l'estrazione, decodifica delle sequenze `\xNN` in `request`, `referer`, `user_agent`.

Parsing vettoriale in **Polars**: le righe entrano in un `DataFrame` e `str.extract_groups()` applica la regex in Rust. Su 7,9M righe è un ordine di grandezza più veloce di un loop Python con `re.match`.

- Righe senza match → `errors/<domain>_unparsed.log`, con contatore e percentuale sul totale riportati nel report (§2 dello spec).
- `request` malformata (handshake TLS: `"\x16\x03\x01..."`) → `resource_type = malformed`, **non** scartata.
- `time_local` → `str.to_datetime("%d/%b/%Y:%H:%M:%S %z")` → **storage in UTC** (la conversione in ora locale avviene una volta sola in `aggregate.py`, vedi "Due scelte esplicite").
- Output partizionato `data/<domain>/events/ym=YYYY-MM/`, compressione zstd, `Categorical` su status/method/section.

### 3. `ipranges.py` — store globale di mapping IP

`config/bot_sources.yaml` elenca le sorgenti di `prompt.md` §3 con `{url, parser, owner, bot, category, trust}`. Parser previsti: `google_prefixes` (`prefixes[].ipv4Prefix|ipv6Prefix`), `bing`, `openai`, `aws`, `plain_cidr`.

Download parallelo (`ThreadPoolExecutor`, pattern preso da `logAnalyzer/files/ip_manager.py`), validazione dello schema, snapshot in `cache/ip_sources/` usato come fallback se il download fallisce.

Normalizzazione in **un unico store** `cache/ip_ranges.parquet`: `cidr, ip_version, lo, hi, owner, bot_name, category, source_url, fetched_at, trust`.

`trust` ha due valori: `identity` (la fonte prova l'identità) e `hint`. **Il range AWS generico è `hint`**: non produce mai `VERIFIED`, solo un indizio, come richiede lo spec.

### 4. `verify.py`

**Match sui range**: i 386k IP unici vengono convertiti in interi e cercati con `bisect` su liste ordinate di intervalli (v4 e v6 separate). È dell'ordine del secondo; il risultato torna in Polars come join. IPv6 supportato nativamente perché il confronto avviene sui 128 bit dell'indirizzo impacchettato.

**rDNS forward-confirmed**: PTR → il suffisso deve corrispondere a quelli attesi in `bots.yaml` → risoluzione A/AAAA che deve riportare all'IP di partenza. Eseguito **solo** per gli IP il cui UA dichiara un bot con `rdns_suffixes` configurati e per cui il match sui range non ha già dato un esito `identity`. `dnspython`, `ThreadPoolExecutor(max_workers=50)`, timeout 3 s, 2 retry.

Il carico è più basso di quanto suggeriscano i 386k IP unici: gli IP con UA riconducibile a un bot sono **49.597**, e da questi vanno tolti Google, Bing, OpenAI, Anthropic e Perplexity, che pubblicano i range e si risolvono senza una query DNS. Restano nell'ordine delle decine di migliaia al primo run (Baidu, Yandex, Ahrefs, Semrush, Apple, …), e quasi zero dai run successivi grazie alla cache.

**Cache** `cache/dns.sqlite` (`ip TEXT PRIMARY KEY, ptr, forward_ok, checked_at, error`), TTL 30 giorni, **condivisa tra tutti i siti**. Senza cache si generano milioni di query DNS.

**Verdetto**: `VERIFIED` / `SPOOFED` / `UNVERIFIABLE` / `DNS_ERROR` / `NOT_APPLICABLE`. Se i due metodi discordano **prevale l'esito negativo**, come richiede lo spec.

### 5. `classify.py` — `bots.yaml`

Regole valutate **nell'ordine del file**, primo match vince, fallback esplicito. Struttura:

```yaml
fallback_bot:   {name: "Unknown bot", category: "General bot"}
fallback_human: {name: "Browser",     category: "Browser"}
rules:
  - id: gptbot
    ua_regex: "(?i)\\bGPTBot\\b"
    name: GPTBot
    category: "AI bot"
    subcategory: training           # training | answer-index | on-demand
    verify: {ip_sources: [openai_gptbot]}
  - id: chatgpt_user
    ua_regex: "(?i)ChatGPT-User"
    name: ChatGPT-User
    category: "AI Agents bot"
    subcategory: on-demand
  - id: googlebot
    ua_regex: "(?i)Googlebot"
    name: Googlebot
    category: "Search engine bot"
    verify: {ip_sources: [google_common], rdns_suffixes: [".googlebot.com", ".google.com"]}
```

Le sei categorie di §4 restano, ma la distinzione che conta è dentro **AI bot**: `training` (GPTBot, ClaudeBot, Google-Extended), `answer-index` (OAI-SearchBot, PerplexityBot), `on-demand` (ChatGPT-User, Claude-User, Perplexity-User).

Seed dai 38 bot di `logAnalyzer/bot_mappings.csv`, **con le anomalie corrette**: `meta-externalagent` è duplicato con due `ip_key` diversi (la verifica Facebook viene silenziosamente persa), `Facebookbot`/`GPTBot`/`Meta-ExternalAgent` collidono come chiavi, e i pattern `omgili|omgilibot` e `screaming frog` contengono metacaratteri/spazi che rompono il lookup nella v1. Da rifare puliti, non da copiare.

### 6. `enrich.py`

- **`section`**: primo segmento URI **filtrato da allowlist per sito** (`sections.known` + override regex in `sites/<domain>.yaml`); tutto il resto → `(other)`. Senza questo la dimensione ha 35.239 valori distinti ed è inutile. Per evemilano il seed è `blog, (root), feed, wp-content, about-me, wp-admin, wp-json, servizi-seo, corsi, guide-seo, pubblicita-google, ai, contatti, category, …`.
- **`resource_type`**: `HTML / feed / sitemap / robots / api / php-endpoint / malformed / other`. **Non** HTML-vs-asset: gli asset non sono loggati.
- **`has_query`** + parametri normalizzati, per il crawl waste.
- **`is_attack_probe`** + `probe_family`: regole in `config/attack_patterns.yaml` — path noti (`.env`, `.git`, `wp-config`, `xmlrpc.php`, `/vendor/phpunit`, `/ssl-vpn`, `/global-protect`, estensioni `.sql|.bak|.old|.key|.yml`), brute force (`POST wp-login.php` ad alta frequenza per IP), raffiche di 4xx dallo stesso IP.
- **`is_ua_anomaly`**: UA browser con volume sproporzionato e referer sempre vuoto — il caso dell'UA Chrome/151 al 23%.

### 7. `gsc.py`

Riuso del pattern di autenticazione di `evemilano_ai_manager/skills/_gsc_api.py` (`authenticate()`, `resolve_site_url()`, `query_gsc()` con paginazione), **copiato** nel progetto. Token path configurabile in `sites/<domain>.yaml`, default `_MCP Servers/GSC_MCP/credenziali/token.json` (scope `webmasters.readonly`, già valido per `sc-domain:evemilano.com`).

- Query `dimensions=["page","date"]`, periodo = min/max effettivi dei log, così log e GSC sono temporalmente coerenti.
- Join su URL normalizzato: schema + host lowercase + path, trailing slash uniformato, query rimossa.
- `DATA_DELAY_DAYS = 3`: gli ultimi 3 giorni della finestra sono marcati **"GSC non consolidato"** nel report, per non far leggere il buco come un calo.
- Token assente → colonne e sezioni GSC nascoste, generazione del report non bloccata.

### 8. `aggregate.py` + `report.py`

Base di partenza: **`ReportBuilder`** da `evemilano_ai_manager/skills/link-graph/_report.py` (868 righe, copiato e adattato) — builder fluente, CSS/JS inline, `add_section` / `add_summary` / `add_table` / `add_html`, tabelle con sort numerico corretto via `data-sort`, e il trucco di caricare la libreria dei grafici **solo alla prima chiamata**. Da lì si sostituisce il layer grafici e si aggiunge il cross-filtering.

Da `seoDATA-report gen/skills/_html_report.py` si riprende `parse_number()` e il gemello JS `parseLocaleNumber()` — risolve il sort lessicografico su numeri formattati all'italiana.

Filename: `log_analysis_evemilano_20250803-20260901.html` — periodo coperto, non solo data di generazione.

---

## Modello dati del report

Il vincolo dei **5 MB di JSON** con 395 giorni, 107.406 path unici e 529.948 UA distinti è ciò che determina tutta la struttura. Cinque decisioni la reggono:

1. **Star schema, non ipercubo.** `categoria` e `sottocategoria` sono attributi di `bot`, non assi. `sezione`, `tipo risorsa`, `is_attack_probe`, `has_query` sono attributi di `url`, non assi. Da 9 assi teorici a **4 assi reali** (data × bot × verifica × status): due ordini di grandezza di celle in meno.
2. **Browser collassati a famiglia** (Chrome/Safari/Firefox/Edge/Samsung/Opera/Other), senza versione. È obbligatorio: **529.948 UA distinti** misurati. `D_bot` scende a ~140 voci. Le UA grezze sopravvivono solo nel widget Top-25.
3. **Probe normalizzati in ~40 famiglie** (`PROBE:env`, `PROBE:wp-config`, `PROBE:xmlrpc`, …), invece di decine di migliaia di path randomici. Libera gli slot di `D_url` per gli URL reali.
4. **Encoding colonnare**: array paralleli di interi invece di array di oggetti. ~12 B/cella invece di ~38.
5. **Nessuna lista IP nel JSON.** 386.347 IP × 19 B sarebbero **7,3 MB da soli**. Si tengono i top 500; gli "IP unici" sono contatori precalcolati.

### Dizionari e cubi

Dizionari (`bot`, `cat`, `ver`, `status`, `section`, `restype`, top IP/referer/UA) ≈ **40 KB**. L'asse `date` si salva come `start` + numero di giorni e si ricostruisce in JS: 30 B invece di 5,1 KB per asse.

`D_url` è la dimensione costosa. Selezione deterministica di 12.000 slot, in quest'ordine: URL in sitemap/Screaming Frog → URL con impression GSC > 0 → URL con almeno un hit da bot `VERIFIED` Search/AI → top per hit → top 1.500 con 4xx/5xx (garantisce i 404 di Googlebot) → top 500 probe individuali. **Mai** scartare un URL in sitemap o con click GSC. Il resto confluisce in `__url_other__` con hit e byte aggregati. ~86 B/URL → **1.030 KB**.

| Cubo | Assi | Misure | Peso |
|---|---|---|---|
| **F1** `f_dbvs` | data × bot × verifica × status | hit | 1.310 KB |
| **F2** `f_day_bot` | data × bot | hit, byte, IP unici/giorno | 378 KB |
| **F5** `f_url_grp` | url × botgroup(12) | hit, last_seen, status | 430 KB |
| **F3/F4/F6-F11** | bot×sezione, data×sezione, url×errori, ora×dow, top-25, period-over-period, attacchi, GSC | — | 690 KB |
| Dizionari + `D_url` + meta | | | 1.074 KB |
| | | **totale stimato** | **~3,7 MB** |

**F1 è la spina dorsale del cross-filtering**: l'unico cubo che regge simultaneamente data + bot + categoria + verifica + status. Deliberatamente non contiene né byte né unici (li porterebbe da 12 a 25 B/cella) né sezione/URL (moltiplicherebbe le celle per ~8).

### Scala di degradazione

Il generatore **non** serializza e poi misura: calcola le cardinalità reali dal Parquet **prima**, stima il peso, e sale nella scala finché non rientra nel budget. Livelli cumulativi:

| L | Azione | Cosa si perde |
|---|---|---|
| L1 | prefix folding sui path + packing varint base-64 | nulla (lossless) |
| L2 | `D_url` 12.000 → 6.000 | coda lunga della tabella URL |
| L3 | F1 giornaliero sugli ultimi 90 gg, settimanale prima | granularità storica |
| L4 | `D_bot` 140 → 60 | bot minori in `__other_<cat>__` |
| L5-L8 | riduzione progressiva di F5, sezioni, e infine tutto settimanale | dettaglio, fino al livello di sintesi |

**Regola invariante: i totali sono sempre esatti, la granularità no.** Ogni troncamento produce una riga sink che conserva hit e byte, così nessun grafico perde traffico. Il livello applicato, il motivo e la copertura percentuale finiscono in `meta` e in un banner permanente in testa al report — non si nascondono.

Due flag opzionali chiudono qualunque problema di budget senza toccare la granularità: `--compress-payload` (gzip + base64 + `DecompressionStream` nativa: 3,7 MB → ~960 KB, ~60 ms al boot, ma JSON non più ispezionabile) e `--inline-libs` (incorpora ECharts+Tabulator per le copie d'archivio; il file cresce, il **JSON** resta sotto i 5 MB — il tetto è sui dati).

### Cross-filtering: limiti dichiarati

Un filtro agisce su un widget **solo se la dimensione è un asse del cubo che lo alimenta, o un attributo di uno dei suoi assi**. Con dati pre-aggregati non ci sono scorciatoie. Combinazioni strutturalmente non rappresentabili, da dichiarare in anticipo:

- **data × url** — 12.000 × 395 = 4,7M celle, fuori budget di un ordine di grandezza. Restano `first_seen`, `last_seen`, `gbot_last_seen` per URL, più le sparkline dei top 25. Modulo opt-in `--url-timeline` (settimana × botgroup × top 2.000 URL ≈ 890 KB) per chi lo vuole davvero.
- **verifica × url** — mitigato da un cubo dedicato con i top 200 URL colpiti da traffico `SPOOFED` (~3 KB), che copre il caso d'uso reale.
- **verifica × sezione**, **verifica × tipo risorsa**, **status × sezione × data** — non rappresentabili.
- **Misure di unicità sotto filtro arbitrario** — `URL unici` e `IP unici` **non sono additivi**: sommare gli unici giornalieri sovrastima di 2-5×. Disponibili solo ai roll-up precalcolati (per bot, per sezione, per bot×sezione, per giorno×bot). Sotto altri filtri la misura si **disabilita**, non si approssima. È l'errore a più alta probabilità dell'intero progetto.

Ogni widget dichiara le dimensioni che sa gestire; lo store le confronta con i filtri attivi e assegna uno di tre stati: **LIVE** (nessun badge), **PARTIAL** (badge giallo con l'elenco esplicito dei filtri ignorati, il widget continua a renderizzare), **N/A** (widget in grigio con il motivo). Mostrare numeri non filtrati senza avviso è l'unica opzione da escludere.

### Implementazione front-end

**Store vanilla, ~150 righe. Niente crossfilter.js**: è pensato per record riga-per-riga, pesa 60 KB, non è manutenuto, e non sa gestire il caso centrale qui — *lo stesso filtro deve colpire 9 cubi con assi diversi*.

Al boot gli array interi diventano `Int32Array`/`Uint16Array` una volta sola. Ogni query è uno scan lineare a maschera di bit: F1 con 110k celle × ~5 confronti interi sta sotto i **2 ms**; dieci widget che si riaggiornano ≈ 20 ms, dentro un frame e mezzo. Coalescing su `requestAnimationFrame` così un brush sull'asse temporale non scatena 60 ricalcoli al secondo. Flusso unidirezionale: widget → store → tutti i widget, mai widget → widget. Lo stato dei filtri va in `history.replaceState` come hash, così una vista filtrata è condivisibile.

**Tabulator 6.x** per le tabelle, non DataTables: standalone (niente jQuery, −87 KB), `replaceData()` con virtual DOM e riuso delle righe — ridisegnare 12.000 righe a ogni cambio filtro è l'operazione centrale del report, e il ciclo `clear().rows.add().draw()` di DataTables è visibilmente più lento. In più `bottomCalc:"sum"` per i totali sotto la vista filtrata e `download("csv")` nativo. Limite da preventivare: Tabulator non fa pivot vero, la pivot va calcolata in JS e passata piatta ricostruendo `columns` (~40 righe).

**ECharts 5.x** per i grafici, non Plotly: ~330 KB gzip contro ~1,1 MB, `setOption` con diffing incrementale (esattamente il caso d'uso del cross-filter), evento `dataZoom` per il brush temporale — il gesto centrale del report — componente `brush` per selezionare barre, coordinate `calendar` per la heatmap ora × giorno, e renderer Canvas che regge 12.000 punti dove Plotly in SVG fatica oltre i 5.000. I punti di forza di Plotly qui sono irrilevanti: l'HTML è generato a mano, non da `pio.to_html`.

Entrambe da jsDelivr con `integrity` (SRI) e `crossorigin`.

### Due scelte esplicite

- **Timezone**: storage in UTC nei Parquet (non ambiguo, corretto in multi-sito), **una sola conversione** in `aggregate.py` che produce `date_local` e `hour_local` con la tz del sito. Gli assi del report sono in ora locale, e la tz finisce in `meta`. Il periodo copre un cambio DST: convertire avanti e indietro è dove nascono gli off-by-one sul giorno.
- **Period-over-period in `--latest`**: la finestra di confronto si legge dai Parquet in archivio anche quando il report copre il solo file più recente. Se l'archivio non ha abbastanza storia, il widget si disabilita dichiarando il motivo, senza inventare un confronto.

---

## Parametri (`config/defaults.yaml`)

| Parametro | Default |
|---|---|
| N giorni "URL mai visitati da Googlebot" | 30 |
| Periodo di confronto crawl budget | periodo precedente di pari durata |
| Tetto JSON embedded | 5 MB |
| TTL cache rDNS | 30 giorni |
| Timeout lookup DNS | 3 s |
| Parallelismo lookup DNS | 50 |
| Lunghezza dei "top" | 25 |
| Finestra di analisi | `--all` (default) / `--latest` |
| Ritardo dati GSC | 3 giorni |

---

## Fuori scope

- `searcus.ch` — l'architettura lo supporta (basta un file in `config/sites/`), ma non viene configurato ora.
- Report aggregato cross-sito (punto aperto §8.3): con un solo sito non serve. Le pre-aggregazioni restano però indicizzate per dominio, così aggiungerlo dopo non impone un rifacimento.
- Modifiche alla configurazione nginx sul server (es. riattivare il log degli asset): è produzione, non si tocca di iniziativa.

---

# Checklist operativa

Da spuntare in ordine. Ogni blocco ha un **gate** finale: se il gate non passa, non si prosegue al blocco successivo.

## Blocco 0 — Documenti e scheletro

- [x] `piano.md` salvato in `logAnalyzer2/`
- [x] `prompt.md` §6: aggiunto il paragrafo "Traffico scanner/attacco" (2 righe)
- [x] `prompt.md` §6: aggiunta la riga che "HTML vs asset" non è calcolabile su evemilano (`access_log off` sugli asset)
- [x] `prompt.md` §7: aggiunta la riga "Finestra di analisi | `--all` / `--latest`"
- [x] Struttura cartelle creata (`config/`, `logs/`, `data/`, `cache/`, `input/`, `errors/`, `output/`, `credenziali/`, `loganalyzer/`)
- [x] venv `amb/` creato (Python 3.12, polars 1.44.1 / pyarrow 25.0.1), `requirements.txt` con versioni pinnate
- [x] `.gitignore`: `amb/`, `logs/`, `data/`, `cache/`, `input/`, `output/`, `errors/`, `credenziali/`
- [x] `CLAUDE.md` del sottoprogetto (venv, comandi CLI, convenzioni, insidie note)
- [x] `main.py` + `loganalyzer/cli.py` con argparse a sottocomandi e logging su stderr
- [x] `config/defaults.yaml` con i parametri della tabella §7
- [x] `config/sites/evemilano.com.yaml`: host ssh, path e pattern log, `log_format`, tz `Europe/Rome`, sezioni note, site_url GSC, token path

**Gate 0** ✅ — `main.py --help` elenca tutti i sottocomandi, `main.py sites` risolve la config di evemilano.com, `git check-ignore` conferma che `amb/`, `credenziali/`, `cache/`, `output/` non sono tracciati.

## Blocco 1 — `fetch`

- [x] Manifest remoto via ssh: per ogni file `size`, `mtime`, `md5` dei primi 4 KB
- [x] Fingerprint = md5 dei primi 4 KB; ledger `logs/<domain>/_manifest.json`
- [x] File nuovo → `ssh "gzip -c <f>"` in locale
- [x] File live cresciuto con stesso fingerprint → `tail -c +offset | gzip -c` appeso al `.gz` locale
- [x] File già completo → skip
- [x] Rinumerazione della rotazione (`.1`→`.2`) non provoca ri-download
- [x] **Scoperto in corso d'opera**: 7 file remoti su 16 sono già compressi. Ricomprimerli produrrebbe un doppio strato gzip illeggibile con `gzip.open()`. Il flag si ricava dai magic bytes (`1f8b`), non dall'estensione, e i file già compressi si copiano con `cat` invece che con `gzip -c`.

**Gate 1** ✅ — primo run 66 s, 16 file, 1,64 GB di log in archivio. Secondo run 2 s: 15 archivi ruotati byte-identici, solo il file live esteso. 16 fingerprint distinti, nessun duplicato. L'archivio del file live si rilegge end-to-end e l'ultima riga è quella appesa dalla coda.

## Blocco 2 — `logformat` + `parse`

- [x] `logformat.py`: da stringa `log_format` a regex con gruppi nominati `(?P<name>...)` — l'unica sintassi accettata sia da `re` sia dal motore Rust di Polars
- [x] `parse.py`: `pl.read_csv` legge il `.gz` direttamente + `str.extract_groups()`
- [x] Split `request` in method / target / protocol; richieste malformate marcate con `request_malformed` e `request_raw`, non scartate
- [x] `time_local` → UTC; Parquet partizionati `ym=YYYY-MM`, zstd; stato in `_parse_state.json` per l'idempotenza
- [x] Righe non parsate → `errors/<domain>_unparsed.log` (composto dai file per archivio, così resta esatto anche nei run incrementali)
- [x] `tzdata` aggiunto alle dipendenze: su Windows `zoneinfo` non ha il database IANA e Polars fallisce su `time_zone="UTC"`
- [ ] Decodifica `\xNN` — implementata in `logformat.unescape()` ma non ancora applicata: nei Parquet i campi restano come li scrive nginx (per le richieste binarie la forma `\x16\x03\x01` è più informativa del byte grezzo)

**Gate 2** ✅ — 7.454.481 righe negli archivi = 7.454.479 parsate + 2 non parsate (**0,0000%**, contro la soglia dell'1%); i Parquet contengono esattamente le righe parsate. Catena 2025-08-02 → 2026-09-01 con **0 buchi e 0 sovrapposizioni**: `.2` (dic 2025) → `.8.gz` (dic 2025) → … → `.2.gz` (lug 2026) → `.1` (lug 2026). Parsing di 7,45M righe in ~20 s.

### Misure che pilotano il modello del report

| Grandezza | Valore misurato | Effetto |
|---|---|---|
| Righe | 7.454.479 | — |
| IP unici | 386.383 | fuori dal JSON, solo top 500 |
| **Path unici** | **107.362** (89.931 non-probe) | `D_url` a 12.000 slot resta necessario |
| **UA unici** | **529.968** | collasso dei browser a famiglia obbligatorio |
| Referer unici | 53.705 | top 25 nel report |
| Status distinti | 23 | — |
| Primi segmenti URI distinti | 35.338 | allowlist per sito obbligatoria |
| Richieste malformate | 51.747 (0,69%) | bucket reale, in crescita nel tempo |
| Richieste con query string | 853.770 (11,5%) | base del crawl waste |
| **Celle di F1** | **~58.000 → 0,66 MB** | contro le 110.000 / 1,31 MB stimate |

**Correzione alla stima del piano**: il 2,13% di righe malformate estrapolato in fase di analisi era un artefatto di `awk`, che spezza la riga sugli spazi e si disallinea quando `$request` ne contiene più di due. Le righe realmente non parsabili sono 2 su 7,45 milioni. Le 51.747 "richieste malformate" sono un'altra cosa: righe valide il cui `$request` non è `METODO URI PROTOCOLLO` (handshake TLS sulla porta 80, scanner con protocolli propri).

**F1 costa un quarto del previsto.** Il budget di 5 MB ha molto margine e la scala di degradazione con ogni probabilità non si attiverà nemmeno al livello L1.

## Blocco 3 — `ipranges` + `verify`

- [x] `config/bot_sources.yaml` con **18 fonti**, tutte verificate raggiungibili
- [x] Parser: `google_prefixes` (lo schema di fatto: Google, Bing, OpenAI, Anthropic, Perplexity, Apple, DuckDuckGo, Ahrefs), `aws_prefixes`, `plain_cidr`
- [x] Download parallelo + validazione schema + snapshot in `cache/ip_sources/` come fallback
- [x] Store normalizzato `cache/ip_ranges.parquet`: **21.275 prefissi**, di cui 4.516 con valore di prova e 16.759 AWS marcati `trust: hint`
- [x] Match range: `numpy.searchsorted` per IPv4, `bisect` su interi Python per IPv6 (che sono a 128 bit)
- [x] rDNS forward-confirmed (PTR → suffisso atteso → A/AAAA che riporta all'IP)
- [x] Cache `cache/dns.sqlite` con TTL 30 gg, condivisa tra siti; 50 worker, timeout 3 s, 2 retry
- [x] Verdetto a 5 stati; in caso di discordanza prevale il negativo
- [x] **Trovata la lista Anthropic**: `https://claude.com/crawling/bots.json` (26 prefissi, copre ClaudeBot, Claude-User e Claude-SearchBot). Gli URL su `anthropic.com` che sembravano ovvi danno tutti 404.
- [x] **Corretto un errore di classificazione**: un NXDOMAIN sul PTR veniva trattato come `DNS_ERROR`. È invece una risposta definitiva — quell'IP non ha reverse, e i crawler che si verificano per rDNS ce l'hanno sempre — quindi è `SPOOFED`. La correzione sposta 11.308 esiti: `DNS_ERROR` da 12.588 a **1.174**, `SPOOFED` da 4.939 a **16.353**.

**Gate 3** ✅ — `66.249.73.129` → `VERIFIED`, owner Google. AWS resta `hint` e non produce mai `VERIFIED`. Fallback allo snapshot testato con URL rotto (26 prefissi recuperati) e con fonte senza snapshot (fallimento pulito). Secondo run: 14.312 IP tutti da cache, 7 s contro 3 minuti.

**Risultato di merito**: **12.875 IP distinti dichiarano di essere Googlebot, solo 374 lo sono.** Su ChatGPT-User il rapporto è 1.058 falsi contro 1.188 veri, su ClaudeBot 388 contro 264.

## Blocco 4 — `classify` + `enrich`

- [x] `config/bots.yaml`: **74 regole** ordinate, primo match vince, fallback espliciti; id univoci verificati al caricamento
- [x] Regole riscritte da zero, non copiate: le tre anomalie della v1 (duplicati `meta-externalagent`/`GPTBot`/`Facebookbot`, metacaratteri in `omgili|omgilibot` e `screaming frog`) non si ripresentano
- [x] Sottocategorie AI: `training` / `answer-index` / `on-demand`
- [x] Browser collassati a famiglia; classificazione sui 529.968 UA distinti in 2,5 s, poi join sulle righe
- [x] `section` da allowlist; le sonde vanno in `(probe)` e non inquinano la dimensione
- [x] `resource_type` a 9 valori
- [x] `has_query`
- [x] `config/attack_patterns.yaml` → 17 famiglie, 15 ostili
- [x] `is_ua_anomaly` su hit-per-IP, non sul volume assoluto
- [x] **Corretto**: la join sulla classificazione perdeva le righe senza user agent (1,6% del traffico), perché Polars non fa match sulle chiavi null. Serve `join_nulls=True`.
- [x] **Corretto due volte la regex `.env`**: la prima versione mancava 8.837 richieste (`/sendgrid.env`, `/aws.env.json`), la seconda ancora 966 varianti codificate per eludere i filtri (`/.env%09`, `/%2f.env%2eexample`). Ancorare al confine di parola invece che alla fine del segmento, senza lookahead — il motore regex di Polars non lo supporta.

**Gate 4** ✅ — zero righe senza categoria, sezione, stato IP o tipo risorsa; la somma per categoria pareggia il totale. **Le sezioni distinte scendono da 35.338 a 24.** `wp-login.php`, `/ssl-vpn`, `/global-protect`, `wp-config` e `xmlrpc.php` intercettati al 100%; `.env` al 99,98% (i 23 residui sono i falsi negativi voluti, tipo `documento.envelope.pdf`).

**Risultati di merito**: le sonde sono il **24,3% del traffico** (1.814.057 richieste, di cui 1.280.325 ostili); le righe da user agent anomali il **31,4%**. Gli asset confermano di non essere loggati: `resource_type = asset` vale lo 0,04%.

## Blocco 5 — `gsc`

- [x] Autenticazione e paginazione riprese da `evemilano_ai_manager/skills/_gsc_api.py` e **copiate** nel progetto
- [x] Token path da config, default `_MCP Servers/GSC_MCP/credenziali/token.json`
- [x] Query `dimensions=["page","date"]` con paginazione, periodo = min/max effettivi dei log
- [x] Join su URL normalizzato
- [x] Ultimi 3 giorni marcati non consolidati
- [x] Token assente → `GscUnavailable`, warning, uscita pulita: il report si genera senza le sezioni GSC

**Gate 5** ✅ — 208.329 righe (URL × giorno), 23.614 click, 4.615.599 impression, sul periodo esatto dei log. Confronto incrociato con l'MCP: i valori **coincidono esattamente** (9344 / 10216 / 12651 / 13207 / 12899 impression, click compresi).

**Da riportare nel report**: le impression aggregate per pagina sono ~9% più alte del totale di proprietà che Search Console mostra nella sua interfaccia. Non è un errore: chiedendo la dimensione `page` l'API passa in modalità `byPage`, e quando due URL dello stesso sito compaiono nella stessa SERP la proprietà conta un'impression sola mentre le pagine ne contano due. Verificato interrogando l'API con `aggregationType=byPage`, che restituisce esattamente i miei numeri.

## Blocco 6 — `aggregate`

- [x] Conversione **unica** UTC → ora locale del sito, in `aggregate.py`
- [x] Dizionari: `bot`, `cat`, `sub`, `ver`, `status`, `section`, `restype`, `probe`, `botgroup`; `date` come start + n
- [x] `D_url`: 12.000 slot nell'ordine di priorità definito, con riga sink; **mai** scartare URL in sitemap o con click GSC
- [x] Cubi in encoding colonnare (array paralleli di interi)
- [x] Misure di unicità solo ai roll-up precalcolati; sotto filtri incompatibili il front-end le disabilita dichiarandolo
- [x] Stima del peso prima della serializzazione
- [x] Blocco `meta` con periodo, righe non parsate, degradazione, copertura
- [x] **Aggiunto l'asse `probe` a F1, F2 e F7 dopo il primo test del front-end**: senza, il traffico di scanner — un quarto delle richieste — non era escludibile dai grafici temporali, che è esattamente ciò che era stato chiesto. Costo: +0,42 MB.

**Gate 6** ✅ — **3,45 MB su un tetto di 5, il 69% del budget.** F1 ha **55.154 celle** (contro le 110.000 stimate), quindi la scala di degradazione non si attiva oltre il troncamento previsto della tabella URL. La somma degli hit di **ogni** cubo fa esattamente 7.454.479, riga sink compresa. `D_url` a 12.000 voci copre il **93% degli hit**; in modalità `--latest` gli URL sono 7.398 e non serve alcun troncamento (copertura 100%).

## Blocco 7 — `report`

- [x] Report scritto da zero invece di adattare `ReportBuilder`: quel builder produce pagine statiche, qui serve uno stato condiviso fra widget
- [x] ECharts 5.5.1 + Tabulator 6.3.1 da jsDelivr, con **hash SRI calcolati sui file effettivi**, non dichiarati a vuoto
- [x] `FilterStore` vanilla: maschere su TypedArray, scan lineare, coalescing su `requestAnimationFrame`, flusso unidirezionale
- [x] Ogni widget dichiara le dimensioni supportate; i filtri che non lo riguardano compaiono in un badge esplicito
- [x] Note in testa alla pagina: asset non loggati, `/analytics/` escluso, impression `byPage`, UA anomali, troncamento, righe non parsate
- [x] Sezioni: traffico nel tempo, verifica identità, pivot + grafico, status dei bot verificati, tabella URL con GSC e first/last seen, copertura AI, distribuzione oraria, sonde e attacchi, classifiche con serie collegata
- [x] Palette conforme alla guida di visualizzazione, **validata con lo script**: tutti i check passano, con il WARN di contrasto coperto dalle tabelle presenti in ogni sezione
- [x] Flag `--compress-payload` e `--inline-libs`
- [x] Filename `log_analysis_evemilano_com_20250803-20260901.html`
- [x] **Sezione «Freschezza del crawl di Googlebot»**, che chiude il requisito «URL mai visitati da Googlebot in N giorni» di `prompt.md` §6. Soglia selezionabile (14/30/60/90), preimpostata da `report.googlebot_stale_days`. L'insieme di riferimento non sono i 107.440 percorsi visti nei log — la maggior parte se li inventano gli scanner — ma i **578 URL che Google conosce**: quelli in sitemap più quelli con impression in Search Console.
- [x] **Colonna «Ultimo Googlebot (gg)»** rinominata da «Googlebot: gg fa», con tooltip che dichiara le tre condizioni implicite: solo Googlebot con IP verificato, esclusi Googlebot-Image/News/GoogleOther/AdsBot, e conteggio rispetto all'ultimo giorno del periodo e non a oggi.
- [ ] Stato dei filtri in `history.replaceState` — non implementato
- [ ] La sezione orphan legge una sitemap da `input/<dominio>/`, ma non è ancora stata eseguita con una sitemap reale: senza, l'insieme di riferimento si appoggia alle sole impression di Search Console

**Tre bug trovati e corretti in questa fase**, tutti silenziosi:
1. **Il JS non partiva.** Il payload emetteva l'evento `logan:ready` prima che il listener fosse registrato. La pagina si disegnava, ma grafici vuoti e select senza opzioni. Risolto invertendo l'ordine dei blocchi: dati, definizione, avvio.
2. **Overflow a 32 bit sui byte.** Convertire i cubi in `Int32Array` mandava in overflow la somma dei byte di un singolo giorno (oltre 2,1 miliardi): il report mostrava 83 GB dove i Parquet ne danno 91. Nessun errore in console, solo un numero sbagliato. Risolto con `Float64Array`, che rappresenta esattamente gli interi fino a 2⁵³.
3. **`c` era sia una misura sia una dimensione** in cubi diversi, il che rendeva fragile qualunque conversione selettiva per nome di colonna.

**Gate 7** ✅ — nessun errore JS in console (l'unico messaggio riguarda l'origine `file:`, non il codice). 8 grafici su 8 disegnati, 3 tabelle popolate. Cross-filtering verificato in tre passaggi: filtro categoria → la pivot passa a Amazonbot/GPTBot/OAI-SearchBot; aggiunta di «solo sonde» → la tabella URL scende da 8.258 a 3.743 voci; azzeramento → stato iniziale. **Ogni cifra confrontata con i Parquet coincide**: 3.264.567 / 309.611 / 264.464 nella vista di default, 115.563 / 54.349 / 31.881 su AI bot, 8.095 / 778 / 647 su AI bot con sole sonde. `--latest` produce 0,67 MB su 122.929 righe senza troncamenti.

## Blocco 8 — Chiusura

- [x] **Sanità sulla classificazione** — verificato, ed è peggio del previsto. Sui 13 mesi l'UA dominante è `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36…` con **2.026.397 hit (27% del totale) da soli 7.748 IP: 261 hit per IP**. Non è traffico umano. Stessa firma per `curl/8.7.1` (322.564 hit, 53 IP, 6.086 hit/IP) e `Screaming Frog SEO Spider/23.3` (99.638 hit, 16 IP). `bots.yaml` deve intercettarli: se finiscono in "Browser", ogni rapporto browser/bot del report è falsato di oltre un quarto.
- [x] Regola `is_ua_anomaly` tarata su hit/IP, non sul volume assoluto
- [x] `main.py run --site evemilano.com` — **pipeline completa in 64,9 s** a caldo, con l'incrementalità visibile a ogni stadio: 15 archivi invariati e 1 esteso nel fetch, 15 archivi saltati nel parse, 1 solo IP da risolvere contro 14.312 dalla cache DNS
- [x] `CLAUDE.md` con i comandi reali e le insidie emerse
- [x] `requirements.txt` rigenerato (aggiunti `numpy` e `tzdata` scoperti in corso d'opera)

**Gate 8** ✅ — pipeline completa riproducibile con un solo comando.

---

## Cosa resta aperto

- **Orphan URL**: il codice legge una sitemap da `input/<dominio>/` ma non è mai stato eseguito con una sitemap vera. Va provato prima di fidarsi di quella sezione.
- **Confronto periodo su periodo**: il cubo è calcolato (prima metà contro seconda metà del periodo) ma non ha ancora un widget nel report.
- **URL mai visitati da Googlebot in N giorni**: il dato per URL c'è nella tabella (colonna «Googlebot: gg fa», con «mai visto» in evidenza), ma manca una vista dedicata che lo incroci con la sitemap.
- **Stato dei filtri nell'URL** per condividere una vista filtrata.
- **`searcus.ch`**: basta aggiungere un file in `config/sites/`.

## Risultati che il report mette in evidenza

Vale la pena guardarli prima di qualunque altra analisi su questo sito:

1. **12.875 IP distinti dichiarano di essere Googlebot; solo 374 lo sono.** Su ChatGPT-User il rapporto è 1.058 falsi contro 1.188 veri.
2. **Un singolo user agent vale il 27% delle richieste di tutto il periodo** — un Chrome su macOS con 2.026.397 hit da 7.748 indirizzi, concentrati in ago–set 2025 e poi spariti. È la causa del picco di traffico di quei due mesi, e senza separarlo qualunque confronto anno su anno sarebbe privo di senso.
3. **Il 24,3% delle richieste sono sonde di scanner**, di cui 1.280.325 ostili: 452.513 ricognizioni e 320.687 tentativi di brute force sul solo `wp-login.php`.
4. **Bytespider fa 8.095 richieste su percorsi da scanner** — un crawler AI che si comporta da ricognizione.
5. **184 dei 578 URL che Google conosce (31,8%) non ricevono una visita di Googlebot verificato da oltre 30 giorni**, e valgono 217.553 impression. In cima ci sono pagine commerciali: `/servizi-web-marketing/` (30.829 impression, ferma da 57 giorni) e `/pubblicita-google/` (29.235 impression, 32 giorni). Di quei 184, **75 non compaiono affatto nei log del server** pur avendo impression in Search Console — vale la pena capire perché.
