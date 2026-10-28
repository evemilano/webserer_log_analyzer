# logAnalyzer2

Analisi degli access log nginx e generazione di un report HTML statico, autoconsistente a livello di dati. Multi-sito.

Documenti: [`prompt.md`](prompt.md) è la specifica, [`piano.md`](piano.md) il piano di lavoro con la checklist operativa, [`_requisiti.md`](_requisiti.md) i vincoli di base.

## Ambiente

```powershell
.\amb\Scripts\python.exe main.py --help
```

Venv `amb/` (Python 3.12). Non usare il Python di sistema: le dipendenze — Polars in particolare — non ci sono.

## Comandi

```
main.py sites                                    # elenca i siti configurati
main.py fetch    --site evemilano.com            # scarico incrementale via ssh
main.py parse    --site evemilano.com            # archivio .gz -> Parquet
main.py ipranges refresh                         # store globale CIDR dei bot
main.py verify   --site evemilano.com            # identità IP: range + rDNS
main.py enrich   --site evemilano.com            # classificazione bot + attributi derivati
main.py gsc      --site evemilano.com            # click/impression da Search Console
main.py report   --site evemilano.com [--all|--latest] [--from GG --to GG]
main.py run      --site evemilano.com [--all|--latest]
```

Ogni stadio è idempotente e produce un artefatto proprio; rilanciarlo non ricomincia da capo.

## Configurazione

- `config/defaults.yaml` — default globali (§7 di `prompt.md`). `report.json_budget_bytes` e `report.url_dict_size` sono le leve del peso: i cubi per URL scalano linearmente sul secondo. `report.compress_payload` e attivo di default — senza, il file passa da ~3,8 a ~19 MB.
- `config/sites/<domain>.yaml` — un file per sito, sovrascrive i default. Chiavi che
  non tutti i siti usano: `source: local` legge i log da disco invece che via ssh
  (`logs.dir` accetta allora anche una lista di cartelle, e l'identita` di un file e` il
  fingerprint del contenuto **decompresso**, cosi` la stessa giornata consegnata sia in
  chiaro sia gia` compressa non entra due volte); `exclude.ip` scarta righe prima del
  Parquet; `client_ip_trusted: false` dichiara che `remote_addr` e` un proxy.
- `config/bots.yaml` — regole UA → categoria, in ordine di valutazione
- `config/bot_sources.yaml` — sorgenti degli IP range ufficiali
- `config/attack_patterns.yaml` — regole `is_attack_probe`

Le regole di classificazione stanno nei YAML, mai nel codice.

## Insidie note (misurate, non ipotizzate)

- **La numerazione della rotazione non è cronologica.** logrotate gira su `size 100M` con `delaycompress`: `evemilano_access.log.2` copre nov–dic 2025 mentre `.2.gz` copre giu–lug 2026. Ordinare i file per nome produce una timeline sbagliata — ordinare sempre per timestamp del contenuto.
- **`rotate 8` cancella lo storico sul server.** L'archivio locale in `logs/<domain>/` è la fonte di verità.
- **Gli asset non sono nei log.** Nel vhost evemilano css, js, font e immagini hanno `access_log off`. Il rapporto HTML vs asset non è calcolabile e la dimensione "tipo risorsa" ha poco da dire.
- **`/analytics/` è escluso dal log** via `map $request_uri $loggable_request`.
- **Il traffico di scanner domina.** I primi segmenti URI distinti sono oltre 35.000: la "sezione" va derivata da allowlist, mai dal primo segmento grezzo. Le richieste marcate `is_attack_probe` vanno in `(probe)`.
- **URL unici e IP unici non sono additivi.** Sommare gli unici giornalieri sovrastima di 2-5×. Nel payload il loro nome comincia per `~`, e l'unica riduzione che il front-end applica è il **massimo**, mai la somma. Dove il cubo che li porta non ha gli assi del filtro attivo — `day_bot` ha solo data, bot e sonda — la pagina mostra un trattino e dice perché, invece di un numero che descrive un perimetro più largo di quello selezionato.
- **Timezone**: storage in UTC, una sola conversione in `aggregate.py`. Serve il pacchetto `tzdata`: su Windows `zoneinfo` non ha il database IANA e Polars fallisce anche solo su `time_zone="UTC"`.
- **Le impression di Search Console sono aggregate per pagina** e risultano ~9% più alte del totale di proprietà mostrato dall'interfaccia. Non è un errore: con la dimensione `page` l'API passa in modalità `byPage`, e due URL dello stesso sito nella stessa SERP contano due impression invece di una.
- **Nel front-end le *misure* vanno in `Float64Array`, mai in `Int32Array`.** La somma dei byte di un giorno supera i 2,1 miliardi e andrebbe in overflow silenzioso: nessun errore in console, solo totali sbagliati. Le colonne *indice* sono un'altra cosa: sono limitate dalla cardinalità del proprio dizionario e vanno dimensionate (`Uint8`/`Uint16`/`Int32`), altrimenti 860.000 celle costano 45 MB di heap invece di 10.
- **`new Date('2025-08-03T00:00:00')` è mezzanotte locale, `toISOString()` la riporta in UTC.** A est di Greenwich il giorno stampato è quello prima: sbagliava ogni etichetta di ogni asse temporale, e siccome il campo «Al» nasceva da lì, l'ultimo giorno del periodo usciva dal filtro appena si toccava una data. Costruire e formattare le date sempre dai componenti locali.
- **`sezione` e `tipo risorsa` sono attributi dell'URL, presi al valore modale.** Vanno ri-joinati sulle righe prima di costruire i cubi: se un cubo li tenesse per riga mentre `dim.url` li ha modali, lo stesso filtro darebbe due totali diversi in due punti della pagina.
- **51.748 richieste malformate hanno `path` nullo.** In una join `null` non è uguale a `null`: senza un'etichetta esplicita quelle righe spariscono da ogni aggregazione per URL, in silenzio, e i totali smettono di quadrare.
- **Un NXDOMAIN sul PTR non è un errore di lookup.** È una risposta definitiva: quell'IP non ha reverse, e i crawler che si verificano per rDNS ce l'hanno sempre. Va classificato `SPOOFED`, non `DNS_ERROR`.

### Insidie che compaiono solo fuori da evemilano

Misurate su `store.lemanicasa.com` (Magento dietro Cloudflare), ma nessuna gli e` propria.

- **Due server possono scrivere sullo stesso access log.** In un vhost a due livelli il
  front-end registra la richiesta con l'IP del client in HTTP/2 e il backend la registra
  di nuovo con `127.0.0.1` in HTTP/1.1: su una giornata, 179.126 righe di cui 95.266 dal
  loopback, e 74.993 richieste remote con un gemello locale esatto su (timestamp, metodo,
  URL). Senza `exclude.ip` ogni cifra di traffico raddoppia e il loopback diventa il primo
  IP del sito. Sull'intero archivio: 8,3 milioni di righe scartate su 16,3.
- **Dietro un proxy che non propaga l'IP di origine la verifica d'identita` non degrada, mente.**
  Il fall-through in coda a `_verdict` legge il mancato match sui range come prova di frode:
  con tutti gli IP di Cloudflare marcava SPOOFED 13.283 coppie, cioe` ogni crawler legittimo
  del sito. `client_ip_trusted: false` taglia corto prima di li`, e il report dice perche`.
  Le regole senza `rdns_suffixes` non passano dal ramo `skipped`: disattivare il DNS non basta.
- **Con la verifica disattivata, ogni misura che pretende `ip_status == "VERIFIED"` non si
  svuota: mente al contrario.** `gbot_last_seen` chiedeva Googlebot *verificato*, e con zero
  righe VERIFIED sul sito dava «mai preso» su tutti e 417.368 gli URL — mentre 301.948
  richieste di Googlebot dichiarato erano li` nei log, l'ultima il giorno di chiusura del
  periodo. La stessa cifra reggeva la scheda Freschezza, che dichiarava il 100% degli URL
  noti mai visitato invece dell'8,3% reale. Dove `client_ip_trusted` e` false le due misure
  cadono sull'agente **dichiarato** e la pagina lo etichetta NON VERIFICATO, invece di
  spacciare «non dimostrabile» per «non successo». Resta cosi` `verified_bot_hits`
  (`aggregate.py`), che e` il tier 3 della priorita` di selezione URL: su un sito dietro
  proxy quel tier e` vuoto e gli URL visitati dai bot non hanno la precedenza che meritano.
- **Un bot con un token `Chrome/` nello user agent finisce fra i browser.** Le regole browser
  di `bots.yaml` sono le ultime e prendono tutto quello che resta: `meta-webindexer`,
  `GeedoShopProductFinder` e `SleepBot` valevano insieme il 5,4% delle richieste di una
  giornata, contate come navigazione umana. Prima di fidarsi del rapporto umani/bot su un
  sito nuovo, guardare i primi 20 user agent e verificare che siano tutti classificati.
- **Il default di `gzip.open` e` il livello 9, e comprime piu` lentamente di quanto il disco
  legga**: misurati 0,8 MB/s contro 4,9. L'import locale usa il 6, lo stesso di `gzip -c`
  sul percorso ssh, e il 2% di spazio in piu` non si sente.
- **Il dizionario URL non compra copertura dove la coda e` piatta.** Su un Magento i path
  distinti in 15 giorni sono 417.000 contro i 94.000 di un blog su 13 mesi: 336.898
  compaiono una volta sola e valgono il 22% delle richieste, mentre 369 URL ne fanno il 44%.
  Passare da 12.000 a 60.000 voci sposta la copertura dal 36% al 39% e triplica il file.
  Dimensionare sulla soglia utile — gli URL con almeno 6 hit — non sulla percentuale.
- **La rotazione non e` sempre bugiarda.** Qui e` giornaliera e cronologica (`.1` = ieri,
  `.14` = quattordici giorni fa), l'opposto di evemilano. Vale sempre la regola generale:
  l'ordine si stabilisce dal contenuto, mai dal nome.

## Convenzioni

- `argparse` a sottocomandi; logging su **stderr**, stdout resta pulito.
- Se servirà `.env`: `dotenv_values()`, mai `load_dotenv()` — in multi-sito inquina `os.environ` e il secondo sito eredita le variabili del primo.
- Questo è un sottoprogetto indipendente: il codice preso da `logAnalyzer/` (v1) o da altre cartelle del repo va **copiato**, mai importato cross-cartella.

## Credenziali

- SSH: alias `evemilano` in `~/.ssh/config`, fuori dal repo.
- GSC: token OAuth riusato dal server MCP, `G:/My Drive/CLAUDE/_secrets/gsc/token.json` (scope `webmasters.readonly`). Percorso configurabile per sito. Il refresh avviene solo in memoria: il file su Drive non viene riscritto.

`logs/`, `data/`, `cache/`, `input/`, `output/`, `errors/`, `credenziali/` e `amb/` sono gitignorati.
