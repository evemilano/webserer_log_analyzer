"""Pre-aggregazione: dal dataset arricchito ai cubi che finiscono nell'HTML.

Con 7,45 milioni di righe il dataset grezzo non può stare in una pagina web.
La struttura che ci sta dentro è uno star schema, non un ipercubo:

- `categoria` e `sottocategoria` sono **attributi del bot**, non assi propri;
- `sezione` e `tipo risorsa` sono **attributi dell'URL**, presi al valore
  modale delle sue richieste e ri-joinati sulle righe: così il conteggio per
  sezione di un grafico e quello della tabella URL sono lo stesso numero,
  invece di due partizioni leggermente diverse dello stesso filtro.

Ogni cubo è colonnare: array paralleli di interi con i valori sostituiti dagli
indici dei dizionari, che pesa circa un terzo di un array di oggetti con le
chiavi ripetute. Il filtro della pagina ha otto campi e ogni cubo dichiara in
`meta.axes` quali sa reggere: il front-end ne deriva il proprio avviso invece
di dichiararlo a mano, così una dimensione tolta per budget non può restare
silenziosamente «applicata».

I cubi sono cinque:

- **C1 `main`** — data x bot x verifica x status x sonda x sezione x tipo, con
  hit e byte. Tutte e otto le dimensioni; regge i quattro widget temporali.
- **C2 `url`** — URL x bot x verifica x classe x sonda x **mese**. La data a
  livello di URL esiste solo al mese: misurato, senza tempo sono 94.000 celle,
  per mese 387.000, per giorno oltre due milioni.
- **C3 `attack`** — le sole sonde, con tutti gli assi tranne il flag sonda,
  che lì è costante.
- **C4 `hour_dow`** — ora x giorno della settimana, con tutti gli assi tranne
  la data: aggiungerla lo trasformerebbe nella tabella dei fatti.
- **C5 `tops`** — un cubo per classifica (user agent, IP, referer) su un pool
  di chiavi candidate; URI e status si ricalcolano da C2 e C1.

Due misure non sono additive: **URL unici** e **IP unici**. Sommare gli unici
giornalieri sovrastima di due o tre volte, perché lo stesso IP torna il giorno
dopo. Nel payload il loro nome comincia per `~`: il prefisso segnala che sopra
quella colonna il front-end può solo prendere il massimo, mai sommare, e che
dove il cubo non regge il filtro attivo la pagina deve mostrare un trattino.

Il peso si stima **prima** di serializzare. La regola che non si viola mai: i
totali restano esatti, la granularità no. Ogni troncamento lascia una riga
sink che conserva hit e byte, così nessun grafico perde traffico.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

import polars as pl

from .config import SiteConfig
from .enrich import read_enriched
from .gsc import read_gsc

log = logging.getLogger(__name__)

URL_OTHER = "… altri URL (aggregato)"
URL_OTHER_PROBE = "… altri URL di sonde (aggregato)"

# Voci di dizionario per gli attributi ignoti. Prima erano l'indice -1, che nel
# front-end diventava `mask[-1] === undefined` e quindi «riga da scartare».
ATTR_NEVER = "(mai nei log)"
ATTR_AGG = "(aggregato)"

# Le richieste malformate non hanno un path: su evemilano sono 51.748 righe.
# Lasciarle a `null` le fa sparire da ogni join su `path` — silenziosamente,
# perché in SQL come in Polars null non e uguale a null — e il totale del cubo
# per URL non torna piu con quello del cubo principale. Meglio una voce
# dichiarata, che resta visibile nella tabella e tiene esatte le somme.
PATH_MALFORMED = "(richiesta malformata)"

STATUS_CLASSES = {0: "altro", 2: "2xx", 3: "3xx", 4: "4xx", 5: "5xx"}


# --------------------------------------------------------------------------
# utilità
# --------------------------------------------------------------------------


def _it(n: int) -> str:
    """Numero con i separatori delle migliaia all'italiana."""
    return f"{n:,}".replace(",", ".")


def _index(values: list) -> dict:
    return {value: position for position, value in enumerate(values)}


def _ints(series: pl.Series) -> list[int]:
    return [int(v) if v is not None else 0 for v in series]


def _cube(frame: pl.DataFrame, columns: dict[str, str]) -> dict[str, list]:
    """Trasforma un DataFrame aggregato in colonne parallele di interi."""
    return {alias: _ints(frame[name]) for name, alias in columns.items()}


def _estimate_bytes(payload: dict) -> int:
    return len(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


# --------------------------------------------------------------------------
# selezione degli URL
# --------------------------------------------------------------------------


def _select_urls(
    per_url: pl.DataFrame,
    limit: int,
) -> tuple[pl.DataFrame, dict]:
    """Sceglie gli URL da rappresentare singolarmente.

    L'ordine di priorità non è negoziabile su due punti: un URL presente in
    sitemap o con click da Search Console non viene mai scartato, per quanto
    poco traffico abbia. Sono esattamente gli URL su cui il report deve poter
    dire "nessun bot lo ha mai visto", ed è un'informazione che si perde se
    l'URL non c'è.
    """
    scored = per_url.with_columns(
        pl.when(pl.col("in_sitemap"))
        .then(0)
        .when(pl.col("gsc_clicks") > 0)
        .then(1)
        .when(pl.col("gsc_impressions") > 0)
        .then(2)
        .when(pl.col("verified_bot_hits") > 0)
        .then(3)
        .when(pl.col("error_hits") > 0)
        .then(4)
        .when(pl.col("is_probe"))
        .then(6)
        .otherwise(5)
        .alias("_priority")
    ).sort(["_priority", "hits"], descending=[False, True])

    kept = scored.head(limit)
    dropped = scored.slice(limit)

    coverage = {
        "urls_total": scored.height,
        "urls_kept": kept.height,
        "urls_dropped": dropped.height,
        "hits_covered_pct": round(
            100 * kept["hits"].sum() / max(scored["hits"].sum(), 1), 2
        ),
    }
    return kept, coverage | {"_dropped": dropped}


# --------------------------------------------------------------------------
# stadio
# --------------------------------------------------------------------------


@dataclass
class Payload:
    data: dict
    size_bytes: int = 0
    degradation: list[str] = field(default_factory=list)

def build(
    cfg: SiteConfig,
    *,
    window: str = "all",
    url_limit: int | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
) -> Payload:
    budget = int(cfg.get("report.json_budget_bytes", 20_971_520))
    url_limit = url_limit or int(cfg.get("report.url_dict_size", 12_000))
    top_n = int(cfg.get("report.top_n", 25))
    top_pool = int(cfg.get("report.top_pool", top_n * 3))
    tz = cfg.timezone

    frame = read_enriched(cfg)

    # Unica conversione dall'UTC dello storage all'ora locale del sito. Farla
    # una volta sola, qui, è ciò che tiene allineati i grafici per fascia
    # oraria e quelli per giorno attraverso il cambio di ora legale.
    frame = frame.with_columns(
        pl.col("ts").dt.convert_time_zone(tz).alias("ts_local")
    ).with_columns(
        [
            pl.col("ts_local").dt.date().alias("day"),
            pl.col("ts_local").dt.hour().alias("hour"),
            pl.col("ts_local").dt.weekday().alias("dow"),
        ]
    )

    if window == "latest":
        frame = _limit_to_latest(cfg, frame)

    # Il ritaglio e` sul giorno **locale**, lo stesso che il report stampa
    # sugli assi: ritagliare sull'istante UTC sposterebbe di un'ora i confini
    # e farebbe entrare o uscire le prime richieste della giornata.
    if date_from is not None:
        frame = frame.filter(pl.col("day") >= pl.lit(date_from))
    if date_to is not None:
        frame = frame.filter(pl.col("day") <= pl.lit(date_to))
    if date_from is not None or date_to is not None:
        log.info(
            "Finestra richiesta: %s -> %s",
            date_from or "inizio archivio", date_to or "fine archivio",
        )

    frame = frame.collect()
    if frame.is_empty():
        raise ValueError("Nessun evento nel periodo selezionato")

    log.info("Aggrego %s righe", format(frame.height, ","))

    frame = frame.with_columns(pl.col("path").fill_null(PATH_MALFORMED))

    start: date = frame["day"].min()
    end: date = frame["day"].max()
    days = (end - start).days + 1

    frame = frame.with_columns(
        [
            (pl.col("day") - pl.lit(start)).dt.total_days().cast(pl.Int32).alias("d"),
            (pl.col("status") // 100).fill_null(0).cast(pl.Int8).alias("scls"),
            # Il flag delle sonde è un asse vero di ogni cubo, non solo un
            # attributo dell'URL: senza, il traffico di scanner — un quarto
            # delle richieste — resterebbe inescludibile dai grafici.
            pl.col("probe_family").is_not_null().cast(pl.Int8).alias("p"),
            # Il mese è l'asse temporale dei cubi a livello di URL. Misurato:
            # senza tempo 94.000 celle, per mese 387.000, per giorno oltre due
            # milioni. È l'unica dimensione che lì resta a grana grossa.
            (
                (pl.col("day").dt.year() - start.year) * 12
                + pl.col("day").dt.month()
                - start.month
            ).cast(pl.Int16).alias("mo"),
        ]
    )
    months = int(frame["mo"].max()) + 1

    payload: dict[str, Any] = {}
    degradation: list[str] = []

    # ---- la tabella per URL viene PRIMA dei cubi --------------------------
    #
    # `sezione` e `tipo risorsa` sono attributi dell'URL, e in `dim.url` sono
    # il valore **modale** delle richieste di quell'URL. Se i cubi li tenessero
    # per riga, sotto un filtro sezione il grafico temporale conterebbe le
    # richieste con quella sezione e la tabella URL gli URL la cui sezione
    # modale è quella, con i loro hit totali: due numeri diversi per lo stesso
    # filtro. Ri-joinare qui il valore modale sulle righe li rende lo stesso
    # numero per costruzione, e rende `sec`/`rt` gratis nel cubo per URL.
    #
    # Effetto collaterale voluto: una richiesta-sonda su un URL normale passa
    # dalla sezione «(probe)» alla sezione dell'URL. Il totale non cambia e il
    # filtro sonde continua a funzionare, perché `p` è un asse a sé.
    gsc = read_gsc(cfg)
    per_url = _per_url_table(frame, gsc, cfg)

    frame = frame.drop("section", "resource_type").join(
        per_url.select(["path", "section", "resource_type"]), on="path", how="left"
    )

    # ---- dizionari --------------------------------------------------------

    bots = (
        frame.group_by(["bot", "category", "subcategory"])
        .agg(pl.len().alias("hits"))
        .sort("hits", descending=True)
    )
    bot_names = bots["bot"].to_list()
    bot_ix = _index(bot_names)

    categories = sorted(frame["category"].unique().to_list())
    cat_ix = _index(categories)
    subcategories = sorted(x for x in frame["subcategory"].unique().to_list() if x)
    sub_ix = _index(subcategories)

    versions = [v for v in ("VERIFIED", "SPOOFED", "UNVERIFIABLE", "DNS_ERROR", "NOT_APPLICABLE")]
    ver_ix = _index(versions)

    statuses = sorted(x for x in frame["status"].unique().to_list() if x is not None)
    status_ix = _index(statuses)

    # Le due sentinelle in coda ai dizionari sostituiscono l'indice -1 usato
    # finora per «attributo ignoto». Con -1 il front-end leggeva `mask[-1]`,
    # che in JavaScript è `undefined` e quindi falso: gli URL noti a Google ma
    # mai comparsi nei log sparivano sempre dalla tabella, che è esattamente il
    # caso che la sezione sulla freschezza del crawl deve mostrare. Da qui in
    # poi ogni indice è valido, le maschere sono sempre definite e le due voci
    # sono selezionabili nel filtro come qualsiasi altra.
    sections = (
        frame.group_by("section").agg(pl.len().alias("h")).sort("h", descending=True)["section"].to_list()
    )
    sections = [s for s in sections if s is not None] + [ATTR_NEVER, ATTR_AGG]
    section_ix = _index(sections)

    restypes = sorted(x for x in frame["resource_type"].unique().to_list() if x is not None)
    restypes = restypes + [ATTR_NEVER, ATTR_AGG]
    restype_ix = _index(restypes)

    probes = sorted(x for x in frame["probe_family"].unique().to_list() if x)
    probe_ix = _index(probes)

    frame = frame.with_columns(
        [
            pl.col("bot").replace_strict(bot_ix, default=0).cast(pl.Int32).alias("b"),
            pl.col("category").replace_strict(cat_ix, default=0).cast(pl.Int8).alias("c"),
            pl.col("ip_status").replace_strict(ver_ix, default=2).cast(pl.Int8).alias("v"),
            pl.col("status").replace_strict(status_ix, default=0).cast(pl.Int16).alias("s"),
            pl.col("section").replace_strict(section_ix, default=0).cast(pl.Int16).alias("sec"),
            pl.col("resource_type").replace_strict(restype_ix, default=0).cast(pl.Int16).alias("rt"),
        ]
    )

    ai_categories = cfg.get("report.ai_categories", ["AI bot", "AI Agents bot"])

    payload["dim"] = {
        "date": {"start": start.isoformat(), "n": days, "tz": tz, "months": months},
        "bot": {
            "name": bot_names,
            "cat": [cat_ix[c] for c in bots["category"].to_list()],
            "sub": [sub_ix.get(s, -1) for s in bots["subcategory"].to_list()],
        },
        "cat": categories,
        # Le categorie che il report considera «AI» stanno in configurazione,
        # non in una regex del front-end: le regole di classificazione vivono
        # nei YAML.
        "cat_ai": [cat_ix[c] for c in ai_categories if c in cat_ix],
        "sub": subcategories,
        "ver": versions,
        "status": {"code": statuses, "cls": [s // 100 for s in statuses]},
        "section": sections,
        "restype": restypes,
        "probe": probes,
    }

    payload["cubes"] = {}

    # ---- C1 «main»: l'asse portante ---------------------------------------
    # data x bot x verifica x status x sonda x sezione x tipo. È il cubo su cui
    # si reggono i quattro widget temporali e la classifica degli status: porta
    # tutte e otto le dimensioni del filtro, e i byte, così la colonna Byte
    # resta filtrabile ovunque invece di dipendere da un secondo cubo con meno
    # assi.

    f_main = (
        frame.group_by(["d", "b", "v", "s", "p", "sec", "rt"])
        .agg([pl.len().alias("h"), pl.col("bytes").sum().alias("by")])
        .sort(["d", "b", "v", "s", "p", "sec", "rt"])
    )
    payload["cubes"]["main"] = _cube(
        f_main,
        {"d": "d", "b": "b", "v": "v", "s": "s", "p": "p", "sec": "sec", "rt": "rt",
         "h": "h", "by": "by"},
    )
    log.info("  C1 main: %s celle", format(f_main.height, ","))

    # ---- C6 «day_bot»: solo la misura non additiva ------------------------
    # Hit e byte li dà C1. Qui resta soltanto il conteggio di IP unici per
    # giorno, che non si ricava da nessun altro cubo e non si può sommare: il
    # prefisso `~` lo dichiara, e il riduttore JS si rifiuta di sommare una
    # colonna che comincia così.

    f_ip = (
        frame.group_by(["d", "b", "p"])
        .agg(pl.col("ip").n_unique().alias("ui"))
        .sort(["d", "b"])
    )
    payload["cubes"]["day_bot"] = _cube(f_ip, {"d": "d", "b": "b", "p": "p", "ui": "~ui"})

    # ---- C4 «hour_dow»: ora x giorno della settimana ----------------------
    # La data resta fuori per costruzione: questo cubo è un aggregato
    # sull'intero periodo, e aggiungere `d` lo trasformerebbe nella tabella dei
    # fatti. È l'unico widget con una dimensione strutturalmente scoperta.

    f_hour = (
        frame.group_by(["hour", "dow", "b", "v", "scls", "p", "sec", "rt"])
        .agg(pl.len().alias("h"))
        .sort(["dow", "hour"])
    )
    payload["cubes"]["hour_dow"] = _cube(
        f_hour,
        {"hour": "hh", "dow": "dw", "b": "b", "v": "v", "scls": "sc", "p": "p",
         "sec": "sec", "rt": "rt", "h": "h"},
    )
    log.info("  C4 hour_dow: %s celle", format(f_hour.height, ","))

    # ---- C3 «attack»: le sonde nel tempo ----------------------------------

    probe_frame = frame.filter(pl.col("probe_family").is_not_null()).with_columns(
        pl.col("probe_family").replace_strict(probe_ix, default=0).cast(pl.Int16).alias("pf")
    )
    f_attack = (
        probe_frame.group_by(["d", "pf", "b", "v", "scls", "sec", "rt"])
        .agg([pl.len().alias("h"), pl.col("ip").n_unique().alias("ui")])
        .sort(["d", "pf"])
    )
    payload["cubes"]["attack"] = _cube(
        f_attack,
        {"d": "d", "pf": "pf", "b": "b", "v": "v", "scls": "sc", "sec": "sec",
         "rt": "rt", "h": "h", "ui": "~ui"},
    )
    log.info("  C3 attack: %s celle", format(f_attack.height, ","))

    # ---- dimensione URL ---------------------------------------------------

    kept, coverage = _select_urls(per_url, url_limit)
    dropped = coverage.pop("_dropped")

    url_names = kept["path"].to_list()
    n_kept = len(url_names)

    # La coda scartata diventa DUE righe di raccolta, non una: separando le
    # sonde dal resto, il totale della tabella resta esatto anche quando il
    # filtro sulle sonde è attivo — che è la vista di default.
    sinks: list[dict] = []
    sink_of: dict[bool, int] = {}
    if dropped.height:
        for is_probe, label in ((False, URL_OTHER), (True, URL_OTHER_PROBE)):
            part = dropped.filter(pl.col("is_probe") == is_probe)
            if part.height:
                sink_of[is_probe] = n_kept + len(sinks)
                sinks.append({
                    "label": label,
                    "is_probe": is_probe,
                    "rows": part.height,
                    "gsc_clicks": int(part["gsc_clicks"].sum()),
                    "gsc_impressions": int(part["gsc_impressions"].sum()),
                })
        url_names = url_names + [s["label"] for s in sinks]
        degradation.append(
            f"tabella URL troncata a {_it(n_kept)} voci su {_it(per_url.height)} "
            f"(copertura {str(coverage['hits_covered_pct']).replace('.', ',')}% degli hit)"
        )

    sec_never, sec_agg = section_ix[ATTR_NEVER], section_ix[ATTR_AGG]
    rt_never, rt_agg = restype_ix[ATTR_NEVER], restype_ix[ATTR_AGG]

    payload["dim"]["url"] = {
        "p": url_names,
        "ag": [0] * n_kept + [1] * len(sinks),
        "sec": [section_ix[s] if s is not None else sec_never for s in kept["section"].to_list()]
        + [sec_agg] * len(sinks),
        "rt": [restype_ix[r] if r is not None else rt_never for r in kept["resource_type"].to_list()]
        + [rt_agg] * len(sinks),
        "pb": [1 if p else 0 for p in kept["is_probe"].to_list()]
        + [1 if s["is_probe"] else 0 for s in sinks],
        "fs": _ints(kept["first_seen"]) + [-1] * len(sinks),
        "ls": _ints(kept["last_seen"]) + [-1] * len(sinks),
        "gls": _ints(kept["gbot_last_seen"]) + [-2] * len(sinks),
        # Hit e byte si ricalcolano dal cubo C2 sotto filtro: questi restano i
        # totali di periodo, usati per l'ordinamento iniziale e come confronto.
        "h": _ints(kept["hits"]) + [0] * len(sinks),
        "by": _ints(kept["bytes"]) + [0] * len(sinks),
        # Gli IP unici di un aggregato non sono sommabili: -1 = non calcolabile.
        "~ui": _ints(kept["ip_uniq"]) + [-1] * len(sinks),
        "gc": _ints(kept["gsc_clicks"]) + [s["gsc_clicks"] for s in sinks],
        "gi": _ints(kept["gsc_impressions"]) + [s["gsc_impressions"] for s in sinks],
        "sm": [1 if x else 0 for x in kept["in_sitemap"].to_list()] + [0] * len(sinks),
    }
    log.info(
        "  D_url: %s URL su %s (copertura %.1f%% degli hit)",
        format(n_kept, ","), format(per_url.height, ","), coverage["hits_covered_pct"],
    )

    # ---- C2 «url»: il cubo per URL ----------------------------------------
    # URL x bot x verifica x classe di status x sonda x mese. Con l'indice bot
    # pieno, non un raggruppamento: misurato, l'esattezza sul filtro user agent
    # costa il 37% di celle in più del raggruppamento a 18 gruppi, e in cambio
    # elimina sia la mappatura approssimata sia l'elenco cablato dei bot AI.
    #
    # La coda scartata va sui DUE sink giusti. Finora `replace_strict(...,
    # default=len(url_ix))` mandava ogni URL scartato sul sink non-sonda: le
    # sonde della coda venivano contate come traffico normale, e i totali del
    # cubo divergevano da quelli della tabella appena si filtrava sulle sonde.

    u_map = pl.DataFrame(
        {"path": url_names[:n_kept], "u": pl.Series(range(n_kept), dtype=pl.Int32)}
    )
    if sinks:
        tail = dropped.select(["path", "is_probe"]).with_columns(
            pl.when(pl.col("is_probe"))
            .then(pl.lit(sink_of.get(True, n_kept)))
            .otherwise(pl.lit(sink_of.get(False, n_kept)))
            .cast(pl.Int32)
            .alias("u")
        ).select(["path", "u"])
        u_map = pl.concat([u_map, tail])

    url_frame = frame.join(u_map, on="path", how="left")
    orphan = int(url_frame["u"].null_count())
    if orphan:
        raise ValueError(
            f"{orphan} righe senza indice URL: la mappatura path->u non copre il frame"
        )

    f_url = (
        url_frame.group_by(["u", "b", "v", "scls", "p", "mo"])
        .agg([pl.len().alias("h"), pl.col("bytes").sum().alias("by")])
        .sort(["u", "b", "v", "scls", "p", "mo"])
    )
    payload["cubes"]["url"] = _cube(
        f_url,
        {"u": "u", "b": "b", "v": "v", "scls": "sc", "p": "p", "mo": "mo",
         "h": "h", "by": "by"},
    )
    log.info("  C2 url: %s celle", format(f_url.height, ","))

    # ---- C5: le classifiche ------------------------------------------------

    payload["tops"] = _tops(frame, top_n, top_pool, bot_ix)

    # ---- meta ---------------------------------------------------------------

    payload["meta"] = _meta(cfg, frame, start, end, days, coverage, gsc is not None)
    payload["meta"]["top_n"] = top_n
    payload["meta"]["top_pool"] = top_pool

    # Gli assi di ogni cubo viaggiano nel payload: il front-end ne deriva il
    # badge «filtri non applicati qui» invece di dichiararlo a mano in ogni
    # widget. Se una leva di budget toglie un asse, l'avviso ricompare da solo
    # — altrimenti la pagina mostrerebbe numeri non filtrati senza dirlo, che è
    # l'unica cosa che questo report non deve fare.
    payload["meta"]["axes"] = {
        "main": {"dims": ["date", "bot", "cat", "ver", "status", "sec", "rt", "probe"]},
        "url": {
            "dims": ["date", "bot", "cat", "ver", "status", "sec", "rt", "probe"],
            "coarse": {"date": "mese"},
        },
        "hour_dow": {"dims": ["bot", "cat", "ver", "status", "sec", "rt", "probe"]},
        "attack": {"dims": ["date", "bot", "cat", "ver", "status", "sec", "rt"]},
        "day_bot": {"dims": ["date", "bot", "cat", "probe"]},
        # La sezione sulla freschezza del crawl ha un universo suo — gli URL
        # che Google conosce — e una misura che è per definizione un totale di
        # periodo su un agente fisso. Sezione e tipo scelgono quali URL
        # guardare; il resto no, e il badge lo dice.
        "stale": {"dims": ["sec", "rt"]},
        "top_ua": {"dims": ["date", "bot", "cat", "ver", "status", "probe"]},
        "top_ip": {"dims": ["date", "cat", "ver", "status", "probe"]},
        "top_referer": {"dims": ["date", "cat", "ver", "status", "probe"]},
    }
    payload["meta"]["selftest"] = _selftest(frame, days, cat_ix, ver_ix)

    size = _estimate_bytes(payload)
    payload["meta"]["json_bytes"] = size
    payload["meta"]["json_budget"] = budget
    payload["meta"]["degradation"] = degradation

    log.info(
        "Payload: %.2f MB su un tetto di %.2f MB (%.0f%%)",
        size / 1_048_576, budget / 1_048_576, 100 * size / budget,
    )
    if size > budget:
        log.warning(
            "Il payload supera il tetto. Le due leve sono `report.url_dict_size` "
            "(ora %d: i cubi per URL scalano linearmente) e `report.top_pool` "
            "(ora %d). In alternativa alza `report.json_budget_bytes`.",
            url_limit, top_pool,
        )

    return Payload(data=payload, size_bytes=size, degradation=degradation)


def _selftest(frame: pl.DataFrame, days: int, cat_ix: dict, ver_ix: dict) -> list[dict]:
    """Stati di filtro con i totali calcolati qui, riga per riga.

    È l'unico controllo che attraversa il confine fra i due linguaggi: tutti
    gli altri ne verificano un lato solo. Il front-end fa girare gli stessi
    stati nel proprio riduttore e confronta; se un numero non torna, la pagina
    lo dice invece di mostrare in silenzio un totale sbagliato.
    """
    half = max(days // 2, 1)
    states: list[dict] = [
        {"d0": 0, "d1": days - 1, "probe": "all"},
        {"d0": 0, "d1": days - 1, "probe": "exclude"},
        {"d0": 0, "d1": days - 1, "probe": "only"},
        {"d0": half, "d1": days - 1, "probe": "all"},
        {"d0": 0, "d1": days - 1, "probe": "all", "ver": [ver_ix["VERIFIED"]]},
        {"d0": 0, "d1": days - 1, "probe": "all", "scls": [4]},
        {"d0": 0, "d1": days - 1, "probe": "exclude", "scls": [2, 3]},
    ]
    if cat_ix:
        first_cat = sorted(cat_ix.values())[0]
        states.append({"d0": 0, "d1": days - 1, "probe": "all", "cat": [first_cat]})
        states.append(
            {"d0": half, "d1": days - 1, "probe": "exclude", "cat": [first_cat],
             "ver": [ver_ix["VERIFIED"]], "scls": [2]}
        )
    top_sec = int(frame["sec"].mode().first())
    states.append({"d0": 0, "d1": days - 1, "probe": "all", "sec": [top_sec]})
    states.append({"d0": 0, "d1": half, "probe": "exclude", "sec": [top_sec]})

    cases = []
    for state in states:
        expr = (pl.col("d") >= state["d0"]) & (pl.col("d") <= state["d1"])
        if state.get("cat"):
            expr &= pl.col("c").is_in(state["cat"])
        if state.get("bot"):
            expr &= pl.col("b").is_in(state["bot"])
        if state.get("ver"):
            expr &= pl.col("v").is_in(state["ver"])
        if state.get("scls"):
            expr &= pl.col("scls").is_in(state["scls"])
        if state.get("sec"):
            expr &= pl.col("sec").is_in(state["sec"])
        if state.get("rt"):
            expr &= pl.col("rt").is_in(state["rt"])
        if state["probe"] == "exclude":
            expr &= pl.col("p") == 0
        elif state["probe"] == "only":
            expr &= pl.col("p") == 1
        sub = frame.filter(expr)
        cases.append({"f": state, "h": sub.height, "by": int(sub["bytes"].sum() or 0)})
    return cases


def _limit_to_latest(cfg: SiteConfig, frame: pl.LazyFrame) -> pl.LazyFrame:
    """Restringe al solo file di log più recente.

    "Più recente" si stabilisce dal contenuto, non dal nome: su questo server
    la numerazione della rotazione non è cronologica.
    """
    from .parse import load_state

    state = load_state(cfg)
    archives = [(a["last_ts"], a["first_ts"]) for a in state["archives"].values() if a.get("last_ts")]
    if not archives:
        return frame
    last_ts, first_ts = max(archives)
    log.info("--latest: mi limito all'archivio che copre %s → %s", first_ts[:10], last_ts[:10])
    return frame.filter(pl.col("ts") >= pl.lit(first_ts).str.to_datetime(time_zone="UTC"))


def _per_url_table(frame: pl.DataFrame, gsc, cfg: SiteConfig) -> pl.DataFrame:
    """Una riga per URL, con tutto ciò che serve a sceglierli e a mostrarli."""
    # Dove `remote_addr` è il nodo di bordo di un proxy nessun IP può risultare
    # VERIFIED — `verify.py` taglia corto prima di guardare i range — e
    # pretendere la verifica qui darebbe «mai preso» su OGNI url del sito.
    # Che è una frase diversa dal fatto: non è che Googlebot non sia passato,
    # è che non si può dimostrare che fosse lui. Meglio contare l'agente
    # dichiarato e dire nel report quanto vale, che tacere un dato che c'è.
    ip_trusted = bool(cfg.get("client_ip_trusted", True))
    googlebot = pl.col("bot") == "Googlebot"
    googlebot_seen = (
        (googlebot & (pl.col("ip_status") == "VERIFIED")) if ip_trusted else googlebot
    )
    verified_discovery = pl.col("ip_status") == "VERIFIED"

    table = frame.group_by("path").agg(
        [
            pl.len().alias("hits"),
            pl.col("bytes").sum().alias("bytes"),
            pl.col("ip").n_unique().alias("ip_uniq"),
            pl.col("d").min().alias("first_seen"),
            pl.col("d").max().alias("last_seen"),
            pl.when(googlebot_seen).then(pl.col("d")).otherwise(None).max().alias("gbot_last_seen"),
            verified_discovery.sum().alias("verified_bot_hits"),
            pl.col("scls").is_in([4, 5]).sum().alias("error_hits"),
            # `.first()` in un group_by Polars restituisce un elemento
            # arbitrario: per un URL le cui richieste ricadono in sezioni
            # diverse — succede, perché la famiglia di sonda dipende anche da
            # metodo e status — mostrerebbe una sezione a caso. Il valore
            # modale è deterministico e rappresenta la maggioranza.
            pl.col("section").mode().first().alias("section"),
            pl.col("resource_type").mode().first().alias("resource_type"),
            # Un URL conta come sonda se lo è per la maggior parte delle sue
            # richieste, coerentemente con le due colonne qui sopra.
            (pl.col("probe_family").is_not_null().mean() > 0.5).alias("is_probe"),
        ]
    ).with_columns(pl.col("gbot_last_seen").fill_null(-1))

    if gsc is not None:
        gsc_url = (
            gsc.group_by("path")
            .agg([pl.col("clicks").sum().alias("gsc_clicks"), pl.col("impressions").sum().alias("gsc_impressions")])
            .collect()
        )
        table = table.join(gsc_url, on="path", how="left")
    else:
        gsc_url = None
        table = table.with_columns(
            [pl.lit(0).alias("gsc_clicks"), pl.lit(0).alias("gsc_impressions")]
        )
    table = table.with_columns(
        [pl.col("gsc_clicks").fill_null(0), pl.col("gsc_impressions").fill_null(0)]
    )

    sitemap = _load_sitemap(cfg)
    table = table.with_columns(
        pl.col("path").is_in(sitemap).alias("in_sitemap") if sitemap else pl.lit(False).alias("in_sitemap")
    )

    # Gli URL che Google conosce ma che nei log non compaiono affatto vanno
    # aggiunti a mano: la tabella nasce dai log, quindi da sola non può
    # contenerli. Su evemilano sono 75 URL con impression in Search Console
    # che in tredici mesi nessuno — Googlebot compreso — ha mai richiesto, ed è
    # esattamente il caso che la sezione sulla freschezza del crawl deve
    # mostrare. Senza questa unione sparirebbero invece di essere segnalati.
    known = set(table["path"].to_list())
    missing: list[str] = [p for p in sitemap if p not in known]
    if gsc_url is not None:
        missing += [
            p for p in gsc_url.filter(pl.col("gsc_impressions") > 0)["path"].to_list()
            if p not in known and p not in set(missing)
        ]
    if missing:
        log.info(
            "  %s URL noti a Google ma mai comparsi nei log: aggiunti con zero richieste",
            format(len(missing), ","),
        )
        extra = pl.DataFrame({"path": missing}).with_columns(
            [
                pl.lit(0, dtype=pl.UInt32).alias("hits"),
                pl.lit(0, dtype=pl.Int64).alias("bytes"),
                pl.lit(0, dtype=pl.UInt32).alias("ip_uniq"),
                pl.lit(-1, dtype=pl.Int32).alias("first_seen"),
                pl.lit(-1, dtype=pl.Int32).alias("last_seen"),
                pl.lit(-1, dtype=pl.Int32).alias("gbot_last_seen"),
                pl.lit(0, dtype=pl.UInt32).alias("verified_bot_hits"),
                pl.lit(0, dtype=pl.UInt32).alias("error_hits"),
                pl.lit(None, dtype=pl.String).alias("section"),
                pl.lit(None, dtype=pl.String).alias("resource_type"),
                pl.lit(False).alias("is_probe"),
            ]
        )
        if gsc_url is not None:
            extra = extra.join(gsc_url, on="path", how="left")
        else:
            extra = extra.with_columns(
                [pl.lit(0).alias("gsc_clicks"), pl.lit(0).alias("gsc_impressions")]
            )
        extra = extra.with_columns(
            [
                pl.col("gsc_clicks").fill_null(0),
                pl.col("gsc_impressions").fill_null(0),
                pl.col("path").is_in(sitemap).alias("in_sitemap") if sitemap else pl.lit(False).alias("in_sitemap"),
            ]
        )
        table = pl.concat(
            [table, extra.select(table.columns)], how="vertical_relaxed"
        )

    return table


def _load_sitemap(cfg: SiteConfig) -> list[str]:
    """Path presenti in una sitemap fornita in `input/<dominio>/`.

    Input opzionale: se manca, la sezione sugli orphan URL si nasconde invece
    di produrre numeri privi di senso.
    """
    import re
    import xml.etree.ElementTree as ET

    paths: list[str] = []
    directory = cfg.paths.input
    if not directory.exists():
        return paths

    host = cfg.get("site.host", cfg.domain)
    for candidate in sorted(directory.glob("*.xml")):
        try:
            root = ET.parse(candidate).getroot()
        except ET.ParseError as exc:
            log.warning("Sitemap non interpretabile, la salto: %s (%s)", candidate.name, exc)
            continue
        for element in root.iter():
            if element.tag.endswith("}loc") or element.tag == "loc":
                url = (element.text or "").strip()
                path = re.sub(r"^https?://[^/]+", "", url) or "/"
                paths.append(path)
    if paths:
        log.info("Sitemap: %s URL da %s", format(len(paths), ","), directory)
    return paths


def _tops(frame: pl.DataFrame, n: int, pool: int, bot_ix: dict) -> dict:
    """Le classifiche filtrabili.

    `uri` e `status` non stanno più qui: si ricalcolano nel front-end dai cubi
    C2 e C1, quindi sono esatti su ogni dimensione e ordinano l'intero
    dizionario invece di venticinque voci congelate.

    Restano user agent, IP e referer, che non sono assi di nessun cubo. Per
    ognuno si serializza un pool di `pool` chiavi candidate con il proprio cubo
    `chiave x giorno x categoria x verifica x classe x sonda`: il front-end
    ri-ordina i primi `n` sotto filtro. Il limite, da dichiarare in pagina, è
    che una chiave fuori dal pool globale non può risalire in classifica.
    """
    out: dict[str, Any] = {"n": n, "pool": pool}

    for kind, column in (("ua", "user_agent"), ("ip", "ip"), ("referer", "referer")):
        base = frame.filter(pl.col(column).is_not_null())
        if base.is_empty():
            continue
        ranked = (
            base.group_by(column)
            .agg([pl.len().alias("h"), pl.col("ip").n_unique().alias("ui")])
            .sort("h", descending=True)
            .head(pool)
        )
        keys = ranked[column].to_list()
        key_ix = {k: i for i, k in enumerate(keys)}
        sub = base.filter(pl.col(column).is_in(keys)).with_columns(
            pl.col(column).replace_strict(key_ix, default=0).cast(pl.Int32).alias("k")
        )
        cube = (
            sub.group_by(["k", "d", "c", "v", "scls", "p"])
            .agg(pl.len().alias("h"))
            .sort(["k", "d"])
        )
        entry: dict[str, Any] = {
            "k": [str(x) for x in keys],
            # IP unici: non additivi, quindi solo al totale di periodo.
            "~ui": _ints(ranked["ui"]),
            "cube": _cube(
                cube,
                {"k": "k", "d": "d", "c": "c", "v": "v", "scls": "sc", "p": "p", "h": "h"},
            ),
        }
        if kind == "ua":
            # Il bot è una funzione dello user agent grezzo: attributo della
            # chiave, non asse del cubo. Così il filtro «user agent» funziona
            # su questa classifica senza moltiplicare le celle.
            owner = sub.group_by(column).agg(pl.col("bot").mode().first().alias("bot"))
            of = dict(zip(owner[column].to_list(), owner["bot"].to_list()))
            entry["b"] = [bot_ix.get(of.get(k), 0) for k in keys]
        out[kind] = entry
        log.info("  C5 top_%s: %s celle su %s chiavi", kind, format(cube.height, ","), len(keys))

    return out


def _meta(
    cfg: SiteConfig,
    frame: pl.DataFrame,
    start: date,
    end: date,
    days: int,
    coverage: dict,
    has_gsc: bool,
) -> dict:
    from .parse import load_state

    state = load_state(cfg)
    parsed = sum(a["rows"] for a in state["archives"].values())
    unparsed = sum(a["unparsed"] for a in state["archives"].values())

    return {
        "domain": cfg.domain,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "period": [start.isoformat(), end.isoformat()],
        "days": days,
        "tz": cfg.timezone,
        "rows": frame.height,
        "rows_parsed_total": parsed,
        "rows_unparsed": unparsed,
        "unparsed_pct": round(100 * unparsed / max(parsed + unparsed, 1), 4),
        "unique_ips": frame["ip"].n_unique(),
        "unique_urls": frame["path"].n_unique(),
        "unique_uas": frame["user_agent"].n_unique(),
        "probe_hits": int(frame["probe_family"].is_not_null().sum()),
        "attack_hits": int(frame["is_attack_probe"].sum()),
        "ua_anomaly_hits": int(frame["is_ua_anomaly"].sum()),
        "coverage": coverage,
        "has_gsc": has_gsc,
        "gsc_delay_days": int(cfg.get("gsc.data_delay_days", 3)),
        "googlebot_stale_days": int(cfg.get("report.googlebot_stale_days", 30)),
        "has_sitemap": bool(_load_sitemap(cfg)),
        "assets_logged": bool(cfg.get("notes.assets_logged", True)),
        "client_ip_trusted": bool(cfg.get("client_ip_trusted", True)),
        "excluded_from_log": cfg.get("notes.excluded_from_log", []),
    }
