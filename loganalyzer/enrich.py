"""Attributi derivati: sezione, tipo di risorsa, sonde, anomalie.

Qui il dataset passa da "cosa dice il log" a "cosa serve al report". Tre
scelte meritano una spiegazione.

**La sezione non è il primo segmento dell'URI.** Preso alla lettera, sui log
di evemilano.com quel campo ha 35.338 valori distinti, quasi tutti generati
da scanner che chiedono percorsi inventati. Una dimensione con quella
cardinalità non è pivotabile. La sezione si ricava quindi da una allowlist
per sito, con override espliciti, e tutto il resto confluisce in `(other)`.

**Il traffico di sonde si tiene, ma si marca.** Escluderlo dal dataset
sarebbe comodo e sbagliato: è la metà delle richieste e dice cose vere sul
sito. Marcarlo permette al report di tenerlo fuori dalle viste SEO e di
dedicargli una sezione propria.

**Uno user agent da browser non basta a dire "browser".** Sui 13 mesi il
singolo user agent più frequente è un Chrome su macOS con 2.026.397 richieste
da 7.748 indirizzi: 261 richieste per IP, concentrate in due mesi. È uno
scraper travestito, e da solo vale il 27% del traffico del sito. La colonna
`is_ua_anomaly` lo separa dal traffico umano, così il rapporto browser/bot
del report non è falsato di oltre un quarto.
"""

from __future__ import annotations

import logging
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

import polars as pl
import yaml

from .classify import classify_user_agents, load_rules
from .config import CONFIG_DIR, SiteConfig
from .parse import read_events
from .verify import read_verdicts

log = logging.getLogger(__name__)

ATTACK_FILE = CONFIG_DIR / "attack_patterns.yaml"

ASSET_EXT = r"\.(css|js|mjs|jpe?g|png|gif|webp|avif|svg|ico|woff2?|ttf|eot|otf|mp4|webm|ogg|mp3)$"


class EnrichError(ValueError):
    pass


# --------------------------------------------------------------------------
# regole delle sonde
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ProbeRule:
    id: str
    family: str
    attack: bool
    path_regex: str
    exclude_path_regex: str | None = None
    methods: tuple[str, ...] = ()
    statuses: tuple[int, ...] = ()


def load_probe_rules(path: Path | None = None) -> list[ProbeRule]:
    path = path or ATTACK_FILE
    if not path.exists():
        raise FileNotFoundError(f"Manca {path}")
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}

    raw = data.get("rules")
    if not isinstance(raw, list) or not raw:
        raise EnrichError(f"{path}: la chiave `rules` deve essere una lista non vuota")

    rules: list[ProbeRule] = []
    seen: set[str] = set()
    for position, item in enumerate(raw):
        for required in ("id", "family", "path_regex"):
            if required not in item:
                raise EnrichError(f"{path}: regola in posizione {position} senza `{required}`")
        if item["id"] in seen:
            raise EnrichError(f"{path}: id duplicato: {item['id']!r}")
        seen.add(item["id"])
        try:
            re.compile(item["path_regex"])
        except re.error as exc:
            raise EnrichError(f"{path}: regola {item['id']!r}, regex non valida: {exc}") from exc
        rules.append(
            ProbeRule(
                id=item["id"],
                family=item["family"],
                attack=bool(item.get("attack", True)),
                path_regex=item["path_regex"],
                exclude_path_regex=item.get("exclude_path_regex"),
                methods=tuple(item.get("methods") or ()),
                statuses=tuple(item.get("statuses") or ()),
            )
        )
    log.info("attack_patterns.yaml: %d regole (%d ostili)", len(rules), sum(r.attack for r in rules))
    return rules


def probe_expressions(rules: list[ProbeRule]) -> tuple[pl.Expr, pl.Expr]:
    """Espressioni per `probe_family` e `is_attack_probe`, primo match vince."""
    family = pl.lit(None, dtype=pl.String)
    attack = pl.lit(None, dtype=pl.Boolean)

    for rule in reversed(rules):
        condition = pl.col("path").str.contains(rule.path_regex)
        if rule.exclude_path_regex:
            condition = condition & ~pl.col("path").str.contains(rule.exclude_path_regex)
        if rule.methods:
            condition = condition & pl.col("method").cast(pl.String).is_in(list(rule.methods))
        if rule.statuses:
            condition = condition & pl.col("status").is_in(list(rule.statuses))
        condition = condition.fill_null(False)

        family = pl.when(condition).then(pl.lit(rule.family)).otherwise(family)
        attack = pl.when(condition).then(pl.lit(rule.attack)).otherwise(attack)

    return family.alias("probe_family"), attack.fill_null(False).alias("is_attack_probe")


# --------------------------------------------------------------------------
# sezione e tipo di risorsa
# --------------------------------------------------------------------------


def section_expression(cfg: SiteConfig) -> pl.Expr:
    settings = cfg.get("sections") or {}
    root_label = settings.get("root_label", "(root)")
    other_label = settings.get("other_label", "(other)")
    probe_label = settings.get("probe_label", "(probe)")
    known = list(settings.get("known") or [])

    first_segment = (
        pl.col("path").str.strip_chars_start("/").str.split("/").list.first()
    )

    # Ordine: le sonde non contribuiscono alla dimensione, poi gli override
    # espliciti, poi la allowlist, infine il calderone.
    expr = (
        pl.when(first_segment.is_null() | (first_segment == ""))
        .then(pl.lit(root_label))
        .when(first_segment.is_in(known))
        .then(first_segment)
        .otherwise(pl.lit(other_label))
    )

    for override in reversed(settings.get("overrides") or []):
        expr = (
            pl.when(pl.col("path").str.contains(override["pattern"]).fill_null(False))
            .then(pl.lit(override["section"]))
            .otherwise(expr)
        )

    return (
        pl.when(pl.col("probe_family").is_not_null())
        .then(pl.lit(probe_label))
        .otherwise(expr)
        .alias("section")
    )


def resource_type_expression() -> pl.Expr:
    """Tipo di risorsa richiesta.

    Non è il rapporto "HTML contro asset" che chiederebbe un'analisi classica:
    sul vhost di evemilano css, js, font e immagini hanno `access_log off` e
    non compaiono nei log. Il valore `asset` resta previsto perché altri siti
    potrebbero loggarli, ma qui sarà praticamente vuoto.
    """
    path = pl.col("path")
    return (
        pl.when(pl.col("request_malformed"))
        .then(pl.lit("malformed"))
        .when(path.str.contains(r"(?i)^/robots\.txt$"))
        .then(pl.lit("robots"))
        .when(path.str.contains(r"(?i)sitemap[^/]*\.xml$|\.xml\.gz$"))
        .then(pl.lit("sitemap"))
        .when(path.str.contains(r"(?i)/feed/?$|/rss/?$|\.rss$|/comments/feed"))
        .then(pl.lit("feed"))
        .when(path.str.contains(r"(?i)^/wp-json/|^/api/|^/graphql"))
        .then(pl.lit("api"))
        .when(path.str.contains(ASSET_EXT))
        .then(pl.lit("asset"))
        .when(path.str.contains(r"(?i)\.(php|phtml|asp|aspx|jsp|cgi)$"))
        .then(pl.lit("php-endpoint"))
        .when(path.str.contains(r"(?i)\.(json|txt|xml|csv|ya?ml)$"))
        .then(pl.lit("data"))
        .otherwise(pl.lit("HTML"))
        .alias("resource_type")
    )


# --------------------------------------------------------------------------
# anomalie sugli user agent
# --------------------------------------------------------------------------


def ua_anomaly_table(events: pl.LazyFrame, cfg: SiteConfig) -> pl.DataFrame:
    """User agent che si dichiarano browser ma si comportano da automa.

    Il segnale è la concentrazione: tante richieste da pochissimi indirizzi.
    Un browser vero, per quanto diffuso, ha molti IP e poche richieste per IP;
    Chrome su questo sito sta a 17 richieste per indirizzo. Uno scraper che si
    traveste ne fa centinaia.
    """
    min_hits = int(cfg.get("anomaly.min_hits", 10_000))
    min_ratio = float(cfg.get("anomaly.min_hits_per_ip", 50))

    return (
        events.group_by("user_agent")
        .agg(
            [
                pl.len().alias("_ua_hits"),
                pl.col("ip").n_unique().alias("_ua_ips"),
            ]
        )
        .with_columns(
            (pl.col("_ua_hits") / pl.col("_ua_ips")).alias("_ua_hits_per_ip")
        )
        .with_columns(
            (
                (pl.col("_ua_hits") >= min_hits)
                & (pl.col("_ua_hits_per_ip") >= min_ratio)
            ).alias("_ua_concentrated")
        )
        .select(["user_agent", "_ua_hits", "_ua_ips", "_ua_hits_per_ip", "_ua_concentrated"])
        .collect()
    )


# --------------------------------------------------------------------------
# stadio
# --------------------------------------------------------------------------


@dataclass
class EnrichStats:
    rows: int = 0
    probes: int = 0
    attacks: int = 0
    anomalous_ua_rows: int = 0
    sections: int = 0

    def summary(self) -> str:
        return (
            f"{self.rows:,} righe; {self.probes:,} sonde ({100 * self.probes / max(self.rows, 1):.1f}%), "
            f"di cui {self.attacks:,} ostili; {self.anomalous_ua_rows:,} righe da UA anomali; "
            f"{self.sections} sezioni distinte"
        )


def enrich_site(cfg: SiteConfig) -> EnrichStats:
    paths = cfg.paths
    ruleset = load_rules()
    probe_rules = load_probe_rules()

    events = read_events(cfg)
    verdicts = read_verdicts(cfg)

    user_agents = events.select("user_agent").unique().collect()["user_agent"]
    ua_map = classify_user_agents(user_agents, ruleset).lazy()
    anomalies = ua_anomaly_table(events, cfg).lazy()

    family_expr, attack_expr = probe_expressions(probe_rules)

    # `join_nulls=True` non è un dettaglio: l'1,6% delle richieste non ha uno
    # user agent, e senza questo quelle righe uscirebbero dalla join con la
    # categoria a null, sparendo da ogni conteggio per categoria.
    enriched = (
        events.join(ua_map, on="user_agent", how="left", join_nulls=True)
        .join(anomalies, on="user_agent", how="left", join_nulls=True)
        .join(verdicts, on=["ip", "bot_id"], how="left", join_nulls=True)
        .with_columns([family_expr, attack_expr])
        .with_columns(
            [
                section_expression(cfg),
                resource_type_expression(),
                pl.col("query").is_not_null().alias("has_query"),
                # Anomalia solo per chi si dichiara browser: un bot dichiarato
                # che fa molte richieste da pochi IP è semplicemente un bot.
                (
                    pl.col("_ua_concentrated").fill_null(False)
                    & (pl.col("category") == "Browser")
                ).alias("is_ua_anomaly"),
                pl.col("ip_status").fill_null(pl.lit("UNVERIFIABLE")),
            ]
        )
        .drop(["_ua_concentrated"])
    )

    log.info("Scrivo il dataset arricchito")
    shutil.rmtree(paths.enriched, ignore_errors=True)
    paths.enriched.mkdir(parents=True, exist_ok=True)

    frame = enriched.with_columns(pl.col("ts").dt.strftime("%Y-%m").alias("_ym")).collect()
    for (ym,), group in frame.group_by(["_ym"], maintain_order=True):
        target = paths.enriched / f"ym={ym}"
        target.mkdir(parents=True, exist_ok=True)
        group.drop("_ym").write_parquet(target / "part.parquet", compression="zstd", statistics=True)

    stats = EnrichStats(
        rows=frame.height,
        probes=int(frame["probe_family"].is_not_null().sum()),
        attacks=int(frame["is_attack_probe"].sum()),
        anomalous_ua_rows=int(frame["is_ua_anomaly"].sum()),
        sections=frame["section"].n_unique(),
    )
    log.info("enrich: %s", stats.summary())
    return stats


def read_enriched(cfg: SiteConfig) -> pl.LazyFrame:
    pattern = cfg.paths.enriched / "ym=*" / "*.parquet"
    if not any(cfg.paths.enriched.glob("ym=*/*.parquet")):
        raise FileNotFoundError(
            f"Dataset arricchito assente. Lancia prima: main.py enrich --site {cfg.domain}"
        )
    return pl.scan_parquet(str(pattern))
