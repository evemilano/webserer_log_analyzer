"""Dall'archivio `.gz` ai Parquet, con parsing vettoriale in Polars.

Le righe non entrano in Python una per una: l'archivio viene letto come una
colonna di testo e la regex generata da `logformat` si applica in blocco con
`str.extract_groups()`, che gira nel motore Rust. Su 7,9 milioni di righe la
differenza rispetto a un ciclo con `re.match` è di un ordine di grandezza.

Lo stadio è idempotente per archivio: `_parse_state.json` ricorda quanti byte
di ciascun archivio erano già stati parsati, e un archivio invariato viene
saltato. Quando il file di log attivo cresce, il suo archivio viene riparsato
per intero — costa pochi secondi e evita la contabilità degli offset, che
sarebbe l'unico punto della pipeline capace di duplicare righe in silenzio.
"""

from __future__ import annotations

import json
import logging
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import polars as pl

from . import logformat
from .config import SiteConfig
from .fetch import load_manifest

log = logging.getLogger(__name__)

STATE_VERSION = 1

# "GET /blog/x/ HTTP/2.0" -> metodo, URI, protocollo.
# L'URI è greedy fino all'ultimo spazio: una richiesta può contenere spazi
# non escapati da nginx, e in quel caso la parte centrale è tutta URI.
_REQUEST_RE = r"^(?P<method>[A-Za-z_-]+) (?P<target>.*) (?P<protocol>HTTP/[0-9.]+)$"

_SENTINEL = "-"


@dataclass
class ParseStats:
    archives_parsed: int = 0
    archives_skipped: int = 0
    rows: int = 0
    unparsed: int = 0
    excluded: int = 0
    malformed_requests: int = 0
    first_ts: datetime | None = None
    last_ts: datetime | None = None
    per_archive: list[dict] = field(default_factory=list)

    @property
    def unparsed_pct(self) -> float:
        total = self.rows + self.unparsed
        return 100.0 * self.unparsed / total if total else 0.0

    def summary(self) -> str:
        span = ""
        if self.first_ts and self.last_ts:
            span = f", {self.first_ts:%Y-%m-%d} → {self.last_ts:%Y-%m-%d}"
        return (
            f"{self.archives_parsed} archivi parsati, {self.archives_skipped} invariati; "
            f"{self.rows:,} righe, {self.unparsed:,} non parsate ({self.unparsed_pct:.4f}%), "
            f"{self.excluded:,} escluse da config, "
            f"{self.malformed_requests:,} richieste malformate{span}"
        )


# --------------------------------------------------------------------------
# stato
# --------------------------------------------------------------------------


def _state_path(cfg: SiteConfig) -> Path:
    return cfg.paths.events.parent / "_parse_state.json"


def load_state(cfg: SiteConfig) -> dict:
    path = _state_path(cfg)
    if not path.exists():
        return {"version": STATE_VERSION, "archives": {}}
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    if data.get("version") != STATE_VERSION:
        return {"version": STATE_VERSION, "archives": {}}
    return data


def save_state(cfg: SiteConfig, state: dict) -> None:
    path = _state_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    state["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    tmp = path.with_suffix(".json.tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2, ensure_ascii=False)
    tmp.replace(path)


# --------------------------------------------------------------------------
# esclusione di righe
# --------------------------------------------------------------------------


def excluded_ips(cfg: SiteConfig) -> list[str]:
    """Indirizzi le cui righe non devono entrare nel dataset.

    Serve dove piu` di un server scrive sullo stesso access log. In un vhost a
    due livelli il front-end registra la richiesta con l'IP del client e poi
    la gira al backend, che la registra una seconda volta con l'IP di loopback:
    tenere entrambe raddoppierebbe ogni cifra di traffico e metterebbe
    127.0.0.1 in cima alla classifica degli indirizzi, che e` un artefatto.

    Le righe escluse non finiscono in `errors/`: non sono righe che non si
    sono capite, sono righe che si e` scelto di non contare.
    """
    value = cfg.get("exclude.ip") or []
    return [str(v) for v in value]


# --------------------------------------------------------------------------
# parsing di un archivio
# --------------------------------------------------------------------------


def _read_lines(path: Path) -> pl.DataFrame:
    """Legge un archivio `.gz` come singola colonna di testo.

    Il separatore è NUL perché nginx non può emetterlo: ogni byte non
    stampabile finisce nel log come testo `\\x00`, mai come byte grezzo.
    """
    return pl.read_csv(
        path,
        has_header=False,
        separator="\x00",
        quote_char=None,
        new_columns=["raw"],
        encoding="utf8-lossy",
        truncate_ragged_lines=True,
        infer_schema=False,
    )


def _extract(df: pl.DataFrame, fmt: logformat.LogFormat) -> tuple[pl.DataFrame, pl.DataFrame]:
    """Applica la regex del formato. Ritorna (righe parsate, righe scartate)."""
    exploded = df.with_columns(
        pl.col("raw").str.extract_groups(fmt.pattern).alias("_g")
    ).unnest("_g")

    anchor = fmt.fields[0]
    ok = exploded.filter(pl.col(anchor).is_not_null())
    bad = exploded.filter(pl.col(anchor).is_null()).select("raw")
    return ok, bad


def _null_if_sentinel(name: str) -> pl.Expr:
    """nginx scrive `-` per un campo assente: qui diventa un null vero."""
    return (
        pl.when(pl.col(name) == _SENTINEL)
        .then(None)
        .otherwise(pl.col(name))
        .alias(name)
    )


def _shape(df: pl.DataFrame, fmt: logformat.LogFormat) -> pl.DataFrame:
    """Dà tipi e struttura alle colonne grezze estratte dalla regex."""
    out = df

    # Timestamp: si parsa con l'offset scritto nel log e si conserva in UTC.
    # La conversione all'ora locale del sito avviene una volta sola, in
    # aggregate.py: farla avanti e indietro è dove nascono gli off-by-one
    # sul giorno, e il periodo coperto contiene un cambio di ora legale.
    out = out.with_columns(
        pl.col("time_local")
        .str.to_datetime(format=logformat.TIME_LOCAL_FORMAT, time_zone="UTC", strict=False)
        .alias("ts")
    )

    # Scomposizione di $request. Quello che non si scompone non è un errore di
    # parsing: sono handshake TLS arrivati sulla porta 80, scanner che parlano
    # protocolli propri, richieste troncate. Vanno tenute e marcate.
    out = out.with_columns(
        pl.col("request").str.extract_groups(_REQUEST_RE).alias("_r")
    ).unnest("_r")

    out = out.with_columns(
        pl.col("target").str.split_exact("?", 1).struct.rename_fields(["path", "query"]).alias("_t")
    ).unnest("_t")

    out = out.with_columns(
        [
            _null_if_sentinel("remote_user"),
            _null_if_sentinel("http_referer"),
            _null_if_sentinel("http_user_agent"),
            pl.col("status").cast(pl.Int16, strict=False).alias("status"),
            pl.col("body_bytes_sent").cast(pl.Int64, strict=False).alias("bytes"),
            pl.col("method").is_null().alias("request_malformed"),
        ]
    )

    columns = [
        pl.col("ts"),
        pl.col("remote_addr").alias("ip"),
        pl.col("method").cast(pl.Categorical).alias("method"),
        pl.col("path"),
        pl.col("query"),
        pl.col("protocol").cast(pl.Categorical).alias("protocol"),
        pl.col("status"),
        pl.col("bytes"),
        pl.col("http_referer").alias("referer"),
        pl.col("http_user_agent").alias("user_agent"),
        pl.col("request_malformed"),
        # La richiesta grezza serve solo quando non si è scomposta: tenerla
        # per tutte le righe raddoppierebbe il Parquet senza aggiungere nulla.
        pl.when(pl.col("request_malformed"))
        .then(pl.col("request"))
        .otherwise(None)
        .alias("request_raw"),
    ]
    if "remote_user" in fmt:
        columns.append(pl.col("remote_user"))

    return out.select(columns)


def _write_partitions(df: pl.DataFrame, events_dir: Path, stem: str) -> list[str]:
    """Scrive un Parquet per ogni mese toccato dall'archivio."""
    written: list[str] = []
    df = df.with_columns(pl.col("ts").dt.strftime("%Y-%m").alias("_ym"))
    for (ym,), group in df.group_by(["_ym"], maintain_order=True):
        if ym is None:
            log.warning("%s: %d righe con timestamp non interpretabile, scartate", stem, group.height)
            continue
        target_dir = events_dir / f"ym={ym}"
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / f"{stem}.parquet"
        group.drop("_ym").write_parquet(target, compression="zstd", statistics=True)
        written.append(str(target.relative_to(events_dir)))
    return written


def _drop_previous(events_dir: Path, stem: str) -> None:
    """Rimuove i Parquet di un archivio prima di riscriverli."""
    if not events_dir.exists():
        return
    for path in events_dir.glob(f"ym=*/{stem}.parquet"):
        path.unlink()


# --------------------------------------------------------------------------
# stadio
# --------------------------------------------------------------------------


def parse_site(cfg: SiteConfig, *, rebuild: bool = False) -> ParseStats:
    paths = cfg.paths
    paths.ensure()
    fmt = logformat.build(cfg.log_format)
    drop_ips = excluded_ips(cfg)
    if drop_ips:
        log.info(
            "exclude.ip: scarto le righe di %s%s",
            ", ".join(drop_ips),
            f" ({cfg.get('exclude.reason')})" if cfg.get("exclude.reason") else "",
        )
    log.info("log_format %r -> %d campi: %s", fmt.source, len(fmt.fields), ", ".join(fmt.fields))

    manifest = load_manifest(paths.manifest)
    if not manifest["files"]:
        raise FileNotFoundError(
            f"Archivio vuoto per {cfg.domain}. Lancia prima: main.py fetch --site {cfg.domain}"
        )

    state = load_state(cfg)
    archives: dict = state.setdefault("archives", {})
    if rebuild:
        log.info("--rebuild: rimuovo i Parquet esistenti")
        shutil.rmtree(paths.events, ignore_errors=True)
        archives.clear()
    paths.events.mkdir(parents=True, exist_ok=True)

    errors_parts = paths.unparsed.parent / "_parts" / cfg.domain
    errors_parts.mkdir(parents=True, exist_ok=True)

    stats = ParseStats()

    for entry in manifest["files"].values():
        local_file = entry["local_file"]
        archive = paths.logs / local_file
        if not archive.exists():
            log.warning("Archivio assente, salto: %s", local_file)
            continue

        stem = archive.name[: -len(".gz")]
        known = archives.get(local_file)
        if known and known.get("plain_bytes") == entry["plain_bytes"]:
            log.debug("%s invariato, salto", local_file)
            stats.archives_skipped += 1
            _accumulate(stats, known)
            continue

        record = _parse_archive(archive, stem, fmt, paths.events, errors_parts, drop_ips)
        archives[local_file] = record | {"plain_bytes": entry["plain_bytes"]}
        stats.archives_parsed += 1
        _accumulate(stats, archives[local_file])
        save_state(cfg, state)

    save_state(cfg, state)
    _merge_error_files(errors_parts, paths.unparsed)

    log.info("parse completato: %s", stats.summary())
    if stats.unparsed_pct > 1.0:
        log.warning(
            "Righe non parsate sopra l'1%%: ispeziona %s, il log_format potrebbe non corrispondere",
            paths.unparsed,
        )
    return stats


def _parse_archive(
    archive: Path,
    stem: str,
    fmt: logformat.LogFormat,
    events_dir: Path,
    errors_parts: Path,
    drop_ips: list[str],
) -> dict:
    log.info("parso %s", archive.name)

    raw = _read_lines(archive)
    ok, bad = _extract(raw, fmt)

    error_file = errors_parts / f"{stem}.log"
    if bad.height:
        error_file.write_text("\n".join(bad["raw"].to_list()) + "\n", encoding="utf-8")
    else:
        error_file.unlink(missing_ok=True)

    shaped = _shape(ok, fmt)

    excluded = 0
    if drop_ips:
        before = shaped.height
        shaped = shaped.filter(~pl.col("ip").is_in(drop_ips))
        excluded = before - shaped.height

    _drop_previous(events_dir, stem)
    partitions = _write_partitions(shaped, events_dir, stem)

    first_ts = shaped["ts"].min()
    last_ts = shaped["ts"].max()
    malformed = int(shaped["request_malformed"].sum())

    log.info(
        "  %s righe, %s non parsate, %s escluse, %s richieste malformate, %s → %s",
        format(shaped.height, ","), format(bad.height, ","), format(excluded, ","),
        format(malformed, ","), first_ts, last_ts,
    )

    return {
        "rows": shaped.height,
        "unparsed": bad.height,
        "excluded": excluded,
        "malformed_requests": malformed,
        "first_ts": first_ts.isoformat() if first_ts else None,
        "last_ts": last_ts.isoformat() if last_ts else None,
        "partitions": partitions,
        "parsed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def _accumulate(stats: ParseStats, record: dict) -> None:
    stats.rows += record["rows"]
    stats.unparsed += record["unparsed"]
    stats.excluded += record.get("excluded", 0)
    stats.malformed_requests += record.get("malformed_requests", 0)
    for key, attr, pick in (("first_ts", "first_ts", min), ("last_ts", "last_ts", max)):
        value = record.get(key)
        if not value:
            continue
        parsed = datetime.fromisoformat(value)
        current = getattr(stats, attr)
        setattr(stats, attr, parsed if current is None else pick(current, parsed))


def _merge_error_files(parts_dir: Path, target: Path) -> None:
    """Unisce i file di errore per archivio nell'unico file previsto dallo spec."""
    parts = sorted(parts_dir.glob("*.log"))
    if not parts:
        target.unlink(missing_ok=True)
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as out:
        for part in parts:
            out.write(f"# {part.stem}\n")
            out.write(part.read_text(encoding="utf-8"))


def read_events(cfg: SiteConfig) -> pl.LazyFrame:
    """LazyFrame su tutti gli eventi parsati del sito."""
    pattern = cfg.paths.events / "ym=*" / "*.parquet"
    return pl.scan_parquet(str(pattern))
