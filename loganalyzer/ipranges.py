"""Store globale degli IP range ufficiali dei bot.

Le fonti dichiarate in `config/bot_sources.yaml` vengono scaricate in
parallelo, validate e normalizzate in un unico Parquet: CIDR, proprietario,
bot coperti, categoria, fonte, data di aggiornamento e livello di fiducia.

Lo store è condiviso fra tutti i siti: gli IP di Googlebot sono gli stessi
ovunque.

Il `trust` non è decorativo. Una fonte `identity` prova che quell'IP
appartiene a quel crawler; una fonte `hint` dice soltanto dove è ospitato.
Il file di AWS contiene diecimila prefissi che coprono l'intera nuvola: dire
"questo IP è su AWS, quindi è ClaudeBot" sarebbe come dire che chiunque
telefoni da Milano è il sindaco. Chi arriva solo da lì non diventa mai
VERIFIED.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import polars as pl
import requests
import yaml

from .config import CONFIG_DIR, PATHS

log = logging.getLogger(__name__)

SOURCES_FILE = CONFIG_DIR / "bot_sources.yaml"
USER_AGENT = "logAnalyzer2/0.1 (nginx log analysis; bot ip range fetcher)"
TIMEOUT = 30

TRUST_LEVELS = {"identity", "hint"}


class IpRangeError(RuntimeError):
    pass


@dataclass(frozen=True)
class Source:
    id: str
    url: str
    parser: str
    owner: str
    category: str
    trust: str
    bots: tuple[str, ...] = ()

    @property
    def snapshot(self) -> Path:
        return PATHS.ip_sources / f"{self.id}.json"


# --------------------------------------------------------------------------
# parser dei formati sorgente
# --------------------------------------------------------------------------


def _parse_google_prefixes(data: object) -> list[str]:
    """`{"prefixes": [{"ipv4Prefix": "..."} | {"ipv6Prefix": "..."}]}`.

    È lo schema che usano Google, Bing, OpenAI, Anthropic, Perplexity, Apple,
    DuckDuckGo e Ahrefs: di fatto uno standard di fatto per la verifica dei
    crawler.
    """
    if not isinstance(data, dict) or not isinstance(data.get("prefixes"), list):
        raise IpRangeError("atteso un oggetto con la chiave 'prefixes'")
    out = []
    for item in data["prefixes"]:
        if not isinstance(item, dict):
            continue
        value = item.get("ipv4Prefix") or item.get("ipv6Prefix")
        if value:
            out.append(value)
    return out


def _parse_aws_prefixes(data: object) -> list[str]:
    """`{"prefixes": [{"ip_prefix": ...}], "ipv6_prefixes": [{"ipv6_prefix": ...}]}`."""
    if not isinstance(data, dict) or not isinstance(data.get("prefixes"), list):
        raise IpRangeError("atteso un oggetto con la chiave 'prefixes'")
    out = [p["ip_prefix"] for p in data["prefixes"] if isinstance(p, dict) and "ip_prefix" in p]
    for p in data.get("ipv6_prefixes") or []:
        if isinstance(p, dict) and "ipv6_prefix" in p:
            out.append(p["ipv6_prefix"])
    return out


def _parse_plain_cidr(data: object) -> list[str]:
    """Lista nuda di stringhe CIDR."""
    if not isinstance(data, list):
        raise IpRangeError("attesa una lista di stringhe CIDR")
    return [str(x) for x in data]


PARSERS = {
    "google_prefixes": _parse_google_prefixes,
    "aws_prefixes": _parse_aws_prefixes,
    "plain_cidr": _parse_plain_cidr,
}


# --------------------------------------------------------------------------
# configurazione
# --------------------------------------------------------------------------


def load_sources() -> list[Source]:
    if not SOURCES_FILE.exists():
        raise FileNotFoundError(f"Manca {SOURCES_FILE}")
    with SOURCES_FILE.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}

    raw = data.get("sources")
    if not isinstance(raw, list) or not raw:
        raise IpRangeError(f"{SOURCES_FILE}: la chiave `sources` deve essere una lista non vuota")

    sources: list[Source] = []
    seen: set[str] = set()
    for item in raw:
        missing = {"id", "url", "parser", "owner", "trust"} - set(item)
        if missing:
            raise IpRangeError(f"{SOURCES_FILE}: fonte incompleta, mancano {sorted(missing)}: {item}")
        if item["parser"] not in PARSERS:
            raise IpRangeError(
                f"{SOURCES_FILE}: parser sconosciuto {item['parser']!r} "
                f"(disponibili: {', '.join(PARSERS)})"
            )
        if item["trust"] not in TRUST_LEVELS:
            raise IpRangeError(
                f"{SOURCES_FILE}: trust {item['trust']!r} non valido, usa uno fra {TRUST_LEVELS}"
            )
        if item["id"] in seen:
            raise IpRangeError(f"{SOURCES_FILE}: id di fonte duplicato: {item['id']}")
        seen.add(item["id"])
        sources.append(
            Source(
                id=item["id"],
                url=item["url"],
                parser=item["parser"],
                owner=item["owner"],
                category=item.get("category", ""),
                trust=item["trust"],
                bots=tuple(item.get("bots") or ()),
            )
        )
    return sources


# --------------------------------------------------------------------------
# download
# --------------------------------------------------------------------------


@dataclass
class SourceResult:
    source: Source
    cidrs: list[str]
    from_snapshot: bool
    fetched_at: str
    error: str | None = None
    invalid: int = 0


def _download(source: Source) -> SourceResult:
    """Scarica e valida una fonte; in caso di problemi ripiega sullo snapshot."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        response = requests.get(source.url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
        response.raise_for_status()
        payload = response.json()
        cidrs = PARSERS[source.parser](payload)
        if not cidrs:
            raise IpRangeError("la fonte non contiene prefissi")
    except Exception as exc:
        return _fallback(source, f"{type(exc).__name__}: {exc}")

    cidrs, invalid = _validate(source, cidrs)
    if not cidrs:
        return _fallback(source, "nessun CIDR valido nella risposta")

    # Lo snapshot si scrive solo dopo la validazione: non ha senso conservare
    # come fallback una risposta che non sappiamo interpretare.
    source.snapshot.parent.mkdir(parents=True, exist_ok=True)
    source.snapshot.write_text(json.dumps(payload), encoding="utf-8")

    return SourceResult(source, cidrs, False, now, invalid=invalid)


def _fallback(source: Source, error: str) -> SourceResult:
    """Ripiega sull'ultimo snapshot valido."""
    if not source.snapshot.exists():
        log.error("%s: download fallito e nessuno snapshot disponibile (%s)", source.id, error)
        return SourceResult(source, [], False, "", error=error)

    try:
        payload = json.loads(source.snapshot.read_text(encoding="utf-8"))
        cidrs, invalid = _validate(source, PARSERS[source.parser](payload))
    except Exception as exc:
        log.error("%s: snapshot illeggibile (%s); errore originale: %s", source.id, exc, error)
        return SourceResult(source, [], False, "", error=error)

    mtime = datetime.fromtimestamp(source.snapshot.stat().st_mtime, timezone.utc)
    log.warning(
        "%s: download fallito (%s). Uso lo snapshot del %s con %d prefissi.",
        source.id, error, mtime.date(), len(cidrs),
    )
    return SourceResult(
        source, cidrs, True, mtime.isoformat(timespec="seconds"), error=error, invalid=invalid
    )


def _validate(source: Source, cidrs: list[str]) -> tuple[list[str], int]:
    valid, invalid = [], 0
    for cidr in cidrs:
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            invalid += 1
            continue
        valid.append(cidr)
    if invalid:
        log.warning("%s: %d prefissi scartati perché non sono CIDR validi", source.id, invalid)
    return valid, invalid


# --------------------------------------------------------------------------
# stadio
# --------------------------------------------------------------------------


@dataclass
class RefreshStats:
    ok: int = 0
    from_snapshot: int = 0
    failed: list[str] = field(default_factory=list)
    prefixes: int = 0

    def summary(self) -> str:
        parts = [f"{self.ok} fonti aggiornate", f"{self.prefixes:,} prefissi"]
        if self.from_snapshot:
            parts.append(f"{self.from_snapshot} da snapshot")
        if self.failed:
            parts.append(f"{len(self.failed)} non disponibili: {', '.join(self.failed)}")
        return "; ".join(parts)


def refresh(max_workers: int = 8) -> RefreshStats:
    """Scarica tutte le fonti e riscrive `cache/ip_ranges.parquet`."""
    sources = load_sources()
    PATHS.ensure()
    log.info("Aggiorno %d fonti di IP range", len(sources))

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        results = list(pool.map(_download, sources))

    rows: list[dict] = []
    stats = RefreshStats()

    for result in results:
        source = result.source
        if not result.cidrs:
            stats.failed.append(source.id)
            continue
        if result.from_snapshot:
            stats.from_snapshot += 1
        else:
            stats.ok += 1

        bots = ",".join(source.bots)
        for cidr in result.cidrs:
            network = ipaddress.ip_network(cidr, strict=False)
            rows.append(
                {
                    "cidr": cidr,
                    "ip_version": network.version,
                    "source_id": source.id,
                    "source_url": source.url,
                    "owner": source.owner,
                    "category": source.category,
                    "bots": bots,
                    "trust": source.trust,
                    "fetched_at": result.fetched_at,
                    "from_snapshot": result.from_snapshot,
                }
            )
        log.info(
            "  %-28s %6d prefissi  trust=%s%s",
            source.id, len(result.cidrs), source.trust,
            "  (snapshot)" if result.from_snapshot else "",
        )

    if not rows:
        raise IpRangeError("Nessuna fonte disponibile: lo store non è stato scritto")

    stats.prefixes = len(rows)
    df = pl.DataFrame(rows)
    PATHS.ip_ranges.parent.mkdir(parents=True, exist_ok=True)
    df.write_parquet(PATHS.ip_ranges, compression="zstd")

    log.info("ipranges: %s", stats.summary())
    if stats.failed:
        log.warning(
            "Le fonti mancanti riducono la copertura della verifica: i bot che dipendono "
            "solo da quelle risulteranno UNVERIFIABLE."
        )
    return stats


def load_store() -> pl.DataFrame:
    if not PATHS.ip_ranges.exists():
        raise FileNotFoundError(
            f"Store degli IP range assente ({PATHS.ip_ranges}). Lancia prima: main.py ipranges refresh"
        )
    return pl.read_parquet(PATHS.ip_ranges)


def summary() -> pl.DataFrame:
    """Riepilogo per fonte, per il sottocomando `ipranges show`."""
    return (
        load_store()
        .group_by(["source_id", "owner", "trust", "from_snapshot"])
        .agg(
            [
                pl.len().alias("prefissi"),
                (pl.col("ip_version") == 4).sum().alias("v4"),
                (pl.col("ip_version") == 6).sum().alias("v6"),
                pl.col("fetched_at").first().alias("aggiornato"),
            ]
        )
        .sort(["trust", "owner", "source_id"])
    )
