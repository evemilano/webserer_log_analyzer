"""Verifica dell'identità dichiarata dagli user agent.

Uno user agent è una stringa che il client sceglie: chiunque può scrivere
"Googlebot" dentro la propria. L'unica prova di identità è l'indirizzo IP, e
si ottiene in due modi:

1. **Match sui range ufficiali.** Google, Bing, OpenAI, Anthropic, Perplexity,
   Apple, DuckDuckGo e Ahrefs pubblicano i propri prefissi. È il metodo più
   rapido e non costa una query di rete.
2. **rDNS forward-confirmed.** PTR dell'IP → il nome deve finire con un
   dominio atteso → risolvendo quel nome si deve tornare all'IP di partenza.
   Il doppio passaggio è ciò che rende il metodo affidabile: un PTR si può
   dichiarare, ma non si può far risolvere `googlebot.com` a un IP altrui.
   Serve per Yandex e Baidu, che non pubblicano range.

Quando i due metodi discordano **vince l'esito negativo**, come prescrive lo
spec: meglio dichiarare non verificato un bot legittimo che il contrario.

Il costo è più basso di quanto sembri. Gli IP distinti sono 386.383, ma il
rDNS serve solo a quelli il cui user agent dichiara un bot con dei suffissi
attesi e che il match sui range non ha già risolto: qualche decina di
migliaia al primo giro, quasi zero dopo, grazie alla cache SQLite condivisa
fra tutti i siti.
"""

from __future__ import annotations

import bisect
import ipaddress
import logging
import socket
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import polars as pl

from .classify import Rule, Ruleset, classify_user_agents, load_rules
from .config import PATHS, SiteConfig
from .ipranges import load_store
from .parse import read_events

log = logging.getLogger(__name__)

VERIFIED = "VERIFIED"
SPOOFED = "SPOOFED"
UNVERIFIABLE = "UNVERIFIABLE"
DNS_ERROR = "DNS_ERROR"
NOT_APPLICABLE = "NOT_APPLICABLE"

STATUSES = (VERIFIED, SPOOFED, UNVERIFIABLE, DNS_ERROR, NOT_APPLICABLE)


# --------------------------------------------------------------------------
# indice dei range
# --------------------------------------------------------------------------


class RangeIndex:
    """Ricerca rapida di quali fonti coprono un dato IP.

    I prefissi di una singola fonte sono disgiunti fra loro, quindi per ogni
    fonte basta una lista ordinata di intervalli e una ricerca binaria. Gli
    IPv4 si confrontano come interi a 64 bit con `numpy`, vettorializzato su
    tutti gli IP in un colpo solo; gli IPv6 sono meno numerosi e si trattano
    con `bisect` su interi Python, che gestiscono nativamente i 128 bit.
    """

    def __init__(self, store: pl.DataFrame) -> None:
        self.sources: list[str] = []
        self.trust: dict[str, str] = {}
        self.owner: dict[str, str] = {}
        self._v4: dict[str, tuple[np.ndarray, np.ndarray]] = {}
        self._v6: dict[str, tuple[list[int], list[int]]] = {}

        for (source_id,), group in store.group_by(["source_id"], maintain_order=True):
            self.sources.append(source_id)
            self.trust[source_id] = group["trust"][0]
            self.owner[source_id] = group["owner"][0]

            v4: list[tuple[int, int]] = []
            v6: list[tuple[int, int]] = []
            for cidr in group["cidr"]:
                net = ipaddress.ip_network(cidr, strict=False)
                bucket = v4 if net.version == 4 else v6
                bucket.append((int(net.network_address), int(net.broadcast_address)))

            if v4:
                v4.sort()
                los = np.fromiter((lo for lo, _ in v4), dtype=np.int64, count=len(v4))
                his = np.fromiter((hi for _, hi in v4), dtype=np.int64, count=len(v4))
                self._v4[source_id] = (los, his)
            if v6:
                v6.sort()
                self._v6[source_id] = ([lo for lo, _ in v6], [hi for _, hi in v6])

    def match(self, ips: list[str]) -> pl.DataFrame:
        """Per ogni IP, l'elenco delle fonti che lo coprono."""
        parsed: list[int | None] = []
        versions = np.zeros(len(ips), dtype=np.int8)
        for i, raw in enumerate(ips):
            try:
                addr = ipaddress.ip_address(raw)
            except ValueError:
                parsed.append(None)
                continue
            parsed.append(int(addr))
            versions[i] = addr.version

        is_v4 = versions == 4
        v4_positions = np.flatnonzero(is_v4)
        v4_values = np.array(
            [parsed[i] for i in v4_positions] or [0], dtype=np.int64
        )
        v6_positions = np.flatnonzero(versions == 6)

        hits: list[list[str]] = [[] for _ in ips]

        for source_id in self.sources:
            if source_id in self._v4 and len(v4_positions):
                los, his = self._v4[source_id]
                slot = np.searchsorted(los, v4_values, side="right") - 1
                valid = slot >= 0
                inside = np.zeros(len(v4_values), dtype=bool)
                inside[valid] = v4_values[valid] <= his[slot[valid]]
                for position in v4_positions[inside]:
                    hits[position].append(source_id)

            if source_id in self._v6:
                los, his = self._v6[source_id]
                for position in v6_positions:
                    value = parsed[position]
                    slot = bisect.bisect_right(los, value) - 1
                    if slot >= 0 and value <= his[slot]:
                        hits[position].append(source_id)

        return pl.DataFrame(
            {
                "ip": ips,
                "ip_sources": hits,
                "ip_owner": [
                    self._pick_owner(sources) for sources in hits
                ],
            }
        )

    def _pick_owner(self, sources: list[str]) -> str | None:
        """Il proprietario dichiarato dalla fonte più affidabile che copre l'IP."""
        identity = [s for s in sources if self.trust.get(s) == "identity"]
        chosen = identity[0] if identity else (sources[0] if sources else None)
        return self.owner.get(chosen) if chosen else None

    def identity_sources(self) -> set[str]:
        return {s for s in self.sources if self.trust.get(s) == "identity"}


# --------------------------------------------------------------------------
# cache rDNS
# --------------------------------------------------------------------------


class DnsCache:
    """Cache persistente dei verdetti rDNS, condivisa fra tutti i siti.

    Conserva il PTR e l'esito della conferma in avanti, che non dipendono dal
    bot che si sta verificando: lo stesso IP serve a più siti e a più regole.
    """

    def __init__(self, path: Path, ttl_days: int) -> None:
        self.path = path
        self.ttl = timedelta(days=ttl_days)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS dns_cache (
                ip         TEXT PRIMARY KEY,
                ptr        TEXT,
                forward_ok INTEGER,
                error      TEXT,
                checked_at TEXT NOT NULL
            )
            """
        )
        self.conn.commit()

    def get_fresh(self, ips: list[str]) -> dict[str, tuple[str | None, int | None, str | None]]:
        cutoff = (datetime.now(timezone.utc) - self.ttl).isoformat()
        out: dict[str, tuple[str | None, int | None, str | None]] = {}
        for chunk in _chunks(ips, 500):
            placeholders = ",".join("?" * len(chunk))
            rows = self.conn.execute(
                f"SELECT ip, ptr, forward_ok, error FROM dns_cache "
                f"WHERE checked_at >= ? AND ip IN ({placeholders})",
                [cutoff, *chunk],
            ).fetchall()
            for ip, ptr, forward_ok, error in rows:
                out[ip] = (ptr, forward_ok, error)
        return out

    def put_many(self, records: list[tuple[str, str | None, int | None, str | None]]) -> None:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.conn.executemany(
            "INSERT OR REPLACE INTO dns_cache (ip, ptr, forward_ok, error, checked_at) "
            "VALUES (?, ?, ?, ?, ?)",
            [(ip, ptr, ok, err, now) for ip, ptr, ok, err in records],
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()


def _chunks(items: list, size: int):
    for start in range(0, len(items), size):
        yield items[start : start + size]


# --------------------------------------------------------------------------
# lookup rDNS
# --------------------------------------------------------------------------


NO_PTR = "NO_PTR"

# Risposte DNS che significano "non esiste", distinte da "non ho saputo".
# I nomi delle eccezioni dnspython restano accettati perché possono già
# trovarsi nella cache scritta prima che questo esito avesse un nome proprio.
DEFINITIVE_NO_PTR = {NO_PTR, "NXDOMAIN", "NoAnswer"}


def _forward_confirmed(ip: str, timeout: float, retries: int):
    """PTR dell'IP e conferma in avanti. Ritorna (ptr, forward_ok, errore).

    L'errore `NO_PTR` è un esito, non un guasto: significa che il DNS ha
    risposto, e ha risposto che quell'indirizzo non ha alcun record inverso.
    Poiché i crawler che si verificano per rDNS ce l'hanno sempre, è la prova
    che l'user agent sta mentendo. Va tenuto distinto da un timeout, dove
    semplicemente non si è saputo.
    """
    import dns.resolver
    import dns.reversename

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    ptr: str | None = None
    for attempt in range(retries + 1):
        try:
            answer = resolver.resolve(dns.reversename.from_address(ip), "PTR")
            ptr = str(answer[0]).rstrip(".")
            break
        except Exception as exc:
            if _is_definitive(exc):
                return None, 0, NO_PTR
            if attempt == retries:
                return None, None, type(exc).__name__

    if not ptr:
        return None, None, NO_PTR

    # Conferma in avanti: il nome del PTR deve risolvere all'IP di partenza.
    # Senza questo passaggio chiunque controlli il reverse del proprio IP
    # potrebbe dichiararsi googlebot.com.
    try:
        addresses = set()
        for record in ("A", "AAAA"):
            try:
                addresses.update(str(r) for r in resolver.resolve(ptr, record))
            except Exception:
                continue
        return ptr, int(ip in addresses), None
    except Exception as exc:
        return ptr, None, type(exc).__name__


def _is_definitive(exc: Exception) -> bool:
    """Distingue "non esiste" (risposta definitiva) da "non ho potuto sapere"."""
    import dns.resolver

    return isinstance(exc, (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer))


def resolve_ptr_batch(
    ips: list[str], cache: DnsCache, timeout: float, retries: int, workers: int
) -> dict[str, tuple[str | None, int | None, str | None]]:
    known = cache.get_fresh(ips)
    todo = [ip for ip in ips if ip not in known]
    if not todo:
        log.info("rDNS: %d IP, tutti già in cache", len(ips))
        return known

    log.info(
        "rDNS: %d IP da risolvere (%d già in cache), %d worker, timeout %.0fs",
        len(todo), len(known), workers, timeout,
    )

    results: list[tuple[str, str | None, int | None, str | None]] = []
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_forward_confirmed, ip, timeout, retries): ip for ip in todo}
        for future in futures:
            ip = futures[future]
            try:
                ptr, ok, error = future.result()
            except Exception as exc:
                ptr, ok, error = None, None, type(exc).__name__
            results.append((ip, ptr, ok, error))
            known[ip] = (ptr, ok, error)
            done += 1
            if done % 2000 == 0:
                log.info("  rDNS: %d/%d", done, len(todo))
                cache.put_many(results)
                results = []

    if results:
        cache.put_many(results)
    return known


# --------------------------------------------------------------------------
# verdetto
# --------------------------------------------------------------------------


def _verdict(
    rule: Rule,
    matched: set[str],
    identity_sources: set[str],
    ptr: str | None,
    forward_ok: int | None,
    dns_error: str | None,
    dns_skipped: bool = False,
    ip_trusted: bool = True,
) -> str:
    if not rule.verifiable:
        return NOT_APPLICABLE if rule.category == "Browser" else UNVERIFIABLE

    # Dove `remote_addr` e` il nodo di bordo di un proxy, nessun indirizzo puo`
    # ricadere nei range del proprietario del crawler: il fall-through in coda
    # a questa funzione leggerebbe quel mancato match come prova di frode e
    # marcherebbe SPOOFED ogni bot legittimo del sito. Senza indirizzo del
    # client non c'e` prova ne` a favore ne` contro.
    if not ip_trusted:
        return UNVERIFIABLE

    # Il match deve avvenire su una fonte che PROVA l'identità. Un IP che
    # ricade solo nel blocco generico di AWS non ha dimostrato niente.
    range_ok = bool(matched & set(rule.ip_sources) & identity_sources)

    rdns_state = "n/a"
    if rule.rdns_suffixes:
        if dns_skipped:
            # Non aver chiesto è diverso dall'aver chiesto e non aver ottenuto
            # risposta: il primo caso è UNVERIFIABLE, non DNS_ERROR.
            rdns_state = "skipped"
        elif dns_error in DEFINITIVE_NO_PTR:
            # Risposta definitiva: quell'IP non ha reverse. I crawler che si
            # verificano per rDNS ce l'hanno sempre, quindi l'identità
            # dichiarata è falsa. Non è un errore di lookup.
            rdns_state = "mismatch"
        elif ptr is None:
            rdns_state = "error"
        elif not any(ptr.endswith(suffix) for suffix in rule.rdns_suffixes):
            rdns_state = "mismatch"
        elif forward_ok == 1:
            rdns_state = "ok"
        elif forward_ok == 0:
            rdns_state = "mismatch"
        else:
            rdns_state = "error"

    # Discordanza: prevale il negativo.
    if rdns_state == "mismatch":
        return SPOOFED
    if range_ok or rdns_state == "ok":
        return VERIFIED
    if rdns_state == "error":
        return DNS_ERROR
    if rdns_state == "skipped":
        return UNVERIFIABLE
    return SPOOFED


# --------------------------------------------------------------------------
# stadio
# --------------------------------------------------------------------------


@dataclass
class VerifyStats:
    pairs: int = 0
    ips: int = 0
    dns_lookups: int = 0
    by_status: dict[str, int] = field(default_factory=dict)

    def summary(self) -> str:
        counts = ", ".join(f"{k}={v:,}" for k, v in sorted(self.by_status.items()))
        return f"{self.pairs:,} coppie (IP, bot) su {self.ips:,} IP distinti; {counts}"


def verify_site(cfg: SiteConfig, *, no_dns: bool = False) -> VerifyStats:
    # Dietro un proxy che non passa l'IP di origine, `remote_addr` e` il nodo
    # di bordo del proxy, non il client: verificare Googlebot contro i range
    # di Google restituirebbe SPOOFED per ogni crawler legittimo del sito.
    # Meglio nessuna prova che una prova costruita sull'indirizzo sbagliato.
    trusted = bool(cfg.get("client_ip_trusted", True))
    if not trusted:
        log.warning(
            "client_ip_trusted: false -> l'identita` degli IP non e` verificabile su questo sito, "
            "ogni bot dichiarato resta UNVERIFIABLE"
        )
        no_dns = True

    ruleset = load_rules()
    store = load_store()
    index = RangeIndex(store)
    identity_sources = index.identity_sources()
    log.info(
        "Indice dei range: %d fonti, %d con valore di prova",
        len(index.sources), len(identity_sources),
    )

    events = read_events(cfg)
    user_agents = events.select("user_agent").unique().collect()["user_agent"]
    ua_map = classify_user_agents(user_agents, ruleset)

    # Le coppie distinte (IP, bot dichiarato): il verdetto vale per la coppia,
    # non per l'IP. Lo stesso indirizzo può ospitare un bot legittimo e uno
    # che ne usurpa il nome.
    pairs = (
        events.join(ua_map.lazy(), on="user_agent", how="left", join_nulls=True)
        .select(["ip", "bot_id"])
        .unique()
        .collect()
    )
    unique_ips = pairs["ip"].unique().to_list()
    log.info("%s coppie (IP, bot), %s IP distinti", format(pairs.height, ","), format(len(unique_ips), ","))

    if trusted:
        matches = index.match(unique_ips)
        matched_by_ip = dict(zip(matches["ip"].to_list(), matches["ip_sources"].to_list()))
        owner_by_ip = dict(zip(matches["ip"].to_list(), matches["ip_owner"].to_list()))
    else:
        # Nessuna prova raccolta: `_verdict` con le mani vuote produce
        # UNVERIFIABLE per i bot dichiarati e NOT_APPLICABLE per i browser,
        # che e` esattamente quello che si puo` onestamente dire.
        matched_by_ip = {}
        owner_by_ip = {}

    # rDNS solo dove serve davvero: regole con suffissi attesi, e solo per gli
    # IP che il match sui range non ha già confermato.
    rules_by_id = {r.id: r for r in ruleset.all_rules}
    needs_dns: set[str] = set()
    if not no_dns:
        for ip, bot_id in zip(pairs["ip"].to_list(), pairs["bot_id"].to_list()):
            rule = rules_by_id.get(bot_id)
            if rule is None or not rule.rdns_suffixes:
                continue
            matched = set(matched_by_ip.get(ip) or [])
            if matched & set(rule.ip_sources) & identity_sources:
                continue
            needs_dns.add(ip)

    dns_results: dict[str, tuple[str | None, int | None, str | None]] = {}
    if needs_dns:
        cache = DnsCache(PATHS.dns_db, int(cfg.get("dns.cache_ttl_days", 30)))
        try:
            dns_results = resolve_ptr_batch(
                sorted(needs_dns),
                cache,
                timeout=float(cfg.get("dns.timeout_seconds", 3)),
                retries=int(cfg.get("dns.retries", 2)),
                workers=int(cfg.get("dns.max_workers", 50)),
            )
        finally:
            cache.close()
    elif no_dns:
        log.info("--no-dns: verifica limitata al match sui range")

    statuses: list[str] = []
    owners: list[str | None] = []
    for ip, bot_id in zip(pairs["ip"].to_list(), pairs["bot_id"].to_list()):
        rule = rules_by_id.get(bot_id) or ruleset.fallback_bot
        matched = set(matched_by_ip.get(ip) or [])
        ptr, forward_ok, dns_error = dns_results.get(ip, (None, None, None))
        statuses.append(
            _verdict(
                rule, matched, identity_sources, ptr, forward_ok, dns_error,
                dns_skipped=no_dns, ip_trusted=trusted,
            )
        )
        owners.append(owner_by_ip.get(ip))

    result = pairs.with_columns(
        [
            pl.Series("ip_status", statuses),
            pl.Series("ip_owner", owners),
        ]
    )

    target = cfg.paths.events.parent / "ip_verdict.parquet"
    target.parent.mkdir(parents=True, exist_ok=True)
    result.write_parquet(target, compression="zstd")

    stats = VerifyStats(
        pairs=result.height,
        ips=len(unique_ips),
        dns_lookups=len(needs_dns),
        by_status=dict(
            result.group_by("ip_status").agg(pl.len().alias("n")).iter_rows()
        ),
    )
    log.info("verify: %s", stats.summary())
    return stats


def read_verdicts(cfg: SiteConfig) -> pl.LazyFrame:
    path = cfg.paths.events.parent / "ip_verdict.parquet"
    if not path.exists():
        raise FileNotFoundError(
            f"Verdetti assenti ({path}). Lancia prima: main.py verify --site {cfg.domain}"
        )
    return pl.scan_parquet(path)
