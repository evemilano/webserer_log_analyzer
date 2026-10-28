"""Click e impression da Google Search Console, per URL e per giorno.

Il server MCP `gsc` non è chiamabile da uno script Python: è un canale per
l'assistente, non una libreria. Qui si parla direttamente con l'API,
riusando lo stesso token OAuth che quel server già usa (scope
`webmasters.readonly`). Il pattern di autenticazione e la paginazione sono
ripresi da `evemilano_ai_manager/skills/_gsc_api.py` e copiati dentro il
progetto: i sottoprogetti di questo repo sono separati e non si importano a
vicenda.

Due cose che il report deve dire e non nascondere:

- **Il periodo è quello dei log**, non un intervallo arbitrario, così le due
  fonti sono confrontabili.
- **Search Console consolida i dati con qualche giorno di ritardo.** Se la
  finestra dei log arriva a ieri, gli ultimi giorni avranno click e
  impression a zero. Vanno marcati come non consolidati, altrimenti si
  leggono come un crollo del traffico.

- **Le impression qui sono aggregate per pagina.** Chiedendo la dimensione
  `page` l'API passa in modalità `byPage`, e i totali risultano circa il 9%
  più alti di quelli che l'interfaccia di Search Console mostra come totale
  di proprietà: quando due URL dello stesso sito compaiono nella stessa
  pagina di risultati, la proprietà conta un'impression e le pagine ne
  contano due. Verificato riga per riga contro l'API con
  `aggregationType=byPage`: i valori coincidono esattamente. Il report deve
  dirlo, altrimenti il confronto con la schermata di Search Console sembra
  un errore.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path

import polars as pl

from .config import SiteConfig, resolve_relative

log = logging.getLogger(__name__)

SCOPES = ["https://www.googleapis.com/auth/webmasters.readonly"]
PAGE_LIMIT = 25_000


class GscUnavailable(RuntimeError):
    """GSC non è configurato o non è raggiungibile.

    Non è un errore fatale: il report si genera lo stesso, nascondendo le
    sezioni che dipendono da questi dati.
    """


@dataclass
class GscStats:
    rows: int = 0
    clicks: int = 0
    impressions: int = 0
    start: str = ""
    end: str = ""
    unconsolidated_from: str = ""

    def summary(self) -> str:
        return (
            f"{self.rows:,} righe (URL × giorno), {self.clicks:,} click, "
            f"{self.impressions:,} impression, {self.start} → {self.end}; "
            f"dati non consolidati dal {self.unconsolidated_from}"
        )


def _service(cfg: SiteConfig):
    token_path = cfg.get("gsc.token_path")
    if not token_path:
        raise GscUnavailable("Nessun `gsc.token_path` nella configurazione del sito")

    path = resolve_relative(token_path)
    if not path.exists():
        raise GscUnavailable(f"Token Search Console non trovato: {path}")

    try:
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
        from googleapiclient.discovery import build
    except ImportError as exc:  # pragma: no cover
        raise GscUnavailable(f"Librerie Google non installate: {exc}") from exc

    creds = Credentials.from_authorized_user_file(str(path), SCOPES)
    if not creds.valid:
        if creds.expired and creds.refresh_token:
            # Refresh solo in memoria: il token sta su Drive, condiviso con il server MCP gsc.
            creds.refresh(Request())
        else:
            # Il flusso OAuth interattivo qui non ha senso: la pipeline gira
            # senza qualcuno davanti allo schermo.
            raise GscUnavailable(
                f"Token {path} scaduto e non rinnovabile. Rigeneralo con un flusso OAuth interattivo."
            )

    return build("searchconsole", "v1", credentials=creds)


def _query(service, site_url: str, start: str, end: str, dimensions: list[str]) -> list[dict]:
    """Interroga searchanalytics paginando fino a esaurire le righe."""
    rows: list[dict] = []
    start_row = 0
    while True:
        body = {
            "startDate": start,
            "endDate": end,
            "dimensions": dimensions,
            "rowLimit": PAGE_LIMIT,
            "startRow": start_row,
            "type": "web",
            "dataState": "all",
        }
        response = service.searchanalytics().query(siteUrl=site_url, body=body).execute()
        page = response.get("rows", [])
        if not page:
            break
        rows.extend(page)
        log.info("  GSC: %s righe", format(len(rows), ","))
        if len(page) < PAGE_LIMIT:
            break
        start_row += PAGE_LIMIT
        time.sleep(0.5)
    return rows


def normalize_url(url: str, scheme: str, host: str) -> str:
    """Riduce un URL alla forma su cui log e GSC si possono incontrare.

    GSC restituisce URL assoluti, il log solo il path. Si normalizzano host
    (minuscolo) e slash finale, e si scarta la query string: le colonne
    click/impression sono per pagina, non per variante parametrica.
    """
    cleaned = url.split("#", 1)[0].split("?", 1)[0]
    for prefix in (f"{scheme}://{host}", f"https://{host}", f"http://{host}"):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix) :]
            break
    if not cleaned.startswith("/"):
        cleaned = "/" + cleaned
    return cleaned


def fetch_site(cfg: SiteConfig, start: date, end: date) -> GscStats:
    if not cfg.get("gsc.enabled", False):
        raise GscUnavailable("Search Console disabilitata nella configurazione del sito")

    site_url = cfg.get("gsc.site_url")
    if not site_url:
        raise GscUnavailable("Nessun `gsc.site_url` nella configurazione del sito")

    service = _service(cfg)
    log.info("Search Console: %s, %s → %s", site_url, start, end)

    rows = _query(service, site_url, start.isoformat(), end.isoformat(), ["page", "date"])
    if not rows:
        raise GscUnavailable(f"Nessun dato Search Console per {site_url} nel periodo richiesto")

    scheme = cfg.get("site.scheme", "https")
    host = cfg.get("site.host", cfg.domain)

    frame = pl.DataFrame(
        {
            "page": [r["keys"][0] for r in rows],
            "date": [r["keys"][1] for r in rows],
            "clicks": [int(r.get("clicks", 0)) for r in rows],
            "impressions": [int(r.get("impressions", 0)) for r in rows],
            "position": [float(r.get("position", 0)) for r in rows],
        }
    ).with_columns(
        [
            pl.col("date").str.to_date("%Y-%m-%d"),
            pl.col("page")
            .map_elements(lambda u: normalize_url(u, scheme, host), return_dtype=pl.String)
            .alias("path"),
        ]
    )

    delay = int(cfg.get("gsc.data_delay_days", 3))
    cutoff = end - timedelta(days=delay)
    frame = frame.with_columns((pl.col("date") > cutoff).alias("unconsolidated"))

    target: Path = cfg.paths.gsc_parquet
    target.parent.mkdir(parents=True, exist_ok=True)
    frame.write_parquet(target, compression="zstd")

    stats = GscStats(
        rows=frame.height,
        clicks=int(frame["clicks"].sum()),
        impressions=int(frame["impressions"].sum()),
        start=start.isoformat(),
        end=end.isoformat(),
        unconsolidated_from=(cutoff + timedelta(days=1)).isoformat(),
    )
    log.info("gsc: %s", stats.summary())
    return stats


def log_period(cfg: SiteConfig) -> tuple[date, date]:
    """Periodo effettivamente coperto dai log, per allineare la finestra GSC."""
    from .parse import read_events

    bounds = (
        read_events(cfg)
        .select([pl.col("ts").min().alias("lo"), pl.col("ts").max().alias("hi")])
        .collect()
    )
    return bounds["lo"][0].date(), bounds["hi"][0].date()


def read_gsc(cfg: SiteConfig) -> pl.LazyFrame | None:
    """Dati GSC se presenti, altrimenti None: le sezioni relative si nascondono."""
    path = cfg.paths.gsc_parquet
    if not path.exists():
        return None
    return pl.scan_parquet(path)
