"""Caricamento della configurazione e risoluzione dei percorsi.

I default globali stanno in `config/defaults.yaml`; ogni sito ha il proprio
file in `config/sites/<domain>.yaml` e può sovrascrivere qualunque default.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent

CONFIG_DIR = ROOT / "config"
SITES_DIR = CONFIG_DIR / "sites"
DEFAULTS_FILE = CONFIG_DIR / "defaults.yaml"


def _deep_merge(base: dict, override: dict) -> dict:
    """Fonde `override` dentro `base` ricorsivamente, senza mutare gli argomenti."""
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def _read_yaml(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"File di configurazione mancante: {path}")
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: la radice del YAML deve essere una mappa")
    return data


@dataclass(frozen=True)
class SitePaths:
    """Percorsi degli artefatti di un singolo sito."""

    domain: str
    logs: Path
    events: Path
    enriched: Path
    gsc_parquet: Path
    input: Path
    unparsed: Path
    manifest: Path

    def ensure(self) -> None:
        for directory in (self.logs, self.events, self.enriched, self.input):
            directory.mkdir(parents=True, exist_ok=True)
        self.unparsed.parent.mkdir(parents=True, exist_ok=True)


@dataclass(frozen=True)
class Paths:
    """Percorsi globali, condivisi fra tutti i siti."""

    root: Path = ROOT
    cache: Path = ROOT / "cache"
    ip_sources: Path = ROOT / "cache" / "ip_sources"
    ip_ranges: Path = ROOT / "cache" / "ip_ranges.parquet"
    dns_db: Path = ROOT / "cache" / "dns.sqlite"
    output: Path = ROOT / "output"
    errors: Path = ROOT / "errors"

    def for_site(self, domain: str) -> SitePaths:
        return SitePaths(
            domain=domain,
            logs=self.root / "logs" / domain,
            events=self.root / "data" / domain / "events",
            enriched=self.root / "data" / domain / "enriched",
            gsc_parquet=self.root / "data" / domain / "gsc.parquet",
            input=self.root / "input" / domain,
            unparsed=self.errors / f"{domain}_unparsed.log",
            manifest=self.root / "logs" / domain / "_manifest.json",
        )

    def ensure(self) -> None:
        for directory in (self.cache, self.ip_sources, self.output, self.errors):
            directory.mkdir(parents=True, exist_ok=True)


PATHS = Paths()


@dataclass(frozen=True)
class SiteConfig:
    """Configurazione di un sito, con i default globali già fusi dentro."""

    domain: str
    settings: dict[str, Any]
    source_file: Path

    # --- accessi comodi ai campi usati più spesso -------------------------

    @property
    def source(self) -> str:
        """Da dove arrivano i log: `ssh` (default) o `local`."""
        return self.settings.get("source", "ssh")

    @property
    def ssh_host(self) -> str:
        host = (self.settings.get("ssh") or {}).get("host")
        if not host:
            raise ValueError(
                f"{self.source_file}: manca `ssh.host`, richiesto da `source: ssh`"
            )
        return host

    @property
    def log_dirs(self) -> list[str]:
        """Directory dei log. `logs.dir` accetta una stringa o una lista.

        Un sito puo` avere lo storico spezzato in piu` cartelle: e` il caso di
        un archivio consegnato a mano, dove ogni consegna e` una cartella e la
        numerazione della rotazione ricomincia da capo dentro ciascuna.
        """
        value = self.settings["logs"]["dir"]
        return [value] if isinstance(value, str) else [str(v) for v in value]

    @property
    def log_dir(self) -> str:
        return self.log_dirs[0]

    @property
    def log_pattern(self) -> str:
        return self.settings["logs"]["pattern"]

    @property
    def log_format(self) -> str:
        return self.settings["log_format"]

    @property
    def timezone(self) -> str:
        return self.settings["timezone"]

    @property
    def paths(self) -> SitePaths:
        return PATHS.for_site(self.domain)

    def get(self, dotted: str, default: Any = None) -> Any:
        """Legge una chiave annidata, es. `get("dns.timeout_seconds")`."""
        node: Any = self.settings
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node


def available_sites() -> list[str]:
    """Domini per cui esiste un file di configurazione."""
    if not SITES_DIR.exists():
        return []
    return sorted(p.stem for p in SITES_DIR.glob("*.yaml"))


def load_site(domain: str) -> SiteConfig:
    """Carica `config/sites/<domain>.yaml` fuso sopra `config/defaults.yaml`."""
    site_file = SITES_DIR / f"{domain}.yaml"
    if not site_file.exists():
        known = ", ".join(available_sites()) or "nessuno"
        raise FileNotFoundError(
            f"Nessuna configurazione per '{domain}' in {SITES_DIR}. Siti disponibili: {known}"
        )

    settings = _deep_merge(_read_yaml(DEFAULTS_FILE), _read_yaml(site_file))

    declared = settings.get("domain")
    if declared and declared != domain:
        raise ValueError(
            f"{site_file}: il campo `domain` vale '{declared}' ma il file si chiama '{domain}.yaml'"
        )
    settings["domain"] = domain

    for required in ("logs", "log_format", "timezone"):
        if required not in settings:
            raise ValueError(f"{site_file}: manca il campo obbligatorio `{required}`")

    source = settings.get("source", "ssh")
    if source not in ("ssh", "local"):
        raise ValueError(f"{site_file}: `source` vale {source!r}, atteso 'ssh' o 'local'")
    if source == "ssh" and "ssh" not in settings:
        raise ValueError(f"{site_file}: `source: ssh` richiede il campo `ssh`")

    return SiteConfig(domain=domain, settings=settings, source_file=site_file)


def resolve_relative(path_str: str) -> Path:
    """Risolve un percorso di configurazione rispetto alla radice del progetto."""
    path = Path(path_str)
    return path if path.is_absolute() else (ROOT / path).resolve()
