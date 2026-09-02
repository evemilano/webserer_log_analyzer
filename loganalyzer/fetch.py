"""Scarico incrementale degli access log dal server, via ssh.

`rsync` non è disponibile su Windows e non vale una dipendenza esterna: qui
si usano ssh e le coreutils remote, che per dei log append-only fanno un
lavoro migliore.

L'idea portante è che **un file remoto è identificato dal contenuto, non dal
nome**. logrotate rinumera gli archivi a ogni giro (`.1` diventa `.2`), e su
questo server le serie compressa e non compressa si intrecciano al punto che
`evemilano_access.log.2` copre nov-dic 2025 mentre `.2.gz` copre giu-lug 2026.
Indicizzare per nome porterebbe a riscaricare tutto ogni volta e a comporre
una timeline sbagliata; indicizzare per fingerprint dei primi byte no.

Il file attivo cresce fra un run e l'altro: se il fingerprint coincide, si
scarica solo la coda e la si appende all'archivio `.gz` locale. I membri gzip
concatenati sono un file gzip valido, quindi l'archivio resta leggibile con
una `gzip.open()` normale.

La deduplica avviene per (fingerprint, intervallo di byte), mai per riga:
due righe identiche possono essere entrambe legittime — stesso IP, stesso
secondo, stesso URL — e scartarne una perderebbe un dato vero.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
import re
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .config import SiteConfig

log = logging.getLogger(__name__)

MANIFEST_VERSION = 1

# I due byte con cui si apre ogni membro gzip.
GZIP_MAGIC = bytes.fromhex("1f8b")
_CHUNK = 1024 * 1024

# I valori arrivano dal nostro YAML, non da input esterno, ma un carattere di
# troppo in una config scritta a mano finirebbe dritto in una shell remota.
_SAFE_REMOTE = re.compile(r"^[A-Za-z0-9._/*?\[\]-]+$")


class FetchError(RuntimeError):
    pass


@dataclass
class RemoteFile:
    path: str
    size: int
    mtime: int
    fingerprint: str
    is_gzip: bool

    @property
    def basename(self) -> str:
        return self.path.rsplit("/", 1)[-1]

    @property
    def stem(self) -> str:
        """Basename senza il suffisso `.gz`, che l'archivio locale riaggiunge."""
        name = self.basename
        return name[:-3] if name.endswith(".gz") else name


# --------------------------------------------------------------------------
# ssh
# --------------------------------------------------------------------------


def _ssh_base(host: str) -> list[str]:
    return [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=15",
        host,
    ]


def _run_ssh_text(host: str, script: str, timeout: int) -> str:
    """Esegue uno script bash sul remoto passandolo su stdin, ritorna stdout."""
    proc = subprocess.run(
        _ssh_base(host) + ["bash -s"],
        input=script.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise FetchError(
            f"ssh {host} fallito (exit {proc.returncode}): "
            f"{proc.stderr.decode('utf-8', 'replace').strip()}"
        )
    return proc.stdout.decode("utf-8", "replace")


def _run_ssh_to_file(host: str, command: str, dest: Path, timeout: int) -> None:
    """Esegue un comando remoto riversandone lo stdout binario su `dest`."""
    with dest.open("wb") as fh:
        proc = subprocess.Popen(
            _ssh_base(host) + [command],
            stdout=fh,
            stderr=subprocess.PIPE,
        )
        _, stderr = proc.communicate(timeout=timeout)
    if proc.returncode != 0:
        dest.unlink(missing_ok=True)
        raise FetchError(
            f"ssh {host} fallito (exit {proc.returncode}): "
            f"{stderr.decode('utf-8', 'replace').strip()}"
        )


# --------------------------------------------------------------------------
# manifest remoto
# --------------------------------------------------------------------------


def remote_manifest(cfg: SiteConfig) -> list[RemoteFile]:
    """Elenca i file remoti con dimensione, mtime e fingerprint dei primi byte."""
    log_dirs = [d.rstrip("/") for d in cfg.log_dirs]
    pattern = cfg.log_pattern
    fp_bytes = int(cfg.get("fetch.fingerprint_bytes", 4096))
    timeout = int(cfg.get("fetch.ssh_timeout_seconds", 600))

    for value in (*log_dirs, pattern):
        if not _SAFE_REMOTE.match(value):
            raise FetchError(f"Percorso o pattern remoto non sicuro nella config: {value!r}")

    # Il flag gz si ricava dai magic bytes, non dall'estensione: su questo
    # server convivono archivi ruotati compressi e non compressi con la stessa
    # numerazione, e non è detto che il nome dica la verità.
    globs = " ".join(f"{d}/{pattern}" for d in log_dirs)
    script = f"""set -u
for f in {globs}; do
  [ -f "$f" ] || continue
  if [ "$(head -c 2 "$f" | od -An -tx1 | tr -d ' \\n')" = "1f8b" ]; then gz=1; else gz=0; fi
  printf '%s\\t%s\\t%s\\t%s\\t%s\\n' \\
    "$f" \\
    "$(stat -c %s "$f")" \\
    "$(stat -c %Y "$f")" \\
    "$(head -c {fp_bytes} "$f" | md5sum | cut -d' ' -f1)" \\
    "$gz"
done
"""
    out = _run_ssh_text(cfg.ssh_host, script, timeout)

    files: list[RemoteFile] = []
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 5:
            log.warning("Riga di manifest remoto non interpretabile: %r", line)
            continue
        path, size, mtime, fingerprint, gz = parts
        files.append(
            RemoteFile(
                path=path,
                size=int(size),
                mtime=int(mtime),
                fingerprint=fingerprint,
                is_gzip=gz == "1",
            )
        )

    if not files:
        raise FetchError(f"Nessun file corrisponde a {globs} su {cfg.ssh_host}")
    return files


# --------------------------------------------------------------------------
# manifest locale
# --------------------------------------------------------------------------


def load_manifest(path: Path) -> dict:
    if not path.exists():
        return {"version": MANIFEST_VERSION, "updated_at": None, "files": {}}
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    if data.get("version") != MANIFEST_VERSION:
        raise FetchError(f"{path}: versione di manifest non gestita ({data.get('version')})")
    return data


def save_manifest(path: Path, manifest: dict) -> None:
    manifest["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    tmp = path.with_suffix(".json.tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, ensure_ascii=False)
    tmp.replace(path)


# --------------------------------------------------------------------------
# utilità locali
# --------------------------------------------------------------------------


def _uncompressed_size(path: Path) -> int:
    """Byte non compressi di un archivio `.gz`, decomprimendolo in streaming.

    Serve a due cose insieme: dare un `bytes_ingested` esatto su cui calcolare
    l'offset della coda al run successivo, e validare l'integrità di quello
    che è appena stato scaricato.
    """
    total = 0
    with gzip.open(path, "rb") as fh:
        while True:
            block = fh.read(_CHUNK)
            if not block:
                break
            total += len(block)
    return total


def _append_gz(source: Path, dest: Path) -> None:
    """Appende i byte compressi di `source` a `dest` come nuovo membro gzip."""
    with source.open("rb") as src, dest.open("ab") as dst:
        while True:
            block = src.read(_CHUNK)
            if not block:
                break
            dst.write(block)


def _local_name(remote: RemoteFile) -> str:
    return f"{remote.stem}__{remote.fingerprint[:12]}.gz"


# --------------------------------------------------------------------------
# stadio
# --------------------------------------------------------------------------


@dataclass
class FetchStats:
    new_files: int = 0
    appended_files: int = 0
    skipped_files: int = 0
    refetched_files: int = 0
    bytes_downloaded: int = 0

    def summary(self) -> str:
        return (
            f"{self.new_files} nuovi, {self.appended_files} estesi, "
            f"{self.skipped_files} invariati, {self.refetched_files} riscaricati; "
            f"{self.bytes_downloaded / 1_048_576:.1f} MB di log acquisiti"
        )


def fetch_site(cfg: SiteConfig, *, force: bool = False) -> FetchStats:
    """Popola l'archivio locale del sito, dalla sorgente dichiarata in config."""
    if cfg.source == "local":
        return import_local(cfg, force=force)
    return _fetch_ssh(cfg, force=force)


def _fetch_ssh(cfg: SiteConfig, *, force: bool = False) -> FetchStats:
    paths = cfg.paths
    paths.ensure()
    timeout = int(cfg.get("fetch.ssh_timeout_seconds", 600))

    log.info("Interrogo %s per %s/%s", cfg.ssh_host, cfg.log_dir, cfg.log_pattern)
    remotes = remote_manifest(cfg)
    log.info("%d file remoti trovati", len(remotes))

    manifest = load_manifest(paths.manifest)
    files: dict = manifest.setdefault("files", {})
    stats = FetchStats()

    # Ordine di elaborazione irrilevante per la correttezza, ma processare
    # prima i file già noti rende il log più leggibile.
    for remote in sorted(remotes, key=lambda r: r.mtime):
        entry = files.get(remote.fingerprint)

        if entry is not None and not force:
            ingested = int(entry["bytes_ingested"])
            if remote.size == ingested:
                log.debug("%s invariato (%d B)", remote.basename, remote.size)
                entry["remote_name"] = remote.basename
                stats.skipped_files += 1
                continue
            if remote.size < ingested:
                log.warning(
                    "%s è più piccolo di quanto in archivio (%d < %d): riscarico per intero. "
                    "Può succedere con una rotazione copytruncate.",
                    remote.basename, remote.size, ingested,
                )
                entry = None
            elif remote.is_gzip:
                # Un archivio già ruotato e compresso non dovrebbe crescere.
                # Se succede, il contenuto è cambiato sotto di noi: riscarico.
                log.warning(
                    "%s è compresso ma è cresciuto (%d > %d): riscarico per intero.",
                    remote.basename, remote.size, ingested,
                )
                entry = None
            else:
                added = _fetch_tail(cfg, remote, entry, paths.logs, ingested, timeout)
                stats.appended_files += 1
                stats.bytes_downloaded += added
                save_manifest(paths.manifest, manifest)
                continue

        was_known = remote.fingerprint in files
        added = _fetch_whole(cfg, remote, files, paths.logs, timeout)
        if was_known:
            stats.refetched_files += 1
        else:
            stats.new_files += 1
        stats.bytes_downloaded += added
        save_manifest(paths.manifest, manifest)

    save_manifest(paths.manifest, manifest)
    log.info("fetch completato: %s", stats.summary())
    return stats


def _fetch_whole(
    cfg: SiteConfig,
    remote: RemoteFile,
    files: dict,
    logs_dir: Path,
    timeout: int,
) -> int:
    """Scarica un file per intero.

    Un file remoto già compresso viene copiato tale e quale: ricomprimerlo
    produrrebbe un doppio strato gzip, e l'archivio non sarebbe più leggibile
    con una `gzip.open()`. Uno in chiaro viene compresso in transito, che su
    100 MB di log significa scaricarne una decina.

    In entrambi i casi `bytes_ingested` conta i **byte del file remoto**: è il
    numero su cui si calcola l'offset della coda al run successivo.
    """
    existing = files.get(remote.fingerprint)
    local_name = existing["local_file"] if existing else _local_name(remote)
    dest = logs_dir / local_name

    command = f"cat '{remote.path}'" if remote.is_gzip else f"gzip -c '{remote.path}'"
    log.info(
        "scarico %s (%.1f MB%s) -> %s",
        remote.basename,
        remote.size / 1_048_576,
        "" if remote.is_gzip else ", compresso in transito",
        local_name,
    )

    with tempfile.NamedTemporaryFile(dir=logs_dir, suffix=".part", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        _run_ssh_to_file(cfg.ssh_host, command, tmp_path, timeout)
        # Decomprimere serve comunque a validare l'integrità di ciò che è arrivato.
        plain_bytes = _uncompressed_size(tmp_path)
        ingested = tmp_path.stat().st_size if remote.is_gzip else plain_bytes
        if ingested != remote.size:
            # Il file attivo può essere cresciuto durante il trasferimento: è
            # normale e innocuo, l'offset che conta è quello effettivamente letto.
            log.debug(
                "%s: %d byte letti contro %d dichiarati dallo stat",
                remote.basename, ingested, remote.size,
            )
        tmp_path.replace(dest)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise

    files[remote.fingerprint] = {
        "remote_name": remote.basename,
        "local_file": local_name,
        "bytes_ingested": ingested,
        "plain_bytes": plain_bytes,
        "remote_is_gzip": remote.is_gzip,
        "remote_mtime": remote.mtime,
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    return plain_bytes


def _fetch_tail(
    cfg: SiteConfig,
    remote: RemoteFile,
    entry: dict,
    logs_dir: Path,
    ingested: int,
    timeout: int,
) -> int:
    """Scarica solo i byte nuovi e li appende all'archivio come membro gzip."""
    dest = logs_dir / entry["local_file"]
    if not dest.exists():
        raise FetchError(
            f"Il manifest cita {dest.name} ma il file non esiste. "
            f"Rimuovi {logs_dir / '_manifest.json'} per ricostruire l'archivio."
        )

    missing = remote.size - ingested
    log.info(
        "estendo %s: +%.1f MB dalla posizione %d",
        entry["local_file"], missing / 1_048_576, ingested,
    )

    with tempfile.NamedTemporaryFile(dir=logs_dir, suffix=".tail", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        # `tail -c +N` conta i byte a partire da 1, quindi il primo byte nuovo è ingested+1.
        _run_ssh_to_file(
            cfg.ssh_host,
            f"tail -c +{ingested + 1} '{remote.path}' | gzip -c",
            tmp_path,
            timeout,
        )
        added = _uncompressed_size(tmp_path)
        if added == 0:
            log.debug("%s: nessun byte nuovo", entry["local_file"])
            return 0
        _append_gz(tmp_path, dest)
    finally:
        tmp_path.unlink(missing_ok=True)

    entry["bytes_ingested"] = ingested + added
    entry["plain_bytes"] = entry.get("plain_bytes", ingested) + added
    entry["remote_name"] = remote.basename
    entry["remote_mtime"] = remote.mtime
    entry["fetched_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return added


# --------------------------------------------------------------------------
# sorgente locale
# --------------------------------------------------------------------------


@dataclass
class LocalFile:
    """Un file di log gia` presente su disco, non da scaricare."""

    path: Path
    size: int
    mtime: int
    fingerprint: str
    is_gzip: bool

    @property
    def stem(self) -> str:
        name = self.path.name
        return name[:-3] if name.endswith(".gz") else name


def _plain_head(path: Path, nbytes: int) -> bytes:
    """Primi byte del contenuto **decompresso**, qualunque sia l'involucro."""
    with path.open("rb") as fh:
        magic = fh.read(2)
    if magic == GZIP_MAGIC:
        with gzip.open(path, "rb") as fh:
            return fh.read(nbytes)
    with path.open("rb") as fh:
        return fh.read(nbytes)


def local_manifest(cfg: SiteConfig) -> list[LocalFile]:
    """Elenca i file che corrispondono al pattern nelle directory configurate.

    L'identita` e` il fingerprint del contenuto **decompresso**, non dei byte
    su disco: la stessa giornata arriva spesso due volte, una in chiaro e una
    gia` compressa dal giro di rotazione successivo, e fingerprintare i byte
    grezzi la importerebbe due volte come se fossero file diversi.
    """
    fp_bytes = int(cfg.get("fetch.fingerprint_bytes", 4096))
    files: list[LocalFile] = []
    seen: set[Path] = set()

    for directory in cfg.log_dirs:
        base = Path(directory).expanduser()
        if not base.is_dir():
            raise FetchError(f"Directory dei log inesistente: {base}")
        for candidate in sorted(base.glob(cfg.log_pattern)):
            if not candidate.is_file():
                continue
            resolved = candidate.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            stat = candidate.stat()
            with candidate.open("rb") as fh:
                is_gzip = fh.read(2) == GZIP_MAGIC
            files.append(
                LocalFile(
                    path=candidate,
                    size=stat.st_size,
                    mtime=int(stat.st_mtime),
                    fingerprint=hashlib.md5(_plain_head(candidate, fp_bytes)).hexdigest(),
                    is_gzip=is_gzip,
                )
            )

    if not files:
        globs = ", ".join(f"{d}/{cfg.log_pattern}" for d in cfg.log_dirs)
        raise FetchError(f"Nessun file corrisponde a {globs}")
    return files


def _ingest_local(source: LocalFile, dest: Path) -> int:
    """Porta un file nell'archivio come `.gz`, ritorna i byte non compressi.

    Un file gia` compresso si copia tale e quale: ricomprimerlo produrrebbe un
    doppio strato gzip e l'archivio non sarebbe piu` leggibile con una
    `gzip.open()` normale. Uno in chiaro si comprime in transito.
    """
    with tempfile.NamedTemporaryFile(dir=dest.parent, suffix=".part", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        plain_bytes = 0
        if source.is_gzip:
            with source.path.open("rb") as src, tmp_path.open("wb") as dst:
                while block := src.read(_CHUNK):
                    dst.write(block)
            # La decompressione non serve solo a contare: valida l'integrita`
            # di cio` che e` stato copiato, prima che il manifest lo dichiari buono.
            plain_bytes = _uncompressed_size(tmp_path)
        else:
            # Livello 6, lo stesso che usa `gzip -c` sul percorso ssh. Il
            # default di `gzip.open` e` 9: misurato su questi log rende 0,8 MB/s
            # contro i 4,9 MB/s a cui il disco li serve, cioe` comprimere
            # costerebbe sei volte il tempo di leggere, per il 2% di spazio.
            with source.path.open("rb") as src, gzip.open(tmp_path, "wb", compresslevel=6) as dst:
                while block := src.read(_CHUNK):
                    plain_bytes += len(block)
                    dst.write(block)
        tmp_path.replace(dest)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise
    return plain_bytes


def import_local(cfg: SiteConfig, *, force: bool = False) -> FetchStats:
    """Importa nell'archivio i log gia` presenti su disco.

    Stessa forma di manifest della sorgente ssh, cosi` `parse` non distingue i
    due casi. Non esiste il concetto di coda: un file locale che e` cresciuto
    viene reimportato per intero, che su un archivio consegnato a mano costa
    quanto leggerlo una volta.
    """
    paths = cfg.paths
    paths.ensure()

    log.info("Sorgente locale: %s", ", ".join(cfg.log_dirs))
    sources = local_manifest(cfg)
    log.info("%d file trovati con pattern %s", len(sources), cfg.log_pattern)

    manifest = load_manifest(paths.manifest)
    files: dict = manifest.setdefault("files", {})
    stats = FetchStats()

    for source in sorted(sources, key=lambda f: f.mtime):
        entry = files.get(source.fingerprint)

        if entry is not None and not force and entry.get("bytes_ingested") == source.size:
            log.debug("%s invariato (%d B)", source.path.name, source.size)
            stats.skipped_files += 1
            continue

        local_name = entry["local_file"] if entry else f"{source.stem}__{source.fingerprint[:12]}.gz"
        dest = paths.logs / local_name
        log.info(
            "importo %s (%.1f MB%s) -> %s",
            source.path.name,
            source.size / 1_048_576,
            "" if source.is_gzip else ", compresso in transito",
            local_name,
        )
        plain_bytes = _ingest_local(source, dest)

        # Stesso contenuto gia` in archivio in copia piu` lunga: succede quando
        # la stessa giornata arriva sia troncata a meta` sia completa. Vince la
        # copia con piu` righe, mai l'ultima vista.
        if entry is not None and plain_bytes < int(entry.get("plain_bytes", 0)):
            log.warning(
                "%s ha meno contenuto della copia gia` in archivio (%s < %s righe di byte): la ignoro",
                source.path.name, f"{plain_bytes:,}", f"{int(entry['plain_bytes']):,}",
            )
            stats.skipped_files += 1
            continue

        if entry is not None:
            stats.refetched_files += 1
        else:
            stats.new_files += 1
        stats.bytes_downloaded += plain_bytes

        files[source.fingerprint] = {
            "remote_name": str(source.path),
            "local_file": local_name,
            "bytes_ingested": source.size,
            "plain_bytes": plain_bytes,
            "remote_is_gzip": source.is_gzip,
            "remote_mtime": source.mtime,
            "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        save_manifest(paths.manifest, manifest)

    save_manifest(paths.manifest, manifest)
    log.info("import completato: %s", stats.summary())
    return stats


def archive_files(cfg: SiteConfig) -> list[Path]:
    """Archivi `.gz` presenti in locale, secondo il manifest."""
    paths = cfg.paths
    manifest = load_manifest(paths.manifest)
    out = []
    for entry in manifest["files"].values():
        candidate = paths.logs / entry["local_file"]
        if candidate.exists():
            out.append(candidate)
        else:
            log.warning("Archivio citato dal manifest ma assente: %s", candidate.name)
    return out
