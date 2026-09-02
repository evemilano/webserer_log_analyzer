"""Interfaccia a riga di comando.

Ogni sottocomando è uno stadio idempotente della pipeline e produce un
artefatto proprio; `run` li esegue in sequenza.

    main.py fetch    --site evemilano.com
    main.py parse    --site evemilano.com
    main.py ipranges refresh
    main.py verify   --site evemilano.com
    main.py enrich   --site evemilano.com
    main.py gsc      --site evemilano.com
    main.py report   --site evemilano.com [--all | --latest]
    main.py run      --site evemilano.com [--all | --latest]
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import date

from . import __version__
from .config import PATHS, available_sites, load_site

log = logging.getLogger("loganalyzer")


def setup_logging(verbose: bool = False) -> None:
    """Log su stderr, così stdout resta pulito per gli output strutturati."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )


# --------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------


def _add_site_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--site",
        required=True,
        metavar="DOMAIN",
        help="dominio con configurazione in config/sites/<domain>.yaml",
    )


def _add_window_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--all",
        dest="window",
        action="store_const",
        const="all",
        help="analizza tutti i log presenti in archivio (default)",
    )
    group.add_argument(
        "--latest",
        dest="window",
        action="store_const",
        const="latest",
        help="analizza solo il file di log più recente",
    )
    parser.set_defaults(window=None)
    parser.add_argument(
        "--from", dest="date_from", metavar="YYYY-MM-DD", type=_iso_date,
        help="ritaglia il report a partire da questo giorno (ora locale del sito)",
    )
    parser.add_argument(
        "--to", dest="date_to", metavar="YYYY-MM-DD", type=_iso_date,
        help="ritaglia il report fino a questo giorno incluso",
    )


def _iso_date(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"data non valida: {value!r}, atteso YYYY-MM-DD") from None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Analisi degli access log nginx e generazione del report HTML.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"logAnalyzer2 {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="log di debug")

    sub = parser.add_subparsers(dest="command", metavar="COMANDO")

    p = sub.add_parser("sites", help="elenca i siti configurati")
    p.set_defaults(func=cmd_sites)

    p = sub.add_parser("fetch", help="scarica gli access log dal server (incrementale)")
    _add_site_arg(p)
    p.add_argument("--force", action="store_true", help="riscarica anche i file già in archivio")
    p.set_defaults(func=cmd_fetch)

    p = sub.add_parser("parse", help="parsa l'archivio in Parquet")
    _add_site_arg(p)
    p.add_argument("--rebuild", action="store_true", help="riparsa tutto, ignorando i Parquet esistenti")
    p.set_defaults(func=cmd_parse)

    p = sub.add_parser("ipranges", help="gestisce lo store globale degli IP range dei bot")
    p.add_argument("action", choices=["refresh", "show"], help="refresh scarica le fonti, show riepiloga lo store")
    p.set_defaults(func=cmd_ipranges)

    p = sub.add_parser("verify", help="verifica l'identità degli IP (range + rDNS)")
    _add_site_arg(p)
    p.add_argument("--no-dns", action="store_true", help="salta le lookup rDNS, usa solo i range")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("enrich", help="classifica i bot e aggiunge gli attributi derivati")
    _add_site_arg(p)
    p.set_defaults(func=cmd_enrich)

    p = sub.add_parser("gsc", help="scarica click e impression da Search Console")
    _add_site_arg(p)
    p.set_defaults(func=cmd_gsc)

    p = sub.add_parser("report", help="genera il report HTML")
    _add_site_arg(p)
    _add_window_args(p)
    p.add_argument("--no-compress-payload", dest="compress_payload", action="store_false",
                   default=None, help="incorpora il JSON in chiaro invece che gzip+base64")
    p.add_argument("--inline-libs", action="store_true", help="incorpora ECharts e Tabulator invece di usare il CDN")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("run", help="esegue l'intera pipeline in sequenza")
    _add_site_arg(p)
    _add_window_args(p)
    p.add_argument("--skip-fetch", action="store_true", help="usa l'archivio locale così com'è")
    p.add_argument("--no-compress-payload", dest="compress_payload", action="store_false",
                   default=None, help="incorpora il JSON in chiaro invece che gzip+base64")
    p.add_argument("--inline-libs", action="store_true", help="incorpora ECharts e Tabulator invece di usare il CDN")
    p.set_defaults(func=cmd_run)

    return parser


# --------------------------------------------------------------------------
# comandi
# --------------------------------------------------------------------------


def _not_implemented(stage: str) -> int:
    log.error("Stadio '%s' non ancora implementato.", stage)
    return 2


def cmd_sites(args: argparse.Namespace) -> int:
    sites = available_sites()
    if not sites:
        log.warning("Nessun sito configurato in config/sites/")
        return 1
    for domain in sites:
        cfg = load_site(domain)
        origin = cfg.ssh_host if cfg.source == "ssh" else "locale"
        dirs = " + ".join(cfg.log_dirs)
        print(f"{domain}\t{cfg.source}={origin}\tlogs={dirs}/{cfg.log_pattern}\ttz={cfg.timezone}")
    return 0


def cmd_fetch(args: argparse.Namespace) -> int:
    from .fetch import FetchError, fetch_site

    cfg = load_site(args.site)
    try:
        fetch_site(cfg, force=args.force)
    except FetchError as exc:
        log.error("%s", exc)
        return 1
    return 0


def cmd_parse(args: argparse.Namespace) -> int:
    from .logformat import LogFormatError
    from .parse import parse_site

    cfg = load_site(args.site)
    try:
        parse_site(cfg, rebuild=args.rebuild)
    except LogFormatError as exc:
        log.error("log_format non valido: %s", exc)
        return 1
    return 0


def cmd_ipranges(args: argparse.Namespace) -> int:
    import polars as pl

    from .ipranges import IpRangeError, refresh, summary

    try:
        if args.action == "refresh":
            refresh()
        with pl.Config(tbl_rows=50, tbl_width_chars=140, fmt_str_lengths=40):
            print(summary())
    except IpRangeError as exc:
        log.error("%s", exc)
        return 1
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    from .verify import verify_site

    cfg = load_site(args.site)
    verify_site(cfg, no_dns=args.no_dns)
    return 0


def cmd_enrich(args: argparse.Namespace) -> int:
    from .enrich import enrich_site

    cfg = load_site(args.site)
    enrich_site(cfg)
    return 0


def cmd_gsc(args: argparse.Namespace) -> int:
    from .gsc import GscUnavailable, fetch_site, log_period

    cfg = load_site(args.site)
    try:
        start, end = log_period(cfg)
        fetch_site(cfg, start, end)
    except GscUnavailable as exc:
        # Non è un errore fatale: il report si genera lo stesso, senza le
        # sezioni che dipendono da Search Console.
        log.warning("Search Console non disponibile: %s", exc)
        log.warning("Il report verrà generato senza le colonne click/impression.")
        return 0
    return 0


def _compress(cfg, args: argparse.Namespace) -> bool:
    """`--no-compress-payload` batte la configurazione; altrimenti il default."""
    if args.compress_payload is None:
        return bool(cfg.get("report.compress_payload", True))
    return bool(args.compress_payload)


def cmd_report(args: argparse.Namespace) -> int:
    from .aggregate import build
    from .report import render

    cfg = load_site(args.site)
    window = args.window or cfg.get("report.window", "all")
    payload = build(cfg, window=window, date_from=args.date_from, date_to=args.date_to)
    path = render(
        cfg,
        payload,
        inline_libs=args.inline_libs,
        compress=_compress(cfg, args),
    )
    print(path)
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """Pipeline completa. Ogni stadio è idempotente: rilanciarla è economico."""
    import time

    from .aggregate import build
    from .enrich import enrich_site
    from .fetch import FetchError, fetch_site
    from .gsc import GscUnavailable, fetch_site as gsc_fetch, log_period
    from .ipranges import IpRangeError, refresh
    from .parse import parse_site
    from .report import render
    from .verify import verify_site

    cfg = load_site(args.site)
    window = args.window or cfg.get("report.window", "all")
    started = time.perf_counter()

    def stage(name: str) -> float:
        log.info("── %s ──", name)
        return time.perf_counter()

    if not args.skip_fetch:
        t = stage("fetch")
        try:
            fetch_site(cfg)
        except FetchError as exc:
            log.error("%s", exc)
            return 1
        log.info("   %.1fs", time.perf_counter() - t)

    t = stage("parse")
    parse_site(cfg)
    log.info("   %.1fs", time.perf_counter() - t)

    t = stage("ipranges")
    try:
        refresh()
    except IpRangeError as exc:
        # Senza store aggiornato la verifica userebbe lo snapshot, ma se non
        # esiste nemmeno quello la pipeline non può proseguire: senza range
        # ogni bot risulterebbe non verificato, che è peggio di fermarsi.
        log.error("%s", exc)
        return 1
    log.info("   %.1fs", time.perf_counter() - t)

    t = stage("verify")
    verify_site(cfg)
    log.info("   %.1fs", time.perf_counter() - t)

    t = stage("enrich")
    enrich_site(cfg)
    log.info("   %.1fs", time.perf_counter() - t)

    t = stage("gsc")
    try:
        start, end = log_period(cfg)
        gsc_fetch(cfg, start, end)
    except GscUnavailable as exc:
        log.warning("Search Console non disponibile: %s", exc)
        log.warning("Il report verrà generato senza le colonne click/impression.")
    log.info("   %.1fs", time.perf_counter() - t)

    t = stage("report")
    payload = build(cfg, window=window, date_from=args.date_from, date_to=args.date_to)
    path = render(
        cfg, payload, inline_libs=args.inline_libs, compress=_compress(cfg, args)
    )
    log.info("   %.1fs", time.perf_counter() - t)

    log.info("Pipeline completata in %.1fs", time.perf_counter() - started)
    print(path)
    return 0


# --------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        parser.print_help()
        return 1

    setup_logging(args.verbose)
    PATHS.ensure()

    try:
        return args.func(args)
    except FileNotFoundError as exc:
        log.error("%s", exc)
        return 1
    except KeyboardInterrupt:
        log.warning("Interrotto.")
        return 130
