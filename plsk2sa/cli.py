"""Kommandozeile: plsk2sa <export|provision|migrate|sync|verify> [-n]"""

import argparse
import logging
import sys

from .config import Config, ConfigError
from .context import Context
from .manifest import ManifestError
from .modules import build_modules
from .plesk_export import PleskExporter
from .runner import CommandError, Runner

log = logging.getLogger("plsk2sa")


def _setup_logging(ctx: Context):
    log.setLevel(logging.DEBUG)
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(console)

    ctx.workdir.mkdir(parents=True, exist_ok=True)
    logfile = logging.FileHandler(ctx.workdir / "plsk2sa.log")
    logfile.setLevel(logging.DEBUG)
    logfile.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(logfile)


def cmd_export(ctx: Context, args):
    PleskExporter(ctx).export()
    log.info("")
    log.info("Nächster Schritt: %s prüfen/anpassen, dann 'plsk2sa provision'.",
             ctx.manifest_path)


def cmd_provision(ctx: Context, args):
    for module in build_modules(ctx):
        module.provision()
    log.info("Basis-Stack steht. Nächster Schritt: 'plsk2sa migrate'.")


def cmd_migrate(ctx: Context, args):
    modules = build_modules(ctx)
    for domain in ctx.domains(args.domain):
        log.info("=== Migriere %s ===", domain.name)
        for module in modules:
            module.migrate_domain(domain)
    log.info("Fertig. Prüfen mit 'plsk2sa verify'; Umzugstag: docs/cutover.md.")


def cmd_sync(ctx: Context, args):
    modules = build_modules(ctx)
    for domain in ctx.domains(args.domain):
        log.info("=== Nachsync %s ===", domain.name)
        for module in modules:
            module.sync_domain(domain)


def cmd_verify(ctx: Context, args):
    failed = 0
    for module in build_modules(ctx):
        for ok, message in module.verify():
            log.info("%s [%s] %s", "OK  " if ok else "FEHL", module.name, message)
            if not ok:
                failed += 1
    if failed:
        log.info("")
        log.info("%d Prüfung(en) fehlgeschlagen.", failed)
        return 1
    log.info("Alle Prüfungen bestanden.")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="plsk2sa",
        description="Migriert Domains (Web + Mail + DB) von Plesk auf Standalone-Ubuntu.",
    )
    parser.add_argument("-c", "--config", default="plsk2sa.yaml",
                        help="Pfad zur Konfiguration (Default: plsk2sa.yaml)")
    parser.add_argument("-n", "--dry-run", action="store_true",
                        help="mutierende Befehle nur anzeigen, nicht ausführen")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("export", help="Plesk-Server auslesen -> Manifest, Dumps, Secrets")
    sub.add_parser("provision", help="Basis-Stack auf dem neuen Server einrichten")
    for name, helptext in (("migrate", "Domains vollständig migrieren"),
                           ("sync", "nur Daten nachziehen (finaler Sync am Umzugstag)")):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("--domain", help="nur diese eine Domain bearbeiten")
    sub.add_parser("verify", help="Zielserver prüfen (Dienste, Ports, Konten, HTTP)")

    args = parser.parse_args(argv)

    try:
        config = Config.load(args.config)
    except ConfigError as e:
        print(f"Konfigurationsfehler: {e}", file=sys.stderr)
        return 2

    runner = Runner(dry_run=args.dry_run, ssh_options=config.ssh_options)
    ctx = Context(config, runner)
    _setup_logging(ctx)
    if args.dry_run:
        log.info("== DRY-RUN: mutierende Befehle werden nur angezeigt ==")

    commands = {
        "export": cmd_export,
        "provision": cmd_provision,
        "migrate": cmd_migrate,
        "sync": cmd_sync,
        "verify": cmd_verify,
    }
    try:
        return commands[args.command](ctx, args) or 0
    except (CommandError, ManifestError) as e:
        log.error("FEHLER: %s", e)
        return 1
    except KeyboardInterrupt:
        log.error("Abgebrochen.")
        return 130
