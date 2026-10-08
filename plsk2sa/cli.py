"""Command line: plsk2sa <ui|export|provision|migrate|sync|verify|check> [-n]"""

import argparse
import json
import logging
import sys

from . import __version__
from .checks import FAIL, WARN, check_source, check_target, default_ptr_lookup
from .config import Config, ConfigError
from .context import Context
from .dnsplan import DnsOptions, DnsRecord, build_report, report_text
from .fsutil import read_text
from .manifest import ManifestError
from .modules import build_modules
from .plesk_export import ExportError, PleskExporter
from .runner import CommandError, Runner
from .transport import TransportError

log = logging.getLogger("plsk2sa")


def _setup_logging(ctx: Context):
    log.setLevel(logging.DEBUG)
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(console)

    ctx.workdir.mkdir(parents=True, exist_ok=True)
    logfile = logging.FileHandler(ctx.workdir / "plsk2sa.log", encoding="utf-8")
    logfile.setLevel(logging.DEBUG)
    logfile.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(logfile)


def cmd_export(ctx: Context, args):
    PleskExporter(ctx).export()
    log.info("")
    log.info("Next step: review %s, then run 'plsk2sa provision'.", ctx.manifest_path)


def cmd_provision(ctx: Context, args):
    for module in build_modules(ctx):
        module.provision()
    log.info("Base stack is in place. Next step: 'plsk2sa migrate'.")


def cmd_migrate(ctx: Context, args):
    modules = build_modules(ctx)
    for domain in ctx.domains(args.domain):
        log.info("=== Migrating %s ===", domain.name)
        for module in modules:
            module.migrate_domain(domain)
    log.info("Done. Verify with 'plsk2sa verify'; for switch day see docs/cutover.md.")


def cmd_sync(ctx: Context, args):
    modules = build_modules(ctx)
    for domain in ctx.domains(args.domain):
        log.info("=== Re-sync %s ===", domain.name)
        for module in modules:
            module.sync_domain(domain)


def cmd_verify(ctx: Context, args):
    failed = 0
    for module in build_modules(ctx):
        for ok, message in module.verify():
            log.info("%s [%s] %s", "OK  " if ok else "FAIL", module.name, message)
            if not ok:
                failed += 1
    if failed:
        log.info("")
        log.info("%d check(s) failed.", failed)
        return 1
    log.info("All checks passed.")
    return 0


def cmd_check(ctx: Context, args):
    """Pre-flight checks for both servers (the GUI runs the same ones)."""
    sections = [("Plesk server", check_source(ctx))]
    results, _ = check_target(ctx, mail_hostname=ctx.config.mail_hostname,
                              ptr_lookup=default_ptr_lookup)
    sections.append(("Target server", results))
    marks = {"ok": "OK  ", WARN: "WARN", FAIL: "FAIL"}
    failures = 0
    for title, results in sections:
        log.info("== %s ==", title)
        for r in results:
            log.info("%s %s%s", marks[r.status], r.title, f" - {r.detail}" if r.detail else "")
            failures += r.status == FAIL
    return 1 if failures else 0


def cmd_dns(ctx: Context, args):
    """Print what the DNS records must look like after the migration (needs a prior export)."""
    opts = DnsOptions(plesk_dns=args.plesk_dns, old_ips=args.old_ip or [],
                      new_ipv4=args.new_ip, new_ipv6=args.new_ipv6 or "")
    problems = opts.validate()
    if problems:
        raise RuntimeError(" ".join(problems))
    domains = [d.name for d in ctx.domains(args.domain)]
    records, dkim = {}, {}
    for name in domains:
        path = ctx.dns_dir / f"{name}.records.json"
        if not path.is_file():
            raise RuntimeError(f"No DNS data for {name} - run 'plsk2sa export' first")
        records[name] = [DnsRecord.from_dict(d) for d in json.loads(read_text(path))]
        key = ctx.dns_dir / f"{name}.dkim.txt"
        if key.is_file():
            from .modules.dkim import dkim_dns_value
            dkim[name] = dkim_dns_value(read_text(key))
    report = build_report(domains, records, opts, mail_hostname=ctx.config.mail_hostname, dkim=dkim)
    print(report_text(report))
    if opts.plesk_dns:
        from .fsutil import write_text
        for dom in report.domains:
            write_text(ctx.dns_dir / f"{dom.domain}.zone", dom.zone or "")
        log.info("Zone files written to %s", ctx.dns_dir)


def cmd_ui(argv):
    from .ui.server import main as ui_main
    return ui_main(argv)


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # The GUI needs no plsk2sa.yaml: hand over before the config is loaded.
    if argv and argv[0] == "ui":
        return cmd_ui(argv[1:])

    parser = argparse.ArgumentParser(
        prog="plsk2sa",
        description="Migrates domains (web + mail + DB) from Plesk to a standalone Ubuntu server. "
                    "Run 'plsk2sa ui' for the graphical wizard.",
    )
    parser.add_argument("--version", action="version", version=f"plsk2sa {__version__}")
    parser.add_argument("-c", "--config", default="plsk2sa.yaml",
                        help="path to the configuration (default: plsk2sa.yaml)")
    parser.add_argument("-n", "--dry-run", action="store_true",
                        help="only show mutating commands instead of running them")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("ui", help="open the graphical wizard in your browser (see 'plsk2sa ui --help')")
    sub.add_parser("check", help="pre-flight checks for both servers")
    sub.add_parser("export", help="read the Plesk server -> manifest, dumps, secrets")
    sub.add_parser("provision", help="set up the base stack on the new server")
    for name, helptext in (("migrate", "migrate domains completely"),
                           ("sync", "only pull data again (final sync on switch day)")):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("--domain", help="process only this domain")
    sub.add_parser("verify", help="check the target (services, ports, accounts, HTTP)")
    p = sub.add_parser("dns", help="show how the DNS records must look after the migration")
    p.add_argument("--new-ip", required=True, help="IPv4 address of the new server")
    p.add_argument("--old-ip", action="append", help="IPv4 address of the Plesk server (repeatable)")
    p.add_argument("--new-ipv6", help="IPv6 address of the new server")
    p.add_argument("--plesk-dns", action="store_true",
                   help="Plesk is the DNS server: also write complete zone files")
    p.add_argument("--domain", help="only this domain")

    args = parser.parse_args(argv)

    try:
        config = Config.load(args.config)
    except ConfigError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        return 2

    runner = Runner(dry_run=args.dry_run, ssh_options=config.ssh_options)
    runner.protect(config.old_server, "Plesk server")
    ctx = Context(config, runner)
    _setup_logging(ctx)
    if args.dry_run:
        log.info("== DRY RUN: mutating commands are only shown ==")

    commands = {
        "check": cmd_check,
        "export": cmd_export,
        "provision": cmd_provision,
        "migrate": cmd_migrate,
        "sync": cmd_sync,
        "verify": cmd_verify,
        "dns": cmd_dns,
    }
    try:
        return commands[args.command](ctx, args) or 0
    except (CommandError, ManifestError, ExportError, TransportError, RuntimeError) as e:
        log.error("ERROR: %s", e)
        return 1
    except KeyboardInterrupt:
        log.error("Aborted.")
        return 130
    finally:
        runner.close()
