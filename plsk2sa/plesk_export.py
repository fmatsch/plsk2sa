"""Reads the old Plesk server (psa database + Plesk CLI).

discover()  strictly read-only: what could be migrated (subscriptions,
            domains, sizes, warnings). Powers the GUI's selection step.
export()    for the chosen domains: manifest, DB dumps, mail passwords,
            DNS/site references and a crontab backup in the workdir.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from .context import Context
from .dnsplan import DnsRecord, parse_records
from .fsutil import write_secret, write_text
from .manifest import Domain, Manifest
from .runner import CommandError

log = logging.getLogger("plsk2sa")

RE_SQL_SAFE_NAME = re.compile(r"^[A-Za-z0-9.-]+$")

SQL_DOMAINS_V2 = (
    "SELECT d.id, d.name, d.webspace_id, h.www_root FROM domains d "
    "JOIN hosting h ON h.dom_id = d.id ORDER BY d.name"
)
SQL_DOMAINS_V1 = (
    "SELECT d.name, h.www_root FROM domains d "
    "JOIN hosting h ON h.dom_id = d.id ORDER BY d.name"
)
SQL_ALL_DOMAINS = "SELECT id, name FROM domains"
SQL_PHP = (
    "SELECT d.name, h.php_handler_id FROM domains d "
    "JOIN hosting h ON h.dom_id = d.id"
)
SQL_SUBDOMAINS = (
    "SELECT d.name, CONCAT(s.name, '.', d.name) FROM subdomains s "
    "JOIN domains d ON d.id = s.dom_id ORDER BY 2"
)
SQL_DOMAIN_ALIASES = (
    "SELECT d.name, a.name FROM domain_aliases a "
    "JOIN domains d ON d.id = a.dom_id ORDER BY 2"
)
SQL_DNS_RECORDS = (
    "SELECT d.name, r.type, r.displayHost, r.displayVal, r.opt FROM dns_recs r "
    "JOIN domains d ON d.dns_zone_id = r.dns_zone_id ORDER BY d.name, r.id"
)
# MySQL table names are case sensitive on Linux; Plesk's spelling differs between versions.
SQL_IP_POOLS = (
    "SELECT ip_address FROM IP_Addresses",
    "SELECT ip_address FROM ip_addresses",
)
SQL_DB_SIZES = (
    "SELECT table_schema, ROUND(SUM(data_length + index_length) / 1048576, 1) "
    "FROM information_schema.tables GROUP BY table_schema"
)
SQL_DATABASES = (
    "SELECT db.name FROM data_bases db "
    "JOIN domains d ON d.id = db.dom_id WHERE d.name = '{dom}' ORDER BY db.name"
)
SQL_MAILBOXES = (
    "SELECT m.mail_name FROM mail m "
    "JOIN domains d ON d.id = m.dom_id WHERE d.name = '{dom}' ORDER BY m.mail_name"
)
SQL_ALIASES = (
    "SELECT a.alias, CONCAT(m.mail_name, '@', d.name) "
    "FROM mail_aliases a "
    "JOIN mail m ON m.id = a.mn_id "
    "JOIN domains d ON d.id = m.dom_id WHERE d.name = '{dom}'"
)


class ExportError(RuntimeError):
    pass


def parse_mail_auth(text: str) -> List[Tuple[str, str]]:
    """Parse the table printed by `plesk sbin mail_auth_view`.

    Expected data rows:  | user@domain | ... | password |
    First column = address, last column = password (inner spaces in the
    password are preserved). Frame and header rows are discarded.
    """
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        parts = [p.strip() for p in line.strip("|").split("|")]
        if len(parts) < 2:
            continue
        addr, password = parts[0], parts[-1]
        if "@" not in addr or not password:
            continue
        entries.append((addr, password))
    return entries


def php_from_handler(handler: str) -> Optional[str]:
    """'plesk-php74-fpm' -> '7.4'; handlers without a version -> None."""
    m = re.search(r"php(\d)(\d+)", handler or "")
    return f"{m.group(1)}.{m.group(2)}" if m else None


def _mb_from_du(stdout: str) -> Optional[float]:
    first = (stdout.split() or [""])[0]
    return round(int(first) / 1024, 1) if first.isdigit() else None


@dataclass
class DomainInfo:
    name: str
    subscription: str
    docroot_src: str
    databases: List[str] = field(default_factory=list)
    mailboxes: List[str] = field(default_factory=list)
    aliases: List[List[str]] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    domain_aliases: List[str] = field(default_factory=list)
    php_handler: str = ""
    size_web_mb: Optional[float] = None
    size_mail_mb: Optional[float] = None
    size_db_mb: Optional[float] = None

    @property
    def source_php(self) -> Optional[str]:
        return php_from_handler(self.php_handler)

    @property
    def size_total_mb(self) -> float:
        return sum(v or 0 for v in (self.size_web_mb, self.size_mail_mb, self.size_db_mb))

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "subscription": self.subscription,
            "docroot": self.docroot_src,
            "databases": self.databases,
            "mailboxes": len(self.mailboxes),
            "aliases": len(self.aliases),
            "subdomains": self.subdomains,
            "domain_aliases": self.domain_aliases,
            "php": self.source_php,
            "php_handler": self.php_handler,
            "size_mb": {"web": self.size_web_mb, "mail": self.size_mail_mb,
                        "db": self.size_db_mb},
        }


@dataclass
class Inventory:
    domains: List[DomainInfo] = field(default_factory=list)
    plesk_version: str = ""
    degraded: bool = False
    notes: List[str] = field(default_factory=list)

    def by_name(self, name: str) -> Optional[DomainInfo]:
        return next((d for d in self.domains if d.name == name), None)

    def to_dict(self) -> dict:
        return {
            "plesk_version": self.plesk_version,
            "degraded": self.degraded,
            "notes": self.notes,
            "domains": [d.to_dict() for d in self.domains],
        }


class PleskExporter:
    def __init__(self, ctx: Context):
        self.ctx = ctx

    def sql(self, query: str) -> List[List[str]]:
        cp = self.ctx.runner.run(self.ctx.old, ["plesk", "db", "-Ne", query],
                                 mutating=False)
        return [line.split("\t") for line in cp.stdout.splitlines() if line.strip()]

    def _try_sql(self, query: str, note: Optional[str] = None) -> Optional[List[List[str]]]:
        """Optional query: on failure return None and log why."""
        try:
            return self.sql(query)
        except CommandError as e:
            log.debug("optional query failed (%s): %s", note or query[:40], e)
            return None

    # ------------------------------------------------------------------
    def discover(self, with_sizes: bool = True) -> Inventory:
        ctx = self.ctx
        inv = Inventory()

        cp = ctx.runner.run(ctx.old, ["plesk", "version"], mutating=False, check=False)
        inv.plesk_version = (cp.stdout.strip().splitlines() or [""])[0]

        hosted = self._hosted_domains(inv)
        if not hosted:
            return inv

        php = {r[0]: r[1] for r in (self._try_sql(SQL_PHP, "php handler") or []) if len(r) >= 2}
        subs = self._group(self._try_sql(SQL_SUBDOMAINS, "subdomains"))
        dom_aliases = self._group(self._try_sql(SQL_DOMAIN_ALIASES, "domain aliases"))
        db_sizes = {}
        if with_sizes:
            for r in self._try_sql(SQL_DB_SIZES, "db sizes") or []:
                try:
                    db_sizes[r[0]] = float(r[1])
                except (IndexError, ValueError):
                    pass

        maildir_root = ctx.config.plesk_maildir_root
        for name, subscription, docroot in hosted:
            if not RE_SQL_SAFE_NAME.match(name):
                inv.notes.append(f"Skipped {name!r}: unexpected characters in the domain name")
                continue
            info = DomainInfo(
                name=name,
                subscription=subscription,
                docroot_src=docroot,
                databases=[r[0] for r in self.sql(SQL_DATABASES.format(dom=name))],
                mailboxes=[r[0] for r in self.sql(SQL_MAILBOXES.format(dom=name))],
                aliases=[[r[0], r[1]] for r in self.sql(SQL_ALIASES.format(dom=name))
                         if len(r) >= 2],
                subdomains=subs.get(name, []),
                domain_aliases=dom_aliases.get(name, []),
                php_handler=php.get(name, ""),
            )
            if with_sizes:
                info.size_web_mb = self._du(docroot)
                if info.mailboxes:
                    info.size_mail_mb = self._du(f"{maildir_root}/{name}")
                if info.databases:
                    info.size_db_mb = sum(db_sizes.get(db, 0.0) for db in info.databases)
            inv.domains.append(info)
        return inv

    def _hosted_domains(self, inv: Inventory) -> List[Tuple[str, str, str]]:
        """(domain, subscription, docroot) for every domain with hosting."""
        rows = self._try_sql(SQL_DOMAINS_V2, "domains with webspace")
        names = self._try_sql(SQL_ALL_DOMAINS, "all domains")
        if rows is not None and names is not None:
            id_to_name = {r[0]: r[1] for r in names if len(r) >= 2}
            result = []
            for r in rows:
                if len(r) < 4:
                    continue
                dom_id, name, webspace_id, docroot = r[0], r[1], r[2], r[3]
                parent = id_to_name.get(webspace_id if webspace_id not in ("0", "NULL", "") else dom_id)
                result.append((name, parent or name, docroot))
            return result

        inv.degraded = True
        inv.notes.append(
            "Subscription grouping is unavailable (psa schema differs from the expected one); "
            "every domain is listed on its own."
        )
        return [(r[0], r[0], r[1]) for r in self.sql(SQL_DOMAINS_V1) if len(r) >= 2]

    @staticmethod
    def _group(rows: Optional[List[List[str]]]) -> Dict[str, List[str]]:
        grouped: Dict[str, List[str]] = {}
        for r in rows or []:
            if len(r) >= 2:
                grouped.setdefault(r[0], []).append(r[1])
        return grouped

    def _du(self, path: str) -> Optional[float]:
        cp = self.ctx.runner.run(self.ctx.old, ["timeout", "120", "du", "-sk", path],
                                 mutating=False, check=False)
        return _mb_from_du(cp.stdout)

    # ------------------------------------------------------------------
    def fetch_dns_records(self, domains: Iterable[str]) -> Dict[str, List[DnsRecord]]:
        """The DNS zones Plesk holds for the given domains (empty dict if unreadable)."""
        rows = self._try_sql(SQL_DNS_RECORDS, "dns records")
        if rows is None:
            log.warning("Could not read DNS records from Plesk (psa schema differs?)")
            return {}
        return parse_records(rows, set(domains))

    def fetch_server_ips(self) -> List[str]:
        """IPv4 addresses Plesk knows for this server (best effort)."""
        for query in SQL_IP_POOLS:
            rows = self._try_sql(query, "ip pool")
            if rows is not None:
                return sorted({r[0] for r in rows if r and re.match(r"^\d+\.\d+\.\d+\.\d+$", r[0])})
        return []

    # ------------------------------------------------------------------
    def export(self, only: Optional[Iterable[str]] = None,
               php_by_domain: Optional[Dict[str, str]] = None) -> Manifest:
        """php_by_domain: PHP version each domain's pool should use (default: config.php_version)."""
        ctx = self.ctx
        if php_by_domain is None:  # written by `plsk2sa prepare` (CLI); the GUI passes it directly
            saved = ctx.workdir / "php_by_domain.json"
            php_by_domain = json.loads(saved.read_text(encoding="utf-8")) if saved.is_file() else {}
        ctx.ensure_workdir()

        wanted = set(only) if only else set(ctx.config.domains)
        inv = self.discover(with_sizes=False)
        selected = [d for d in inv.domains if not wanted or d.name in wanted]
        missing = wanted - {d.name for d in selected}
        if missing:
            raise ExportError("Not found on the Plesk server: " + ", ".join(sorted(missing)))
        if not selected:
            raise ExportError("No domains with hosting found on the Plesk server.")

        manifest = Manifest(source=ctx.old, domains=[
            Domain(name=d.name, docroot_src=d.docroot_src,
                   php=php_by_domain.get(d.name, ctx.config.php_version),
                   databases=d.databases, mailboxes=d.mailboxes, aliases=d.aliases)
            for d in selected
        ])
        # Names end up in remote shell commands - validate before using any of them.
        problems = manifest.validate()
        if problems:
            raise ExportError("Plesk data failed validation:\n  " + "\n  ".join(problems))

        zones = self.fetch_dns_records(d.name for d in manifest.domains)
        for domain in manifest.domains:
            log.info("Exporting domain: %s", domain.name)
            self._save_reference(domain.name)
            write_text(ctx.dns_dir / f"{domain.name}.records.json", json.dumps(
                [r.to_dict() for r in zones.get(domain.name, [])], indent=2) + "\n")
            self._dump_databases(domain)

        self._export_mail_auth(manifest)
        self._export_crontabs()

        manifest.save(ctx.manifest_path)
        ctx.set_manifest(manifest)
        log.info("Manifest written: %s (%d domains)", ctx.manifest_path, len(manifest.domains))
        return manifest

    # ------------------------------------------------------------------
    def _save_reference(self, name: str):
        """Save site info and DNS zone as human-readable reference."""
        ctx = self.ctx
        for args, dest in (
            (["plesk", "bin", "site", "--info", name], ctx.raw_dir / f"{name}.siteinfo.txt"),
            (["plesk", "bin", "dns", "--info", name], ctx.dns_dir / f"{name}.zone.txt"),
        ):
            cp = ctx.runner.run(ctx.old, args, mutating=False, check=False)
            write_text(dest, cp.stdout or cp.stderr or "")

    def _dump_databases(self, domain: Domain):
        ctx = self.ctx
        for db in domain.databases:
            dest = ctx.db_dir / f"{db}.sql"
            log.info("  DB dump: %s", db)
            # 'plesk db dump' is the official way; fall back to the Plesk
            # admin credentials if that variant is unavailable.
            cmd = (
                f"plesk db dump '{db}' 2>/dev/null || "
                f"mysqldump --single-transaction -uadmin "
                f"-p$(cat /etc/psa/.psa.shadow) '{db}'"
            )
            ctx.runner.download(ctx.old, ["bash", "-c", cmd], dest)

    def _export_mail_auth(self, manifest: Manifest):
        """Mail passwords of the SELECTED domains only (other domains'
        passwords never touch the workdir)."""
        ctx = self.ctx
        cp = ctx.runner.run(ctx.old, ["plesk", "sbin", "mail_auth_view"], mutating=False)

        suffixes = tuple("@" + d.name for d in manifest.domains)
        raw_lines = []
        for line in cp.stdout.splitlines():
            if "@" not in line or any(s in line for s in suffixes):
                raw_lines.append(line)
        write_secret(ctx.secrets_dir / "mail_auth_raw.txt", "\n".join(raw_lines) + "\n")

        entries = [(a, p) for a, p in parse_mail_auth(cp.stdout) if a.endswith(suffixes)]
        write_secret(ctx.secrets_dir / "mail_auth.tsv",
                     "".join(f"{a}\t{p}\n" for a, p in entries))

        expected = sum(len(d.mailboxes) for d in manifest.domains)
        if len(entries) < expected:
            log.warning("Mail passwords: only %d of %d mailboxes have a readable password "
                        "(the others cannot be migrated automatically)", len(entries), expected)
        else:
            log.info("Mail passwords: %d accounts", len(entries))

    def _export_crontabs(self):
        ctx = self.ctx
        dest = ctx.workdir / "crontabs.tar"
        ctx.runner.download(
            ctx.old,
            ["tar", "-C", "/var/spool/cron", "-cf", "-", "crontabs"],
            dest, check=False,
        )
        log.info("Crontab backup: %s (carry over manually)", dest)
