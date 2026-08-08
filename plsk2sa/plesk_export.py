"""Export: liest den alten Plesk-Server aus (psa-DB + Plesk-CLI) und
erzeugt Manifest, DB-Dumps, Mail-Passwortliste, DNS-/Site-Referenzen
und Crontab-Sicherung im Workdir.
"""

import logging
from typing import List, Tuple

from .context import Context
from .manifest import Domain, Manifest

log = logging.getLogger("plsk2sa")

SQL_DOMAINS = (
    "SELECT d.name, h.www_root FROM domains d "
    "JOIN hosting h ON h.dom_id = d.id ORDER BY d.name"
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


def parse_mail_auth(text: str) -> List[Tuple[str, str]]:
    """Parst die Tabellen-Ausgabe von `plesk sbin mail_auth_view`.

    Erwartete Datenzeilen:  | user@domain | ... | passwort |
    Erste Spalte = Adresse, letzte Spalte = Passwort (innere Leerzeichen
    im Passwort bleiben erhalten). Rahmen-/Kopfzeilen werden verworfen.
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


class PleskExporter:
    def __init__(self, ctx: Context):
        self.ctx = ctx

    def sql(self, query: str) -> List[List[str]]:
        cp = self.ctx.runner.run(self.ctx.old, ["plesk", "db", "-Ne", query],
                                 mutating=False)
        return [line.split("\t") for line in cp.stdout.splitlines() if line.strip()]

    def export(self) -> Manifest:
        ctx = self.ctx
        ctx.ensure_workdir()
        manifest = Manifest(source=ctx.old)

        wanted = set(ctx.config.domains)
        for name, docroot in self.sql(SQL_DOMAINS):
            if wanted and name not in wanted:
                log.info("überspringe %s (nicht in config.domains)", name)
                continue
            log.info("exportiere Domain: %s", name)
            domain = Domain(
                name=name,
                docroot_src=docroot,
                php=ctx.config.php_version,
                databases=[r[0] for r in self.sql(SQL_DATABASES.format(dom=name))],
                mailboxes=[r[0] for r in self.sql(SQL_MAILBOXES.format(dom=name))],
                aliases=[[r[0], r[1]] for r in self.sql(SQL_ALIASES.format(dom=name))],
            )
            manifest.domains.append(domain)

            self._save_reference(name)
            self._dump_databases(domain)

        if not manifest.domains:
            raise SystemExit("Keine Domains mit Hosting gefunden — Abbruch.")

        self._export_mail_auth()
        self._export_crontabs()

        problems = manifest.validate()
        if problems:
            log.warning("Manifest hat Auffälligkeiten:\n  %s", "\n  ".join(problems))
        manifest.save(ctx.manifest_path)
        log.info("Manifest geschrieben: %s (%d Domains)",
                 ctx.manifest_path, len(manifest.domains))
        return manifest

    # ------------------------------------------------------------------
    def _save_reference(self, name: str):
        """Site-Info und DNS-Zone als menschenlesbare Referenz sichern."""
        ctx = self.ctx
        for args, dest in (
            (["plesk", "bin", "site", "--info", name], ctx.raw_dir / f"{name}.siteinfo.txt"),
            (["plesk", "bin", "dns", "--info", name], ctx.dns_dir / f"{name}.zone.txt"),
        ):
            cp = ctx.runner.run(ctx.old, args, mutating=False, check=False)
            dest.write_text(cp.stdout or cp.stderr or "")

    def _dump_databases(self, domain: Domain):
        ctx = self.ctx
        for db in domain.databases:
            dest = ctx.db_dir / f"{db}.sql"
            log.info("  DB-Dump: %s", db)
            # 'plesk db dump' ist der offizielle Weg; Fallback direkt über
            # den Plesk-Admin-Zugang, falls die CLI-Variante fehlt.
            cmd = (
                f"plesk db dump '{db}' 2>/dev/null || "
                f"mysqldump --single-transaction -uadmin "
                f"-p$(cat /etc/psa/.psa.shadow) '{db}'"
            )
            ctx.runner.download(ctx.old, ["bash", "-c", cmd], dest)

    def _export_mail_auth(self):
        ctx = self.ctx
        cp = ctx.runner.run(ctx.old, ["plesk", "sbin", "mail_auth_view"],
                            mutating=False)
        raw = ctx.secrets_dir / "mail_auth_raw.txt"
        raw.write_text(cp.stdout)
        raw.chmod(0o600)

        entries = parse_mail_auth(cp.stdout)
        tsv = ctx.secrets_dir / "mail_auth.tsv"
        tsv.write_text("".join(f"{a}\t{p}\n" for a, p in entries))
        tsv.chmod(0o600)
        log.info("Mail-Passwörter: %d Konten -> %s (gegen %s gegenprüfen!)",
                 len(entries), tsv, raw)

    def _export_crontabs(self):
        ctx = self.ctx
        dest = ctx.workdir / "crontabs.tar"
        ctx.runner.download(
            ctx.old,
            ["tar", "-C", "/var/spool/cron", "-cf", "-", "crontabs"],
            dest, check=False,
        )
        log.info("Crontab-Sicherung: %s (manuell übernehmen)", dest)
