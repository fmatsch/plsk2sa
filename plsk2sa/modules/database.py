"""Datenbanken pro Domain: anlegen, Dump einspielen, Nutzer verwalten.

DB-Passwörter werden NEU generiert (Plesk gibt die alten nicht sauber
her) und lokal in workdir/secrets/db-credentials.tsv gehalten — bei
Wiederholungsläufen wird das gespeicherte Passwort wiederverwendet,
damit der Lauf idempotent bleibt und App-Configs gültig bleiben.
"""

import logging
import secrets
import string
from typing import Dict

from . import Module
from ..manifest import Domain

log = logging.getLogger("plsk2sa")

_ALPHABET = string.ascii_letters + string.digits


def _gen_password() -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(24))


class DatabaseModule(Module):
    name = "database"

    @property
    def creds_path(self):
        return self.ctx.secrets_dir / "db-credentials.tsv"

    def _load_creds(self) -> Dict[str, str]:
        if not self.creds_path.is_file():
            return {}
        creds = {}
        for line in self.creds_path.read_text().splitlines():
            parts = line.split("\t")
            if len(parts) == 2:
                creds[parts[0]] = parts[1]
        return creds

    def _save_creds(self, creds: Dict[str, str]):
        self.ctx.secrets_dir.mkdir(parents=True, exist_ok=True)
        self.creds_path.write_text(
            "".join(f"{db}\t{pw}\n" for db, pw in sorted(creds.items()))
        )
        self.creds_path.chmod(0o600)

    def migrate_domain(self, domain: Domain):
        creds = self._load_creds()
        for db in domain.databases:
            dump = self.ctx.db_dir / f"{db}.sql"
            if not dump.is_file():
                raise SystemExit(f"[database] Dump fehlt: {dump} — 'plsk2sa export' ausführen")

            password = creds.get(db) or _gen_password()
            creds[db] = password

            log.info("[database] %s: DB %s anlegen und einspielen", domain.name, db)
            # DB-Name ist manifest-validiert ([A-Za-z0-9_-]+), Passwort
            # rein alphanumerisch — beides SQL-sicher.
            self.runner.script(self.ctx.new, f"""set -euo pipefail
mysql <<'SQL'
CREATE DATABASE IF NOT EXISTS `{db}`;
CREATE USER IF NOT EXISTS '{db}'@'localhost' IDENTIFIED BY '{password}';
ALTER USER '{db}'@'localhost' IDENTIFIED BY '{password}';
GRANT ALL PRIVILEGES ON `{db}`.* TO '{db}'@'localhost';
FLUSH PRIVILEGES;
SQL
""")
            self.runner.run(self.ctx.new, ["mysql", db], input_path=dump)

        self._save_creds(creds)
        if domain.databases:
            log.info("[database] Zugangsdaten: %s — in App-Configs eintragen!",
                     self.creds_path)

    # Nachsync = Dump erneut einspielen (Dumps vorher frisch exportieren)
    def sync_domain(self, domain: Domain):
        self.migrate_domain(domain)

    def verify(self):
        results = []
        for domain in self.ctx.domains():
            for db in domain.databases:
                cp = self.runner.run(self.ctx.new, [
                    "mysql", "-Ne",
                    f"SELECT COUNT(*) FROM information_schema.tables "
                    f"WHERE table_schema = '{db}'",
                ], mutating=False, check=False)
                count = cp.stdout.strip()
                ok = cp.returncode == 0 and count.isdigit() and int(count) > 0
                results.append((ok, f"DB {db}: {count or '?'} Tabellen"))
        return results
