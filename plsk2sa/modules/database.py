"""Databases per domain: create, import the dump, manage the DB user.

DB passwords are generated NEW (Plesk does not hand over the old ones
cleanly) and kept locally in workdir/secrets/db-credentials.tsv - on
repeated runs the stored password is reused, so runs stay idempotent
and app configs stay valid.
"""

import logging
import secrets
import string
from typing import Dict

from . import Module
from ..fsutil import read_text, write_secret
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
        for line in read_text(self.creds_path).splitlines():
            parts = line.split("\t")
            if len(parts) == 2:
                creds[parts[0]] = parts[1]
        return creds

    def _save_creds(self, creds: Dict[str, str]):
        write_secret(self.creds_path,
                     "".join(f"{db}\t{pw}\n" for db, pw in sorted(creds.items())))

    def migrate_domain(self, domain: Domain):
        creds = self._load_creds()
        for db in domain.databases:
            dump = self.ctx.db_dir / f"{db}.sql"
            if not dump.is_file():
                raise RuntimeError(f"[database] Dump missing: {dump} - run the export first")

            password = creds.get(db) or _gen_password()
            creds[db] = password

            log.info("[database] %s: creating and importing %s", domain.name, db)
            # The DB name is manifest-validated ([A-Za-z0-9_-]+) and the
            # password purely alphanumeric - both are SQL-safe.
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
            log.info("[database] Credentials: %s - enter them into the app configs!",
                     self.creds_path)

    # Re-sync = import the dump again (export fresh dumps first)
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
                results.append((ok, f"Database {db}: {count or '?'} tables"))
        return results
