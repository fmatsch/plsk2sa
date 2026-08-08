"""Mail pro Domain: Postfix-Registrierung, Dovecot-Konten mit den
originalen Passwörtern (als SHA512-CRYPT-Hash), Aliasse, Maildir-Sync.
"""

import logging
import shlex
from typing import Dict

from . import Module
from ..manifest import Domain

log = logging.getLogger("plsk2sa")


class MailModule(Module):
    name = "mail"

    def _passwords(self) -> Dict[str, str]:
        path = self.ctx.secrets_dir / "mail_auth.tsv"
        if not path.is_file():
            raise SystemExit(f"[mail] Passwortliste fehlt: {path} — 'plsk2sa export' ausführen")
        result = {}
        for line in path.read_text().splitlines():
            parts = line.split("\t", 1)
            if len(parts) == 2:
                result[parts[0]] = parts[1]
        return result

    def _hash_password(self, password: str) -> str:
        """SHA512-CRYPT auf dem Zielserver erzeugen; Passwort geht nur
        über stdin, nie in eine Prozessliste oder ein Log."""
        if self.runner.dry_run:
            return "$6$DRYRUN$..."
        cp = self.runner.run(self.ctx.new, ["openssl", "passwd", "-6", "-stdin"],
                             input_text=password + "\n", mutating=False)
        return cp.stdout.strip()

    def migrate_domain(self, domain: Domain):
        new = self.ctx.new
        passwords = self._passwords()

        log.info("[mail] %s: Domain registrieren", domain.name)
        qdom = shlex.quote(domain.name)
        self.runner.script(new, f"""set -euo pipefail
grep -qxF {qdom} /etc/postfix/virtual_domains || echo {qdom} >> /etc/postfix/virtual_domains
""")

        for mailbox in domain.mailboxes:
            addr = f"{mailbox}@{domain.name}"
            password = passwords.get(addr)
            if not password:
                log.warning("[mail] kein Passwort für %s in mail_auth.tsv — "
                            "Konto wird NICHT angelegt (manuell nachziehen)", addr)
                continue

            log.info("[mail] Konto %s", addr)
            pw_hash = self._hash_password(password)
            entry = f"{addr}:{{SHA512-CRYPT}}{pw_hash}"
            qaddr = shlex.quote(addr)
            self.runner.script(new, f"""set -euo pipefail
sed -i '\\|^{addr}:|d' /etc/dovecot/users
echo {shlex.quote(entry)} >> /etc/dovecot/users
grep -q "^{addr} " /etc/postfix/vmailbox || \\
    echo {shlex.quote(f"{addr} {domain.name}/{mailbox}/")} >> /etc/postfix/vmailbox
mkdir -p {shlex.quote(f"/var/vmail/{domain.name}/{mailbox}")}
""")

        for alias, target in domain.aliases:
            src = f"{alias}@{domain.name}"
            log.info("[mail] Alias %s -> %s", src, target)
            self.runner.script(new, f"""set -euo pipefail
grep -q "^{src} " /etc/postfix/virtual || \\
    echo {shlex.quote(f"{src} {target}")} >> /etc/postfix/virtual
""")

        self.runner.script(new, """set -euo pipefail
postmap /etc/postfix/vmailbox /etc/postfix/virtual
systemctl reload postfix dovecot
""")

        self.sync_domain(domain)

    def sync_domain(self, domain: Domain):
        maildir_root = self.config.plesk_maildir_root
        for mailbox in domain.mailboxes:
            src = f"{self.ctx.old}:{maildir_root}/{domain.name}/{mailbox}/Maildir/"
            dst = f"/var/vmail/{domain.name}/{mailbox}/"
            log.info("[mail] %s@%s: Maildir-Sync", mailbox, domain.name)
            cp = self.runner.run(self.ctx.new, ["rsync", "-a", src, dst],
                                 check=False)
            if cp.returncode != 0:
                log.warning("[mail] Maildir-Sync für %s@%s fehlgeschlagen:\n%s",
                            mailbox, domain.name, (cp.stderr or "").strip())
        self.runner.run(self.ctx.new, [
            "chown", "-R", "vmail:vmail", f"/var/vmail/{domain.name}",
        ])

    def verify(self):
        results = []
        cp = self.runner.run(self.ctx.new, ["postfix", "check"],
                             mutating=False, check=False)
        results.append((cp.returncode == 0, "Postfix-Konfiguration gültig"))

        users = self.runner.run(self.ctx.new, ["cat", "/etc/dovecot/users"],
                                mutating=False, check=False).stdout
        for domain in self.ctx.domains():
            for mailbox in domain.mailboxes:
                addr = f"{mailbox}@{domain.name}"
                ok = any(line.startswith(addr + ":") for line in users.splitlines())
                results.append((ok, f"Mailkonto {addr} in Dovecot angelegt"))
        return results
