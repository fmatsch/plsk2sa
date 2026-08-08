"""DKIM pro Domain: Key erzeugen, OpenDKIM registrieren, DNS-Record
im Workdir ablegen (muss beim DNS-Anbieter veröffentlicht werden).
"""

import logging
import shlex

from . import Module
from ..manifest import Domain

log = logging.getLogger("plsk2sa")

SELECTOR = "mail"


class DkimModule(Module):
    name = "dkim"

    def migrate_domain(self, domain: Domain):
        new = self.ctx.new
        dom = domain.name
        keydir = f"/etc/opendkim/keys/{dom}"
        qdom, qkeydir = shlex.quote(dom), shlex.quote(keydir)

        log.info("[dkim] %s: Key sicherstellen", dom)
        self.runner.script(new, f"""set -euo pipefail
if [ ! -f {qkeydir}/{SELECTOR}.private ]; then
    mkdir -p {qkeydir}
    opendkim-genkey -D {qkeydir} -d {qdom} -s {SELECTOR}
    chown -R opendkim:opendkim {qkeydir}
fi
grep -q "^{SELECTOR}._domainkey.{dom} " /etc/opendkim/KeyTable || \\
    echo "{SELECTOR}._domainkey.{dom} {dom}:{SELECTOR}:{keydir}/{SELECTOR}.private" \\
    >> /etc/opendkim/KeyTable
grep -q "^\\*@{dom} " /etc/opendkim/SigningTable || \\
    echo "*@{dom} {SELECTOR}._domainkey.{dom}" >> /etc/opendkim/SigningTable
systemctl restart opendkim
""")

        record = self.runner.run(
            new, ["cat", f"{keydir}/{SELECTOR}.txt"],
            mutating=False, check=False,
        ).stdout
        if record:
            dest = self.ctx.dns_dir / f"{dom}.dkim.txt"
            dest.write_text(record)
            log.info("[dkim] %s: DNS-Record liegt in %s — veröffentlichen!", dom, dest)

    def verify(self):
        results = []
        for domain in self.ctx.domains():
            cp = self.runner.run(self.ctx.new, [
                "test", "-f", f"/etc/opendkim/keys/{domain.name}/{SELECTOR}.private",
            ], mutating=False, check=False)
            results.append((cp.returncode == 0,
                            f"DKIM-Key für {domain.name} vorhanden"))
        return results
