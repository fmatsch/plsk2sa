"""DKIM per domain: generate the key, register it with OpenDKIM and store
the DNS record in the workdir (it must be published at the DNS provider).
"""

import logging
import re
import shlex

from . import Module
from ..fsutil import write_text
from ..manifest import Domain

log = logging.getLogger("plsk2sa")

SELECTOR = "mail"


def dkim_dns_value(zone_text: str) -> str:
    """Flatten the BIND-style record written by opendkim-genkey into the
    single TXT value that DNS panels expect (v=DKIM1; k=rsa; p=...)."""
    start, end = zone_text.find("("), zone_text.rfind(")")
    body = zone_text[start + 1:end] if 0 <= start < end else zone_text
    return "".join(re.findall(r'"([^"]*)"', body)).strip()


class DkimModule(Module):
    name = "dkim"

    def migrate_domain(self, domain: Domain):
        new = self.ctx.new
        dom = domain.name
        keydir = f"/etc/opendkim/keys/{dom}"
        qdom, qkeydir = shlex.quote(dom), shlex.quote(keydir)

        log.info("[dkim] %s: ensuring key", dom)
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
            write_text(dest, record)
            log.info("[dkim] %s: DNS record stored in %s - publish it!", dom, dest)

    def verify(self):
        results = []
        for domain in self.ctx.domains():
            cp = self.runner.run(self.ctx.new, [
                "test", "-f", f"/etc/opendkim/keys/{domain.name}/{SELECTOR}.private",
            ], mutating=False, check=False)
            results.append((cp.returncode == 0,
                            f"DKIM key for {domain.name} exists"))
        return results
