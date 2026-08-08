"""Web pro Domain: Site-Nutzer, Docroot-Sync, PHP-FPM-Pool, nginx-vHost."""

import logging
import shlex

from . import Module
from ..manifest import Domain
from ..render import render_template

log = logging.getLogger("plsk2sa")


class WebModule(Module):
    name = "web"

    def migrate_domain(self, domain: Domain):
        new = self.ctx.new
        user = domain.site_user
        docroot = domain.docroot
        php = domain.php

        log.info("[web] %s: Nutzer %s, Docroot %s", domain.name, user, docroot)
        self.runner.script(new, f"""set -euo pipefail
id {shlex.quote(user)} &>/dev/null || \\
    useradd -d {shlex.quote(docroot)} -s /usr/sbin/nologin {shlex.quote(user)}
mkdir -p {shlex.quote(docroot)}
""")

        self.sync_domain(domain)

        mapping = {
            "DOMAIN": domain.name,
            "DOCROOT": docroot,
            "SITEUSER": user,
            "PHP": php,
        }
        self.runner.put(new, f"/etc/php/{php}/fpm/pool.d/{domain.name}.conf",
                        render_template("php-fpm-pool.conf", mapping))
        self.runner.put(new, f"/etc/nginx/sites-available/{domain.name}",
                        render_template("nginx-vhost.conf", mapping))

        self.runner.script(new, f"""set -euo pipefail
ln -sf /etc/nginx/sites-available/{shlex.quote(domain.name)} \\
       /etc/nginx/sites-enabled/{shlex.quote(domain.name)}
nginx -t
systemctl reload php{php}-fpm nginx
""")

    def sync_domain(self, domain: Domain):
        log.info("[web] %s: rsync Webdateien", domain.name)
        src = f"{self.ctx.old}:{domain.docroot_src}/"
        self.runner.run(self.ctx.new, [
            "rsync", "-a", "--delete", src, f"{domain.docroot}/",
        ])
        self.runner.run(self.ctx.new, [
            "chown", "-R", f"{domain.site_user}:{domain.site_user}", domain.docroot,
        ])

    def verify(self):
        results = []
        cp = self.runner.run(self.ctx.new, ["nginx", "-t"],
                             mutating=False, check=False)
        results.append((cp.returncode == 0, "nginx-Konfiguration gültig"))

        for domain in self.ctx.domains():
            cp = self.runner.run(self.ctx.new, [
                "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                "-H", f"Host: {domain.name}", "http://127.0.0.1/",
            ], mutating=False, check=False)
            code = cp.stdout.strip()
            ok = code.startswith(("2", "3"))
            results.append((ok, f"HTTP {domain.name}: Status {code or 'keine Antwort'}"))
        return results
