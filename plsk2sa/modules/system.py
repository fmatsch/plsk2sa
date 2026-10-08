"""Base stack on the new Ubuntu server: packages, vmail user,
Dovecot, Postfix and OpenDKIM base configuration.
"""

import logging

from . import Module
from ..render import load_template, render_template

log = logging.getLogger("plsk2sa")

PACKAGES = (
    "nginx "
    "php{v}-fpm php{v}-cli php{v}-mysql php{v}-curl php{v}-xml "
    "php{v}-mbstring php{v}-zip php{v}-gd php{v}-intl "
    "mariadb-server "
    "postfix postfix-pcre "
    "dovecot-imapd dovecot-lmtpd "
    "opendkim opendkim-tools "
    "certbot python3-certbot-nginx "
    "rsync"
)

SERVICES = ["nginx", "php{v}-fpm", "mariadb", "postfix", "dovecot", "opendkim"]


class SystemModule(Module):
    name = "system"

    def provision(self):
        new = self.ctx.new
        v = self.config.php_version

        log.info("[system] Installing packages")
        self.runner.script(new, f"""set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q {PACKAGES.format(v=v)}
""")

        log.info("[system] vmail user and /var/vmail")
        self.runner.script(new, """set -euo pipefail
if ! id vmail &>/dev/null; then
    groupadd -g 5000 vmail
    useradd -u 5000 -g vmail -d /var/vmail -s /usr/sbin/nologin vmail
fi
mkdir -p /var/vmail
chown vmail:vmail /var/vmail
chmod 770 /var/vmail
""")

        log.info("[system] Configuring Dovecot")
        self.runner.put(new, "/etc/dovecot/conf.d/99-vmail.conf",
                        load_template("dovecot-vmail.conf"))
        self.runner.script(new, """set -euo pipefail
touch /etc/dovecot/users
chown root:dovecot /etc/dovecot/users
chmod 640 /etc/dovecot/users
# System auth (PAM) off - only the passwd-file applies
sed -i 's/^!include auth-system.conf.ext/#!include auth-system.conf.ext/' \\
    /etc/dovecot/conf.d/10-auth.conf
""")

        log.info("[system] Configuring OpenDKIM")
        self.runner.put(new, "/etc/opendkim.conf", load_template("opendkim.conf"))
        self.runner.script(new, """set -euo pipefail
mkdir -p /etc/opendkim/keys /var/spool/postfix/opendkim
touch /etc/opendkim/KeyTable /etc/opendkim/SigningTable
chown -R opendkim:opendkim /etc/opendkim /var/spool/postfix/opendkim
usermod -aG opendkim postfix
""")

        log.info("[system] Configuring Postfix (hostname: %s)",
                 self.config.mail_hostname)
        self.runner.script(new, render_template("postfix-setup.sh", {
            "MAIL_HOSTNAME": self.config.mail_hostname,
        }))

        log.info("[system] Enabling services")
        services = " ".join(s.format(v=v) for s in SERVICES)
        self.runner.script(new, f"""set -euo pipefail
systemctl enable --now {services}
systemctl restart dovecot postfix opendkim
""")

    def verify(self):
        results = []
        v = self.config.php_version
        for svc in (s.format(v=v) for s in SERVICES):
            cp = self.runner.run(self.ctx.new, ["systemctl", "is-active", svc],
                                 mutating=False, check=False)
            active = cp.stdout.strip() == "active"
            results.append((active, f"Service {svc}: {cp.stdout.strip() or 'unknown'}"))

        cp = self.runner.run(self.ctx.new, ["ss", "-tln"],
                             mutating=False, check=False)
        for port, what in ((25, "SMTP"), (80, "HTTP"), (143, "IMAP"),
                           (465, "SMTPS"), (587, "Submission"), (993, "IMAPS")):
            listening = f":{port} " in cp.stdout
            results.append((listening, f"Port {port} ({what}) is listening"))
        return results
