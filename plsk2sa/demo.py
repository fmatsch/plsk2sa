"""Simulated servers for the GUI's demo mode (`plsk2sa ui --demo`).

Lets you click through the whole wizard - connect, checks, selection,
migration, results - without any real server. The data is invented; every
command succeeds after a short delay. Nothing leaves this computer.
"""

import hashlib
import re
import subprocess
import time
from typing import Dict, List

from .transport import Transport

# (id, name, webspace_id, docroot)
DOMAINS = [
    (1, "acme-shop.com", 0, "/var/www/vhosts/acme-shop.com/httpdocs"),
    (2, "mueller-architekten.de", 0, "/var/www/vhosts/mueller-architekten.de/httpdocs"),
    (3, "mueller-bau.de", 2, "/var/www/vhosts/mueller-architekten.de/mueller-bau.de"),
    (4, "club-sonnenhof.at", 0, "/var/www/vhosts/club-sonnenhof.at/httpdocs"),
]
DATABASES = {
    "acme-shop.com": ["acme_shop_wp"],
    "mueller-architekten.de": ["mueller_cms"],
    "club-sonnenhof.at": ["sonnenhof_joomla"],
}
MAILBOXES = {
    "acme-shop.com": ["info", "orders", "max"],
    "mueller-architekten.de": ["kontakt", "f.mueller"],
    "mueller-bau.de": ["info"],
}
ALIASES = {
    "acme-shop.com": [("sales", "orders@acme-shop.com")],
    "mueller-architekten.de": [("empfang", "kontakt@mueller-architekten.de")],
}
PHP_HANDLERS = {
    "acme-shop.com": "plesk-php74-fpm",
    "mueller-architekten.de": "plesk-php81-fpm",
    "mueller-bau.de": "plesk-php81-fpm",
    "club-sonnenhof.at": "plesk-php83-fpm",
}
SUBDOMAINS = {"acme-shop.com": ["blog.acme-shop.com"]}
DOMAIN_ALIASES = {"acme-shop.com": ["acme-shop.de"]}
SIZES_KB = {  # keyed by path
    "/var/www/vhosts/acme-shop.com/httpdocs": 1_450_000,
    "/var/www/vhosts/mueller-architekten.de/httpdocs": 380_000,
    "/var/www/vhosts/mueller-architekten.de/mueller-bau.de": 120_000,
    "/var/www/vhosts/club-sonnenhof.at/httpdocs": 640_000,
    "/var/qmail/mailnames/acme-shop.com": 2_900_000,
    "/var/qmail/mailnames/mueller-architekten.de": 910_000,
    "/var/qmail/mailnames/mueller-bau.de": 85_000,
}
DB_SIZES_MB = {"acme_shop_wp": 310.5, "mueller_cms": 42.0, "sonnenhof_joomla": 88.7}

PORT_LISTING = [
    (22, "sshd"), (25, "master"), (80, "nginx"), (143, "dovecot"),
    (465, "master"), (587, "master"), (993, "dovecot"),
]

OLD_IP = "203.0.113.10"
NEW_IP = "203.0.113.20"
CDN_IP = "198.51.100.7"


def _zone(domain, *, mail=True, extra=()):
    d = domain
    rows = [
        ("NS", f"{d}.", f"ns1.{d}.", ""), ("NS", f"{d}.", f"ns2.{d}.", ""),
        ("A", f"{d}.", OLD_IP, ""), ("A", f"ns1.{d}.", OLD_IP, ""),
        ("CNAME", f"www.{d}.", f"{d}.", ""),
    ]
    if mail:
        rows += [
            ("A", f"mail.{d}.", OLD_IP, ""),
            ("MX", f"{d}.", f"mail.{d}.", "10"),
            ("TXT", f"{d}.", f"v=spf1 +a +mx ip4:{OLD_IP} ~all", ""),
            ("TXT", f"default._domainkey.{d}.", "v=DKIM1; k=rsa; p=OLDPLESKKEYdemo", ""),
            ("TXT", f"_dmarc.{d}.", "v=DMARC1; p=none", ""),
        ]
    return rows + list(extra)


DNS_RECORDS = {
    "acme-shop.com": _zone("acme-shop.com", extra=[
        ("A", "shop.acme-shop.com.", CDN_IP, ""),          # points elsewhere: must stay
        ("AAAA", "acme-shop.com.", "2001:db8::10", ""),
    ]),
    "mueller-architekten.de": _zone("mueller-architekten.de"),
    "mueller-bau.de": _zone("mueller-bau.de", mail=False, extra=[
        ("MX", "mueller-bau.de.", "mail.mueller-architekten.de.", "10"),
    ]),
    "club-sonnenhof.at": _zone("club-sonnenhof.at", mail=False),
}

DKIM_TEMPLATE = (
    'mail._domainkey\tIN\tTXT\t( "v=DKIM1; h=sha256; k=rsa; "\n'
    '\t  "p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA-DEMO-KEY-NOT-REAL-{domain}-"\n'
    '\t  "AQAB" )  ; ----- DKIM key mail for {domain}\n'
)


class DemoWorld:
    """State shared by the simulated old and new server."""

    def __init__(self, delay: float = 0.25):
        self.delay = delay
        self.provisioned = False


class DemoTransport(Transport):
    def __init__(self, role: str, world: DemoWorld):
        assert role in ("old", "new")
        self.role = role
        self.world = world

    def is_alive(self) -> bool:
        return True

    def host_key_line(self) -> str:
        return "demo-old ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDEMODEMODEMODEMODEMODEMODEMODEMODEMODE"

    # ------------------------------------------------------------------
    def exec(self, argv, *, stdin_text=None, stdin_path=None, stdout_path=None):
        out, rc = self._dispatch(list(argv), stdin_text or "", stdout_path)
        if self.world.delay:
            time.sleep(self.world.delay)
        return subprocess.CompletedProcess(argv, rc, out, "")

    def _dispatch(self, argv: List[str], stdin: str, stdout_path):
        cmd = argv[0]
        if stdout_path is not None:
            with open(stdout_path, "wb") as f:
                if cmd == "bash":
                    f.write(b"-- demo dump, not real data\n")
            return "", 0
        if cmd == "id":
            return "0\n", 0
        if cmd == "cat" and argv[1:] == ["/etc/os-release"]:
            return self._os_release(), 0
        if self.role == "old":
            return self._old(argv, stdin)
        return self._new(argv, stdin)

    def _os_release(self) -> str:
        if self.role == "old":
            return 'PRETTY_NAME="Ubuntu 20.04.6 LTS"\nID=ubuntu\nVERSION_ID="20.04"\n'
        return 'PRETTY_NAME="Ubuntu 24.04.1 LTS"\nID=ubuntu\nVERSION_ID="24.04"\n'

    # ----------------------------- old server -------------------------
    def _old(self, argv, stdin):
        cmd = argv[0]
        if cmd == "plesk":
            if argv[1] == "version":
                return "Plesk Obsidian 18.0.62.1\n", 0
            if argv[1] == "db":
                return self._sql(argv[3]), 0
            if argv[1:3] == ["sbin", "mail_auth_view"]:
                return self._mail_auth_table(), 0
            if argv[1] == "bin":
                return f"Demo output of plesk bin {argv[2]} for {argv[-1]}\n", 0
        if cmd == "bash" and "command -v rsync" in argv[-1]:
            return "/usr/bin/rsync\n", 0
        if cmd == "bash" and "mail_auth_view" in argv[-1]:
            return f"{sum(len(v) for v in MAILBOXES.values())}\n", 0
        if cmd == "timeout" and argv[2:3] == ["du"]:
            kb = SIZES_KB.get(argv[-1])
            return (f"{kb}\t{argv[-1]}\n", 0) if kb else ("", 1)
        return "", 0

    def _sql(self, sql: str) -> str:
        s = " ".join(sql.split())
        if s.startswith("SELECT COUNT(*) FROM domains"):
            return f"{len(DOMAINS)}\n"
        if "webspace_id" in s:
            return "".join(f"{i}\t{n}\t{w}\t{p}\n" for i, n, w, p in DOMAINS)
        if s.startswith("SELECT d.name, h.www_root FROM domains d"):
            return "".join(f"{n}\t{p}\n" for _, n, _, p in DOMAINS)
        if s == "SELECT id, name FROM domains":
            return "".join(f"{i}\t{n}\n" for i, n, _, _ in DOMAINS)
        if "php_handler_id" in s:
            return "".join(f"{n}\t{h}\n" for n, h in PHP_HANDLERS.items())
        if "FROM dns_recs" in s:
            return "".join(f"{dom}\t{t}\t{h}\t{v}\t{o or 'NULL'}\n"
                           for dom, recs in DNS_RECORDS.items() for t, h, v, o in recs)
        if "FROM IP_Addresses" in s:
            return f"{OLD_IP}\n"
        if "FROM subdomains" in s:
            return "".join(f"{d}\t{sub}\n" for d, subs in SUBDOMAINS.items() for sub in subs)
        if "FROM domain_aliases" in s:
            return "".join(f"{d}\t{a}\n" for d, als in DOMAIN_ALIASES.items() for a in als)
        if "information_schema.tables" in s:
            return "".join(f"{db}\t{mb}\n" for db, mb in DB_SIZES_MB.items())
        m = re.search(r"d\.name = '([^']+)'", s)
        dom = m.group(1) if m else ""
        if "FROM data_bases" in s:
            return "".join(f"{db}\n" for db in DATABASES.get(dom, []))
        if "FROM mail_aliases" in s:
            return "".join(f"{a}\t{t}\n" for a, t in ALIASES.get(dom, []))
        if "FROM mail m" in s:
            return "".join(f"{mb}\n" for mb in MAILBOXES.get(dom, []))
        return ""

    def _mail_auth_table(self) -> str:
        rows = ["+-----------------------+-------+------------------+",
                "| Mail address          | Type  | Password         |",
                "+-----------------------+-------+------------------+"]
        for dom, boxes in MAILBOXES.items():
            for i, mb in enumerate(boxes, 1):
                rows.append(f"| {mb}@{dom} | plain | demo-Passw0rd-{i} |")
        rows.append("+-----------------------+-------+------------------+")
        return "\n".join(rows) + "\n"

    # ----------------------------- new server -------------------------
    def _new(self, argv, stdin):
        cmd = argv[0]
        if cmd == "df":
            return ("Filesystem 1024-blocks Used Available Capacity Mounted on\n"
                    "/dev/sda1 83886080 9437184 74448896 12% /\n"), 0
        if cmd == "timeout" and argv[2:3] == ["bash"]:
            port = argv[-1]
            return "", (1 if port == "25" else 0)
        if cmd == "ss":
            return self._ss(argv), 0
        if cmd == "bash":
            script = argv[-1] if len(argv) > 1 else ""
            if argv[1:2] == ["-s"]:
                if "apt-get install" in stdin:
                    self.world.provisioned = True
                return "", 0
            if "pgrep" in script:
                return "free\n", 0
            if any("route get" in a for a in argv):
                return "203.0.113.20\n", 0
            return "", 0
        if cmd == "cat":
            path = argv[1]
            if path.endswith(".pub"):
                return ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDEMODEMODEMODEMODEMODEMODEMODEMODEMODE "
                        "plsk2sa-temporary\n"), 0
            if path == "/etc/dovecot/users":
                return "".join(f"{mb}@{dom}:{{SHA512-CRYPT}}$6$demo$x\n"
                               for dom, boxes in MAILBOXES.items() for mb in boxes), 0
            m = re.match(r"/etc/opendkim/keys/([^/]+)/mail\.txt$", path)
            if m:
                return DKIM_TEMPLATE.format(domain=m.group(1)), 0
        if cmd == "openssl":
            return "$6$demosalt$" + hashlib.sha512(stdin.encode()).hexdigest()[:40] + "\n", 0
        if cmd == "systemctl" and argv[1] == "is-active":
            return "active\n", 0
        if cmd == "curl":
            return "200", 0
        if cmd == "mysql" and "-Ne" in argv:
            return "42\n", 0
        if cmd == "rsync":
            time.sleep(self.world.delay * 4)
        return "", 0

    def _ss(self, argv) -> str:
        ports = PORT_LISTING if self.world.provisioned else PORT_LISTING[:1]
        if "-ltnpH" in argv:
            return "".join(f'LISTEN 0 128 0.0.0.0:{p} 0.0.0.0:* users:(("{n}",pid=800,fd=3))\n'
                           for p, n in ports)
        return "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n" + \
            "".join(f"LISTEN 0 128 0.0.0.0:{p} 0.0.0.0:*\n" for p, _ in ports)


def make_demo_transports(delay: float = 0.25) -> Dict[str, DemoTransport]:
    world = DemoWorld(delay)
    return {"old": DemoTransport("old", world), "new": DemoTransport("new", world)}


DEMO_FINGERPRINT = "SHA256:DEMOdemoDEMOdemoDEMOdemoDEMOdemoDEMO0"


def demo_ptr_lookup(host: str):
    return "static.203-0-113-20.example-isp.net"
