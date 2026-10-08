"""What does the Plesk server rely on?  (strictly read-only)

The result feeds prepare.py, which turns it into a list of Ubuntu packages
for the target. Every probe is fail-soft: a probe that cannot run simply
reports nothing, so a missing tool never produces a wrong requirement.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .context import Context
from .plesk_export import Inventory, PleskExporter
from .runner import CommandError
from .transport import TransportError

log = logging.getLogger("plsk2sa")

# command name on the source -> label used in the plan
TOOL_COMMANDS = [
    "node", "npm", "composer", "git", "wp", "convert", "ffmpeg", "wkhtmltopdf", "gs",
    "unzip", "zip", "tesseract", "java", "python3", "pip3", "ruby", "redis-server",
    "memcached", "fail2ban-client", "clamscan", "spamassassin", "psql", "mongod",
]

# systemd unit names (any spelling) -> service label
SERVICE_UNITS = {
    "redis": "redis", "redis-server": "redis",
    "memcached": "memcached",
    "fail2ban": "fail2ban",
    "clamav-daemon": "clamav", "clamd": "clamav", "clamd@amavisd": "clamav",
    "spamassassin": "spamassassin", "spamd": "spamassassin", "psa-spamassassin": "spamassassin",
    "postgresql": "postgresql",
    "mongod": "mongodb",
}

RE_MODULE = re.compile(r"^[a-z0-9_.+-]+$")


@dataclass
class Requirements:
    php_versions: List[str] = field(default_factory=list)        # versions used by the selected sites
    php_extensions: Dict[str, List[str]] = field(default_factory=dict)  # version -> loaded modules
    tools: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    db_types: Dict[str, int] = field(default_factory=dict)       # "mysql": 3, "postgresql": 1
    htaccess_sites: List[str] = field(default_factory=list)      # domains whose docroot has an .htaccess
    os_name: str = ""
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "php_versions": self.php_versions, "php_extensions": self.php_extensions,
            "tools": self.tools, "services": self.services, "db_types": self.db_types,
            "htaccess_sites": self.htaccess_sites, "os_name": self.os_name, "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Requirements":
        return cls(**{k: d.get(k, getattr(cls(), k)) for k in cls().to_dict()})


def parse_php_modules(output: str) -> List[str]:
    """`php -m` -> sorted module names (Zend modules and section headers dropped)."""
    modules = set()
    for line in output.splitlines():
        line = line.strip().lower()
        if line.startswith("[") or not line:
            continue
        if RE_MODULE.match(line):
            modules.add(line)
    return sorted(modules)


def _lines(output: str) -> List[str]:
    return [l.strip() for l in output.splitlines() if l.strip()]


def detect(ctx: Context, inventory: Optional[Inventory], domains: Optional[List[str]] = None) -> Requirements:
    """Probe the Plesk server. `domains` limits site-specific probes (default: all in the inventory)."""
    req = Requirements()
    run = lambda argv: ctx.runner.run(ctx.old, argv, mutating=False, check=False)  # noqa: E731
    selected = [d for d in (inventory.domains if inventory else []) if domains is None or d.name in domains]

    try:
        out = run(["cat", "/etc/os-release"]).stdout
        m = re.search(r'^PRETTY_NAME="?([^"\n]+)', out, re.M)
        req.os_name = m.group(1) if m else ""

        # PHP versions of the sites and the modules each version has loaded
        req.php_versions = sorted({d.source_php for d in selected if d.source_php})
        for v in req.php_versions:
            cp = run([f"/opt/plesk/php/{v}/bin/php", "-m"])
            if cp.returncode == 0:
                req.php_extensions[v] = parse_php_modules(cp.stdout)
            else:
                req.notes.append(f"Could not list the PHP {v} modules on the Plesk server; "
                                 f"only the standard extensions will be installed for it.")

        cp = run(["bash", "-c", 'for c in "$@"; do command -v "$c" >/dev/null 2>&1 && echo "$c"; done',
                  "_", *TOOL_COMMANDS])
        req.tools = [t for t in _lines(cp.stdout) if t in TOOL_COMMANDS]

        cp = run(["bash", "-c", 'for s in "$@"; do systemctl is-active --quiet "$s" 2>/dev/null && echo "$s"; done',
                  "_", *SERVICE_UNITS])
        req.services = sorted({SERVICE_UNITS[u] for u in _lines(cp.stdout) if u in SERVICE_UNITS})

        rows = PleskExporter(ctx)._try_sql("SELECT type, COUNT(*) FROM data_bases GROUP BY type", "db types")
        for r in rows or []:
            if len(r) >= 2 and r[1].isdigit():
                req.db_types[r[0].lower()] = int(r[1])

        for d in selected:
            cp = run(["bash", "-c", '[ -f "$0/.htaccess" ] && echo yes', d.docroot_src])
            if cp.stdout.strip() == "yes":
                req.htaccess_sites.append(d.name)
    except (CommandError, TransportError) as e:
        req.notes.append(f"Reading the server's software failed part-way: {e}")
        log.debug("requirements probe failed", exc_info=True)
    return req
