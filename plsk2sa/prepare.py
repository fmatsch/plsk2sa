"""Prepare the target server: install what the Plesk server's sites rely on.

requirements.py finds out what the source uses (PHP versions and modules,
command line tools, background services, ...). build_plan() maps that to
Ubuntu packages and says honestly which items are merely *installed* and
which are also *set up*. apply_plan() installs the selected items,
verify_plan() checks the result.

The base stack (nginx, PHP-FPM, MariaDB, Postfix, Dovecot, OpenDKIM,
certbot) is installed and configured by modules/system.py; this module adds
the extras on top and is idempotent like everything else.
"""

import logging
import re
import shlex
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

from .context import Context
from .modules.system import PACKAGES as BASE_PACKAGES
from .plesk_export import DomainInfo
from .requirements import Requirements

log = logging.getLogger("plsk2sa")

RE_PACKAGE = re.compile(r"^[a-z0-9][a-z0-9+.-]*$")
RE_PHP_VERSION = re.compile(r"^\d\.\d$")
PPA = "ppa:ondrej/php"
PHP_BASE_EXTENSIONS = ["fpm", "cli", "mysql", "curl", "xml", "mbstring", "zip", "gd", "intl"]

# PHP module on the source -> Ubuntu package suffix (php<version>-<suffix>).
# Modules that ship inside php-common/php-cli (json, ctype, ...) have no entry on purpose.
PHP_MODULE_PACKAGES = {
    "mysqli": "mysql", "mysqlnd": "mysql", "pdo_mysql": "mysql",
    "curl": "curl", "gd": "gd", "intl": "intl", "mbstring": "mbstring", "zip": "zip",
    "dom": "xml", "xml": "xml", "simplexml": "xml", "xmlreader": "xml", "xmlwriter": "xml",
    "xsl": "xsl", "soap": "soap", "bcmath": "bcmath", "gmp": "gmp", "imap": "imap", "ldap": "ldap",
    "apcu": "apcu", "redis": "redis", "memcached": "memcached", "memcache": "memcache",
    "imagick": "imagick", "pgsql": "pgsql", "pdo_pgsql": "pgsql", "sqlite3": "sqlite3",
    "pdo_sqlite": "sqlite3", "bz2": "bz2", "snmp": "snmp", "tidy": "tidy", "pspell": "pspell",
    "enchant": "enchant", "dba": "dba", "xmlrpc": "xmlrpc", "opcache": "opcache",
}

# command found on the source -> Ubuntu packages (one combined "tools" item)
TOOL_PACKAGES = {
    "node": ["nodejs", "npm"], "composer": ["composer"], "git": ["git"], "convert": ["imagemagick"],
    "ffmpeg": ["ffmpeg"], "wkhtmltopdf": ["wkhtmltopdf"], "gs": ["ghostscript"], "unzip": ["unzip"],
    "zip": ["zip"], "tesseract": ["tesseract-ocr"], "java": ["default-jre-headless"],
    "python3": ["python3"], "pip3": ["python3-pip"], "ruby": ["ruby"], "psql": ["postgresql-client"],
}

# service on the source -> (title, packages, systemd units on Ubuntu, install by default, note)
SERVICES = {
    "redis": ("Redis", ["redis-server"], ["redis-server"], True, ""),
    "memcached": ("Memcached", ["memcached"], ["memcached"], True, ""),
    "fail2ban": ("fail2ban", ["fail2ban"], ["fail2ban"], True,
                 "Ubuntu's default setup protects SSH; the jails of the Plesk server are not copied."),
    "clamav": ("ClamAV virus scanner", ["clamav-daemon"], ["clamav-daemon"], False,
               "Installed only - it is not connected to Postfix, so mail is not scanned until you set that up."),
    "spamassassin": ("SpamAssassin", ["spamassassin", "spamc"], ["spamassassin"], False,
                     "Installed only - it is not connected to Postfix, so mail is not filtered until you set that up."),
    "postgresql": ("PostgreSQL server", ["postgresql"], ["postgresql"], False,
                   "Installed only - plsk2sa does not migrate PostgreSQL databases; dump and restore them yourself."),
}


@dataclass
class PrepItem:
    id: str
    title: str
    reason: str
    packages: List[str]
    default: bool = True
    required: bool = False
    third_party: bool = False
    note: str = ""
    units: List[str] = field(default_factory=list)  # systemd units to enable afterwards
    php: str = ""

    def to_dict(self) -> dict:
        return {"id": self.id, "title": self.title, "reason": self.reason, "packages": self.packages,
                "default": self.default, "required": self.required, "third_party": self.third_party,
                "note": self.note, "php": self.php}


@dataclass
class PreparePlan:
    default_php: str
    items: List[PrepItem] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def item(self, item_id: str) -> Optional[PrepItem]:
        return next((i for i in self.items if i.id == item_id), None)

    def default_selection(self) -> List[str]:
        return [i.id for i in self.items if i.default and not i.required]

    def resolve_selection(self, selected: Optional[Iterable[str]]) -> List[str]:
        """Selected optional item ids (validated); None means the defaults."""
        if selected is None:
            return self.default_selection()
        ids = []
        for s in selected:
            it = self.item(str(s))
            if it is None:
                raise ValueError(f"Unknown item: {s}")
            if not it.required and it.id not in ids:
                ids.append(it.id)
        return ids

    def php_versions_for(self, selected: Iterable[str]) -> List[str]:
        """PHP versions that will exist on the target: the default plus selected php items."""
        chosen = {self.default_php}
        for sid in selected:
            it = self.item(sid)
            if it and it.php and it.id.startswith("php:"):
                chosen.add(it.php)
        return sorted(chosen)

    def php_assignment(self, domains: Iterable[DomainInfo], selected: Iterable[str]) -> Dict[str, str]:
        """domain -> PHP version its pool will use: its own version when that is installed, else the default."""
        available = set(self.php_versions_for(selected))
        return {d.name: (d.source_php if d.source_php in available else self.default_php) for d in domains}

    def to_dict(self) -> dict:
        return {"default_php": self.default_php, "items": [i.to_dict() for i in self.items],
                "notes": self.notes, "default_selection": self.default_selection()}


def php_packages(version: str, extensions: Iterable[str]) -> List[str]:
    return [f"php{version}-{e}" for e in extensions]


def build_plan(req: Requirements, domains: List[DomainInfo], *, default_php: str) -> PreparePlan:
    plan = PreparePlan(default_php=default_php)
    plan.items.append(PrepItem(
        "base", "Base stack",
        "Web server, PHP, database and mail services that every migrated domain needs.",
        BASE_PACKAGES.format(v=default_php).split(), required=True))

    # PHP versions the selected sites use
    used = sorted({d.source_php for d in domains if d.source_php})
    sites = {v: [d.name for d in domains if d.source_php == v] for v in used}
    for v in used:
        extras = sorted({PHP_MODULE_PACKAGES[m] for m in req.php_extensions.get(v, []) if m in PHP_MODULE_PACKAGES}
                        - set(PHP_BASE_EXTENSIONS))
        who = ", ".join(sites[v])
        if v == default_php:
            if extras:
                plan.items.append(PrepItem(
                    f"php-ext:{v}", f"PHP {v} extensions", f"{who} use extensions beyond the standard set: {', '.join(extras)}.",
                    php_packages(v, extras), php=v))
        else:
            plan.items.append(PrepItem(
                f"php:{v}", f"PHP {v}", f"{who} run PHP {v}, which Ubuntu does not ship "
                f"(it has PHP {default_php}). Installed from the third-party repository {PPA}; "
                f"without it these sites would run on PHP {default_php}.",
                php_packages(v, PHP_BASE_EXTENSIONS + extras), third_party=True, php=v,
                units=[f"php{v}-fpm"],
                note="Adds the widely used PPA of Ondrej Sury to the target's package sources."))

    tools = sorted({p for t in req.tools for p in TOOL_PACKAGES.get(t, [])})
    if tools:
        found = [t for t in req.tools if t in TOOL_PACKAGES]
        plan.items.append(PrepItem("tools", "Command line tools", "Found on the Plesk server: " + ", ".join(found) + ".",
                                   tools))

    for key in req.services:
        title, packages, units, default, note = SERVICES.get(key, (None,) * 5)
        if title:
            plan.items.append(PrepItem(f"svc:{key}", title, f"{title} is running on the Plesk server.",
                                       packages, default=default, units=units, note=note))

    names = [d.name for d in domains]
    ht = [s for s in req.htaccess_sites if s in names]
    if ht:
        plan.notes.append(
            f"{len(ht)} site(s) have an .htaccess file ({', '.join(ht[:6])}{' ...' if len(ht) > 6 else ''}). "
            "nginx ignores it: the generated vhost handles WordPress-style permalinks, but custom rewrites, "
            "redirects, password protection or access rules must be ported by hand.")
    if "wp" in req.tools:
        plan.notes.append("WP-CLI is used on the Plesk server but is not in Ubuntu's repositories; install it from wp-cli.org.")
    if "mongodb" in req.services or "mongod" in req.tools:
        plan.notes.append("MongoDB is used on the Plesk server but is not in Ubuntu's repositories; install it from MongoDB's own repository.")
    if req.db_types.get("postgresql"):
        plan.notes.append(f"{req.db_types['postgresql']} PostgreSQL database(s) exist on the Plesk server; plsk2sa migrates MySQL/MariaDB only.")
    plan.notes.extend(req.notes)

    for it in plan.items:  # names end up on an apt command line
        bad = [p for p in it.packages if not RE_PACKAGE.match(p)]
        if bad or (it.php and not RE_PHP_VERSION.match(it.php)):
            raise ValueError(f"Unsafe package or version in plan item {it.id}: {bad}")
    return plan


@dataclass
class PrepResult:
    id: str
    title: str
    packages: List[str]
    status: str          # installed | partial | failed | planned
    failed: List[str] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict:
        return {"id": self.id, "title": self.title, "packages": self.packages, "status": self.status,
                "failed": self.failed, "note": self.note}


_INSTALL = """set -u
export DEBIAN_FRONTEND=noninteractive
APT="apt-get install -y -q -o Dpkg::Options::=--force-confold"
failed=""
if ! $APT "$@" >/dev/null 2>&1; then
    for p in "$@"; do $APT "$p" >/dev/null 2>&1 || failed="$failed $p"; done
fi
echo "FAILED:$failed"
"""


def _install(ctx: Context, packages: List[str]):
    """Install all packages; on failure retry one by one so a single missing package
    does not block the rest. Returns the list of packages that could not be installed."""
    cp = ctx.runner.run(ctx.new, ["bash", "-s", "--", *packages], input_text=_INSTALL)
    m = re.search(r"^FAILED:(.*)$", cp.stdout, re.M)
    return m.group(1).split() if m else []


def apply_plan(ctx: Context, plan: PreparePlan, selected: List[str]) -> List[PrepResult]:
    """Install the selected optional items (the base stack is installed by SystemModule.provision)."""
    run = ctx.runner
    items = [plan.item(s) for s in selected if plan.item(s) and not plan.item(s).required]
    results: List[PrepResult] = []
    if not items:
        return results

    if any(i.third_party for i in items):
        log.info("[prepare] Adding the third-party repository %s", PPA)
        run.script(ctx.new, f"""set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q software-properties-common ca-certificates
add-apt-repository -y {PPA}
""")
    run.script(ctx.new, "set -e\nexport DEBIAN_FRONTEND=noninteractive\napt-get update -q\n")

    for it in items:
        log.info("[prepare] %s: installing %s", it.title, " ".join(it.packages))
        if run.dry_run:
            _install(ctx, it.packages)  # announced as a dry-run command, not executed
            results.append(PrepResult(it.id, it.title, it.packages, "planned", note=it.note))
            continue
        failed = _install(ctx, it.packages)
        status = "installed" if not failed else ("failed" if len(failed) == len(it.packages) else "partial")
        if failed:
            log.warning("[prepare] %s: could not install %s", it.title, " ".join(failed))
        elif it.units:
            run.script(ctx.new, "set -e\nsystemctl enable --now " + " ".join(shlex.quote(u) for u in it.units) + "\n")
        results.append(PrepResult(it.id, it.title, it.packages, status, failed, it.note))
    return results


_CHECK = """for p in "$@"; do
    dpkg-query -W -f='${Status}\\n' "$p" 2>/dev/null | grep -q 'install ok installed' || echo "$p"
done
"""


def verify_plan(ctx: Context, plan: PreparePlan, selected: List[str]):
    """[(ok, message)] - are the selected packages installed and the PHP-FPM services running?"""
    results = []
    for sid in selected:
        it = plan.item(sid)
        if it is None or it.required:
            continue
        cp = ctx.runner.run(ctx.new, ["bash", "-c", _CHECK, "_", *it.packages], mutating=False, check=False)
        missing = cp.stdout.split()
        results.append((not missing, f"{it.title}: " + ("all packages installed" if not missing
                                                       else "missing " + ", ".join(missing))))
        if it.php and it.id.startswith("php:"):
            active = ctx.runner.run(ctx.new, ["systemctl", "is-active", f"php{it.php}-fpm"],
                                    mutating=False, check=False).stdout.strip() == "active"
            results.append((active, f"Service php{it.php}-fpm: {'active' if active else 'not running'}"))
    return results
