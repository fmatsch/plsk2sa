"""Pre-flight checks for the old (Plesk) and the new (Ubuntu) server.

Every check returns a CheckResult: ok / warn / fail. Only failures block
a migration; warnings are shown and must be acknowledged by the user.
All checks are read-only.
"""

import logging
import re
import shutil
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from .context import Context
from .manifest import RE_PHP
from .plesk_export import DomainInfo, Inventory
from .runner import CommandError
from .transport import TransportError

log = logging.getLogger("plsk2sa")

OK, WARN, FAIL = "ok", "warn", "fail"

RE_FQDN = re.compile(r"^(?=.{4,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$")

# Distribution release -> PHP version in the stock Ubuntu repositories
UBUNTU_PHP = {"24.04": "8.3", "22.04": "8.1"}

MAIL_PORTS = (25, 80, 143, 443, 465, 587, 993)


@dataclass
class CheckResult:
    id: str
    status: str
    title: str
    detail: str = ""

    def to_dict(self) -> dict:
        return {"id": self.id, "status": self.status, "title": self.title,
                "detail": self.detail}


def has_failures(results: List[CheckResult]) -> bool:
    return any(r.status == FAIL for r in results)


def _guard(check_id: str, title: str, fn: Callable[[], CheckResult]) -> CheckResult:
    try:
        return fn()
    except (CommandError, TransportError, OSError) as e:
        return CheckResult(check_id, FAIL, title, str(e))


def _run(ctx: Context, host: str, argv: List[str]):
    return ctx.runner.run(host, argv, mutating=False, check=False)


def _host_of(target: str) -> str:
    return target.rsplit("@", 1)[-1]


def _os_release(ctx: Context, host: str) -> Dict[str, str]:
    out = _run(ctx, host, ["cat", "/etc/os-release"]).stdout
    info = {}
    for line in out.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            info[key.strip()] = value.strip().strip('"')
    return info


def _tcp_probe(ctx: Context, host: str, dest_host: str, port: int, timeout: int = 8) -> bool:
    """Can `host` open a TCP connection to dest_host:port? (arguments are
    passed positionally, never interpolated into the shell string)"""
    cp = _run(ctx, host, ["timeout", str(timeout), "bash", "-c",
                          "exec 3<>/dev/tcp/$0/$1", dest_host, str(port)])
    return cp.returncode == 0


def _plural(n: int, one: str, many: str = "") -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def _fmt_mb(mb: float) -> str:
    return f"{mb / 1024:.1f} GB" if mb >= 1024 else f"{mb:.0f} MB"


# ----------------------------------------------------------------------
# Source (Plesk) server
# ----------------------------------------------------------------------
def check_source(ctx: Context, inventory: Optional[Inventory] = None) -> List[CheckResult]:
    old = ctx.old
    results: List[CheckResult] = []

    def root():
        cp = _run(ctx, old, ["id", "-u"])
        if cp.stdout.strip() == "0":
            return CheckResult("src.root", OK, "Connected as root")
        return CheckResult("src.root", FAIL, "root access required",
                           "The migration reads Plesk's database and system files. "
                           "Connect as root (or a user with full root rights).")

    def os_info():
        info = _os_release(ctx, old)
        return CheckResult("src.os", OK, "Operating system",
                           info.get("PRETTY_NAME") or "unknown")

    def plesk():
        cp = _run(ctx, old, ["plesk", "version"])
        if cp.returncode != 0:
            return CheckResult("src.plesk", FAIL, "Plesk not found",
                               "The `plesk` command is not available on this server. "
                               "Is this really a Plesk server?")
        version = (cp.stdout.strip().splitlines() or ["?"])[0]
        return CheckResult("src.plesk", OK, "Plesk installed", version)

    def psa():
        cp = _run(ctx, old, ["plesk", "db", "-Ne", "SELECT COUNT(*) FROM domains"])
        if cp.returncode != 0 or not cp.stdout.strip().isdigit():
            return CheckResult("src.psa", FAIL, "Plesk database not readable",
                               (cp.stderr or cp.stdout).strip()[:300])
        return CheckResult("src.psa", OK, "Plesk database readable",
                           f"{cp.stdout.strip()} domains registered")

    def rsync():
        cp = _run(ctx, old, ["bash", "-c", "command -v rsync"])
        if cp.returncode != 0:
            return CheckResult("src.rsync", FAIL, "rsync missing on the Plesk server",
                               "Web files and mailboxes are copied with rsync, which must "
                               "exist on both servers. Install it there "
                               "(e.g. `apt install rsync` or `yum install rsync`).")
        return CheckResult("src.rsync", OK, "rsync available", cp.stdout.strip())

    results.append(_guard("src.root", "Connected as root", root))
    if results[-1].status == FAIL:
        return results  # nothing else is meaningful without root
    results.append(_guard("src.os", "Operating system", os_info))
    results.append(_guard("src.plesk", "Plesk installed", plesk))
    results.append(_guard("src.psa", "Plesk database readable", psa))
    results.append(_guard("src.rsync", "rsync available", rsync))

    if inventory is not None:
        results.extend(check_inventory(ctx, inventory))
    return results


def check_inventory(ctx: Context, inventory: Inventory) -> List[CheckResult]:
    """Checks that need the discovered domains (sizes, mail, warnings)."""
    results = [_inventory_summary(inventory)]
    results.extend(_inventory_warnings(inventory))

    total_mailboxes = sum(len(d.mailboxes) for d in inventory.domains)
    if total_mailboxes:
        results.append(_guard("src.mail_auth", "Mail passwords readable",
                              lambda: _mail_auth_check(ctx, total_mailboxes)))
        results.append(_guard("src.maildir", "Mail storage found",
                              lambda: _maildir_check(ctx)))

    results.append(_local_disk_check(ctx, inventory))
    return results


def _inventory_summary(inv: Inventory) -> CheckResult:
    if not inv.domains:
        return CheckResult("src.domains", FAIL, "No domains with hosting found",
                           "There is nothing to migrate on this Plesk server.")
    subs = {d.subscription for d in inv.domains}
    web = sum(d.size_web_mb or 0 for d in inv.domains)
    mail = sum(d.size_mail_mb or 0 for d in inv.domains)
    db = sum(d.size_db_mb or 0 for d in inv.domains)
    detail = (f"{_plural(len(subs), 'subscription')}. Data: web {_fmt_mb(web)}, "
              f"mail {_fmt_mb(mail)}, databases {_fmt_mb(db)}")
    return CheckResult("src.domains", OK, f"{_plural(len(inv.domains), 'domain')} with hosting found", detail)


def _inventory_warnings(inv: Inventory) -> List[CheckResult]:
    results = []
    for note in inv.notes:
        results.append(CheckResult("src.note", WARN, "Inventory note", note))
    subs = [s for d in inv.domains for s in d.subdomains]
    if subs:
        results.append(CheckResult(
            "src.subdomains", WARN,
            f"{_plural(len(subs), 'subdomain')} {'is' if len(subs) == 1 else 'are'} not migrated automatically",
            "Subdomains have their own document roots and vhosts in Plesk. "
            "Migrate them by hand: " + ", ".join(subs[:12]) + (" ..." if len(subs) > 12 else "")))
    aliases = [a for d in inv.domains for a in d.domain_aliases]
    if aliases:
        results.append(CheckResult(
            "src.domain_aliases", WARN,
            f"{_plural(len(aliases), 'domain alias', 'domain aliases')} "
            f"{'is' if len(aliases) == 1 else 'are'} not migrated automatically",
            "Add them to the nginx server_name and mail domains by hand: "
            + ", ".join(aliases[:12]) + (" ..." if len(aliases) > 12 else "")))
    return results


def _mail_auth_check(ctx: Context, expected: int) -> CheckResult:
    # Count on the server so that no password leaves it during a mere check.
    cp = _run(ctx, ctx.old, ["bash", "-c",
                             "plesk sbin mail_auth_view 2>/dev/null | grep -c '@' || true"])
    count = int(cp.stdout.strip()) if cp.stdout.strip().isdigit() else 0
    if count == 0:
        return CheckResult(
            "src.mail_auth", WARN, "Mail passwords are not readable",
            "`plesk sbin mail_auth_view` returned no passwords (Plesk may store them hashed only). "
            "Mailboxes will be skipped and need new passwords on the target.")
    if count < expected:
        return CheckResult(
            "src.mail_auth", WARN, "Some mail passwords are not readable",
            f"{count} password entries for {expected} mailboxes. The rest cannot be migrated "
            f"automatically (forwarders without a mailbox are counted too).")
    return CheckResult("src.mail_auth", OK, "Mail passwords readable",
                       f"{count} accounts - users keep their passwords")


def _maildir_check(ctx: Context) -> CheckResult:
    root = ctx.config.plesk_maildir_root
    cp = _run(ctx, ctx.old, ["test", "-d", root])
    if cp.returncode != 0:
        return CheckResult("src.maildir", WARN, "Mail storage directory not found",
                           f"{root} does not exist; set plesk_maildir_root if Plesk keeps mail elsewhere.")
    return CheckResult("src.maildir", OK, "Mail storage found", root)


def _local_disk_check(ctx: Context, inv: Inventory) -> CheckResult:
    need_mb = sum(d.size_db_mb or 0 for d in inv.domains) * 1.2 + 200
    probe = ctx.workdir
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    free_mb = shutil.disk_usage(probe).free / 1048576
    if free_mb < need_mb:
        return CheckResult("src.local_disk", FAIL, "Not enough free disk space on this computer",
                           f"Database dumps need about {_fmt_mb(need_mb)} in {ctx.workdir}, "
                           f"only {_fmt_mb(free_mb)} free.")
    return CheckResult("src.local_disk", OK, "Enough free disk space on this computer",
                       f"{_fmt_mb(free_mb)} free for dumps (about {_fmt_mb(need_mb)} needed)")


# ----------------------------------------------------------------------
# Target (Ubuntu) server
# ----------------------------------------------------------------------
def check_target(ctx: Context, domains: Optional[List[DomainInfo]] = None, *,
                 mail_hostname: str = "",
                 ptr_lookup: Optional[Callable[[str], Optional[str]]] = None,
                 ) -> Tuple[List[CheckResult], dict]:
    """Returns (results, info). info["php_version"] is the PHP version that
    fits the target's distribution."""
    new = ctx.new
    results: List[CheckResult] = []
    info: dict = {"php_version": ctx.config.php_version, "os": ""}
    domains = domains or []
    names = [d.name for d in domains]

    def root():
        cp = _run(ctx, new, ["id", "-u"])
        if cp.stdout.strip() == "0":
            return CheckResult("dst.root", OK, "Connected as root")
        return CheckResult("dst.root", FAIL, "root access required",
                           "Installing packages and writing /etc requires root.")

    results.append(_guard("dst.root", "Connected as root", root))
    if results[-1].status == FAIL:
        return results, info

    def os_check():
        rel = _os_release(ctx, new)
        pretty = rel.get("PRETTY_NAME", "unknown")
        info["os"] = pretty
        if rel.get("ID") != "ubuntu":
            return CheckResult("dst.os", FAIL, "Not an Ubuntu server",
                               f"Found: {pretty}. The target stack is built for Ubuntu 22.04/24.04.")
        version = rel.get("VERSION_ID", "")
        if version in UBUNTU_PHP:
            info["php_version"] = UBUNTU_PHP[version]
            return CheckResult("dst.os", OK, "Supported Ubuntu release",
                               f"{pretty} - PHP {UBUNTU_PHP[version]} will be installed")
        return CheckResult("dst.os", WARN, "Untested Ubuntu release",
                           f"{pretty}. Only 22.04 and 24.04 are tested; PHP {ctx.config.php_version} "
                           f"is assumed to exist in its repositories.")

    results.append(_guard("dst.os", "Operating system", os_check))
    if not RE_PHP.match(info["php_version"]):
        info["php_version"] = ctx.config.php_version

    if mail_hostname:
        if RE_FQDN.match(mail_hostname):
            results.append(CheckResult("dst.mailhost", OK, "Mail hostname", mail_hostname))
        else:
            results.append(CheckResult("dst.mailhost", FAIL, "Invalid mail hostname",
                                       f"{mail_hostname!r} is not a fully qualified domain name "
                                       f"(example: mail.example.com)."))

    results.append(_guard("dst.disk", "Free disk space", lambda: _target_disk(ctx, domains)))
    results.append(_guard("dst.internet", "Package repositories reachable",
                          lambda: _probe_check(ctx, new, "dst.internet", "archive.ubuntu.com", 80,
                                               "Package repositories reachable",
                                               "Package repositories NOT reachable",
                                               "Cannot reach archive.ubuntu.com:80 - "
                                               "packages cannot be installed.", FAIL)))
    old_host, old_port = _host_of(ctx.old), ctx.config.old_ssh_port
    results.append(_guard("dst.old_reach", "Target can reach the Plesk server",
                          lambda: _probe_check(ctx, new, "dst.old_reach", old_host, old_port,
                                               "Target can reach the Plesk server (SSH)",
                                               "Target cannot reach the Plesk server",
                                               f"The new server cannot open {old_host}:{old_port}. "
                                               f"Data is copied server-to-server, so this must work "
                                               f"(firewall?).", FAIL)))
    results.append(_guard("dst.smtp_out", "Outbound mail (port 25)",
                          lambda: _probe_check(ctx, new, "dst.smtp_out", "gmail-smtp-in.l.google.com", 25,
                                               "Outbound port 25 open",
                                               "Outbound port 25 is blocked",
                                               "Port 25 is blocked outbound. Many hosters block it by "
                                               "default; ask yours to unblock it, otherwise outgoing "
                                               "mail will not be delivered.", WARN)))
    results.append(_guard("dst.ports", "Required ports free", lambda: _ports_check(ctx)))
    results.append(_guard("dst.apt", "Package manager idle", lambda: _apt_check(ctx)))
    if names:
        results.append(_guard("dst.existing", "Fresh target", lambda: _existing_check(ctx, names)))

    if mail_hostname and ptr_lookup is not None:
        results.append(_ptr_check(ctx, mail_hostname, ptr_lookup))

    results.extend(_php_check(domains, info["php_version"]))
    return results, info


def _target_disk(ctx: Context, domains: List[DomainInfo]) -> CheckResult:
    cp = _run(ctx, ctx.new, ["df", "-Pk", "/var"])
    try:
        free_mb = int(cp.stdout.strip().splitlines()[-1].split()[3]) / 1024
    except (IndexError, ValueError):
        return CheckResult("dst.disk", WARN, "Free disk space unknown", cp.stdout.strip()[:200])
    need_mb = sum(d.size_total_mb for d in domains) * 1.3 + 2048
    if free_mb < need_mb:
        return CheckResult("dst.disk", FAIL, "Not enough free disk space on the target",
                           f"About {_fmt_mb(need_mb)} needed (data + packages), "
                           f"{_fmt_mb(free_mb)} free on /var.")
    return CheckResult("dst.disk", OK, "Enough free disk space on the target",
                       f"{_fmt_mb(free_mb)} free, about {_fmt_mb(need_mb)} needed")


def _probe_check(ctx, host, check_id, dest, port, ok_title, fail_title, fail_detail, fail_status):
    if _tcp_probe(ctx, host, dest, port):
        return CheckResult(check_id, OK, ok_title, f"{dest}:{port}")
    return CheckResult(check_id, fail_status, fail_title, fail_detail)


def _ports_check(ctx: Context) -> CheckResult:
    cp = _run(ctx, ctx.new, ["ss", "-ltnpH"])
    busy = {}
    for line in cp.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        port_text = parts[3].rsplit(":", 1)[-1]
        if port_text.isdigit() and int(port_text) in MAIL_PORTS:
            proc = re.search(r'\(\("([^"]+)"', line)
            busy[int(port_text)] = proc.group(1) if proc else "unknown process"
    if busy:
        listing = ", ".join(f"{p} ({n})" for p, n in sorted(busy.items()))
        return CheckResult("dst.ports", WARN, "Some required ports are already in use",
                           f"{listing}. Provisioning installs nginx, Postfix and Dovecot, which need "
                           f"these ports; existing services may conflict or be reconfigured.")
    return CheckResult("dst.ports", OK, "Required ports are free", "25, 80, 143, 443, 465, 587, 993")


def _apt_check(ctx: Context) -> CheckResult:
    cp = _run(ctx, ctx.new, ["bash", "-c",
                             "pgrep -x 'apt|apt-get|dpkg|unattended-upgr' >/dev/null && echo busy || echo free"])
    if cp.stdout.strip() == "busy":
        return CheckResult("dst.apt", WARN, "Package manager is busy",
                           "apt/dpkg or unattended-upgrades is running (common right after the "
                           "first boot). Wait a few minutes, or the installation step may fail.")
    return CheckResult("dst.apt", OK, "Package manager idle")


def _existing_check(ctx: Context, names: List[str]) -> CheckResult:
    script = ('for d in "$@"; do [ -e "/etc/nginx/sites-available/$d" ] && echo "site:$d"; done; '
              '[ -s /etc/dovecot/users ] && echo "dovecot-users"; true')
    cp = _run(ctx, ctx.new, ["bash", "-c", script, "_", *names])
    found = [line.strip() for line in cp.stdout.splitlines() if line.strip()]
    if found:
        return CheckResult("dst.existing", WARN, "The target is not a fresh system",
                           "Existing configuration found (" + ", ".join(found) + "). It will be "
                           "updated or overwritten. Re-running a migration is safe, but do not "
                           "point this at a server that hosts something else.")
    return CheckResult("dst.existing", OK, "The target looks like a fresh system")


def _ptr_check(ctx: Context, mail_hostname: str, lookup) -> CheckResult:
    host = _host_of(ctx.new)
    try:
        ptr = lookup(host)
    except OSError:
        ptr = None
    if ptr and ptr.rstrip(".").lower() == mail_hostname.lower():
        return CheckResult("dst.ptr", OK, "Reverse DNS (PTR) matches the mail hostname", ptr)
    detail = (f"The PTR record of {host} is {ptr!r}, not {mail_hostname!r}. "
              if ptr else f"No PTR record found for {host}. ")
    return CheckResult("dst.ptr", WARN, "Reverse DNS (PTR) does not match the mail hostname",
                       detail + "Set it at your hosting provider, otherwise large providers "
                       "will reject or spam-filter your outgoing mail.")


def _php_check(domains: List[DomainInfo], target_php: str) -> List[CheckResult]:
    by_version: Dict[str, List[str]] = {}
    for d in domains:
        if d.source_php and d.source_php != target_php:
            by_version.setdefault(d.source_php, []).append(d.name)
    return [
        CheckResult(
            f"dst.php.{src}", WARN, f"PHP version changes from {src} to {target_php}",
            f"{', '.join(names)} {'runs' if len(names) == 1 else 'run'} PHP {src} on Plesk and will "
            f"run PHP {target_php} on the target. Check that the application supports it.")
        for src, names in sorted(by_version.items())
    ]


def default_ptr_lookup(host: str) -> Optional[str]:
    """Reverse DNS of a host name or IP, resolved from this computer."""
    import socket
    ip = socket.gethostbyname(host)
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None
