"""DNS planning: what must the DNS records of a migrated domain look like?

Pure functions, no I/O. Input are the records Plesk holds for a domain
plus the old/new server addresses; output is a list of changes (keep /
change / add / remove / review) and, if Plesk was the DNS server, a
complete zone file that can be imported at the new DNS provider.

Two situations, chosen by the user:
  * DNS elsewhere (registrar, Cloudflare, ...): the changes tell what to
    edit at that provider.
  * DNS hosted by Plesk: the Plesk server answers queries for the domain,
    so its zone has to move with the domain. The zone file with the new
    addresses is the hand-over.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

KEEP, CHANGE, ADD, REMOVE, REVIEW = "keep", "change", "add", "remove", "review"

PLESK_DKIM_SELECTOR = "default"   # selector Plesk signs with
NEW_DKIM_SELECTOR = "mail"        # selector created by plsk2sa (see modules/dkim.py)
DKIM_PLACEHOLDER = "(created during the migration)"

ZONE_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS")


@dataclass
class DnsRecord:
    name: str
    type: str
    value: str
    opt: str = ""   # MX priority, SRV parameters, ...

    def to_dict(self) -> dict:
        return {"name": self.name, "type": self.type, "value": self.value, "opt": self.opt}

    @classmethod
    def from_dict(cls, d: dict) -> "DnsRecord":
        return cls(d["name"], d["type"], d["value"], d.get("opt", ""))


@dataclass
class DnsOptions:
    plesk_dns: bool
    old_ips: List[str]
    new_ipv4: str
    new_ipv6: str = ""

    def validate(self) -> List[str]:
        problems = []
        try:
            ipaddress.IPv4Address(self.new_ipv4)
        except ValueError:
            problems.append("The new server's IPv4 address is not valid.")
        for ip in self.old_ips:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                problems.append(f"Not an IP address: {ip!r}")
        if self.new_ipv6:
            try:
                ipaddress.IPv6Address(self.new_ipv6)
            except ValueError:
                problems.append("The new server's IPv6 address is not valid.")
        return problems


@dataclass
class DnsChange:
    action: str
    type: str
    name: str
    old: str = ""
    new: str = ""
    note: str = ""

    def to_dict(self) -> dict:
        return {"action": self.action, "type": self.type, "name": self.name,
                "old": self.old, "new": self.new, "note": self.note}


@dataclass
class DomainDns:
    domain: str
    changes: List[DnsChange] = field(default_factory=list)
    zone: Optional[str] = None
    note: str = ""

    def to_dict(self) -> dict:
        return {"domain": self.domain, "changes": [c.to_dict() for c in self.changes],
                "zone": self.zone, "note": self.note}


@dataclass
class DnsReport:
    mode: str   # "plesk" | "external"
    domains: List[DomainDns] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"mode": self.mode, "domains": [d.to_dict() for d in self.domains], "notes": self.notes}


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------
def clean_name(name: str, domain: str) -> str:
    """Absolute lower-case name without trailing dot. A bare label ("www") is
    relative to the zone; anything containing a dot is taken as absolute."""
    n = (name or "").strip().rstrip(".").lower()
    if n in ("", "@"):
        return domain
    return n if "." in n else f"{n}.{domain}"


def parse_records(rows: List[List[str]], domain_filter=None) -> Dict[str, List[DnsRecord]]:
    """rows: [domain, type, host, value, opt] as returned by the psa query."""
    result: Dict[str, List[DnsRecord]] = {}
    for r in rows:
        if len(r) < 4:
            continue
        domain, rtype, host, value = r[0], r[1].upper(), r[2], r[3]
        opt = r[4] if len(r) > 4 and r[4] != "NULL" else ""
        if domain_filter is not None and domain not in domain_filter:
            continue
        if rtype in ("SOA", "PTR"):
            continue
        result.setdefault(domain, []).append(
            DnsRecord(clean_name(host, domain), rtype, value.strip(), opt.strip()))
    return result


def _value_text(rec: DnsRecord) -> str:
    if rec.type == "MX":
        return f"{rec.opt or '10'} {rec.value.rstrip('.')}"
    if rec.type in ("CNAME", "NS"):
        return rec.value.rstrip(".")
    return rec.value


def _rewrite_spf(value: str, old_ips: List[str], new_ip: str) -> str:
    tokens = value.split()
    changed = False
    for i, tok in enumerate(tokens):
        m = re.match(r"^([+?~-]?)ip4:([0-9.]+)(/\d+)?$", tok)
        if m and m.group(2) in old_ips:
            tokens[i] = f"{m.group(1)}ip4:{new_ip}{m.group(3) or ''}"
            changed = True
    return " ".join(tokens) if changed else value


def _is_spf(rec: DnsRecord) -> bool:
    return rec.type == "TXT" and rec.value.lower().startswith("v=spf1")


# ----------------------------------------------------------------------
# planning
# ----------------------------------------------------------------------
def plan_domain(domain: str, records: List[DnsRecord], opts: DnsOptions, *,
                mail_hostname: str = "", dkim_value: Optional[str] = None) -> DomainDns:
    out = DomainDns(domain)
    if not records:
        out.note = ("Plesk holds no DNS records for this domain (its DNS service may be off). "
                    "Compare with the records at your DNS provider.")
    old = set(opts.old_ips)

    for rec in records:
        name, text = rec.name, _value_text(rec)
        if rec.type == "A":
            if rec.value in old:
                out.changes.append(DnsChange(CHANGE, "A", name, rec.value, opts.new_ipv4,
                                             "Points to the old server"))
            else:
                out.changes.append(DnsChange(KEEP, "A", name, rec.value, "",
                                             "Points to another address - left unchanged"))
        elif rec.type == "AAAA":
            out.changes.append(DnsChange(
                REVIEW, "AAAA", name, rec.value, opts.new_ipv6,
                "IPv6 address - replace it with the new server's IPv6 address, or delete the "
                "record if the new server has none (an old address would send visitors to the wrong server)"))
        elif rec.type == "NS":
            if opts.plesk_dns:
                first = not any(c.type == "NS" for c in out.changes)
                out.changes.append(DnsChange(
                    REVIEW, "NS", name, text, "",
                    "Name server of the Plesk zone. Once the Plesk server is gone, set the domain's "
                    "name servers at your registrar to your new DNS provider." if first
                    else "Name server of the Plesk zone (see above)"))
        elif _is_spf(rec):
            new = _rewrite_spf(rec.value, opts.old_ips, opts.new_ipv4)
            if new != rec.value:
                out.changes.append(DnsChange(CHANGE, "TXT", name, rec.value, new,
                                             "SPF: the old server's address is replaced"))
            else:
                out.changes.append(DnsChange(KEEP, "TXT", name, rec.value, "",
                                             "SPF does not name the old server's address"))
        elif rec.type == "TXT" and name == f"{PLESK_DKIM_SELECTOR}._domainkey.{domain}":
            out.changes.append(DnsChange(
                REMOVE, "TXT", name, rec.value, "",
                "Key of Plesk's mail server. Mail is signed by the new key below after the switch; "
                "delete this record once the switch is done."))
        else:
            out.changes.append(DnsChange(KEEP, rec.type, name, text))

    names_in_zone = {r.name for r in records if r.type in ("A", "AAAA", "CNAME")}
    if _within(mail_hostname, domain) and mail_hostname.lower() not in names_in_zone:
        out.changes.append(DnsChange(ADD, "A", mail_hostname.lower(), "", opts.new_ipv4,
                                     "The mail server's host name must resolve to the new server"))

    dkim_name = f"{NEW_DKIM_SELECTOR}._domainkey.{domain}"
    out.changes.append(DnsChange(ADD, "TXT", dkim_name, "", dkim_value or DKIM_PLACEHOLDER,
                                 "DKIM key of the new mail server" if dkim_value
                                 else "Available after the migration has run"))

    if opts.plesk_dns:
        out.zone = render_zone(domain, out.changes)
    return out


def _within(host: str, domain: str) -> bool:
    host = (host or "").lower()
    return bool(host) and (host == domain or host.endswith("." + domain))


def build_report(domains: List[str], records: Dict[str, List[DnsRecord]], opts: DnsOptions, *,
                 mail_hostname: str = "", dkim: Optional[Dict[str, str]] = None) -> DnsReport:
    dkim = dkim or {}
    report = DnsReport("plesk" if opts.plesk_dns else "external")
    for d in domains:
        report.domains.append(plan_domain(d, records.get(d, []), opts,
                                          mail_hostname=mail_hostname, dkim_value=dkim.get(d)))

    if not opts.old_ips:
        report.notes.append("No old server address was given, so A records and SPF could not be "
                            "matched - compare them by hand.")
    if opts.plesk_dns:
        report.notes.append(
            "Plesk answers DNS queries for these domains. Import the zone files at your new DNS "
            "provider (or serve them yourself), then change the name servers at the registrar. "
            "Keep the Plesk server running until the new name servers answer.")
    else:
        report.notes.append(
            "These records are read from Plesk's copy of the zone. If your DNS provider's records "
            "differ, apply the same changes there.")
    report.notes.append("Lower the TTL of the records you change to 300 seconds a day before the switch.")
    return report


# ----------------------------------------------------------------------
# zone file
# ----------------------------------------------------------------------
def _rel(name: str, domain: str) -> str:
    return "@" if name == domain else (name[:-len(domain) - 1] if name.endswith("." + domain) else name + ".")


def _txt_literal(value: str) -> str:
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] == '"':
        v = v[1:-1]
    chunks = [v[i:i + 255] for i in range(0, len(v), 255)] or [""]
    return " ".join('"' + c.replace("\\", "\\\\").replace('"', '\\"') + '"' for c in chunks)


def render_zone(domain: str, changes: List[DnsChange], ttl: int = 3600) -> str:
    lines = [
        f"; Zone for {domain} - generated by plsk2sa. Review before importing.",
        "; SOA and NS records are supplied by your DNS provider.",
        f"$ORIGIN {domain}.",
        f"$TTL {ttl}",
    ]
    for c in changes:
        value = c.new if c.action in (CHANGE, ADD) else c.old
        if c.action in (REMOVE, REVIEW) and c.type != "AAAA":
            continue
        if c.type == "AAAA":
            if not c.new:
                lines.append(f"; REVIEW: AAAA {_rel(c.name, domain)} {c.old} - points to the old server, not exported")
                continue
            value = c.new
        if c.action == ADD and value == DKIM_PLACEHOLDER:
            lines.append(f"; {_rel(c.name, domain)} TXT - the new DKIM key is created during the migration")
            continue
        rel = _rel(c.name, domain)
        if c.type in ("A", "AAAA"):
            lines.append(f"{rel}\tIN\t{c.type}\t{value}")
        elif c.type == "CNAME":
            lines.append(f"{rel}\tIN\tCNAME\t{_abs(value)}")
        elif c.type == "MX":
            prio, _, target = value.partition(" ")
            lines.append(f"{rel}\tIN\tMX\t{prio} {_abs(target)}")
        elif c.type == "TXT":
            lines.append(f"{rel}\tIN\tTXT\t{_txt_literal(value)}")
        else:
            lines.append(f"; REVIEW: {c.type} {rel} {value} - record type not converted automatically")
    return "\n".join(lines) + "\n"


def _abs(host: str) -> str:
    host = host.strip()
    return host if host.endswith(".") or host == "@" else host + "."


def report_text(report: DnsReport) -> str:
    """Human-readable version of a report (written to the workdir, printed by the CLI)."""
    lines = []
    for dom in report.domains:
        lines.append(f"== {dom.domain} ==")
        if dom.note:
            lines.append(f"   {dom.note}")
        shown = [c for c in dom.changes if c.action != KEEP]
        for c in shown:
            lines.append(f"  [{c.action.upper():6}] {c.type:5} {c.name}")
            if c.old:
                lines.append(f"           now: {c.old}")
            if c.new:
                lines.append(f"           new: {c.new}")
            if c.note:
                lines.append(f"           ({c.note})")
        unchanged = len(dom.changes) - len(shown)
        if unchanged:
            lines.append(f"  {unchanged} record(s) stay as they are.")
        lines.append("")
    lines.extend(f"* {n}" for n in report.notes)
    return "\n".join(lines) + "\n"
