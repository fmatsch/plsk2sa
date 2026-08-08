"""Das Manifest ist die zentrale Wahrheit der Migration: welche Domains
mit welchen Docroots, Datenbanken, Mailkonten und Aliassen umziehen.
Es wird vom Export erzeugt (JSON im Workdir), kann von Hand korrigiert
werden und wird vor jeder Verwendung validiert.

Klartext-Passwörter gehören NICHT ins Manifest — die liegen separat
unter secrets/ im Workdir.
"""

import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List

RE_DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$")
RE_PHP = re.compile(r"^\d+\.\d+$")
RE_MAILBOX = re.compile(r"^[A-Za-z0-9._+-]+$")
RE_DBNAME = re.compile(r"^[A-Za-z0-9_-]+$")


class ManifestError(RuntimeError):
    pass


@dataclass
class Domain:
    name: str
    docroot_src: str
    php: str
    databases: List[str] = field(default_factory=list)
    mailboxes: List[str] = field(default_factory=list)
    # [alias, ziel@domain] — Ziel kann auch extern sein
    aliases: List[List[str]] = field(default_factory=list)

    @property
    def site_user(self) -> str:
        return "w_" + self.name.replace(".", "_").replace("-", "_")[:28]

    @property
    def docroot(self) -> str:
        return f"/var/www/{self.name}"

    def validate(self) -> List[str]:
        problems = []
        if not RE_DOMAIN.match(self.name):
            problems.append(f"{self.name}: kein gültiger Domainname")
        if not self.docroot_src.startswith("/"):
            problems.append(f"{self.name}: docroot_src muss absoluter Pfad sein: {self.docroot_src!r}")
        if not RE_PHP.match(self.php):
            problems.append(f"{self.name}: ungültige PHP-Version: {self.php!r}")
        for db in self.databases:
            if not RE_DBNAME.match(db):
                problems.append(f"{self.name}: ungültiger DB-Name: {db!r}")
        for mb in self.mailboxes:
            if not RE_MAILBOX.match(mb):
                problems.append(f"{self.name}: ungültiger Mailbox-Name: {mb!r}")
        for entry in self.aliases:
            if len(entry) != 2 or not RE_MAILBOX.match(entry[0]) or "@" not in entry[1]:
                problems.append(f"{self.name}: ungültiger Alias-Eintrag: {entry!r}")
        return problems


@dataclass
class Manifest:
    source: str
    created: str = ""
    domains: List[Domain] = field(default_factory=list)

    def __post_init__(self):
        if not self.created:
            self.created = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def validate(self) -> List[str]:
        problems = []
        seen = set()
        for d in self.domains:
            if d.name in seen:
                problems.append(f"{d.name}: doppelt im Manifest")
            seen.add(d.name)
            problems.extend(d.validate())
        return problems

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Manifest":
        try:
            domains = [Domain(**d) for d in data.get("domains", [])]
            return cls(source=data["source"], created=data.get("created", ""),
                       domains=domains)
        except (KeyError, TypeError) as e:
            raise ManifestError(f"Manifest hat unerwartete Struktur: {e}") from e

    def save(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n")

    @classmethod
    def load(cls, path) -> "Manifest":
        path = Path(path)
        if not path.is_file():
            raise ManifestError(f"Manifest fehlt: {path} — zuerst 'plsk2sa export' ausführen")
        m = cls.from_dict(json.loads(path.read_text()))
        problems = m.validate()
        if problems:
            raise ManifestError("Manifest ungültig:\n  " + "\n  ".join(problems))
        return m
