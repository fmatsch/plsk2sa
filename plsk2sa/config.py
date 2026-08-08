"""Konfiguration (plsk2sa.yaml) laden und validieren."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List


class ConfigError(RuntimeError):
    pass


@dataclass
class Config:
    old_server: str
    mail_hostname: str
    new_server: str = "local"
    workdir: str = "~/plsk2sa-work"
    php_version: str = "8.3"
    domains: List[str] = field(default_factory=list)
    plesk_maildir_root: str = "/var/qmail/mailnames"
    ssh_options: List[str] = field(default_factory=lambda: ["-o", "BatchMode=yes"])

    KNOWN_KEYS = {
        "old_server", "new_server", "mail_hostname", "workdir",
        "php_version", "domains", "plesk_maildir_root", "ssh_options",
    }

    @classmethod
    def load(cls, path) -> "Config":
        p = Path(path)
        if not p.is_file():
            raise ConfigError(
                f"Konfigurationsdatei fehlt: {p} "
                f"(Vorlage: plsk2sa.example.yaml)"
            )
        try:
            import yaml  # bewusst hier: Tests ohne PyYAML bleiben lauffähig
        except ImportError:
            raise ConfigError(
                "PyYAML fehlt — installieren mit: pip install -e . "
                "(oder pip install pyyaml)"
            ) from None
        data = yaml.safe_load(p.read_text()) or {}
        if not isinstance(data, dict):
            raise ConfigError(f"{p}: erwartet ein YAML-Mapping")

        unknown = set(data) - cls.KNOWN_KEYS
        if unknown:
            raise ConfigError(f"{p}: unbekannte Schlüssel: {', '.join(sorted(unknown))}")
        for key in ("old_server", "mail_hostname"):
            if not data.get(key):
                raise ConfigError(f"{p}: Pflichtfeld fehlt: {key}")

        cfg = cls(**data)
        cfg.workdir = str(Path(cfg.workdir).expanduser())
        return cfg

    @property
    def workdir_path(self) -> Path:
        return Path(self.workdir)
