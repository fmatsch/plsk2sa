"""Load and validate the configuration (plsk2sa.yaml)."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from .fsutil import read_text


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
    # SSH port of the old server as seen from the new server (for rsync)
    old_ssh_port: int = 22
    # Optional: key and known_hosts file ON THE NEW SERVER used to pull from
    # the old one. The GUI sets these for its temporary server-to-server key.
    transfer_key: str = ""
    transfer_known_hosts: str = ""

    KNOWN_KEYS = {
        "old_server", "new_server", "mail_hostname", "workdir",
        "php_version", "domains", "plesk_maildir_root", "ssh_options",
        "old_ssh_port", "transfer_key", "transfer_known_hosts",
    }

    @classmethod
    def load(cls, path) -> "Config":
        p = Path(path)
        if not p.is_file():
            raise ConfigError(
                f"Configuration file missing: {p} "
                f"(template: plsk2sa.example.yaml)"
            )
        try:
            import yaml  # deliberately here: the GUI does not need PyYAML
        except ImportError:
            raise ConfigError(
                "PyYAML is missing - install it with: pip install -e . "
                "(or pip install pyyaml)"
            ) from None
        data = yaml.safe_load(read_text(p)) or {}
        if not isinstance(data, dict):
            raise ConfigError(f"{p}: expected a YAML mapping")

        unknown = set(data) - cls.KNOWN_KEYS
        if unknown:
            raise ConfigError(f"{p}: unknown keys: {', '.join(sorted(unknown))}")
        for key in ("old_server", "mail_hostname"):
            if not data.get(key):
                raise ConfigError(f"{p}: required field missing: {key}")

        cfg = cls(**data)
        cfg.workdir = str(Path(cfg.workdir).expanduser())
        return cfg

    @property
    def workdir_path(self) -> Path:
        return Path(self.workdir)
