"""Gemeinsamer Zustand für alle Kommandos und Module."""

from pathlib import Path
from typing import List, Optional

from .config import Config
from .manifest import Domain, Manifest
from .runner import Runner


class Context:
    def __init__(self, config: Config, runner: Runner):
        self.config = config
        self.runner = runner
        self._manifest: Optional[Manifest] = None

    # --- Pfade im Workdir -------------------------------------------------
    @property
    def workdir(self) -> Path:
        return self.config.workdir_path

    @property
    def manifest_path(self) -> Path:
        return self.workdir / "manifest.json"

    @property
    def db_dir(self) -> Path:
        return self.workdir / "db"

    @property
    def secrets_dir(self) -> Path:
        return self.workdir / "secrets"

    @property
    def raw_dir(self) -> Path:
        return self.workdir / "raw"

    @property
    def dns_dir(self) -> Path:
        return self.workdir / "dns"

    def ensure_workdir(self):
        for d in (self.workdir, self.db_dir, self.secrets_dir,
                  self.raw_dir, self.dns_dir):
            d.mkdir(parents=True, exist_ok=True)
        self.workdir.chmod(0o700)

    # --- Manifest ---------------------------------------------------------
    @property
    def manifest(self) -> Manifest:
        if self._manifest is None:
            self._manifest = Manifest.load(self.manifest_path)
        return self._manifest

    def domains(self, only: Optional[str] = None) -> List[Domain]:
        """Zu bearbeitende Domains: --domain-Filter > Config-Liste > alle."""
        result = self.manifest.domains
        if self.config.domains:
            result = [d for d in result if d.name in self.config.domains]
        if only:
            result = [d for d in result if d.name == only]
            if not result:
                raise SystemExit(f"Domain nicht im Manifest: {only}")
        return result

    # --- Kurzformen -------------------------------------------------------
    @property
    def old(self) -> str:
        return self.config.old_server

    @property
    def new(self) -> str:
        return self.config.new_server
