"""Shared state for all commands and modules."""

import shlex
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

    # --- paths inside the workdir -----------------------------------------
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
        try:
            self.workdir.chmod(0o700)
        except OSError:
            pass

    # --- manifest ---------------------------------------------------------
    @property
    def manifest(self) -> Manifest:
        if self._manifest is None:
            self._manifest = Manifest.load(self.manifest_path)
        return self._manifest

    def set_manifest(self, manifest: Manifest):
        self._manifest = manifest

    def domains(self, only: Optional[str] = None) -> List[Domain]:
        """Domains to process: --domain filter > config list > all."""
        result = self.manifest.domains
        if self.config.domains:
            result = [d for d in result if d.name in self.config.domains]
        if only:
            result = [d for d in result if d.name == only]
            if not result:
                raise SystemExit(f"Domain not in manifest: {only}")
        return result

    # --- shorthands -------------------------------------------------------
    @property
    def old(self) -> str:
        return self.config.old_server

    @property
    def new(self) -> str:
        return self.config.new_server

    # --- data transfer ----------------------------------------------------
    def rsync_pull(self, remote_path: str, local_path: str, *,
                   delete: bool = False, check: bool = True):
        """Run rsync on the NEW server, pulling from the OLD server."""
        cfg = self.config
        ssh = ["ssh", "-p", str(cfg.old_ssh_port)]
        custom = cfg.old_ssh_port != 22
        if cfg.transfer_key:
            ssh += ["-i", cfg.transfer_key, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes"]
            custom = True
        if cfg.transfer_known_hosts:
            ssh += ["-o", f"UserKnownHostsFile={cfg.transfer_known_hosts}",
                    "-o", "StrictHostKeyChecking=yes"]
            custom = True

        argv = ["rsync", "-a"]
        if delete:
            argv.append("--delete")
        if custom:
            argv += ["-e", " ".join(shlex.quote(a) for a in ssh)]
        argv += [f"{self.old}:{remote_path}", local_path]
        return self.runner.run(self.new, argv, check=check)
