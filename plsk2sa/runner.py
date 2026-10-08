"""Command execution on the old/new server, with dry-run and logging.

A host is an opaque string. "local" runs on this machine; any other
string is looked up in the registered transports (the GUI registers
Paramiko connections under "user@host") and otherwise falls back to the
system `ssh` binary.

Dry-run skips only *mutating* commands; read-only calls (export, status
queries) still run so the previewed plan is realistic.
"""

import logging
import posixpath
import shlex
import subprocess
from pathlib import Path

from .transport import LocalTransport, OpenSSHTransport, Transport

log = logging.getLogger("plsk2sa")


class CommandError(RuntimeError):
    pass


class Runner:
    def __init__(self, dry_run: bool = False, ssh_options=None):
        self.dry_run = dry_run
        self.ssh_options = list(ssh_options or [])
        self._transports = {}
        self._protected = {}  # host -> label; mutating commands there are always announced

    def protect(self, host: str, label: str = "Plesk server"):
        """Mark a host as one that must stay untouched unless announced: every mutating
        command sent to it is logged (and flagged for the GUI) before it runs."""
        self._protected[host] = label

    def _announce(self, host: str, argv, purpose, revert: bool):
        label = self._protected[host]
        what = purpose or ("Run a command that may change data: " + " ".join(argv)[:120])
        if self.dry_run:
            log.warning("WOULD CHANGE the %s: %s", label, what,
                        extra={"source_change": True, "revert": revert, "dry_run": True})
        else:
            log.warning("CHANGING the %s: %s", label, what,
                        extra={"source_change": True, "revert": revert, "dry_run": False})

    def register(self, host: str, transport: Transport):
        self._transports[host] = transport

    def unregister(self, host: str):
        self._protected.pop(host, None)
        t = self._transports.pop(host, None)
        if t is not None:
            t.close()

    def transport(self, host: str) -> Transport:
        t = self._transports.get(host)
        if t is None:
            t = LocalTransport() if host == "local" else OpenSSHTransport(host, self.ssh_options)
            self._transports[host] = t
        return t

    def run(self, host, argv, *, input_text=None, input_path=None,
            mutating=True, check=True, purpose=None, revert=False) -> subprocess.CompletedProcess:
        desc = f"[{host}] {' '.join(argv)}"
        if mutating and host in self._protected:
            self._announce(host, argv, purpose, revert)
        if self.dry_run and mutating:
            log.info("dry-run: %s", desc)
            return subprocess.CompletedProcess(argv, 0, "", "")
        log.debug("run: %s", desc)

        cp = self.transport(host).exec(argv, stdin_text=input_text, stdin_path=input_path)
        if check and cp.returncode != 0:
            stderr = (cp.stderr or "").strip()
            raise CommandError(f"Command failed (exit {cp.returncode}): {desc}\n{stderr}")
        return cp

    def script(self, host, script_text, *, mutating=True, check=True, purpose=None, revert=False):
        """Run a bash script via stdin (avoids all quoting problems)."""
        return self.run(host, ["bash", "-s"], input_text=script_text,
                        mutating=mutating, check=check, purpose=purpose, revert=revert)

    def put(self, host, path, content, mode="0644", purpose=None):
        """Write file content on the target host (heredoc)."""
        token = "PLSK2SA_EOF"
        if token in content:
            raise ValueError(f"File content contains the heredoc token {token}")
        if not content.endswith("\n"):
            content += "\n"
        qpath = shlex.quote(str(path))
        qparent = shlex.quote(posixpath.dirname(str(path)) or "/")
        script = (
            f"set -e\nmkdir -p {qparent}\n"
            f"cat > {qpath} <<'{token}'\n{content}{token}\n"
            f"chmod {mode} {qpath}\n"
        )
        log.debug("put: [%s] %s (%s)", host, path, mode)
        return self.script(host, script, purpose=purpose or f"Write the file {path}")

    def download(self, host, argv, dest, *, check=True):
        """Run a command and stream its stdout (binary) into a local file."""
        desc = f"[{host}] {' '.join(argv)} > {dest}"
        log.debug("download: %s", desc)
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        cp = self.transport(host).exec(argv, stdout_path=dest)
        if check and cp.returncode != 0:
            raise CommandError(
                f"Download failed (exit {cp.returncode}): {desc}\n{(cp.stderr or '').strip()}")
        return cp

    def close(self):
        for t in self._transports.values():
            t.close()
        self._transports.clear()
