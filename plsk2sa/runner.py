"""Befehlsausführung — lokal oder per SSH, mit Dry-Run und Logging.

host == "local"  -> Befehl läuft direkt auf dieser Maschine.
host == SSH-Ziel -> Befehl läuft remote; Argumente werden shell-sicher
                    gequotet, Skripte gehen über stdin (kein Quoting-Risiko).

Dry-Run überspringt nur *mutierende* Befehle; Lesezugriffe (Export,
Statusabfragen) laufen auch im Dry-Run, damit der Plan realistisch ist.
"""

import logging
import shlex
import subprocess
from pathlib import Path

log = logging.getLogger("plsk2sa")


class CommandError(RuntimeError):
    pass


class Runner:
    def __init__(self, dry_run: bool = False, ssh_options=None):
        self.dry_run = dry_run
        self.ssh_options = list(ssh_options or [])

    def _argv(self, host: str, argv):
        if host == "local":
            return list(argv)
        remote = " ".join(shlex.quote(a) for a in argv)
        return ["ssh", *self.ssh_options, host, remote]

    def run(self, host, argv, *, input_text=None, input_path=None,
            mutating=True, check=True) -> subprocess.CompletedProcess:
        desc = f"[{host}] {' '.join(argv)}"
        if self.dry_run and mutating:
            log.info("dry-run: %s", desc)
            return subprocess.CompletedProcess(argv, 0, "", "")
        log.debug("run: %s", desc)

        stdin = open(input_path, "rb") if input_path else None
        try:
            cp = subprocess.run(
                self._argv(host, argv),
                input=input_text if stdin is None else None,
                stdin=stdin,
                text=True,
                capture_output=True,
            )
        finally:
            if stdin:
                stdin.close()

        if check and cp.returncode != 0:
            stderr = (cp.stderr or "").strip()
            raise CommandError(f"Befehl fehlgeschlagen (exit {cp.returncode}): {desc}\n{stderr}")
        return cp

    def script(self, host, script_text, *, mutating=True, check=True):
        """Bash-Skript über stdin ausführen (umgeht SSH-Quoting komplett)."""
        return self.run(host, ["bash", "-s"], input_text=script_text,
                        mutating=mutating, check=check)

    def put(self, host, path, content, mode="0644"):
        """Dateiinhalt auf dem Zielhost ablegen (Heredoc, atomar genug)."""
        token = "PLSK2SA_EOF"
        if token in content:
            raise ValueError(f"Dateiinhalt enthält das Heredoc-Token {token}")
        if not content.endswith("\n"):
            content += "\n"
        qpath = shlex.quote(str(path))
        qparent = shlex.quote(str(Path(path).parent))
        script = (
            f"set -e\nmkdir -p {qparent}\n"
            f"cat > {qpath} <<'{token}'\n{content}{token}\n"
            f"chmod {mode} {qpath}\n"
        )
        log.debug("put: [%s] %s (%s)", host, path, mode)
        return self.script(host, script)

    def download(self, host, argv, dest, *, check=True):
        """Befehl ausführen und stdout binär in eine lokale Datei streamen."""
        desc = f"[{host}] {' '.join(argv)} > {dest}"
        log.debug("download: %s", desc)
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "wb") as f:
            cp = subprocess.run(self._argv(host, argv), stdout=f,
                                stderr=subprocess.PIPE)
        if check and cp.returncode != 0:
            stderr = cp.stderr.decode(errors="replace").strip()
            raise CommandError(f"Download fehlgeschlagen (exit {cp.returncode}): {desc}\n{stderr}")
        return cp
