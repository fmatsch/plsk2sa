"""GUI logic, independent of HTTP: connections, checks, selection, run.

One Backend instance serves one local user session. Passwords are used to
open the SSH connection and are never stored, logged or written to disk.
"""

import logging
import os
import re
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .. import __version__
from ..checks import (RE_FQDN, CheckResult, FAIL, check_inventory, check_source,
                      check_target, default_ptr_lookup, has_failures)
from ..config import Config
from ..context import Context
from ..demo import DEMO_FINGERPRINT, NEW_IP, OLD_IP, demo_ptr_lookup, make_demo_transports
from ..dnsplan import DnsOptions
from ..pipeline import FULL, SYNC, Pipeline
from ..plesk_export import Inventory, PleskExporter
from ..runner import CommandError, Runner
from ..transport import HostKeyUnknown, ParamikoTransport, TransportError

log = logging.getLogger("plsk2sa")

RE_HOST = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")
RE_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


class UserError(Exception):
    """Bad input or wrong order of steps; shown to the user as-is."""


@dataclass
class Endpoint:
    role: str
    host: str
    port: int
    user: str
    transport: object
    fingerprint: str = ""

    @property
    def key(self) -> str:
        return f"{self.user}@{self.host}"

    def to_dict(self) -> dict:
        return {"host": self.host, "port": self.port, "user": self.user,
                "fingerprint": self.fingerprint}


@dataclass
class RunState:
    state: str = "idle"  # idle | running | done | failed | cancelled
    steps: List[dict] = field(default_factory=list)
    log: List[dict] = field(default_factory=list)
    result: Optional[dict] = None
    source_changes: List[dict] = field(default_factory=list)
    cancel: threading.Event = field(default_factory=threading.Event)
    thread: Optional[threading.Thread] = None


class _RunLogHandler(logging.Handler):
    """Collects log records of the run thread for the GUI."""

    def __init__(self, run: RunState, thread_id: int):
        super().__init__(level=logging.INFO)
        self.run, self.thread_id = run, thread_id

    def emit(self, record):
        if record.thread != self.thread_id:
            return
        stamp = time.strftime("%H:%M:%S", time.localtime(record.created))
        is_change = getattr(record, "source_change", False)
        self.run.log.append({
            "n": len(self.run.log),
            "level": "source" if is_change else record.levelname.lower(),
            "time": stamp,
            "message": record.getMessage(),
        })
        if is_change:
            self.run.source_changes.append({
                "time": stamp,
                "text": record.getMessage(),
                "revert": bool(getattr(record, "revert", False)),
                "dry_run": bool(getattr(record, "dry_run", False)),
            })


class Backend:
    def __init__(self, workdir: Path, demo: bool = False, demo_delay: float = 0.25):
        self.workdir = Path(workdir)
        self.demo = demo
        self.runner = Runner()
        self.lock = threading.RLock()
        self.source: Optional[Endpoint] = None
        self.target: Optional[Endpoint] = None
        self.inventory: Optional[Inventory] = None
        self.target_info: Dict[str, str] = {}
        self.source_report: Optional[dict] = None
        self.target_report: Optional[dict] = None
        self.run = RunState()
        self._demo_transports = make_demo_transports(demo_delay) if demo else None

    # ------------------------------------------------------------------
    def state(self) -> dict:
        return {
            "version": __version__,
            "demo": self.demo,
            "workdir": str(self.workdir),
            "source": self.source.to_dict() if self.source else None,
            "target": self.target.to_dict() if self.target else None,
            "source_report": self.source_report,
            "target_report": self.target_report,
            "run": {"state": self.run.state},
        }

    def _require_idle(self):
        if self.run.state == "running":
            raise UserError("A migration is running - wait for it to finish or cancel it first.")

    # ------------------------------------------------------------------
    # Connections
    # ------------------------------------------------------------------
    def connect(self, role: str, p: dict) -> dict:
        with self.lock:
            self._require_idle()
            if role not in ("source", "target"):
                raise UserError("Unknown role")
            host = str(p.get("host", "")).strip()
            user = str(p.get("user", "") or "root").strip()
            try:
                port = int(p.get("port") or 22)
            except (TypeError, ValueError):
                raise UserError("The port must be a number") from None
            if not RE_HOST.match(host):
                raise UserError("Enter a host name or IPv4 address (IPv6 literals are not supported yet).")
            if not 1 <= port <= 65535:
                raise UserError("The port must be between 1 and 65535")
            if not RE_USER.match(user):
                raise UserError("Invalid user name")
            auth = p.get("auth") or "password"
            if auth not in ("password", "key", "agent"):
                raise UserError("Unknown authentication method")
            if role == "target":
                if not self.source:
                    raise UserError("Connect to the Plesk server first.")
                if host.lower() == self.source.host.lower():
                    raise UserError("The target must be a different server than the Plesk server.")

            accept = p.get("accept_fingerprint") or None
            if self.demo:
                if accept != DEMO_FINGERPRINT:
                    return {"ok": False, "host_key": {
                        "host": host, "port": port, "key_type": "ssh-ed25519",
                        "fingerprint": DEMO_FINGERPRINT}}
                transport = self._demo_transports["old" if role == "source" else "new"]
                fingerprint = DEMO_FINGERPRINT
            else:
                try:
                    transport = ParamikoTransport.connect(
                        host=host, port=port, user=user, auth=auth,
                        password=p.get("password") or "",
                        key_path=p.get("key_path") or None,
                        passphrase=p.get("passphrase") or None,
                        known_hosts_file=self.workdir / "known_hosts",
                        accept_fingerprint=accept)
                except HostKeyUnknown as e:
                    return {"ok": False, "host_key": {
                        "host": e.host, "port": e.port, "key_type": e.key_type,
                        "fingerprint": e.fingerprint}}
                except TransportError as e:
                    return {"ok": False, "error": str(e)}
                fingerprint = transport.host_key_fingerprint()

            previous = self.source if role == "source" else self.target
            if previous:
                self.runner.unregister(previous.key)
            endpoint = Endpoint(role, host, port, user, transport, fingerprint)
            self.runner.register(endpoint.key, transport)
            if role == "source":
                self.runner.protect(endpoint.key, "Plesk server")
            if role == "source":
                self.source = endpoint
                self.inventory = None
                self.source_report = None
                self.target_report = None
            else:
                self.target = endpoint
                self.target_info = {}
                self.target_report = None
            log.info("Connected to %s (%s)", endpoint.key, role)
            return {"ok": True, "endpoint": endpoint.to_dict()}

    def _ctx(self, mail_hostname: str = "") -> Context:
        src = self.source
        cfg = Config(
            old_server=src.key if src else "not-connected",
            new_server=self.target.key if self.target else "not-connected",
            mail_hostname=mail_hostname or "mail.invalid",
            workdir=str(self.workdir),
            php_version=self.target_info.get("php_version") or "8.3",
            old_ssh_port=src.port if src else 22,
        )
        return Context(cfg, self.runner)

    # ------------------------------------------------------------------
    # Step 2: checks + inventory of the Plesk server
    # ------------------------------------------------------------------
    def source_checks(self) -> dict:
        with self.lock:
            self._require_idle()
            if not self.source:
                raise UserError("Connect to the Plesk server first.")
            ctx = self._ctx()
            ctx.ensure_workdir()
            results: List[CheckResult] = check_source(ctx)
            inventory = None
            if not has_failures(results):
                try:
                    inventory = PleskExporter(ctx).discover()
                    results.extend(check_inventory(ctx, inventory))
                except (CommandError, TransportError) as e:
                    results.append(CheckResult("src.discover", FAIL,
                                               "Reading the Plesk configuration failed", str(e)))
            self.inventory = inventory if not has_failures(results) else None
            self.target_report = None
            self.source_report = {
                "checks": [r.to_dict() for r in results],
                "can_continue": not has_failures(results),
                "inventory": inventory.to_dict() if inventory else None,
            }
            return self.source_report

    # ------------------------------------------------------------------
    # Step 4: checks on the target server
    # ------------------------------------------------------------------
    def _selection(self, names) -> list:
        if not self.inventory:
            raise UserError("Run the checks on the Plesk server first.")
        if not isinstance(names, list) or not names:
            raise UserError("Select at least one domain.")
        selected = []
        for name in names:
            info = self.inventory.by_name(str(name))
            if info is None:
                raise UserError(f"Unknown domain: {name}")
            selected.append(info)
        return selected

    def target_checks(self, p: dict) -> dict:
        with self.lock:
            self._require_idle()
            if not self.target:
                raise UserError("Connect to the target server first.")
            selected = self._selection(p.get("domains"))
            mail_hostname = str(p.get("mail_hostname", "")).strip()
            ctx = self._ctx(mail_hostname)
            results, info = check_target(
                ctx, selected, mail_hostname=mail_hostname,
                ptr_lookup=demo_ptr_lookup if self.demo else default_ptr_lookup)
            self.target_info = info
            self.target_report = {
                "checks": [r.to_dict() for r in results],
                "can_continue": not has_failures(results),
                "php_version": info.get("php_version"),
                "os": info.get("os"),
                "dns_defaults": self._dns_defaults(ctx),
            }
            return self.target_report

    def _dns_defaults(self, ctx: Context) -> dict:
        """Suggested values for the DNS step; the user can edit all of them."""
        if self.demo:
            return {"old_ips": [OLD_IP], "new_ipv4": NEW_IP, "new_ipv6": ""}

        def resolve(host):
            try:
                return socket.gethostbyname_ex(host)[2]
            except OSError:
                return []

        old_ips = set(resolve(self.source.host))
        try:
            old_ips.update(PleskExporter(ctx).fetch_server_ips())
        except (CommandError, TransportError):
            pass
        new = resolve(self.target.host)
        return {"old_ips": sorted(old_ips), "new_ipv4": new[0] if new else "", "new_ipv6": ""}

    # ------------------------------------------------------------------
    # Step 5: the run
    # ------------------------------------------------------------------
    def start_run(self, p: dict) -> dict:
        with self.lock:
            self._require_idle()
            if not self.source or not self.target:
                raise UserError("Connect to both servers first.")
            selected = self._selection(p.get("domains"))
            mode = p.get("mode") or FULL
            if mode not in (FULL, SYNC):
                raise UserError("Unknown mode")
            dry_run = bool(p.get("dry_run", True))
            mail_hostname = str(p.get("mail_hostname", "")).strip()
            if not RE_FQDN.match(mail_hostname):
                raise UserError("Enter a valid mail hostname (example: mail.example.com).")
            if not dry_run and not p.get("confirmed"):
                raise UserError("Please confirm that you want to change the target server.")
            if not self.target_info:
                raise UserError("Run the checks on the target server first.")

            dns = self._dns_options(p.get("dns"))

            ctx = self._ctx(mail_hostname)
            ctx.ensure_workdir()
            self.runner.dry_run = dry_run
            host_key_line = getattr(self.source.transport, "host_key_line", lambda: "")()
            run = RunState(state="running")
            pipeline = Pipeline(
                ctx, [d.name for d in selected], mode=mode,
                old_host_key_line=host_key_line,
                restrict_ip=bool(p.get("restrict_ip", True)),
                dns=dns,
                progress=lambda steps: self._on_progress(run, steps),
                cancel=run.cancel)
            run.steps = [s.to_dict() for s in pipeline.steps]
            self.run = run
            run.thread = threading.Thread(target=self._worker, args=(pipeline, run),
                                          name="plsk2sa-run", daemon=True)
            run.thread.start()
            return {"ok": True}

    @staticmethod
    def _dns_options(raw) -> DnsOptions:
        if not isinstance(raw, dict):
            raise UserError("Fill in the DNS section first.")
        old_ips = raw.get("old_ips") or []
        if isinstance(old_ips, str):
            old_ips = [x for x in re.split(r"[\s,;]+", old_ips) if x]
        opts = DnsOptions(plesk_dns=raw.get("mode") == "plesk",
                          old_ips=[str(x).strip() for x in old_ips],
                          new_ipv4=str(raw.get("new_ipv4", "")).strip(),
                          new_ipv6=str(raw.get("new_ipv6", "")).strip())
        problems = opts.validate()
        if problems:
            raise UserError(" ".join(problems))
        return opts

    def _on_progress(self, run: RunState, steps):
        run.steps = [s.to_dict() for s in steps]

    def _worker(self, pipeline: Pipeline, run: RunState):
        ui_handler = _RunLogHandler(run, threading.get_ident())
        file_handler = None
        log.setLevel(logging.DEBUG)
        log.addHandler(ui_handler)
        try:
            self.workdir.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(self.workdir / "plsk2sa.log", encoding="utf-8")
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
            file_handler.addFilter(lambda r: r.thread == threading.get_ident())
            log.addHandler(file_handler)

            result = pipeline.run()
            run.result = result.to_dict()
            run.state = "cancelled" if result.cancelled else ("done" if result.ok else "failed")
        except Exception as e:  # noqa: BLE001 - never leave the UI hanging in "running"
            log.error("Unexpected error: %s", e)
            run.result = {"ok": False, "error": str(e), "verify": [], "dkim": [],
                          "dry_run": self.runner.dry_run, "workdir": str(self.workdir),
                          "credentials_file": "", "cancelled": False}
            run.state = "failed"
        finally:
            self.runner.dry_run = False
            log.removeHandler(ui_handler)
            if file_handler:
                log.removeHandler(file_handler)
                file_handler.close()

    def run_status(self, since: int = 0) -> dict:
        run = self.run
        return {
            "state": run.state,
            "steps": run.steps,
            "log": run.log[since:],
            "next": len(run.log),
            "result": run.result,
            "source_changes": run.source_changes,
            "source_state": self._source_state(run),
        }

    @staticmethod
    def _source_state(run: RunState) -> str:
        """unchanged: nothing was altered | modified: altered and not (yet) reverted | restored."""
        real = [c for c in run.source_changes if not c["dry_run"]]
        if not real:
            return "unchanged"
        cleanup = next((s for s in run.steps if s["key"] == "cleanup"), None)
        return "restored" if cleanup and cleanup["state"] == "done" else "modified"

    def cancel_run(self) -> dict:
        if self.run.state == "running":
            self.run.cancel.set()
            log.warning("Cancel requested - finishing the current step, then cleaning up")
        return {"ok": True}

    def reset_run(self) -> dict:
        with self.lock:
            self._require_idle()
            self.run = RunState()
            return {"ok": True}

    # ------------------------------------------------------------------
    def open_workdir(self) -> dict:
        path = str(self.workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        if sys.platform.startswith("win"):
            os.startfile(path)  # noqa: S606 - fixed, app-controlled path
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
        return {"ok": True}

    def close(self):
        self.runner.close()
