"""End-to-end run used by the GUI: export -> provision -> temporary trust ->
per-domain migration -> verify -> cleanup, with step progress and
cancellation between steps.

Cleanup of the temporary server-to-server key happens in a finally
block, so it also runs after errors and after cancellation.
"""

import json
import logging
import threading
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from . import trust
from .context import Context
from .dnsplan import DnsOptions, DnsRecord, build_report, report_text
from .fsutil import read_text, write_text
from .modules import build_modules
from .modules.dkim import dkim_dns_value
from .plesk_export import PleskExporter
from .prepare import PreparePlan, apply_plan, verify_plan

log = logging.getLogger("plsk2sa")

FULL, SYNC, PREPARE = "full", "sync", "prepare"


@dataclass
class Step:
    key: str
    label: str
    state: str = "pending"  # pending | running | done | failed | skipped

    def to_dict(self) -> dict:
        return {"key": self.key, "label": self.label, "state": self.state}


@dataclass
class PipelineResult:
    ok: bool = True
    cancelled: bool = False
    error: str = ""
    dry_run: bool = False
    verify: List[dict] = field(default_factory=list)
    dkim: List[dict] = field(default_factory=list)
    credentials_file: str = ""
    workdir: str = ""
    dns: Optional[dict] = None
    prepare: List[dict] = field(default_factory=list)
    mode: str = ""

    def to_dict(self) -> dict:
        return {
            "ok": self.ok, "cancelled": self.cancelled, "error": self.error,
            "dry_run": self.dry_run, "verify": self.verify, "dkim": self.dkim,
            "credentials_file": self.credentials_file, "workdir": self.workdir,
            "dns": self.dns, "prepare": self.prepare, "mode": self.mode,
        }


class Pipeline:
    def __init__(self, ctx: Context, domain_names: List[str], *, mode: str = FULL,
                 old_host_key_line: str = "", restrict_ip: bool = True,
                 dns: Optional[DnsOptions] = None,
                 prepare_plan: Optional[PreparePlan] = None,
                 prepare_selected: Optional[List[str]] = None,
                 php_by_domain: Optional[dict] = None,
                 progress: Optional[Callable[[List[Step]], None]] = None,
                 cancel: Optional[threading.Event] = None):
        if mode not in (FULL, SYNC, PREPARE):
            raise ValueError(f"Unknown mode: {mode}")
        self.ctx = ctx
        self.domain_names = list(domain_names)
        self.mode = mode
        self.old_host_key_line = old_host_key_line
        self.restrict_ip = restrict_ip
        self.dns = dns
        self.prepare_plan = prepare_plan
        self.prepare_selected = list(prepare_selected or [])
        self.php_by_domain = php_by_domain or {}
        self._progress = progress or (lambda steps: None)
        self._cancel = cancel or threading.Event()
        self.steps = self.plan()

    def plan(self) -> List[Step]:
        dry = self.ctx.runner.dry_run
        extras = bool(self.prepare_plan and self.prepare_selected)
        if self.mode == PREPARE:
            steps = [Step("provision", "Install and configure the base stack")]
            if extras:
                steps.append(Step("prepare", "Install the software the Plesk sites use"))
            if not dry:
                steps.append(Step("verify", "Verify the target server"))
            return steps

        steps = [Step("export", "Read data from the Plesk server")]
        if self.mode == FULL:
            steps.append(Step("provision", "Install and configure the target stack"))
            if extras:
                steps.append(Step("prepare", "Install the software the Plesk sites use"))
        steps.append(Step("trust", "Set up temporary server-to-server access"))
        verb = "Migrate" if self.mode == FULL else "Sync"
        for name in self.domain_names:
            steps.append(Step(f"domain:{name}", f"{verb} {name}"))
        if self.mode == FULL and not dry:
            steps.append(Step("verify", "Verify the target server"))
        steps.append(Step("cleanup", "Remove temporary access"))
        return steps

    # ------------------------------------------------------------------
    def run(self) -> PipelineResult:
        ctx = self.ctx
        result = PipelineResult(dry_run=ctx.runner.dry_run, workdir=str(ctx.workdir), mode=self.mode)
        self._progress(self.steps)
        if not result.dry_run:
            # A real run regenerates these; never show a record left over from an earlier run.
            for name in self.domain_names:
                (ctx.dns_dir / f"{name}.dkim.txt").unlink(missing_ok=True)
        trust_touched = False
        try:
            for step in self.steps:
                if step.key == "cleanup":
                    continue  # handled in finally
                if self._cancel.is_set():
                    result.cancelled = True
                    log.warning("Cancelled by the user - stopping before '%s'", step.label)
                    break
                self._set(step, "running")
                try:
                    if step.key == "trust":
                        trust_touched = True
                    self._execute(step, result)
                except Exception as e:  # noqa: BLE001 - report any failure to the UI
                    log.error("%s failed: %s", step.label, e)
                    log.debug("traceback", exc_info=True)
                    self._set(step, "failed")
                    result.ok = False
                    result.error = f"{step.label}: {e}"
                    break
                self._set(step, "done")
        finally:
            cleanup = next((s for s in self.steps if s.key == "cleanup"), None)
            if cleanup is None:
                pass  # modes without a connection to the Plesk server have nothing to clean up
            elif trust_touched:
                self._set(cleanup, "running")
                removed = trust.teardown(ctx)
                self._set(cleanup, "done" if removed else "failed")
                if not removed:
                    result.error = (result.error + " | " if result.error else "") + \
                        "Temporary SSH access could not be removed completely - see the log."
            else:
                self._set(cleanup, "skipped")
            for step in self.steps:
                if step.state == "pending":
                    self._set(step, "skipped")

        self._collect_outputs(result)
        return result

    def _set(self, step: Step, state: str):
        step.state = state
        self._progress(self.steps)

    # ------------------------------------------------------------------
    def _execute(self, step: Step, result: PipelineResult):
        ctx = self.ctx
        if step.key == "export":
            PleskExporter(ctx).export(only=self.domain_names, php_by_domain=self.php_by_domain)
        elif step.key == "provision":
            for module in build_modules(ctx):
                module.provision()
        elif step.key == "prepare":
            result.prepare = [r.to_dict() for r in apply_plan(ctx, self.prepare_plan, self.prepare_selected)]
        elif step.key == "trust":
            trust.setup(ctx, old_host_key_line=self.old_host_key_line,
                        restrict_ip=self.restrict_ip)
        elif step.key.startswith("domain:"):
            domain = ctx.domains(only=step.key.split(":", 1)[1])[0]
            for module in build_modules(ctx):
                if self.mode == FULL:
                    module.migrate_domain(domain)
                else:
                    module.sync_domain(domain)
        elif step.key == "verify":
            modules = build_modules(ctx)
            if self.mode == PREPARE:  # no domains were migrated, so only the stack itself can be checked
                modules = [m for m in modules if m.name == "system"]
            for module in modules:
                for ok, message in module.verify():
                    log.info("%s [%s] %s", "OK  " if ok else "FAIL", module.name, message)
                    result.verify.append({"ok": ok, "module": module.name, "message": message})
            if self.prepare_plan and self.prepare_selected:
                for ok, message in verify_plan(ctx, self.prepare_plan, self.prepare_selected):
                    log.info("%s [prepare] %s", "OK  " if ok else "FAIL", message)
                    result.verify.append({"ok": ok, "module": "prepare", "message": message})

    def _collect_outputs(self, result: PipelineResult):
        ctx = self.ctx
        if not result.dry_run and self.mode != PREPARE:  # a preview or a prepare-only run creates no keys or credentials
            for name in self.domain_names:
                path = ctx.dns_dir / f"{name}.dkim.txt"
                if path.is_file():
                    value = dkim_dns_value(read_text(path))
                    if value:
                        result.dkim.append({"domain": name, "name": f"mail._domainkey.{name}",
                                            "value": value})
            creds = ctx.secrets_dir / "db-credentials.tsv"
            if creds.is_file():
                result.credentials_file = str(creds)
        if self.dns:
            self._plan_dns(result)

    def _plan_dns(self, result: PipelineResult):
        ctx = self.ctx
        records = {}
        for name in self.domain_names:
            path = ctx.dns_dir / f"{name}.records.json"
            if not path.is_file():
                return  # the export did not get that far
            records[name] = [DnsRecord.from_dict(d) for d in json.loads(read_text(path))]
        report = build_report(self.domain_names, records, self.dns,
                              mail_hostname=ctx.config.mail_hostname,
                              dkim={d["domain"]: d["value"] for d in result.dkim})
        for dom in report.domains:
            if dom.zone:
                write_text(ctx.dns_dir / f"{dom.domain}.zone", dom.zone)
        write_text(ctx.dns_dir / "dns-plan.txt", report_text(report))
        result.dns = report.to_dict()
