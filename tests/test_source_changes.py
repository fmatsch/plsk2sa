import logging
import unittest
from pathlib import Path

from plsk2sa.demo import DEMO_FINGERPRINT
from plsk2sa.dnsplan import DnsOptions
from plsk2sa.pipeline import FULL, SYNC, Pipeline
from plsk2sa.runner import Runner
from plsk2sa.ui.backend import Backend
from support import demo_context, temp_workdir

SELECTION = ["acme-shop.com", "mueller-architekten.de"]
DNS = DnsOptions(plesk_dns=False, old_ips=["203.0.113.10"], new_ipv4="203.0.113.20")


class Capture(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.changes = []

    def emit(self, record):
        if getattr(record, "source_change", False):
            self.changes.append({"text": record.getMessage(), "revert": record.revert,
                                 "dry_run": record.dry_run, "level": record.levelname})


class capture_changes:
    def __enter__(self):
        self.handler = Capture()
        self.logger = logging.getLogger("plsk2sa")
        self.old_level = self.logger.level
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(self.handler)
        return self.handler

    def __exit__(self, *exc):
        self.logger.removeHandler(self.handler)
        self.logger.setLevel(self.old_level)


class TestRunnerAnnouncements(unittest.TestCase):
    def runner(self, dry_run=False):
        from plsk2sa.demo import make_demo_transports
        t = make_demo_transports(delay=0)
        r = Runner(dry_run=dry_run)
        r.register("root@old", t["old"])
        r.register("root@new", t["new"])
        r.protect("root@old", "Plesk server")
        return r

    def test_mutating_command_on_protected_host_is_announced_before_it_runs(self):
        r = self.runner()
        with capture_changes() as seen:
            r.script("root@old", "echo hi", purpose="Write something")
        self.assertEqual([c["text"] for c in seen.changes], ["CHANGING the Plesk server: Write something"])
        self.assertFalse(seen.changes[0]["dry_run"])
        self.assertEqual(seen.changes[0]["level"], "WARNING")

    def test_command_without_purpose_still_gets_a_generic_announcement(self):
        r = self.runner()
        with capture_changes() as seen:
            r.run("root@old", ["rm", "-rf", "/tmp/x"])
        self.assertIn("rm -rf /tmp/x", seen.changes[0]["text"])

    def test_read_only_commands_are_never_announced(self):
        r = self.runner()
        with capture_changes() as seen:
            r.run("root@old", ["plesk", "version"], mutating=False)
            r.run("root@old", ["cat", "/etc/os-release"], mutating=False)
        self.assertEqual(seen.changes, [])

    def test_other_hosts_are_not_announced(self):
        r = self.runner()
        with capture_changes() as seen:
            r.script("root@new", "echo hi")
        self.assertEqual(seen.changes, [])

    def test_dry_run_says_would_change(self):
        r = self.runner(dry_run=True)
        with capture_changes() as seen:
            r.script("root@old", "echo hi", purpose="Write something")
        self.assertEqual(seen.changes[0]["text"], "WOULD CHANGE the Plesk server: Write something")
        self.assertTrue(seen.changes[0]["dry_run"])

    def test_unprotect_on_unregister(self):
        r = self.runner()
        r.unregister("root@old")
        r.register("root@old", r.transport("root@new"))
        with capture_changes() as seen:
            r.script("root@old", "echo hi")
        self.assertEqual(seen.changes, [])


class TestPipelineSourceChanges(unittest.TestCase):
    def run_pipeline(self, *, dry_run, mode=FULL):
        ctx = demo_context(dry_run=dry_run)
        ctx.runner.protect(ctx.old, "Plesk server")
        with capture_changes() as seen:
            result = Pipeline(ctx, SELECTION, mode=mode, old_host_key_line="h ssh-ed25519 AAAA", dns=DNS).run()
        self.assertTrue(result.ok, result.error)
        return seen.changes, result, ctx

    def test_a_real_run_changes_the_plesk_server_exactly_twice_and_reverts_it(self):
        changes, _, _ = self.run_pipeline(dry_run=False)
        self.assertEqual(len(changes), 2, changes)
        self.assertIn("temporary SSH key", changes[0]["text"])
        self.assertFalse(changes[0]["revert"])
        self.assertIn("Remove the temporary SSH key", changes[1]["text"])
        self.assertTrue(changes[1]["revert"])
        self.assertTrue(all(not c["dry_run"] for c in changes))

    def test_a_preview_only_ever_says_would_change_and_lists_both_changes(self):
        changes, _, _ = self.run_pipeline(dry_run=True)
        self.assertEqual(len(changes), 2, changes)
        self.assertTrue(all(c["dry_run"] and c["text"].startswith("WOULD CHANGE") for c in changes))
        self.assertIn("Add a temporary SSH key", changes[0]["text"])
        self.assertIn("Remove the temporary SSH key", changes[1]["text"])

    def test_sync_mode_is_announced_too(self):
        changes, _, _ = self.run_pipeline(dry_run=False, mode=SYNC)
        self.assertEqual(len(changes), 2)

    def test_failed_run_still_announces_the_cleanup(self):
        import subprocess
        ctx = demo_context()
        ctx.runner.protect(ctx.old, "Plesk server")
        new = ctx.runner.transport("root@new")
        orig = new.exec
        new.exec = lambda argv, **kw: (subprocess.CompletedProcess(argv, 23, "", "boom")
                                       if argv[:1] == ["rsync"] else orig(argv, **kw))
        with capture_changes() as seen:
            result = Pipeline(ctx, SELECTION, old_host_key_line="h ssh-ed25519 AAAA", dns=DNS).run()
        self.assertFalse(result.ok)
        self.assertEqual([c["revert"] for c in seen.changes], [False, True])


class TestPipelineDns(unittest.TestCase):
    def test_preview_contains_the_dns_plan_with_a_dkim_placeholder(self):
        ctx = demo_context(dry_run=True)
        result = Pipeline(ctx, SELECTION, old_host_key_line="x", dns=DNS).run()
        self.assertEqual(result.dkim, [])
        self.assertEqual(result.dns["mode"], "external")
        acme = next(d for d in result.dns["domains"] if d["domain"] == "acme-shop.com")
        self.assertIsNone(acme["zone"])
        dkim = next(c for c in acme["changes"] if c["name"] == "mail._domainkey.acme-shop.com")
        self.assertIn("created during the migration", dkim["new"])
        self.assertTrue((ctx.dns_dir / "dns-plan.txt").is_file())

    def test_real_run_has_the_real_dkim_value_and_plesk_mode_writes_zone_files(self):
        ctx = demo_context()
        dns = DnsOptions(plesk_dns=True, old_ips=["203.0.113.10"], new_ipv4="203.0.113.20")
        result = Pipeline(ctx, SELECTION, old_host_key_line="x", dns=dns).run()
        self.assertTrue(result.ok, result.error)
        acme = next(d for d in result.dns["domains"] if d["domain"] == "acme-shop.com")
        dkim = next(c for c in acme["changes"] if c["name"] == "mail._domainkey.acme-shop.com")
        self.assertTrue(dkim["new"].startswith("v=DKIM1"))
        self.assertIn(dkim["new"], acme["zone"])
        for name in SELECTION:
            self.assertTrue((ctx.dns_dir / f"{name}.zone").is_file())

    def test_no_dns_options_means_no_dns_report(self):
        result = Pipeline(demo_context(), SELECTION, old_host_key_line="x").run()
        self.assertIsNone(result.dns)


class TestBackendSourceState(unittest.TestCase):
    def backend_ready(self):
        b = Backend(Path(temp_workdir()), demo=True, demo_delay=0)
        cred = {"user": "root", "auth": "password", "password": "x", "accept_fingerprint": DEMO_FINGERPRINT}
        b.connect("source", {"host": "plesk.example.com", **cred})
        b.source_checks()
        b.connect("target", {"host": "new.example.com", **cred})
        b.target_checks({"domains": SELECTION, "mail_hostname": "mail.acme-shop.com"})
        return b

    def finish(self, b, **start):
        import time
        body = {"mode": "full", "domains": SELECTION, "mail_hostname": "mail.acme-shop.com",
                "dns": {"mode": "external", "old_ips": "203.0.113.10", "new_ipv4": "203.0.113.20"}}
        body.update(start)
        b.start_run(body)
        deadline = time.time() + 30
        while b.run_status()["state"] == "running" and time.time() < deadline:
            time.sleep(0.05)
        return b.run_status()

    def test_preview_leaves_the_source_unchanged(self):
        b = self.backend_ready()
        status = self.finish(b, dry_run=True)
        self.assertEqual(status["source_state"], "unchanged")
        self.assertTrue(status["source_changes"])
        self.assertTrue(all(c["dry_run"] for c in status["source_changes"]))
        self.assertTrue(any(e["level"] == "source" for e in status["log"] + b.run.log))

    def test_real_run_reports_changed_and_restored(self):
        b = self.backend_ready()
        status = self.finish(b, dry_run=False, confirmed=True)
        self.assertEqual(status["state"], "done")
        self.assertEqual(status["source_state"], "restored")
        self.assertEqual([c["revert"] for c in status["source_changes"]], [False, True])

    def test_target_report_offers_dns_defaults(self):
        b = self.backend_ready()
        self.assertEqual(b.target_report["dns_defaults"],
                         {"old_ips": ["203.0.113.10"], "new_ipv4": "203.0.113.20", "new_ipv6": ""})

    def test_dns_options_are_required_and_validated(self):
        from plsk2sa.ui.backend import UserError
        b = self.backend_ready()
        base = {"mode": "full", "dry_run": True, "domains": SELECTION, "mail_hostname": "mail.acme-shop.com"}
        with self.assertRaises(UserError):
            b.start_run(base)
        with self.assertRaises(UserError):
            b.start_run({**base, "dns": {"mode": "external", "old_ips": [], "new_ipv4": "nope"}})
        with self.assertRaises(UserError):
            b.start_run({**base, "dns": {"mode": "external", "old_ips": ["x.y"], "new_ipv4": "203.0.113.20"}})


if __name__ == "__main__":
    unittest.main()
