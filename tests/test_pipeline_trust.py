import subprocess
import unittest

from plsk2sa import trust
from plsk2sa.modules.dkim import dkim_dns_value
from plsk2sa.pipeline import FULL, SYNC, Pipeline
from support import demo_context

SELECTION = ["acme-shop.com", "mueller-architekten.de"]


def states(pipeline):
    return {s.key.split(":")[-1]: s.state for s in pipeline.steps}


class TestPipeline(unittest.TestCase):
    def test_full_run_completes_and_cleans_up(self):
        ctx = demo_context()
        seen = []
        p = Pipeline(ctx, SELECTION, mode=FULL, old_host_key_line="old ssh-ed25519 AAAA",
                     progress=lambda steps: seen.append([s.state for s in steps]))
        result = p.run()
        self.assertTrue(result.ok, result.error)
        self.assertEqual(set(states(p).values()), {"done"})
        self.assertEqual(len(result.verify), 28 - 3)  # two selected domains: fewer accounts/DBs/HTTP checks
        self.assertTrue(all(v["ok"] for v in result.verify))
        self.assertEqual(ctx.config.transfer_key, "")
        self.assertEqual({d["domain"] for d in result.dkim}, set(SELECTION))
        self.assertTrue(result.credentials_file.endswith("db-credentials.tsv"))
        self.assertGreater(len(seen), len(p.steps))  # progress was reported repeatedly

    def test_dry_run_changes_nothing_and_skips_verify(self):
        ctx = demo_context(dry_run=True)
        seen = []
        original = ctx.runner.transport("root@new").exec
        ctx.runner.transport("root@new").exec = lambda argv, **kw: (seen.append(argv), original(argv, **kw))[1]
        p = Pipeline(ctx, SELECTION, mode=FULL, old_host_key_line="x")
        result = p.run()
        self.assertTrue(result.ok, result.error)
        self.assertTrue(result.dry_run)
        self.assertEqual(result.dkim, [])             # a preview must not present DKIM records
        self.assertEqual(result.credentials_file, "")  # nor credentials that were never applied
        self.assertNotIn("verify", states(p))
        # nothing mutating reached the target: only read-only helper commands may run
        for argv in seen:
            self.assertNotIn(argv[0], ("rsync", "chown", "mysql"))
            self.assertNotEqual(argv, ["bash", "-s"])

    def test_stale_dkim_file_is_not_reported_after_a_real_run_that_produced_none(self):
        ctx = demo_context()
        stale = ctx.dns_dir
        stale.mkdir(parents=True, exist_ok=True)
        (stale / "acme-shop.com.dkim.txt").write_text('x ( "v=DKIM1; p=STALE" )', encoding="utf-8")
        transport = ctx.runner.transport("root@new")
        original = transport.exec

        def no_dkim_file(argv, **kw):
            if argv[:1] == ["cat"] and argv[1].endswith("/mail.txt"):
                return subprocess.CompletedProcess(argv, 1, "", "No such file")
            return original(argv, **kw)

        transport.exec = no_dkim_file
        result = Pipeline(ctx, ["acme-shop.com"], mode=FULL, old_host_key_line="x").run()
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.dkim, [])

    def test_sync_mode_skips_provisioning(self):
        ctx = demo_context()
        p = Pipeline(ctx, ["acme-shop.com"], mode=SYNC, old_host_key_line="x")
        keys = [s.key for s in p.steps]
        self.assertNotIn("provision", keys)
        self.assertNotIn("verify", keys)
        self.assertTrue(p.run().ok)

    def test_failure_stops_but_still_removes_temporary_access(self):
        ctx = demo_context()
        transport = ctx.runner.transport("root@new")
        original = transport.exec

        def failing(argv, **kw):
            if argv and argv[0] == "rsync":
                return subprocess.CompletedProcess(argv, 23, "", "rsync: connection unexpectedly closed")
            return original(argv, **kw)

        transport.exec = failing
        removed = []
        old_exec = ctx.runner.transport("root@old").exec
        ctx.runner.transport("root@old").exec = lambda argv, **kw: (
            removed.append((kw.get("stdin_text") or "")), old_exec(argv, **kw))[1]
        p = Pipeline(ctx, SELECTION, mode=FULL, old_host_key_line="x")
        result = p.run()
        self.assertFalse(result.ok)
        self.assertIn("rsync", result.error)
        st = states(p)
        self.assertEqual(st["acme-shop.com"], "failed")
        self.assertEqual(st["mueller-architekten.de"], "skipped")
        self.assertEqual(st["cleanup"], "done")
        self.assertTrue(any(trust.MARKER in text for text in removed), "authorized_keys was not cleaned")
        self.assertEqual(ctx.config.transfer_key, "")

    def test_cancel_before_start_skips_everything(self):
        import threading
        ctx = demo_context()
        cancel = threading.Event()
        cancel.set()
        p = Pipeline(ctx, SELECTION, mode=FULL, old_host_key_line="x", cancel=cancel)
        result = p.run()
        self.assertTrue(result.cancelled)
        self.assertEqual(set(states(p).values()), {"skipped"})

    def test_cancel_between_steps_still_cleans_up(self):
        import threading
        ctx = demo_context()
        cancel = threading.Event()

        def progress(steps):
            if any(s.key == "trust" and s.state == "done" for s in steps):
                cancel.set()

        p = Pipeline(ctx, SELECTION, mode=FULL, old_host_key_line="x", progress=progress, cancel=cancel)
        result = p.run()
        self.assertTrue(result.cancelled)
        self.assertEqual(states(p)["trust"], "done")
        self.assertEqual(states(p)["acme-shop.com"], "skipped")
        self.assertEqual(states(p)["cleanup"], "done")

    def test_invalid_mode_rejected(self):
        with self.assertRaises(ValueError):
            Pipeline(demo_context(), SELECTION, mode="bogus")


class TestTrust(unittest.TestCase):
    def test_setup_restricts_key_and_pins_host_key(self):
        ctx = demo_context()
        scripts = {"root@old": [], "root@new": []}
        for host in scripts:
            t = ctx.runner.transport(host)
            orig = t.exec
            t.exec = (lambda h, o: lambda argv, **kw: (scripts[h].append((list(argv), (kw.get("stdin_text") or ""))), o(argv, **kw))[1])(host, orig)
        trust.setup(ctx, old_host_key_line="plesk.example ssh-ed25519 AAAAKEY")
        old_text = "\n".join(text for _, text in scripts["root@old"])
        self.assertIn('from="203.0.113.20"', old_text)
        self.assertIn("no-agent-forwarding", old_text)
        self.assertIn("no-pty", old_text)
        self.assertIn(trust.MARKER, old_text)
        new_text = "\n".join(text for _, text in scripts["root@new"])
        self.assertIn("plesk.example ssh-ed25519 AAAAKEY", new_text)
        self.assertEqual(ctx.config.transfer_key, trust.KEY_PATH)
        test_login = next(a for a, _ in scripts["root@new"] if a[:1] == ["ssh"])
        self.assertIn("StrictHostKeyChecking=yes", test_login)
        self.assertIn("IdentitiesOnly=yes", test_login)

    def test_setup_without_ip_restriction(self):
        ctx = demo_context()
        old = ctx.runner.transport("root@old")
        recorded = []
        orig = old.exec
        old.exec = lambda argv, **kw: (recorded.append((kw.get("stdin_text") or "")), orig(argv, **kw))[1]
        trust.setup(ctx, old_host_key_line="h ssh-ed25519 AAAA", restrict_ip=False)
        self.assertNotIn("from=", "\n".join(recorded))

    def test_setup_rejects_malformed_public_key(self):
        ctx = demo_context()
        new = ctx.runner.transport("root@new")
        orig = new.exec

        def evil(argv, **kw):
            if argv[:1] == ["cat"] and argv[1].endswith(".pub"):
                return subprocess.CompletedProcess(argv, 0, 'ssh-ed25519 AAAA plsk2sa-temporary"\ncommand="evil"\n', "")
            return orig(argv, **kw)

        new.exec = evil
        with self.assertRaises(trust.TrustError):
            trust.setup(ctx, old_host_key_line="h ssh-ed25519 AAAA")

    def test_rsync_pull_uses_pinned_key_after_setup(self):
        ctx = demo_context()
        trust.setup(ctx, old_host_key_line="h ssh-ed25519 AAAA")
        calls = []
        new = ctx.runner.transport("root@new")
        orig = new.exec
        new.exec = lambda argv, **kw: (calls.append(list(argv)), orig(argv, **kw))[1]
        ctx.rsync_pull("/src/", "/dst/", delete=True)
        argv = calls[-1]
        self.assertEqual(argv[:3], ["rsync", "-a", "--delete"])
        e_arg = argv[argv.index("-e") + 1]
        self.assertIn(trust.KEY_PATH, e_arg)
        self.assertIn("StrictHostKeyChecking=yes", e_arg)
        self.assertEqual(argv[-2:], ["root@old:/src/", "/dst/"])

    def test_rsync_pull_is_plain_without_trust_or_port(self):
        ctx = demo_context()
        calls = []
        new = ctx.runner.transport("root@new")
        orig = new.exec
        new.exec = lambda argv, **kw: (calls.append(list(argv)), orig(argv, **kw))[1]
        ctx.rsync_pull("/src/", "/dst/")
        self.assertEqual(calls[-1], ["rsync", "-a", "root@old:/src/", "/dst/"])

    def test_teardown_never_raises(self):
        ctx = demo_context()
        ctx.runner.transport("root@old").exec = lambda argv, **kw: (_ for _ in ()).throw(RuntimeError("down"))
        self.assertFalse(trust.teardown(ctx))


class TestDkimValue(unittest.TestCase):
    def test_flattens_bind_record(self):
        text = ('mail._domainkey\tIN\tTXT\t( "v=DKIM1; h=sha256; k=rsa; "\n'
                '\t  "p=AAAA"\n\t  "BBBB" )  ; ----- DKIM key mail for example.com\n')
        self.assertEqual(dkim_dns_value(text), "v=DKIM1; h=sha256; k=rsa; p=AAAABBBB")

    def test_garbage_gives_empty_value(self):
        self.assertEqual(dkim_dns_value("nothing quoted here"), "")


if __name__ == "__main__":
    unittest.main()
