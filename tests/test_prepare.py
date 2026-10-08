import argparse
import json
import subprocess
import time
import unittest
from pathlib import Path

from plsk2sa.cli import cmd_prepare
from plsk2sa.demo import DEMO_FINGERPRINT
from plsk2sa.pipeline import FULL, PREPARE, Pipeline
from plsk2sa.plesk_export import DomainInfo, PleskExporter
from plsk2sa.prepare import PrepItem, PreparePlan, apply_plan, build_plan, verify_plan
from plsk2sa.requirements import Requirements, detect, parse_php_modules
from plsk2sa.ui.backend import Backend, UserError
from support import demo_context, temp_workdir
from test_source_changes import capture_changes


def domain(name, php_handler="", docroot="/var/www/x"):
    return DomainInfo(name=name, subscription=name, docroot_src=docroot, php_handler=php_handler)


def recording(ctx, host="root@new", stdout=None):
    """Spy on a demo transport: returns the list of (argv, stdin) it received."""
    t = ctx.runner.transport(host)
    orig, seen = t.exec, []

    def spy(argv, **kw):
        seen.append((list(argv), kw.get("stdin_text") or ""))
        if stdout and (cp := stdout(argv, kw.get("stdin_text") or "")) is not None:
            return cp
        return orig(argv, **kw)

    t.exec = spy
    return seen


class TestDetection(unittest.TestCase):
    def test_parse_php_modules(self):
        out = "[PHP Modules]\nCore\ncurl\nmysqli\nPDO_mysql\n\n[Zend Modules]\nZend OPcache\n"
        self.assertEqual(parse_php_modules(out), ["core", "curl", "mysqli", "pdo_mysql"])

    def test_detects_the_demo_servers_software(self):
        ctx = demo_context()
        inv = PleskExporter(ctx).discover(with_sizes=False)
        req = detect(ctx, inv)
        self.assertEqual(req.php_versions, ["7.4", "8.1", "8.3"])
        self.assertIn("imagick", req.php_extensions["7.4"])
        self.assertIn("composer", req.tools)
        self.assertEqual(req.services, ["fail2ban", "redis"])
        self.assertEqual(req.htaccess_sites, ["acme-shop.com"])
        self.assertEqual(req.db_types, {"mysql": 3})

    def test_detection_never_runs_a_mutating_command_on_the_source(self):
        ctx = demo_context()
        ctx.runner.protect(ctx.old)
        inv = PleskExporter(ctx).discover(with_sizes=False)
        with capture_changes() as seen:
            detect(ctx, inv)
        self.assertEqual(seen.changes, [])

    def test_a_failing_probe_leaves_a_note_not_a_wrong_requirement(self):
        ctx = demo_context()
        inv = PleskExporter(ctx).discover(with_sizes=False)
        old = ctx.runner.transport("root@old")
        orig = old.exec
        old.exec = lambda argv, **kw: (subprocess.CompletedProcess(argv, 127, "", "not found")
                                       if argv[0].startswith("/opt/plesk/php/7.4") else orig(argv, **kw))
        req = detect(ctx, inv)
        self.assertNotIn("7.4", req.php_extensions)
        self.assertTrue(any("PHP 7.4" in n for n in req.notes))


class TestPlan(unittest.TestCase):
    def setUp(self):
        ctx = demo_context()
        self.inv = PleskExporter(ctx).discover(with_sizes=False)
        self.req = detect(ctx, self.inv)
        self.plan = build_plan(self.req, self.inv.domains, default_php="8.3")

    def ids(self):
        return [i.id for i in self.plan.items]

    def test_items_follow_what_the_sites_use(self):
        self.assertEqual(self.ids(), ["base", "php:7.4", "php:8.1", "tools", "svc:fail2ban", "svc:redis"])
        base = self.plan.item("base")
        self.assertTrue(base.required)
        self.assertIn("nginx", base.packages)
        self.assertIn("php8.3-fpm", base.packages)

    def test_other_php_versions_need_the_third_party_repository_and_get_their_extensions(self):
        p74 = self.plan.item("php:7.4")
        self.assertTrue(p74.third_party)
        for pkg in ("php7.4-fpm", "php7.4-imagick", "php7.4-redis", "php7.4-bcmath", "php7.4-soap", "php7.4-mysql"):
            self.assertIn(pkg, p74.packages)
        self.assertNotIn("php7.4-json", p74.packages)  # ships inside php-common
        self.assertFalse(self.plan.item("tools").third_party)

    def test_tools_become_distribution_packages(self):
        self.assertEqual(self.plan.item("tools").packages,
                         ["composer", "git", "imagemagick", "nodejs", "npm", "unzip", "zip"])

    def test_installed_only_items_are_off_by_default_with_an_honest_note(self):
        req = Requirements(services=["clamav", "spamassassin", "postgresql", "redis"],
                           db_types={"postgresql": 2}, tools=["wp", "mongod"])
        plan = build_plan(req, self.inv.domains, default_php="8.3")
        for sid in ("svc:clamav", "svc:spamassassin", "svc:postgresql"):
            self.assertFalse(plan.item(sid).default, sid)
            self.assertIn("Installed only", plan.item(sid).note)
        self.assertTrue(plan.item("svc:redis").default)
        joined = " ".join(plan.notes)
        self.assertIn("WP-CLI", joined)
        self.assertIn("MongoDB", joined)
        self.assertIn("PostgreSQL", joined)

    def test_htaccess_sites_are_flagged(self):
        self.assertTrue(any(".htaccess" in n and "acme-shop.com" in n for n in self.plan.notes))

    def test_selection_is_validated(self):
        self.assertEqual(self.plan.resolve_selection(None), self.plan.default_selection())
        self.assertEqual(self.plan.resolve_selection(["tools", "base", "tools"]), ["tools"])
        with self.assertRaises(ValueError):
            self.plan.resolve_selection(["tools; rm -rf /"])

    def test_php_assignment_uses_the_sites_own_version_when_it_will_exist(self):
        sel = self.plan.default_selection()
        self.assertEqual(self.plan.php_assignment(self.inv.domains, sel),
                         {"acme-shop.com": "7.4", "mueller-architekten.de": "8.1",
                          "mueller-bau.de": "8.1", "club-sonnenhof.at": "8.3"})
        without_ppa = [s for s in sel if s != "php:7.4"]
        self.assertEqual(self.plan.php_assignment(self.inv.domains, without_ppa)["acme-shop.com"], "8.3")
        self.assertEqual(self.plan.php_versions_for(without_ppa), ["8.1", "8.3"])

    def test_plan_for_a_selection_only_covers_those_sites(self):
        only = [d for d in self.inv.domains if d.name == "club-sonnenhof.at"]
        plan = build_plan(self.req, only, default_php="8.3")
        self.assertNotIn("php:7.4", [i.id for i in plan.items])
        self.assertFalse(any("acme-shop.com" in n for n in plan.notes))

    def test_default_version_with_extra_modules_gets_an_extension_item(self):
        req = Requirements(php_versions=["8.3"], php_extensions={"8.3": ["curl", "imagick", "gd"]})
        plan = build_plan(req, [domain("a.example", "plesk-php83-fpm")], default_php="8.3")
        self.assertEqual(plan.item("php-ext:8.3").packages, ["php8.3-imagick"])


class TestApply(unittest.TestCase):
    def setUp(self):
        self.ctx = demo_context()
        inv = PleskExporter(self.ctx).discover(with_sizes=False)
        self.plan = build_plan(detect(self.ctx, inv), inv.domains, default_php="8.3")

    def test_packages_are_passed_as_arguments_and_the_ppa_is_added_only_when_selected(self):
        seen = recording(self.ctx)
        apply_plan(self.ctx, self.plan, ["tools"])
        scripts = "\n".join(s for _, s in seen)
        self.assertNotIn("add-apt-repository", scripts)
        install = next(a for a, _ in seen if a[:3] == ["bash", "-s", "--"])
        self.assertEqual(install[3:], self.plan.item("tools").packages)

        seen = recording(self.ctx)
        apply_plan(self.ctx, self.plan, ["php:7.4"])
        self.assertIn("add-apt-repository -y ppa:ondrej/php", "\n".join(s for _, s in seen))

    def test_results_and_service_enabling(self):
        seen = recording(self.ctx)
        results = apply_plan(self.ctx, self.plan, ["php:7.4", "svc:redis"])
        self.assertEqual([(r.id, r.status) for r in results], [("php:7.4", "installed"), ("svc:redis", "installed")])
        enabled = "\n".join(s for _, s in seen if "systemctl enable" in s)
        self.assertIn("php7.4-fpm", enabled)
        self.assertIn("redis-server", enabled)

    def test_one_missing_package_does_not_hide_the_rest(self):
        def fake(argv, stdin):
            if argv[:3] == ["bash", "-s", "--"] and "php7.4-soap" in argv:
                return subprocess.CompletedProcess(argv, 0, "FAILED: php7.4-soap\n", "")
        seen = recording(self.ctx, stdout=fake)
        results = apply_plan(self.ctx, self.plan, ["php:7.4"])
        self.assertEqual((results[0].status, results[0].failed), ("partial", ["php7.4-soap"]))
        self.assertFalse(any("systemctl enable --now php7.4-fpm" in s for _, s in seen))

    def test_everything_failing_is_reported_as_failed(self):
        def fake(argv, stdin):
            if argv[:3] == ["bash", "-s", "--"]:
                return subprocess.CompletedProcess(argv, 0, "FAILED: " + " ".join(argv[3:]) + "\n", "")
        recording(self.ctx, stdout=fake)
        results = apply_plan(self.ctx, self.plan, ["svc:redis"])
        self.assertEqual(results[0].status, "failed")

    def test_dry_run_only_plans(self):
        ctx = demo_context(dry_run=True)
        seen = recording(ctx)
        results = apply_plan(ctx, self.plan, ["php:7.4", "tools"])
        self.assertEqual([r.status for r in results], ["planned", "planned"])
        self.assertEqual(seen, [], "nothing may reach the target in a preview")

    def test_required_and_unknown_items_are_ignored(self):
        self.assertEqual(apply_plan(self.ctx, self.plan, ["base"]), [])

    def test_verify_reports_missing_packages_and_a_stopped_php_service(self):
        def fake(argv, stdin):
            if argv[:2] == ["bash", "-c"] and "php7.4-soap" in argv:
                return subprocess.CompletedProcess(argv, 0, "php7.4-soap\n", "")
            if argv[:2] == ["systemctl", "is-active"] and argv[2] == "php7.4-fpm":
                return subprocess.CompletedProcess(argv, 3, "inactive\n", "")
        recording(self.ctx, stdout=fake)
        results = dict((m, ok) for ok, m in verify_plan(self.ctx, self.plan, ["php:7.4", "tools"]))
        self.assertFalse(results["PHP 7.4: missing php7.4-soap"])
        self.assertFalse(results["Service php7.4-fpm: not running"])
        self.assertTrue(results["Command line tools: all packages installed"])


class TestPipelineIntegration(unittest.TestCase):
    def prepared(self, ctx, domains, selected=None):
        inv = PleskExporter(ctx).discover(with_sizes=False)
        plan = build_plan(detect(ctx, inv), inv.domains, default_php="8.3")
        sel = plan.default_selection() if selected is None else selected
        names = [d.name for d in inv.domains if d.name in domains]
        chosen = [d for d in inv.domains if d.name in domains]
        return plan, sel, names, plan.php_assignment(chosen, sel)

    def test_prepare_mode_installs_without_touching_the_plesk_server(self):
        ctx = demo_context()
        ctx.runner.protect(ctx.old)
        plan, sel, _, _ = self.prepared(ctx, [])
        p = Pipeline(ctx, [], mode=PREPARE, prepare_plan=plan, prepare_selected=sel)
        self.assertEqual([s.key for s in p.steps], ["provision", "prepare", "verify"])
        with capture_changes() as seen:
            result = p.run()
        self.assertTrue(result.ok, result.error)
        self.assertEqual(seen.changes, [])
        self.assertEqual({r["id"] for r in result.prepare}, set(sel))
        self.assertTrue(all(r["status"] == "installed" for r in result.prepare))
        self.assertTrue(all(v["ok"] for v in result.verify))
        self.assertFalse((ctx.workdir / "manifest.json").exists(), "prepare must not export anything")

    def test_prepare_mode_never_reports_credentials_or_dkim_left_over_from_earlier_runs(self):
        ctx = demo_context()
        ctx.secrets_dir.mkdir(parents=True, exist_ok=True)
        (ctx.secrets_dir / "db-credentials.tsv").write_text("old_db\told_password\n", encoding="utf-8")
        ctx.dns_dir.mkdir(parents=True, exist_ok=True)
        (ctx.dns_dir / "acme-shop.com.dkim.txt").write_text('x ( "v=DKIM1; p=STALE" )', encoding="utf-8")
        plan, sel, _, _ = self.prepared(ctx, [])
        result = Pipeline(ctx, ["acme-shop.com"], mode=PREPARE, prepare_plan=plan, prepare_selected=sel).run()
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.credentials_file, "")
        self.assertEqual(result.dkim, [])
        self.assertEqual(result.mode, "prepare")

    def test_prepare_mode_preview_has_no_verify_step(self):
        ctx = demo_context(dry_run=True)
        plan, sel, _, _ = self.prepared(ctx, [])
        p = Pipeline(ctx, [], mode=PREPARE, prepare_plan=plan, prepare_selected=sel)
        self.assertEqual([s.key for s in p.steps], ["provision", "prepare"])
        result = p.run()
        self.assertTrue(result.ok)
        self.assertEqual({r["status"] for r in result.prepare}, {"planned"})

    def test_prepare_mode_with_nothing_selected_only_installs_the_base(self):
        ctx = demo_context()
        plan, _, _, _ = self.prepared(ctx, [])
        p = Pipeline(ctx, [], mode=PREPARE, prepare_plan=plan, prepare_selected=[])
        self.assertEqual([s.key for s in p.steps], ["provision", "verify"])

    def test_full_run_gives_each_site_its_own_php_pool(self):
        ctx = demo_context()
        names = ["acme-shop.com", "mueller-architekten.de"]
        plan, sel, names, assign = self.prepared(ctx, names)
        seen = recording(ctx)
        result = Pipeline(ctx, names, mode=FULL, old_host_key_line="x", prepare_plan=plan,
                          prepare_selected=sel, php_by_domain=assign,
                          dns=None).run()
        self.assertTrue(result.ok, result.error)
        self.assertEqual({d.name: d.php for d in ctx.manifest.domains},
                         {"acme-shop.com": "7.4", "mueller-architekten.de": "8.1"})
        scripts = "\n".join(s for _, s in seen)
        self.assertIn("/etc/php/7.4/fpm/pool.d/acme-shop.com.conf", scripts)
        self.assertIn("/etc/php/8.1/fpm/pool.d/mueller-architekten.de.conf", scripts)
        self.assertIn("systemctl reload php7.4-fpm", scripts)
        self.assertTrue(all(v["ok"] for v in result.verify))

    def test_without_the_ppa_sites_fall_back_to_the_default_php(self):
        ctx = demo_context()
        plan, sel, names, assign = self.prepared(ctx, ["acme-shop.com"],
                                                 selected=["tools"])
        Pipeline(ctx, names, mode=FULL, old_host_key_line="x", prepare_plan=plan,
                 prepare_selected=sel, php_by_domain=assign).run()
        self.assertEqual(ctx.manifest.domains[0].php, "8.3")

    def test_export_reads_the_assignment_saved_by_the_cli(self):
        ctx = demo_context()
        ctx.workdir.mkdir(parents=True, exist_ok=True)
        (ctx.workdir / "php_by_domain.json").write_text(json.dumps({"acme-shop.com": "7.4"}), encoding="utf-8")
        manifest = PleskExporter(ctx).export(only=["acme-shop.com", "mueller-bau.de"])
        self.assertEqual({d.name: d.php for d in manifest.domains}, {"acme-shop.com": "7.4", "mueller-bau.de": "8.3"})


class TestBackendAndCli(unittest.TestCase):
    CHOSEN = ["acme-shop.com", "mueller-architekten.de"]

    def ready(self):
        b = Backend(Path(temp_workdir()), demo=True, demo_delay=0)
        cred = {"user": "root", "auth": "password", "password": "x", "accept_fingerprint": DEMO_FINGERPRINT}
        b.connect("source", {"host": "plesk.example.com", **cred})
        b.source_checks()
        b.connect("target", {"host": "new.example.com", **cred})
        b.target_checks({"domains": self.CHOSEN, "mail_hostname": "mail.acme-shop.com"})
        return b

    def finish(self, b, **body):
        base = {"mode": "prepare", "domains": self.CHOSEN, "mail_hostname": "mail.acme-shop.com"}
        base.update(body)
        b.start_run(base)
        deadline = time.time() + 30
        while b.run_status()["state"] == "running" and time.time() < deadline:
            time.sleep(0.05)
        return b.run_status()

    def test_reports_carry_the_requirements_and_the_plan(self):
        b = self.ready()
        self.assertEqual(b.source_report["requirements"]["php_versions"], ["7.4", "8.1", "8.3"])
        plan = b.target_report["prepare_plan"]
        self.assertEqual(plan["default_php"], "8.3")
        self.assertIn("php:7.4", [i["id"] for i in plan["items"]])
        self.assertEqual(plan["default_selection"], ["php:7.4", "php:8.1", "tools", "svc:fail2ban", "svc:redis"])

    def test_plan_only_covers_the_selected_domains(self):
        b = self.ready()
        b.target_checks({"domains": ["club-sonnenhof.at"], "mail_hostname": "mail.acme-shop.com"})
        self.assertNotIn("php:7.4", [i["id"] for i in b.target_report["prepare_plan"]["items"]])

    def test_prepare_only_run_needs_no_dns_and_leaves_the_source_alone(self):
        b = self.ready()
        status = self.finish(b, dry_run=False, confirmed=True)
        self.assertEqual(status["state"], "done", status["result"])
        self.assertEqual(status["source_state"], "unchanged")
        self.assertEqual(status["source_changes"], [])
        self.assertEqual([s["key"] for s in status["steps"]], ["provision", "prepare", "verify"])
        self.assertEqual(len(status["result"]["prepare"]), 5)
        self.assertIsNone(status["result"]["dns"])

    def test_the_selection_decides_what_is_installed(self):
        b = self.ready()
        status = self.finish(b, dry_run=True, prepare={"selected": ["tools"]})
        self.assertEqual([r["id"] for r in status["result"]["prepare"]], ["tools"])

    def test_unknown_item_is_rejected(self):
        b = self.ready()
        with self.assertRaises(UserError):
            b.start_run({"mode": "prepare", "dry_run": True, "domains": self.CHOSEN,
                         "mail_hostname": "mail.acme-shop.com", "prepare": {"selected": ["evil;x"]}})

    def test_full_run_with_the_ppa_unticked_falls_back_to_the_default_php(self):
        b = self.ready()
        dns = {"mode": "external", "old_ips": "203.0.113.10", "new_ipv4": "203.0.113.20"}
        self.finish(b, mode="full", dry_run=True, dns=dns, prepare={"selected": ["tools"]})
        manifest = json.loads((b.workdir / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual({d["name"]: d["php"] for d in manifest["domains"]}, {d: "8.3" for d in self.CHOSEN})

    def test_cli_prepare_command(self):
        ctx = demo_context()
        args = argparse.Namespace(domain=None, no_ppa=False, skip=["svc:redis"], yes=True)
        self.assertEqual(cmd_prepare(ctx, args), 0)
        saved = json.loads((ctx.workdir / "php_by_domain.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["acme-shop.com"], "7.4")

    def test_cli_prepare_without_ppa(self):
        ctx = demo_context()
        args = argparse.Namespace(domain=["acme-shop.com"], no_ppa=True, skip=None, yes=True)
        self.assertEqual(cmd_prepare(ctx, args), 0)
        saved = json.loads((ctx.workdir / "php_by_domain.json").read_text(encoding="utf-8"))
        self.assertEqual(saved, {"acme-shop.com": "8.3"})


class TestItemModel(unittest.TestCase):
    def test_plan_serialises(self):
        plan = PreparePlan("8.3", [PrepItem("x", "X", "why", ["pkg"], default=False)])
        d = plan.to_dict()
        self.assertEqual(d["default_selection"], [])
        self.assertEqual(d["items"][0]["packages"], ["pkg"])


if __name__ == "__main__":
    unittest.main()
