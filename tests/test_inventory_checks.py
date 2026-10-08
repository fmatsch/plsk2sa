import unittest

from plsk2sa.checks import FAIL, OK, WARN, check_source, check_target, has_failures
from plsk2sa.demo import demo_ptr_lookup
from plsk2sa.plesk_export import (ExportError, PleskExporter, php_from_handler)
from support import demo_context


class TestPhpHandler(unittest.TestCase):
    def test_parses_versions(self):
        self.assertEqual(php_from_handler("plesk-php74-fpm"), "7.4")
        self.assertEqual(php_from_handler("plesk-php83-fastcgi"), "8.3")
        self.assertEqual(php_from_handler("plesk-php56-fpm"), "5.6")

    def test_unknown_handler(self):
        self.assertIsNone(php_from_handler("module"))
        self.assertIsNone(php_from_handler(""))


class TestDiscover(unittest.TestCase):
    def setUp(self):
        self.ctx = demo_context()
        self.inv = PleskExporter(self.ctx).discover()

    def test_groups_domains_into_subscriptions(self):
        subs = {d.name: d.subscription for d in self.inv.domains}
        self.assertEqual(subs["mueller-bau.de"], "mueller-architekten.de")
        self.assertEqual(subs["mueller-architekten.de"], "mueller-architekten.de")
        self.assertEqual(subs["acme-shop.com"], "acme-shop.com")
        self.assertFalse(self.inv.degraded)

    def test_collects_details(self):
        acme = self.inv.by_name("acme-shop.com")
        self.assertEqual(acme.databases, ["acme_shop_wp"])
        self.assertEqual(acme.mailboxes, ["info", "orders", "max"])
        self.assertEqual(acme.aliases, [["sales", "orders@acme-shop.com"]])
        self.assertEqual(acme.subdomains, ["blog.acme-shop.com"])
        self.assertEqual(acme.source_php, "7.4")
        self.assertAlmostEqual(acme.size_web_mb, 1450000 / 1024, delta=0.1)
        self.assertGreater(acme.size_mail_mb, 0)
        self.assertEqual(acme.size_db_mb, 310.5)

    def test_without_sizes_skips_du(self):
        inv = PleskExporter(self.ctx).discover(with_sizes=False)
        self.assertIsNone(inv.by_name("acme-shop.com").size_web_mb)

    def test_falls_back_when_subscription_columns_are_missing(self):
        from plsk2sa import plesk_export

        exporter = PleskExporter(self.ctx)
        original = exporter._try_sql

        def failing(query, note=None):
            if query == plesk_export.SQL_DOMAINS_V2:
                return None
            return original(query, note)

        exporter._try_sql = failing
        inv = exporter.discover(with_sizes=False)
        self.assertTrue(inv.degraded)
        self.assertEqual(len(inv.domains), 4)
        self.assertTrue(all(d.subscription == d.name for d in inv.domains))
        self.assertTrue(any("Subscription grouping" in n for n in inv.notes))


class TestExport(unittest.TestCase):
    def test_exports_only_selected_domains(self):
        ctx = demo_context()
        manifest = PleskExporter(ctx).export(only=["acme-shop.com"])
        self.assertEqual([d.name for d in manifest.domains], ["acme-shop.com"])
        self.assertTrue((ctx.db_dir / "acme_shop_wp.sql").is_file())
        self.assertFalse((ctx.db_dir / "mueller_cms.sql").exists())
        self.assertIs(ctx.manifest, manifest)

    def test_only_selected_mail_passwords_reach_the_workdir(self):
        ctx = demo_context()
        PleskExporter(ctx).export(only=["acme-shop.com"])
        tsv = (ctx.secrets_dir / "mail_auth.tsv").read_text(encoding="utf-8")
        raw = (ctx.secrets_dir / "mail_auth_raw.txt").read_text(encoding="utf-8")
        self.assertIn("info@acme-shop.com", tsv)
        for text in (tsv, raw):
            self.assertNotIn("mueller-architekten.de", text)
            self.assertNotIn("mueller-bau.de", text)

    def test_unknown_domain_is_reported(self):
        with self.assertRaises(ExportError):
            PleskExporter(demo_context()).export(only=["does-not-exist.com"])


class TestSourceChecks(unittest.TestCase):
    def test_demo_source_passes_with_warnings(self):
        ctx = demo_context()
        inv = PleskExporter(ctx).discover()
        results = check_source(ctx, inv)
        self.assertFalse(has_failures(results))
        ids = {r.id: r.status for r in results}
        self.assertEqual(ids["src.plesk"], OK)
        self.assertEqual(ids["src.subdomains"], WARN)
        self.assertEqual(ids["src.domain_aliases"], WARN)
        self.assertEqual(ids["src.mail_auth"], OK)

    def test_titles_use_correct_singular(self):
        ctx = demo_context()
        titles = [r.title for r in check_source(ctx, PleskExporter(ctx).discover())]
        self.assertIn("1 subdomain is not migrated automatically", titles)
        self.assertIn("1 domain alias is not migrated automatically", titles)

    def test_non_root_stops_early(self):
        ctx = demo_context()
        ctx.runner.transport("root@old").exec = lambda argv, **kw: __import__("subprocess").CompletedProcess(
            argv, 0, "1000\n" if argv == ["id", "-u"] else "", "")
        results = check_source(ctx)
        self.assertEqual([r.id for r in results], ["src.root"])
        self.assertEqual(results[0].status, FAIL)

    def test_missing_plesk_fails(self):
        ctx = demo_context()
        transport = ctx.runner.transport("root@old")
        original = transport.exec

        def exec_without_plesk(argv, **kw):
            if argv[:2] == ["plesk", "version"]:
                import subprocess
                return subprocess.CompletedProcess(argv, 127, "", "plesk: command not found")
            return original(argv, **kw)

        transport.exec = exec_without_plesk
        results = {r.id: r for r in check_source(ctx)}
        self.assertEqual(results["src.plesk"].status, FAIL)


class TestTargetChecks(unittest.TestCase):
    def setUp(self):
        self.ctx = demo_context()
        self.inv = PleskExporter(self.ctx).discover()

    def run_checks(self, **kw):
        kw.setdefault("mail_hostname", "mail.acme-shop.com")
        kw.setdefault("ptr_lookup", demo_ptr_lookup)
        return check_target(self.ctx, self.inv.domains, **kw)

    def test_demo_target_has_expected_warnings(self):
        results, info = self.run_checks()
        status = {r.id: r.status for r in results}
        self.assertFalse(has_failures(results))
        self.assertEqual(status["dst.smtp_out"], WARN)   # port 25 blocked in the demo
        self.assertEqual(status["dst.ptr"], WARN)
        self.assertEqual(status["dst.os"], OK)
        self.assertEqual(info["php_version"], "8.3")

    def test_php_warnings_are_grouped_per_version(self):
        results, _ = self.run_checks()
        php = [r for r in results if r.id.startswith("dst.php.")]
        self.assertEqual(sorted(r.id for r in php), ["dst.php.7.4", "dst.php.8.1"])
        grouped = next(r for r in php if r.id == "dst.php.8.1")
        self.assertIn("mueller-architekten.de", grouped.detail)
        self.assertIn("mueller-bau.de", grouped.detail)

    def test_invalid_mail_hostname_fails(self):
        results, _ = self.run_checks(mail_hostname="not a hostname")
        self.assertEqual({r.id: r.status for r in results}["dst.mailhost"], FAIL)

    def test_matching_ptr_is_ok(self):
        results, _ = self.run_checks(ptr_lookup=lambda host: "mail.acme-shop.com.")
        self.assertEqual({r.id: r.status for r in results}["dst.ptr"], OK)

    def test_tcp_probe_never_interpolates_host_into_shell(self):
        seen = []
        transport = self.ctx.runner.transport("root@new")
        original = transport.exec

        def spy(argv, **kw):
            seen.append(list(argv))
            return original(argv, **kw)

        transport.exec = spy
        self.ctx.config.old_server = "root@evil;rm -rf /"
        self.run_checks()
        probes = [a for a in seen if a[:1] == ["timeout"] and "bash" in a]
        self.assertTrue(probes)
        for argv in probes:
            self.assertEqual(argv[argv.index("-c") + 1], "exec 3<>/dev/tcp/$0/$1")


if __name__ == "__main__":
    unittest.main()
