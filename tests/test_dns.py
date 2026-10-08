import argparse
import contextlib
import io
import unittest

from plsk2sa import dnsplan
from plsk2sa.dnsplan import (ADD, CHANGE, KEEP, REMOVE, REVIEW, DnsOptions, DnsRecord, build_report,
                             clean_name, parse_records, plan_domain)
from plsk2sa.plesk_export import PleskExporter
from support import demo_context

OLD, NEW = "203.0.113.10", "203.0.113.20"
D = "example.com"


def rec(name, type_, value, opt=""):
    return DnsRecord(name, type_, value, opt)


def opts(**kw):
    kw.setdefault("plesk_dns", False)
    kw.setdefault("old_ips", [OLD])
    kw.setdefault("new_ipv4", NEW)
    return DnsOptions(**kw)


def find(changes, type_, name):
    return next(c for c in changes if c.type == type_ and c.name == name)


class TestParsing(unittest.TestCase):
    def test_names_are_made_absolute(self):
        self.assertEqual(clean_name("www.example.com.", D), "www.example.com")
        self.assertEqual(clean_name("www", D), "www.example.com")
        self.assertEqual(clean_name("@", D), D)
        self.assertEqual(clean_name("", D), D)
        self.assertEqual(clean_name("mail.other.org.", D), "mail.other.org")

    def test_parse_rows_skips_soa_and_unselected(self):
        rows = [[D, "A", "example.com.", OLD, "NULL"], [D, "SOA", "example.com.", "x", ""],
                [D, "MX", "example.com.", "mail.example.com.", "10"], ["other.org", "A", "other.org.", "1.2.3.4", ""]]
        parsed = parse_records(rows, {D})
        self.assertEqual(list(parsed), [D])
        self.assertEqual([r.type for r in parsed[D]], ["A", "MX"])
        self.assertEqual(parsed[D][1].opt, "10")
        self.assertEqual(parsed[D][0].opt, "")


class TestPlan(unittest.TestCase):
    def plan(self, records, **kw):
        return plan_domain(D, records, kw.pop("opts", opts()), **kw).changes

    def test_a_record_of_old_server_changes_others_stay(self):
        ch = self.plan([rec(D, "A", OLD), rec(f"shop.{D}", "A", "198.51.100.7")])
        self.assertEqual((find(ch, "A", D).action, find(ch, "A", D).new), (CHANGE, NEW))
        self.assertEqual(find(ch, "A", f"shop.{D}").action, KEEP)

    def test_ipv6_is_always_a_review_item(self):
        ch = self.plan([rec(D, "AAAA", "2001:db8::10")])
        self.assertEqual(find(ch, "AAAA", D).action, REVIEW)
        ch = self.plan([rec(D, "AAAA", "2001:db8::10")], opts=opts(new_ipv6="2001:db8::20"))
        self.assertEqual(find(ch, "AAAA", D).new, "2001:db8::20")

    def test_ns_only_matters_when_plesk_hosts_the_dns(self):
        records = [rec(D, "NS", "ns1.example.com.")]
        self.assertFalse([c for c in self.plan(records) if c.type == "NS"])
        ns = find(self.plan(records, opts=opts(plesk_dns=True)), "NS", D)
        self.assertEqual(ns.action, REVIEW)

    def test_spf_old_address_is_replaced(self):
        spf = f"v=spf1 +a +mx ip4:{OLD} ip4:{OLD}/32 ip4:198.51.100.7 ~all"
        c = find(self.plan([rec(D, "TXT", spf)]), "TXT", D)
        self.assertEqual(c.action, CHANGE)
        self.assertEqual(c.new, f"v=spf1 +a +mx ip4:{NEW} ip4:{NEW}/32 ip4:198.51.100.7 ~all")

    def test_spf_without_old_address_stays(self):
        c = find(self.plan([rec(D, "TXT", "v=spf1 include:_spf.google.com ~all")]), "TXT", D)
        self.assertEqual(c.action, KEEP)

    def test_old_plesk_dkim_is_marked_for_removal_other_selectors_stay(self):
        ch = self.plan([rec(f"default._domainkey.{D}", "TXT", "v=DKIM1; p=OLD"),
                        rec(f"google._domainkey.{D}", "TXT", "v=DKIM1; p=G")])
        self.assertEqual(find(ch, "TXT", f"default._domainkey.{D}").action, REMOVE)
        self.assertEqual(find(ch, "TXT", f"google._domainkey.{D}").action, KEEP)

    def test_new_dkim_record_is_added_with_value_or_placeholder(self):
        name = f"mail._domainkey.{D}"
        placeholder = find(self.plan([]), "TXT", name)
        self.assertEqual((placeholder.action, placeholder.new), (ADD, dnsplan.DKIM_PLACEHOLDER))
        real = find(self.plan([], dkim_value="v=DKIM1; p=NEW"), "TXT", name)
        self.assertEqual(real.new, "v=DKIM1; p=NEW")

    def test_mail_host_a_record_is_added_only_when_missing_and_inside_the_zone(self):
        host = f"mail.{D}"
        added = [c for c in self.plan([], mail_hostname=host) if c.action == ADD and c.type == "A"]
        self.assertEqual([(c.name, c.new) for c in added], [(host, NEW)])
        existing = [c for c in self.plan([rec(host, "A", OLD)], mail_hostname=host) if c.action == ADD and c.type == "A"]
        self.assertEqual(existing, [])
        elsewhere = [c for c in self.plan([], mail_hostname="mail.other.org") if c.action == ADD and c.type == "A"]
        self.assertEqual(elsewhere, [])

    def test_mx_and_cname_are_kept(self):
        ch = self.plan([rec(D, "MX", "mail.example.com.", "10"), rec(f"www.{D}", "CNAME", "example.com.")])
        self.assertEqual(find(ch, "MX", D).old, "10 mail.example.com")
        self.assertEqual(find(ch, "CNAME", f"www.{D}").action, KEEP)

    def test_empty_zone_is_explained(self):
        d = plan_domain(D, [], opts())
        self.assertIn("no DNS records", d.note)


class TestZoneFile(unittest.TestCase):
    def zone(self, records, **kw):
        return plan_domain(D, records, opts(plesk_dns=True, **kw.pop("o", {})), **kw).zone

    def test_zone_contains_new_values_and_skips_ns_and_removed(self):
        z = self.zone([rec(D, "A", OLD), rec(D, "NS", "ns1.example.com."), rec(f"www.{D}", "CNAME", "example.com."),
                       rec(D, "MX", "mail.example.com.", "10"),
                       rec(D, "TXT", f"v=spf1 ip4:{OLD} ~all"),
                       rec(f"default._domainkey.{D}", "TXT", "v=DKIM1; p=OLD")], dkim_value="v=DKIM1; p=NEW")
        self.assertIn("$ORIGIN example.com.", z)
        self.assertIn(f"@\tIN\tA\t{NEW}", z)
        self.assertNotIn(OLD, z)
        self.assertIn("www\tIN\tCNAME\texample.com.", z)
        self.assertIn("@\tIN\tMX\t10 mail.example.com.", z)
        self.assertIn(f'"v=spf1 ip4:{NEW} ~all"', z)
        self.assertIn('mail._domainkey\tIN\tTXT\t"v=DKIM1; p=NEW"', z)
        self.assertNotIn("IN\tNS", z)
        self.assertNotIn("default._domainkey", z)

    def test_long_txt_is_split_into_255_char_chunks_and_quotes_are_escaped(self):
        long_value = 'v=DKIM1; k=rsa; p=' + "A" * 400 + '"'
        z = self.zone([rec(f"x._domainkey.{D}", "TXT", long_value)])
        line = next(l for l in z.splitlines() if l.startswith("x._domainkey"))
        self.assertGreaterEqual(line.count('" "'), 1)
        self.assertIn('\\"', line)

    def test_ipv6_is_exported_only_with_a_new_address(self):
        without = self.zone([rec(D, "AAAA", "2001:db8::10")])
        self.assertNotIn("IN\tAAAA", without)
        self.assertIn("REVIEW: AAAA", without)
        with_new = self.zone([rec(D, "AAAA", "2001:db8::10")], o={"new_ipv6": "2001:db8::20"})
        self.assertIn("IN\tAAAA\t2001:db8::20", with_new)

    def test_placeholder_dkim_becomes_a_comment(self):
        z = self.zone([])
        self.assertNotIn(dnsplan.DKIM_PLACEHOLDER, z)
        self.assertIn("created during the migration", z)
        self.assertNotIn("IN\tTXT", z)


class TestOptions(unittest.TestCase):
    def test_validation(self):
        self.assertEqual(opts().validate(), [])
        self.assertTrue(opts(new_ipv4="999.1.1.1").validate())
        self.assertTrue(opts(new_ipv4="").validate())
        self.assertTrue(opts(old_ips=["not-an-ip"]).validate())
        self.assertTrue(opts(new_ipv6="1.2.3.4").validate())


class TestDemoZonesEndToEnd(unittest.TestCase):
    def test_report_for_the_demo_server(self):
        ctx = demo_context()
        exporter = PleskExporter(ctx)
        records = exporter.fetch_dns_records(["acme-shop.com", "mueller-bau.de"])
        self.assertEqual(exporter.fetch_server_ips(), ["203.0.113.10"])
        report = build_report(["acme-shop.com", "mueller-bau.de"], records, opts(plesk_dns=True),
                              mail_hostname="mail.acme-shop.com")
        acme = next(d for d in report.domains if d.domain == "acme-shop.com")
        actions = {(c.type, c.name): c.action for c in acme.changes}
        self.assertEqual(actions[("A", "acme-shop.com")], CHANGE)
        self.assertEqual(actions[("A", "shop.acme-shop.com")], KEEP)      # CDN address stays
        self.assertEqual(actions[("TXT", "acme-shop.com")], CHANGE)       # SPF
        self.assertEqual(actions[("TXT", "default._domainkey.acme-shop.com")], REMOVE)
        self.assertEqual(actions[("AAAA", "acme-shop.com")], REVIEW)
        self.assertIsNotNone(acme.zone)
        self.assertNotIn("203.0.113.10", acme.zone)

    def test_cli_dns_command_prints_the_plan_and_writes_zone_files(self):
        from plsk2sa.cli import cmd_dns
        ctx = demo_context()
        PleskExporter(ctx).export(only=["acme-shop.com"])
        args = argparse.Namespace(new_ip=NEW, old_ip=[OLD], new_ipv6=None, plesk_dns=True, domain=None)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cmd_dns(ctx, args)
        self.assertIn("== acme-shop.com ==", out.getvalue())
        self.assertIn("[CHANGE]", out.getvalue())
        self.assertTrue((ctx.dns_dir / "acme-shop.com.zone").is_file())


if __name__ == "__main__":
    unittest.main()
