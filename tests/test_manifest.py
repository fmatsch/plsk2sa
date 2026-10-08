import json
import tempfile
import unittest
from pathlib import Path

from plsk2sa.manifest import Domain, Manifest, ManifestError


def make_domain(**overrides):
    data = dict(
        name="example.de",
        docroot_src="/var/www/vhosts/example.de/httpdocs",
        php="8.3",
        databases=["example_db"],
        mailboxes=["info", "max.mustermann"],
        aliases=[["kontakt", "info@example.de"]],
    )
    data.update(overrides)
    return Domain(**data)


class TestDomain(unittest.TestCase):
    def test_valid_domain_has_no_problems(self):
        self.assertEqual(make_domain().validate(), [])

    def test_derived_paths(self):
        d = make_domain()
        self.assertEqual(d.docroot, "/var/www/example.de")
        self.assertEqual(d.site_user, "w_example_de")

    def test_invalid_values_are_reported(self):
        d = make_domain(name="kein_domainname", php="acht",
                        docroot_src="relativ/pfad",
                        databases=["böse;drop"],
                        aliases=[["nur-ein-feld"]])
        problems = "\n".join(d.validate())
        for fragment in ("domain name", "PHP version", "absolute path",
                         "database name", "alias"):
            self.assertIn(fragment, problems)


class TestManifest(unittest.TestCase):
    def test_roundtrip_via_json(self):
        m = Manifest(source="root@alt", domains=[make_domain()])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            m.save(path)
            loaded = Manifest.load(path)
        self.assertEqual(loaded.to_dict(), m.to_dict())

    def test_load_rejects_invalid_manifest(self):
        m = Manifest(source="root@alt", domains=[make_domain(php="kaputt")])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            path.write_text(json.dumps(m.to_dict()))
            with self.assertRaises(ManifestError):
                Manifest.load(path)

    def test_load_missing_file(self):
        with self.assertRaises(ManifestError):
            Manifest.load("/gibt/es/nicht/manifest.json")

    def test_duplicate_domains_detected(self):
        m = Manifest(source="x", domains=[make_domain(), make_domain()])
        self.assertTrue(any("twice" in p for p in m.validate()))


if __name__ == "__main__":
    unittest.main()
