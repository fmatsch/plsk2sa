import unittest

from plsk2sa.plesk_export import parse_mail_auth

SAMPLE = """\
+----------------------+-------------+--------------+
| address              | type        | password     |
+----------------------+-------------+--------------+
| info@example.de      | plain       | s3cret!      |
| max@beispiel.de      | plain       | geheim wort  |
| leer@beispiel.de     | plain       |              |
+----------------------+-------------+--------------+
"""


class TestParseMailAuth(unittest.TestCase):
    def test_parses_data_rows_only(self):
        entries = parse_mail_auth(SAMPLE)
        self.assertEqual(entries, [
            ("info@example.de", "s3cret!"),
            ("max@beispiel.de", "geheim wort"),
        ])

    def test_password_keeps_inner_spaces(self):
        entries = dict(parse_mail_auth(SAMPLE))
        self.assertEqual(entries["max@beispiel.de"], "geheim wort")

    def test_skips_rows_without_password(self):
        entries = dict(parse_mail_auth(SAMPLE))
        self.assertNotIn("leer@beispiel.de", entries)

    def test_empty_input(self):
        self.assertEqual(parse_mail_auth(""), [])


if __name__ == "__main__":
    unittest.main()
