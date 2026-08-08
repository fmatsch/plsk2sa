import unittest

from plsk2sa.render import RenderError, render, render_template


class TestRender(unittest.TestCase):
    def test_replaces_placeholders(self):
        self.assertEqual(render("a {{X}} b {{X}}{{Y}}", {"X": "1", "Y": "2"}),
                         "a 1 b 12")

    def test_missing_variable_raises(self):
        with self.assertRaises(RenderError):
            render("hallo {{FEHLT}}", {})

    def test_leaves_shell_and_nginx_vars_alone(self):
        text = "try_files $uri $uri/ /index.php?$args; $(cat x) %{http_code}"
        self.assertEqual(render(text, {}), text)

    def test_real_templates_render_completely(self):
        mapping = {"DOMAIN": "example.de", "DOCROOT": "/var/www/example.de",
                   "SITEUSER": "w_example_de", "PHP": "8.3"}
        for name in ("nginx-vhost.conf", "php-fpm-pool.conf"):
            out = render_template(name, mapping)
            self.assertNotIn("{{", out, f"{name}: unaufgelöste Platzhalter")
            self.assertIn("example.de", out)
        out = render_template("postfix-setup.sh", {"MAIL_HOSTNAME": "mail.example.de"})
        self.assertIn("myhostname = mail.example.de", out)
        self.assertNotIn("{{", out)


if __name__ == "__main__":
    unittest.main()
