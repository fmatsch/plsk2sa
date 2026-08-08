import unittest

from plsk2sa.runner import Runner


class TestRunner(unittest.TestCase):
    def test_local_argv_passthrough(self):
        r = Runner()
        self.assertEqual(r._argv("local", ["echo", "hallo welt"]),
                         ["echo", "hallo welt"])

    def test_ssh_argv_quotes_arguments(self):
        r = Runner(ssh_options=["-o", "BatchMode=yes"])
        argv = r._argv("root@host", ["echo", "hallo welt", "a;b"])
        self.assertEqual(argv[:4], ["ssh", "-o", "BatchMode=yes", "root@host"])
        self.assertEqual(argv[4], "echo 'hallo welt' 'a;b'")

    def test_dry_run_skips_mutating(self):
        r = Runner(dry_run=True)
        cp = r.run("local", ["rm", "-rf", "/darf/nicht/passieren"])
        self.assertEqual(cp.returncode, 0)

    def test_dry_run_executes_readonly(self):
        r = Runner(dry_run=True)
        cp = r.run("local", ["echo", "lesen"], mutating=False)
        self.assertEqual(cp.stdout.strip(), "lesen")

    def test_local_run_and_script(self):
        r = Runner()
        self.assertEqual(r.run("local", ["echo", "x"]).stdout.strip(), "x")
        self.assertEqual(r.script("local", "echo skript").stdout.strip(), "skript")

    def test_put_rejects_heredoc_token(self):
        r = Runner(dry_run=True)
        with self.assertRaises(ValueError):
            r.put("local", "/tmp/x", "enthält PLSK2SA_EOF token")


if __name__ == "__main__":
    unittest.main()
