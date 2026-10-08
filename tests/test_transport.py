import sys
import tempfile
import unittest
from pathlib import Path

try:
    import paramiko
    from sshserver import FakeSSHServer
except ImportError:  # pragma: no cover
    paramiko = None

from plsk2sa.runner import CommandError, Runner
from plsk2sa.transport import (AuthenticationFailed, HostKeyMismatch,
                               HostKeyUnknown, LocalTransport, OpenSSHTransport,
                               ParamikoTransport, fingerprint)


NO_BASH = unittest.skipIf(sys.platform.startswith("win"),
                          "needs a POSIX shell; the controller never runs local commands on Windows")


class TestOpenSSHTransport(unittest.TestCase):
    def test_argv_quotes_arguments(self):
        t = OpenSSHTransport("root@host", ["-o", "BatchMode=yes"])
        argv = t.argv(["echo", "hallo welt", "a;b"])
        self.assertEqual(argv[:4], ["ssh", "-o", "BatchMode=yes", "root@host"])
        self.assertEqual(argv[4], "echo 'hallo welt' 'a;b'")


@NO_BASH
class TestLocalTransport(unittest.TestCase):
    def test_exec_stdin_and_exit_code(self):
        t = LocalTransport()
        cp = t.exec(["bash", "-c", "cat; echo err >&2; exit 3"], stdin_text="hi")
        self.assertEqual((cp.returncode, cp.stdout, cp.stderr.strip()), (3, "hi", "err"))


@unittest.skipIf(paramiko is None, "paramiko not installed")
class TestParamikoTransport(unittest.TestCase):
    def setUp(self):
        self.server = FakeSSHServer(password="secret")
        self.tmp = tempfile.TemporaryDirectory()
        self.known_hosts = Path(self.tmp.name) / "known_hosts"

    def tearDown(self):
        self.server.close()
        self.tmp.cleanup()

    def connect(self, **overrides):
        args = dict(host="127.0.0.1", port=self.server.port, user="root",
                    auth="password", password="secret",
                    known_hosts_file=self.known_hosts, timeout=10)
        args.update(overrides)
        return ParamikoTransport.connect(**args)

    def fp(self):
        return fingerprint(self.server.host_key)

    def test_unknown_host_key_requires_confirmation(self):
        with self.assertRaises(HostKeyUnknown) as ctx:
            self.connect()
        self.assertEqual(ctx.exception.fingerprint, self.fp())
        self.assertFalse(self.known_hosts.exists())

    def test_wrong_fingerprint_is_not_accepted(self):
        with self.assertRaises(HostKeyUnknown):
            self.connect(accept_fingerprint="SHA256:wrong")

    @NO_BASH
    def test_accepted_key_is_persisted(self):
        t = self.connect(accept_fingerprint=self.fp())
        t.close()
        self.assertTrue(self.known_hosts.is_file())
        t2 = self.connect()  # no confirmation needed any more
        self.assertEqual(t2.exec(["echo", "ok"]).stdout.strip(), "ok")
        t2.close()

    def test_changed_host_key_is_rejected(self):
        t = self.connect(accept_fingerprint=self.fp())
        t.close()
        # known_hosts now claims a different key for this host:port than the server presents
        name = self.known_hosts.read_text().split()[0]
        other = paramiko.ECDSAKey.generate()
        self.known_hosts.write_text(f"{name} {other.get_name()} {other.get_base64()}\n")
        with self.assertRaises(HostKeyMismatch):
            self.connect()

    def test_wrong_password(self):
        with self.assertRaises(AuthenticationFailed):
            self.connect(password="nope", accept_fingerprint=self.fp())

    @NO_BASH
    def test_exec_roundtrip(self):
        t = self.connect(accept_fingerprint=self.fp())
        try:
            cp = t.exec(["echo", "hallo welt; $(touch /tmp/never)"])
            self.assertEqual(cp.stdout.strip(), "hallo welt; $(touch /tmp/never)")
            cp = t.exec(["bash", "-c", "echo out; echo err >&2; exit 7"])
            self.assertEqual((cp.returncode, cp.stdout.strip(), cp.stderr.strip()),
                             (7, "out", "err"))
            self.assertEqual(t.exec(["cat"], stdin_text="Grüße").stdout, "Grüße")
        finally:
            t.close()

    @NO_BASH
    def test_stdin_file_and_binary_stdout(self):
        t = self.connect(accept_fingerprint=self.fp())
        try:
            src = Path(self.tmp.name) / "in.bin"
            dst = Path(self.tmp.name) / "out.bin"
            payload = bytes(range(256)) * 20000  # ~5 MB, exercises chunking
            src.write_bytes(payload)
            cp = t.exec(["cat"], stdin_path=src, stdout_path=dst)
            self.assertEqual(cp.returncode, 0)
            self.assertEqual(dst.read_bytes(), payload)
        finally:
            t.close()

    def test_host_key_line_format(self):
        t = self.connect(accept_fingerprint=self.fp())
        try:
            line = t.host_key_line()
            self.assertTrue(line.startswith(f"[127.0.0.1]:{self.server.port} ecdsa-sha2-"))
        finally:
            t.close()

    @NO_BASH
    def test_runner_uses_registered_transport(self):
        t = self.connect(accept_fingerprint=self.fp())
        runner = Runner()
        runner.register("root@box", t)
        try:
            self.assertEqual(runner.run("root@box", ["echo", "via runner"]).stdout.strip(),
                             "via runner")
            with self.assertRaises(CommandError):
                runner.run("root@box", ["bash", "-c", "exit 2"])
            self.assertEqual(runner.script("root@box", "echo skript").stdout.strip(), "skript")
        finally:
            runner.close()


if __name__ == "__main__":
    unittest.main()
