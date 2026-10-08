import json
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from plsk2sa.demo import DEMO_FINGERPRINT
from plsk2sa.ui.backend import Backend, UserError
from plsk2sa.ui.server import create_server
from support import temp_workdir

TOKEN = "test-token-123"
DNS = {"mode": "external", "old_ips": ["203.0.113.10"], "new_ipv4": "203.0.113.20", "new_ipv6": ""}


class ServerCase(unittest.TestCase):
    def setUp(self):
        self.backend = Backend(Path(temp_workdir()), demo=True, demo_delay=0)
        self.server = create_server(self.backend, port=0, token=TOKEN)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.backend.close()

    def request(self, method, path, body=None, headers=None, token=TOKEN, raw=None):
        h = {"Host": f"127.0.0.1:{self.port}"}
        if token is not None:
            h["X-Plsk2sa-Token"] = token
        data = raw
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        h.update(headers or {})
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=data,
                                     method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def api(self, method, path, body=None, **kw):
        status, headers, data = self.request(method, path, body, **kw)
        return status, json.loads(data.decode())


class TestServerSecurity(ServerCase):
    def test_serves_page_with_strict_headers(self):
        status, headers, body = self.request("GET", "/", token=None)
        self.assertEqual(status, 200)
        self.assertIn(b"plsk2sa", body)
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")

    def test_page_has_no_inline_script_or_third_party_resources(self):
        _, _, html = self.request("GET", "/", token=None)
        _, _, js = self.request("GET", "/app.js", token=None)
        text = html.decode()
        self.assertNotIn("http://", text.replace("http://www.w3.org", ""))
        self.assertNotIn("https://", text)
        self.assertNotIn("innerHTML", js.decode())

    def test_api_requires_token(self):
        self.assertEqual(self.request("GET", "/api/state", token=None)[0], 401)
        self.assertEqual(self.request("GET", "/api/state", token="wrong")[0], 401)
        self.assertEqual(self.request("GET", "/api/state")[0], 200)

    def test_foreign_host_header_is_rejected(self):
        for host in ("evil.example.com", f"evil.example.com:{self.port}", "127.0.0.1"):
            status, _, _ = self.request("GET", "/api/state", headers={"Host": host})
            self.assertEqual(status, 403, host)
            status, _, _ = self.request("GET", "/", headers={"Host": host}, token=None)
            self.assertEqual(status, 403, host)

    def test_localhost_name_is_allowed(self):
        status, _, _ = self.request("GET", "/api/state", headers={"Host": f"localhost:{self.port}"})
        self.assertEqual(status, 200)

    def test_post_requires_json_content_type(self):
        status, _, _ = self.request("POST", "/api/run/cancel", raw=b"{}",
                                    headers={"Content-Type": "text/plain"})
        self.assertEqual(status, 415)

    def test_invalid_json_and_non_object_rejected(self):
        h = {"Content-Type": "application/json"}
        self.assertEqual(self.request("POST", "/api/run/cancel", raw=b"{nope", headers=h)[0], 400)
        self.assertEqual(self.request("POST", "/api/run/cancel", raw=b"[1]", headers=h)[0], 400)

    def test_unknown_paths_and_traversal(self):
        self.assertEqual(self.request("GET", "/nope", token=None)[0], 404)
        self.assertEqual(self.request("GET", "/../../etc/passwd", token=None)[0], 404)
        self.assertEqual(self.request("GET", "/api/unknown")[0], 404)
        self.assertEqual(self.request("GET", "/static/app.js", token=None)[0], 404)


class TestWizardFlow(ServerCase):
    def connect(self, role, host, **extra):
        body = {"host": host, "port": 22, "user": "root", "auth": "password", "password": "x"}
        body.update(extra)
        return self.api("POST", f"/api/{role}/connect", body)[1]

    def connect_both(self):
        self.assertIn("host_key", self.connect("source", "plesk.example.com"))
        ok = self.connect("source", "plesk.example.com", accept_fingerprint=DEMO_FINGERPRINT)
        self.assertTrue(ok["ok"])
        ok = self.connect("target", "new.example.com", accept_fingerprint=DEMO_FINGERPRINT)
        self.assertTrue(ok["ok"])

    def wait_for_run(self, timeout=30):
        deadline = time.time() + timeout
        since, log = 0, []
        while time.time() < deadline:
            _, status = self.api("GET", f"/api/run/status?since={since}")
            log += status["log"]
            since = status["next"]
            if status["state"] != "running":
                status["all_log"] = log
                return status
            time.sleep(0.05)
        self.fail("run did not finish")

    def test_state_reports_demo_mode(self):
        _, state = self.api("GET", "/api/state")
        self.assertTrue(state["demo"])
        self.assertIsNone(state["source"])
        self.assertEqual(state["run"]["state"], "idle")

    def test_full_flow_preview_then_real_run(self):
        self.connect_both()
        _, report = self.api("POST", "/api/source/checks", {})
        self.assertTrue(report["can_continue"])
        names = [d["name"] for d in report["inventory"]["domains"]]
        self.assertEqual(len(names), 4)

        chosen = ["acme-shop.com", "mueller-architekten.de"]
        _, target = self.api("POST", "/api/target/checks",
                             {"domains": chosen, "mail_hostname": "mail.acme-shop.com"})
        self.assertTrue(target["can_continue"])
        self.assertEqual(target["php_version"], "8.3")

        start = {"mode": "full", "dry_run": True, "domains": chosen, "mail_hostname": "mail.acme-shop.com",
                 "dns": DNS}
        self.assertEqual(self.api("POST", "/api/run/start", start)[0], 200)
        status = self.wait_for_run()
        self.assertEqual(status["state"], "done")
        self.assertTrue(status["result"]["dry_run"])
        self.assertTrue(any("dry-run:" in e["message"] for e in status["all_log"]))
        self.assertEqual(self.api("POST", "/api/run/reset", {})[0], 200)

        start.update(dry_run=False, confirmed=True)
        self.assertEqual(self.api("POST", "/api/run/start", start)[0], 200)
        status = self.wait_for_run()
        self.assertEqual(status["state"], "done", status["result"])
        result = status["result"]
        self.assertFalse(result["dry_run"])
        self.assertTrue(all(v["ok"] for v in result["verify"]))
        self.assertEqual({d["domain"] for d in result["dkim"]}, set(chosen))
        self.assertEqual([s["state"] for s in status["steps"]].count("done"), len(status["steps"]))

    def test_real_run_needs_explicit_confirmation(self):
        self.connect_both()
        self.api("POST", "/api/source/checks", {})
        self.api("POST", "/api/target/checks", {"domains": ["acme-shop.com"], "mail_hostname": "mail.acme-shop.com"})
        status, body = self.api("POST", "/api/run/start", {
            "mode": "full", "dry_run": False, "domains": ["acme-shop.com"],
            "mail_hostname": "mail.acme-shop.com", "dns": DNS})
        self.assertEqual(status, 400)
        self.assertIn("confirm", body["error"].lower())

    def test_cannot_start_without_connections_or_checks(self):
        status, body = self.api("POST", "/api/run/start", {"domains": ["x.com"]})
        self.assertEqual(status, 400)
        self.assertEqual(self.api("POST", "/api/source/checks", {})[0], 400)
        self.assertEqual(self.api("POST", "/api/target/checks", {"domains": ["x.com"]})[0], 400)

    def test_target_must_differ_from_source(self):
        self.connect("source", "same.example.com", accept_fingerprint=DEMO_FINGERPRINT)
        status, body = self.api("POST", "/api/target/connect", {
            "host": "SAME.example.com", "user": "root", "auth": "password", "password": "x"})
        self.assertEqual(status, 400)
        self.assertIn("different", body["error"])

    def test_unknown_domain_in_selection_is_rejected(self):
        self.connect_both()
        self.api("POST", "/api/source/checks", {})
        status, body = self.api("POST", "/api/target/checks",
                                {"domains": ["acme-shop.com", "ghost.example"], "mail_hostname": "mail.acme-shop.com"})
        self.assertEqual(status, 400)
        self.assertIn("ghost.example", body["error"])

    def test_connect_validates_input(self):
        for bad in ({"host": ""}, {"host": "a b"}, {"host": "x;rm -rf /"}, {"host": "ok.example", "port": "abc"},
                    {"host": "ok.example", "port": 70000}, {"host": "ok.example", "user": "ro ot"},
                    {"host": "ok.example", "auth": "magic"}):
            body = {"user": "root", "auth": "password", "password": "x"}
            body.update(bad)
            status, _ = self.api("POST", "/api/source/connect", body)
            self.assertEqual(status, 400, bad)

    def test_selection_change_flow_state_restore(self):
        self.connect_both()
        self.api("POST", "/api/source/checks", {})
        _, state = self.api("GET", "/api/state")
        self.assertEqual(state["source"]["host"], "plesk.example.com")
        self.assertEqual(state["target"]["host"], "new.example.com")
        self.assertTrue(state["source_report"]["can_continue"])
        self.assertIsNone(state["target_report"])
        # reconnecting the source invalidates everything downstream
        self.connect("source", "plesk.example.com", accept_fingerprint=DEMO_FINGERPRINT)
        _, state = self.api("GET", "/api/state")
        self.assertIsNone(state["source_report"])

    def test_passwords_never_appear_in_state_or_logs(self):
        self.connect("source", "plesk.example.com", password="SuperSecretPw!", accept_fingerprint=DEMO_FINGERPRINT)
        _, _, body = self.request("GET", "/api/state")
        self.assertNotIn(b"SuperSecretPw", body)


class TestBackendDirect(unittest.TestCase):
    def test_start_run_rejected_while_running_is_guarded(self):
        backend = Backend(Path(temp_workdir()), demo=True, demo_delay=0)
        backend.run.state = "running"
        with self.assertRaises(UserError):
            backend.connect("source", {"host": "x.example", "auth": "password"})
        with self.assertRaises(UserError):
            backend.source_checks()
        backend.close()

    def test_quit_endpoint_stops_server(self):
        backend = Backend(Path(temp_workdir()), demo=True, demo_delay=0)
        server = create_server(backend, port=0, token=TOKEN)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        req = urllib.request.Request(
            f"http://127.0.0.1:{server.server_address[1]}/api/quit", data=b"{}", method="POST",
            headers={"Host": f"127.0.0.1:{server.server_address[1]}", "X-Plsk2sa-Token": TOKEN,
                     "Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5).read()
        t.join(timeout=5)
        self.assertFalse(t.is_alive())
        server.server_close()


if __name__ == "__main__":
    unittest.main()
