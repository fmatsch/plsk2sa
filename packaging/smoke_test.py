"""Smoke test for a built program (or `python -m plsk2sa`):

    python packaging/smoke_test.py dist/plsk2sa
    python packaging/smoke_test.py python -m plsk2sa

Starts the GUI in demo mode, drives the whole wizard over HTTP (connect,
checks, preview run) and fails loudly if anything is missing from the
bundle - the preview run loads every bundled template.
"""

import json
import queue
import re
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

FINGERPRINT = "SHA256:DEMOdemoDEMOdemoDEMOdemoDEMOdemoDEMO0"


def main(command):
    version = subprocess.run(command + ["--version"], capture_output=True, text=True, timeout=120)
    assert version.returncode == 0 and "plsk2sa" in version.stdout, f"--version failed: {version}"
    print("version:", version.stdout.strip())

    with tempfile.TemporaryDirectory() as workdir:
        proc = subprocess.Popen(
            command + ["ui", "--demo", "--no-browser", "--port", "0", "--demo-delay", "0",
                       "--workdir", workdir],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        lines = queue.Queue()
        threading.Thread(target=lambda: [lines.put(l) for l in proc.stdout], daemon=True).start()
        try:
            url = None
            deadline = time.time() + 120
            while time.time() < deadline and url is None:
                try:
                    m = re.search(r"http://127\.0\.0\.1:(\d+)/#token=(\S+)", lines.get(timeout=1))
                    url = m and (int(m.group(1)), m.group(2))
                except queue.Empty:
                    assert proc.poll() is None, "program exited before printing its link"
            assert url, "program did not print its link in time"
            port, token = url
            drive(port, token)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
    print("smoke test passed")


def drive(port, token):
    def call(method, path, body=None):
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}{path}", method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"X-Plsk2sa-Token": token, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            raise AssertionError(f"{method} {path} -> {e.code}: {e.read()[:200]}")

    with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=30) as r:
        assert b"plsk2sa" in r.read(), "index page missing"
    for asset in ("app.js", "style.css"):
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/{asset}", timeout=30) as r:
            assert r.status == 200, asset

    assert call("GET", "/api/state")["demo"] is True
    cred = {"user": "root", "auth": "password", "password": "x"}
    assert "host_key" in call("POST", "/api/source/connect", {"host": "plesk.example.com", **cred})
    assert call("POST", "/api/source/connect",
                {"host": "plesk.example.com", "accept_fingerprint": FINGERPRINT, **cred})["ok"]
    report = call("POST", "/api/source/checks", {})
    assert report["can_continue"] and len(report["inventory"]["domains"]) == 4
    assert call("POST", "/api/target/connect",
                {"host": "new.example.com", "accept_fingerprint": FINGERPRINT, **cred})["ok"]
    domains = ["acme-shop.com", "mueller-architekten.de"]
    assert call("POST", "/api/target/checks",
                {"domains": domains, "mail_hostname": "mail.acme-shop.com"})["can_continue"]
    call("POST", "/api/run/start", {
        "mode": "full", "dry_run": True, "domains": domains, "mail_hostname": "mail.acme-shop.com",
        "dns": {"mode": "plesk", "old_ips": ["203.0.113.10"], "new_ipv4": "203.0.113.20"}})
    deadline = time.time() + 120
    while time.time() < deadline:
        status = call("GET", "/api/run/status?since=0")
        if status["state"] != "running":
            break
        time.sleep(0.2)
    assert status["state"] == "done", f"preview run ended as {status['state']}: {status['result']}"
    dns = status["result"]["dns"]
    assert dns and dns["mode"] == "plesk" and all(d["zone"] for d in dns["domains"]), "no DNS zones in the result"
    assert status["source_state"] == "unchanged", "a preview must not change the Plesk server"
    print("wizard flow ok:", [s["state"] for s in status["steps"]])


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1:])
