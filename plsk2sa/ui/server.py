"""Local web server for the GUI.

Security model - this program can run commands as root on servers, so the
local interface is locked down:
  * binds to 127.0.0.1 only,
  * every API call needs a random per-start token (sent as a header; the
    page receives it in the URL fragment, which is never sent over the
    network or leaked via Referer),
  * the Host header must be the loopback address (blocks DNS rebinding),
  * POST bodies must be application/json (forces a CORS preflight for
    foreign web pages, which this server never answers),
  * a strict Content-Security-Policy and no third-party resources.
"""

import argparse
import hmac
import json
import logging
import secrets
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

from .. import __version__
from .backend import Backend, UserError

log = logging.getLogger("plsk2sa")

STATIC_DIR = Path(__file__).parent / "static"
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}
MAX_BODY = 1024 * 1024

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class AppServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, backend: Backend, token: str):
        super().__init__(address, Handler)
        self.backend = backend
        self.token = token
        port = self.server_address[1]
        self.allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}


class Handler(BaseHTTPRequestHandler):
    server_version = "plsk2sa"
    protocol_version = "HTTP/1.0"  # one request per connection: no unread-body pitfalls

    def log_message(self, fmt, *args):  # keep the console quiet
        log.debug("http: " + fmt, *args)

    # ------------------------------------------------------------------
    def _send(self, status: int, body: bytes, content_type: str, extra=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", CSP)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict):
        self._send(status, json.dumps(payload).encode("utf-8"), "application/json")

    def _host_ok(self) -> bool:
        return self.headers.get("Host", "") in self.server.allowed_hosts

    def _token_ok(self) -> bool:
        supplied = self.headers.get("X-Plsk2sa-Token", "")
        return hmac.compare_digest(supplied.encode(), self.server.token.encode())

    # ------------------------------------------------------------------
    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def _handle(self, method: str):
        if not self._host_ok():
            return self._json(403, {"error": "Forbidden host"})
        url = urlparse(self.path)
        path = url.path

        if method == "GET" and path in STATIC_FILES:
            name, ctype = STATIC_FILES[path]
            return self._send(200, (STATIC_DIR / name).read_bytes(), ctype)
        if not path.startswith("/api/"):
            return self._json(404, {"error": "Not found"})
        if not self._token_ok():
            return self._json(401, {"error": "Invalid or missing token - reopen the link printed by the program"})

        body = {}
        if method == "POST":
            if "application/json" not in self.headers.get("Content-Type", ""):
                return self._json(415, {"error": "JSON required"})
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                return self._json(413, {"error": "Request too large"})
            raw = self.rfile.read(length) if length else b""
            try:
                body = json.loads(raw.decode("utf-8")) if raw else {}
            except (ValueError, UnicodeDecodeError):
                return self._json(400, {"error": "Invalid JSON"})
            if not isinstance(body, dict):
                return self._json(400, {"error": "Expected a JSON object"})

        backend: Backend = self.server.backend
        routes = {
            ("GET", "/api/state"): lambda: backend.state(),
            ("GET", "/api/run/status"): lambda: backend.run_status(
                int(parse_qs(url.query).get("since", ["0"])[0] or 0)),
            ("POST", "/api/source/connect"): lambda: backend.connect("source", body),
            ("POST", "/api/source/checks"): lambda: backend.source_checks(),
            ("POST", "/api/target/connect"): lambda: backend.connect("target", body),
            ("POST", "/api/target/checks"): lambda: backend.target_checks(body),
            ("POST", "/api/run/start"): lambda: backend.start_run(body),
            ("POST", "/api/run/cancel"): lambda: backend.cancel_run(),
            ("POST", "/api/run/reset"): lambda: backend.reset_run(),
            ("POST", "/api/open-workdir"): lambda: backend.open_workdir(),
            ("POST", "/api/quit"): self._quit,
        }
        handler = routes.get((method, path))
        if handler is None:
            return self._json(404, {"error": "Not found"})
        try:
            self._json(200, handler())
        except UserError as e:
            self._json(400, {"error": str(e)})
        except ValueError as e:
            self._json(400, {"error": f"Invalid request: {e}"})
        except Exception as e:  # noqa: BLE001 - report instead of dropping the connection
            log.exception("Unhandled error in %s %s", method, path)
            self._json(500, {"error": f"Unexpected error: {e}"})

    def _quit(self):
        threading.Thread(target=self.server.shutdown, daemon=True).start()
        return {"ok": True}


def create_server(backend: Backend, port: int = 0, token: Optional[str] = None) -> AppServer:
    return AppServer(("127.0.0.1", port), backend, token or secrets.token_urlsafe(24))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="plsk2sa-gui",
        description="Graphical wizard for migrating Plesk hostings to a standalone Ubuntu server.")
    parser.add_argument("--version", action="version", version=f"plsk2sa {__version__}")
    parser.add_argument("--demo", action="store_true",
                        help="use simulated servers (nothing is contacted or changed)")
    parser.add_argument("--no-browser", action="store_true", help="do not open the browser")
    parser.add_argument("--port", type=int, default=0, help="port on 127.0.0.1 (default: any free port)")
    parser.add_argument("--workdir", help="working directory for dumps, secrets and logs")
    parser.add_argument("--token", help=argparse.SUPPRESS)
    parser.add_argument("--demo-delay", type=float, default=0.25, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    default_dir = "~/plsk2sa-work-demo" if args.demo else "~/plsk2sa-work"
    workdir = Path(args.workdir or default_dir).expanduser()
    backend = Backend(workdir, demo=args.demo, demo_delay=args.demo_delay)
    server = create_server(backend, args.port, args.token)

    url = f"http://127.0.0.1:{server.server_address[1]}/#token={server.token}"
    print(f"plsk2sa {__version__} - {'DEMO MODE (simulated servers)' if args.demo else 'GUI'}", flush=True)
    print(f"Working directory: {workdir}", flush=True)
    print(f"Open this link in your browser:\n\n  {url}\n", flush=True)
    print("Press Ctrl+C to quit.", flush=True)
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        backend.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
