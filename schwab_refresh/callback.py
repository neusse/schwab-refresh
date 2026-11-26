"""Local loopback callback server for the OAuth redirect.

Why a server at all: the browser must land somewhere after the consent flow,
and the URL it lands on carries ``?code=...&state=...``. Serving that URL makes
the capture deterministic; the browser URL is kept as a second capture path
for the case where the page itself fails to render.

TLS: Schwab requires an https redirect URI. We mint a self-signed leaf for
127.0.0.1/localhost and let Chrome skip the interstitial via
``--ignore-certificate-errors`` (see browser.py). That avoids installing a
root CA into the Windows trust store — the reference implementation's
macOS-keychain step has no clean Windows equivalent, and this needs no admin.
"""

from __future__ import annotations

import datetime as dt
import http.server
import ipaddress
import queue
import socket
import ssl
import threading
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

from schwab_refresh.config import Settings

_SUCCESS_HTML = b"""<!doctype html><html><head><meta charset="utf-8">
<title>Schwab login complete</title>
<style>body{font:16px/1.5 system-ui,sans-serif;margin:4rem auto;max-width:32rem}
code{background:#f2f2f2;padding:.1rem .3rem;border-radius:4px}</style></head>
<body><h1>Login complete</h1>
<p>The authorization code was received. You can close this tab.</p></body></html>"""


@dataclass(frozen=True)
class CallbackResult:
    code: str | None = None
    state: str | None = None
    error: str | None = None
    error_description: str | None = None
    url: str | None = None

    @property
    def should_stop(self) -> bool:
        return bool(self.code or self.error)


class CallbackError(Exception):
    pass


def _ensure_cert(cert_path: Path, key_path: Path) -> None:
    """Create (or reuse) a self-signed leaf for 127.0.0.1 / localhost / ::1."""
    if cert_path.exists() and key_path.exists():
        age_days = (dt.datetime.now().timestamp() - cert_path.stat().st_mtime) / 86400
        if 0 <= age_days < 300:
            return

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=825))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    x509.IPAddress(ipaddress.ip_address("::1")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    try:
        key_path.chmod(0o600)
    except OSError:
        pass


class CallbackServer:
    """Serves the redirect URI on loopback and queues the parsed result."""

    def __init__(self, cfg: Settings, *, log=print):
        self._cfg = cfg
        self._log = log
        self._queue: queue.Queue[CallbackResult] = queue.Queue()
        self._httpd: http.server.HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._expected_path = cfg.redirect.path or "/"
        self._bound_port = cfg.callback_port
        self._scheme = cfg.redirect.scheme
        self._host = cfg.redirect.hostname or "127.0.0.1"

    # -- lifecycle -----------------------------------------------------
    def start(self) -> None:
        handler = self._make_handler()
        try:
            self._httpd = http.server.HTTPServer((self._host, self._bound_port), handler)
        except OSError as exc:
            raise CallbackError(
                f"cannot bind {self._host}:{self._bound_port} for the OAuth callback "
                f"({exc}). Close whatever is using that port, or register a different "
                "callback URL and set SCHWAB_CALLBACK_URL."
            ) from exc

        self._httpd.daemon_threads = True
        if self._scheme == "https":
            tls = self._cfg.state_dir / "tls"
            cert, key = tls / "loopback-cert.pem", tls / "loopback-key.pem"
            _ensure_cert(cert, key)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(cert), str(key))
            self._httpd.socket = context.wrap_socket(self._httpd.socket, server_side=True)

        self._thread = threading.Thread(target=self._httpd.serve_forever, name="oauth-callback", daemon=True)
        self._thread.start()
        self._log(f"callback server listening on {self._scheme}://{self._host}:{self._bound_port}{self._expected_path}")

    def stop(self) -> None:
        httpd, self._httpd = self._httpd, None
        if httpd is not None:
            threading.Thread(target=httpd.shutdown, daemon=True).start()
            try:
                httpd.server_close()
            except OSError:
                pass

    def __enter__(self) -> "CallbackServer":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    # -- result --------------------------------------------------------
    def poll(self) -> CallbackResult | None:
        try:
            return self._queue.get_nowait()
        except queue.Empty:
            return None

    def wait(self, timeout: float) -> CallbackResult:
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty as exc:
            raise TimeoutError(f"no OAuth callback within {timeout:.0f}s") from exc

    # -- internals -----------------------------------------------------
    def _make_handler(self):
        expected_path = self._expected_path.rstrip("/")
        queue_ = self._queue
        log = self._log

        def _norm(path: str) -> str:
            return urllib.parse.urlsplit(path).path.rstrip("/")

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):  # noqa: N802 - http.server convention
                parsed = urllib.parse.urlsplit(self.path)
                if _norm(parsed.path) != expected_path:
                    # favicon etc. — answer, but do not consume the flow
                    self._respond(204, b"")
                    return

                params = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
                result = CallbackResult(
                    code=params.get("code"),
                    state=params.get("state"),
                    error=params.get("error"),
                    error_description=params.get("error_description"),
                    url=self.path,
                )
                if result.should_stop:
                    queue_.put(result)
                    log("callback received" + (" (error)" if result.error else " (code)"))
                self._respond(200, _SUCCESS_HTML)

            def _respond(self, status: int, body: bytes) -> None:
                self.send_response(status)
                if body:
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                if body:
                    self.wfile.write(body)

            def log_message(self, fmt, *args):  # silence stderr noise
                if "favicon" not in (args[0] if args else ""):
                    log("callback server: " + fmt % args)

        return Handler


def port_is_free(host: str, port: int) -> bool:
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True
