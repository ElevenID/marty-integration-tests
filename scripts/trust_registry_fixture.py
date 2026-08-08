#!/usr/bin/env python3
"""Disposable HTTPS Marty Sync v1 adapter for owned released-stack evidence.

The control API is published only on runner loopback by its Compose file. The
product reaches only the HTTPS feed on the project-scoped Docker network.
"""

from __future__ import annotations

import hmac
import json
import os
import ssl
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

MAX_CONTROL_BYTES = 2 * 1024 * 1024
FEED_PATH = "/marty-sync/v1"


class FixtureState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._feed: dict[str, Any] | None = None
        self._request_count = 0
        self._last_since: str | None = None
        self._last_host: str | None = None

    def replace(self, feed: dict[str, Any]) -> None:
        with self._lock:
            self._feed = json.loads(json.dumps(feed))

    def reset(self) -> None:
        with self._lock:
            self._feed = None
            self._request_count = 0
            self._last_since = None
            self._last_host = None

    def read_feed(self, *, since: str | None, host: str | None) -> dict[str, Any] | None:
        with self._lock:
            self._request_count += 1
            self._last_since = since
            self._last_host = host
            return json.loads(json.dumps(self._feed)) if self._feed is not None else None

    def report(self) -> dict[str, Any]:
        with self._lock:
            return {
                "configured": self._feed is not None,
                "request_count": self._request_count,
                "last_since": self._last_since,
                "last_host": self._last_host,
            }


STATE = FixtureState()
CONTROL_TOKEN = os.environ.get("TRUST_REGISTRY_FIXTURE_TOKEN", "")


class Handler(BaseHTTPRequestHandler):
    server_version = "ElevenIDTrustRegistryFixture/1"

    def _json(self, status: HTTPStatus, value: object) -> None:
        body = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        supplied = self.headers.get("Authorization", "")
        expected = f"Bearer {CONTROL_TOKEN}"
        return bool(CONTROL_TOKEN) and hmac.compare_digest(supplied, expected)

    def _control_body(self) -> dict[str, Any] | None:
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if size <= 0 or size > MAX_CONTROL_BYTES:
            return None
        try:
            parsed: object = json.loads(self.rfile.read(size))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return parsed if isinstance(parsed, dict) else None

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        parsed = urlsplit(self.path)
        if parsed.path == FEED_PATH:
            since_values = parse_qs(parsed.query, keep_blank_values=True).get("since", [])
            if len(since_values) > 1:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "duplicate since token"})
                return
            feed = STATE.read_feed(
                since=since_values[0] if since_values else None,
                host=self.headers.get("Host"),
            )
            if feed is None:
                self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "feed not configured"})
                return
            self._json(HTTPStatus.OK, feed)
            return
        if parsed.path == "/control/state":
            if not self._authorized():
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                return
            self._json(HTTPStatus.OK, STATE.report())
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        if not self._authorized():
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        if self.path == "/control/reset":
            STATE.reset()
            self._json(HTTPStatus.OK, {"reset": True})
            return
        if self.path != "/control/feed":
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        body = self._control_body()
        feed = body.get("feed") if body is not None else None
        if not isinstance(feed, dict):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "feed object required"})
            return
        STATE.replace(feed)
        self._json(HTTPStatus.OK, {"configured": True})

    def log_message(self, _format: str, *_args: object) -> None:
        return


def main() -> None:
    if len(CONTROL_TOKEN) < 32:
        raise SystemExit("TRUST_REGISTRY_FIXTURE_TOKEN must contain at least 32 characters")
    certificate = Path(os.environ.get("TRUST_REGISTRY_FIXTURE_CERT", "/material/tls.crt"))
    key = Path(os.environ.get("TRUST_REGISTRY_FIXTURE_KEY", "/material/tls.key"))
    if not certificate.is_file() or not key.is_file():
        raise SystemExit("fixture TLS material is missing")

    control = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
    control_thread = threading.Thread(target=control.serve_forever, daemon=True)
    control_thread.start()

    feed = ThreadingHTTPServer(("0.0.0.0", 443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, key)
    feed.socket = context.wrap_socket(feed.socket, server_side=True)
    try:
        feed.serve_forever()
    finally:
        control.shutdown()


if __name__ == "__main__":
    main()
