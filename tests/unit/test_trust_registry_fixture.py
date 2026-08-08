"""Tests for the disposable owned Marty Sync adapter."""

from __future__ import annotations

import importlib.util
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "trust_registry_fixture",
    ROOT / "scripts" / "trust_registry_fixture.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load trust registry fixture")
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


def test_control_api_configures_feed_and_records_the_product_request() -> None:
    fixture.STATE = fixture.FixtureState()
    fixture.CONTROL_TOKEN = "test-control-token-which-is-long-enough"
    server = ThreadingHTTPServer(("127.0.0.1", 0), fixture.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    headers = {"Authorization": f"Bearer {fixture.CONTROL_TOKEN}"}
    feed = {
        "sync_token": "1",
        "sequence": 1,
        "entries": [],
        "has_more": False,
        "generated_at": "2026-08-07T12:00:00Z",
    }
    try:
        unauthorized = httpx.get(f"{origin}/control/state")
        assert unauthorized.status_code == 401

        configured = httpx.post(
            f"{origin}/control/feed", json={"feed": feed}, headers=headers
        )
        assert configured.status_code == 200

        product = httpx.get(
            f"{origin}{fixture.FEED_PATH}?since=cursor-1",
            headers={"Host": "trust-registry-fixture"},
        )
        assert product.status_code == 200
        assert product.json() == feed

        state = httpx.get(f"{origin}/control/state", headers=headers).json()
        assert state == {
            "configured": True,
            "last_host": "trust-registry-fixture",
            "last_since": "cursor-1",
            "request_count": 1,
        }
    finally:
        server.shutdown()
        server.server_close()
