"""Tests for the disposable owned Marty Sync adapter."""

from __future__ import annotations

import importlib.util
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "trust_registry_fixture",
    ROOT / "scripts" / "trust_registry_fixture.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load trust registry fixture")
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


def test_sender_creation_is_control_only_and_never_serializes_provider_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    class Sender:
        def __init__(self) -> None:
            self.calls = 0

        def provision(self, _organization_id: str, _issuer_did: str) -> dict[str, str]:
            self.calls += 1
            raise ValueError("synthetic-provider-authority-must-not-be-serialized")

    sender = Sender()
    monkeypatch.setattr(fixture, "SENDER", sender)
    monkeypatch.setattr(fixture, "CONTROL_TOKEN", "synthetic-controller-token-long-enough")
    headers = {"Authorization": f"Bearer {fixture.CONTROL_TOKEN}"}
    body = {"organization_id": "public-organization", "issuer_did": "did:web:owned.test"}
    for server_type, expected_status in ((ThreadingHTTPServer, 404), (fixture.ControlServer, 409)):
        server = server_type(("127.0.0.1", 0), fixture.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            origin = f"http://127.0.0.1:{server.server_port}"
            response = httpx.post(origin + "/control/didcomm/sender", json=body)
            assert response.status_code == 401
            response = httpx.post(origin + "/control/didcomm/sender", json=body, headers=headers)
            assert response.status_code == expected_status
            assert "synthetic-provider-authority" not in response.text
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        assert not thread.is_alive()
    assert sender.calls == 1


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
