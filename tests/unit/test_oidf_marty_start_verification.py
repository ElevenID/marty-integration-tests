"""Unit tests for the authenticated OIDF verifier-flow deployment adapter."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("oidf_start", ROOT / "scripts" / "oidf_marty_start_verification.py")
assert SPEC and SPEC.loader
oidf_start = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(oidf_start)


def test_flow_body_uses_real_flow_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OIDF_MARTY_PRESENTATION_POLICY_ID", "policy-1")
    monkeypatch.setenv("OIDF_MARTY_TRUST_PROFILE_ID", "trust-1")
    monkeypatch.setenv("OIDF_MARTY_VERIFIER_PROFILE", "haip")
    assert oidf_start.flow_body({"test_id": "module-1", "request_method": "request_uri_signed"}) == {
        "presentation_policy_id": "policy-1", "trust_profile_id": "trust-1", "expiry_minutes": 15,
        "oid4vp_profile": "haip", "request_uri_method": "post",
    }


def test_start_flow_sends_authenticated_gateway_request(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    class Response:
        status = 200
        def read(self) -> bytes:
            return json.dumps({"authorization_request": "openid4vp://authorize?request_uri=https://marty.test/request"}).encode()
        def __enter__(self) -> "Response": return self
        def __exit__(self, *_args: object) -> None: return None

    def fake_open(request: object, **_kwargs: object) -> Response:
        captured["url"] = request.full_url
        captured["cookie"] = request.get_header("Cookie")
        captured["body"] = json.loads(request.data.decode())
        return Response()

    monkeypatch.setattr(oidf_start, "urlopen", fake_open)
    result = oidf_start.start_flow("https://marty.test", "session-1", {"presentation_policy_id": "policy-1"}, insecure=False)
    assert result["authorization_request"].startswith("openid4vp://")
    assert captured == {"url": "https://marty.test/v1/flows/verify", "cookie": "sessionId=session-1", "body": {"presentation_policy_id": "policy-1"}}


def test_gateway_must_be_https() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        oidf_start.https_url("http://localhost:8000", "OIDF_MARTY_GATEWAY_URL")
