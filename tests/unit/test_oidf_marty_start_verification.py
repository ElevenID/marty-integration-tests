"""Unit tests for the authenticated OIDF verifier-flow deployment adapter."""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("oidf_start", ROOT / "scripts" / "oidf_marty_start_verification.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load OIDF verifier-flow adapter")
oidf_start = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(oidf_start)


def test_flow_body_uses_real_flow_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OIDF_MARTY_PRESENTATION_POLICY_ID", "policy-1")
    monkeypatch.setenv("OIDF_MARTY_TRUST_PROFILE_ID", "trust-1")
    monkeypatch.setenv("OIDF_MARTY_VERIFIER_PROFILE", "haip")
    assert oidf_start.flow_body({"test_id": "module-1", "request_method": "request_uri_signed"}) == {
        "presentation_policy_id": "policy-1",
        "trust_profile_id": "trust-1",
        "expiry_minutes": 15,
        "oid4vp_profile": "haip",
        "request_uri_method": "post",
    }


def test_start_flow_sends_authenticated_gateway_request(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_request(origin: str, session_id: str, path: str, **kwargs: object) -> dict[str, str]:
        captured.update({"origin": origin, "session_id": session_id, "path": path, **kwargs})
        return {"authorization_request": "openid4vp://authorize?request_uri=https://marty.test/request"}

    monkeypatch.setattr(oidf_start, "authenticated_json_request", fake_request)
    result = oidf_start.start_flow(
        "https://marty.test", "session-1", {"presentation_policy_id": "policy-1"}
    )
    assert result["authorization_request"].startswith("openid4vp://")
    assert captured == {
        "origin": "https://marty.test",
        "session_id": "session-1",
        "path": "/v1/flows/verify",
        "method": "POST",
        "json_body": {"presentation_policy_id": "policy-1"},
    }


def test_gateway_must_be_https() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        oidf_start.https_url("http://localhost:8000", "OIDF_MARTY_GATEWAY_URL")


def test_gateway_session_uses_public_login_only_when_not_preconfigured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OIDF_MARTY_SESSION_ID", raising=False)
    monkeypatch.setattr(
        oidf_start.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "public-session\n", ""),
    )

    assert oidf_start.gateway_session_id() == "public-session"

    monkeypatch.setenv("OIDF_MARTY_SESSION_ID", "operator-supplied-session")
    assert oidf_start.gateway_session_id() == "operator-supplied-session"
