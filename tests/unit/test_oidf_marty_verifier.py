"""Tests for the official-runner to public-Marty interaction bridge."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("oidf_verifier", ROOT / "scripts" / "oidf_marty_verifier.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load OIDF verifier adapter")
oidf_verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(oidf_verifier)


def test_local_resolver_is_limited_to_the_configured_public_marty_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OIDF_MARTY_GATEWAY_URL", "https://marty-oidf.local:28443")
    monkeypatch.setenv("OIDF_MARTY_RESOLVE_IP", "127.0.0.1")

    assert oidf_verifier.local_marty_resolve("https://marty-oidf.local:28443/v1/request") == [
        "--resolve",
        "marty-oidf.local:28443:127.0.0.1",
    ]
    assert oidf_verifier.local_marty_resolve("https://localhost.emobix.co.uk:8443/test") == []
    assert oidf_verifier.local_marty_resolve("http://marty-oidf.local:28443/v1/request") == []


def test_conformance_resolver_is_limited_to_the_published_runner_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONFORMANCE_SERVER", "https://localhost.emobix.co.uk:8443")
    monkeypatch.setenv("OIDF_CONFORMANCE_RESOLVE_IP", "127.0.0.1")

    assert oidf_verifier.local_conformance_resolve("https://localhost.emobix.co.uk:8443/api/runner/test") == [
        "--resolve",
        "localhost.emobix.co.uk:8443:127.0.0.1",
    ]
    assert oidf_verifier.local_conformance_resolve("https://marty-oidf.local:28443/v1/request") == []
    assert oidf_verifier.local_conformance_resolve("http://localhost.emobix.co.uk:8443/api/runner/test") == []


def test_mock_wallet_tls_exception_never_disables_marty_tls(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, bool]] = []

    def request(
        url: str,
        *,
        headers: dict[str, str] | None = None,
        insecure: bool = False,
    ) -> tuple[int, object]:
        _ = headers
        calls.append((url, insecure))
        if "marty.example" in url:
            return 200, "eyJhbGciOiJFUzI1NiJ9.eyJjbGllbnRfaWQiOiJjbGllbnQifQ.signature"
        return 200, {}

    monkeypatch.setattr(oidf_verifier, "request_json", request)
    oidf_verifier.call_mock_wallet(
        "https://localhost.emobix.co.uk:8443/authorize",
        "https://marty.example/request.jwt",
        request_method="request_uri_signed",
        conformance_insecure=True,
    )
    assert calls[0] == ("https://marty.example/request.jwt", False)
    assert calls[1][1] is True
