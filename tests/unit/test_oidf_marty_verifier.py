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
        "--resolve", "marty-oidf.local:28443:127.0.0.1"
    ]
    assert oidf_verifier.local_marty_resolve("https://localhost.emobix.co.uk:8443/test") == []
    assert oidf_verifier.local_marty_resolve("http://marty-oidf.local:28443/v1/request") == []
