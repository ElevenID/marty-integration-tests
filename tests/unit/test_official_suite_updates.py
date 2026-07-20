from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("official_suite_updates", ROOT / "scripts" / "official_suite_updates.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load official-suite update helper")
updates = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(updates)


def test_drift_requires_a_real_pinned_to_latest_difference() -> None:
    no_drift = {
        "upstreams": {
            "oidf": {"pinned_release": "release-v1", "latest_release": "release-v1"},
            "w3c": {"pinned_commit": "a" * 40, "latest_commit": "a" * 40},
        }
    }
    assert updates.has_drift(no_drift) is False
    no_drift["upstreams"]["w3c"]["latest_commit"] = "b" * 40
    assert updates.has_drift(no_drift) is True


def test_observation_tracks_every_eudi_wallet_library(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(updates, "latest_oidf_release", lambda: "release-v5.2.0")
    monkeypatch.setattr(updates, "git_head", lambda *_args: "f" * 40)
    observation = updates.observe()
    assert {
        "eudi_wallet_kit_oid4vp",
        "eudi_wallet_kit_oid4vci",
        "eudi_wallet_kit_sd_jwt",
    } <= observation["upstreams"].keys()
