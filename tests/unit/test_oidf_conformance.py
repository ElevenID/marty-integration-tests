"""Tests for the pinned official OIDF conformance boundary."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("oidf_conformance", ROOT / "scripts" / "oidf_conformance.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load OIDF conformance helper")
oidf = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(oidf)


def test_pinned_official_runner_manifest_is_valid() -> None:
    manifest = oidf.load_manifest()
    assert manifest["official_runner"]["repository"].startswith("https://gitlab.com/openid/")
    assert manifest["profiles"]["oid4vci-issuer"]["status"] == "active"


def test_example_configuration_is_rejected(tmp_path: Path) -> None:
    config = tmp_path / "issuer.json"
    example = ROOT / "conformance" / "marty-issuer.example.json"
    config.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.raises(ValueError, match="example values"):
        oidf.validate_config(config)


def test_real_gateway_configuration_is_accepted(tmp_path: Path) -> None:
    config = tmp_path / "issuer.json"
    config.write_text(
        json.dumps(
            {
                "vci": {
                    "credential_issuer_url": "https://conformance.example.test/org/test",
                    "authorization_server": "https://conformance.example.test",
                    "credential_configuration_id": "UniversityDegree_JWT",
                }
            }
        ),
        encoding="utf-8",
    )
    oidf.validate_config(config)
