from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("eudi_reference_interop", ROOT / "scripts" / "eudi_reference_interop.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load EUDI reference interop helper")
eudi = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(eudi)


def test_eudi_reference_components_are_immutable_and_complete() -> None:
    manifest = eudi.load_manifest()
    assert "@sha256:" in manifest["components"]["wallet_tester"]["image"]
    assert "@sha256:" in manifest["components"]["verifier_endpoint"]["image"]
    assert "replayed_response" in manifest["coverage"]["negative"]
