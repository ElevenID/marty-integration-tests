from __future__ import annotations

import importlib.util
import json
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


def test_eudi_evidence_records_pinned_components(tmp_path: Path) -> None:
    output = tmp_path / "report"
    output.mkdir()
    (output / "junit.xml").write_text("<testsuites/>", encoding="utf-8")
    endpoints = {"gateway": "https://marty.test", "wallet_tester": "http://wallet:5050", "verifier": "http://verifier:8090", "wallet_kit": "http://kit:9090"}
    eudi.write_evidence(output, eudi.load_manifest(), endpoints, 0)
    evidence = json.loads((output / "evidence.json").read_text(encoding="utf-8"))
    assert evidence["result"]["passed"] is True
    assert evidence["components"]["wallet_tester"]["image"].startswith("ghcr.io/")
