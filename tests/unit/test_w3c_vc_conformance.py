from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("w3c_vc_conformance", ROOT / "scripts" / "w3c_vc_conformance.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load W3C VC conformance helper")
w3c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(w3c)


def test_pinned_w3c_vc_suite_manifest_is_valid() -> None:
    manifest = w3c.load_manifest()
    assert manifest["official_suite"]["repository"].startswith("https://github.com/w3c/")
    assert manifest["adapter"]["path"] == "/__test__/vc-api"
    assert manifest["exclusions"][0]["review_date"]


def test_w3c_local_config_registers_only_verification_adapters(tmp_path: Path) -> None:
    output = tmp_path / "localConfig.cjs"
    w3c.write_local_config(output, "https://interop.example.test/__test__/vc-api")
    config = output.read_text(encoding="utf-8")
    assert "/credentials/verify" in config
    assert "/presentations/verify" in config
    assert "issuers:" not in config
