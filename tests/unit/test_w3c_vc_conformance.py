from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("w3c_vc_conformance", ROOT / "scripts" / "w3c_vc_conformance.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load W3C VC conformance helper")
w3c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(w3c)


def test_pinned_w3c_vc_suite_manifest_is_valid() -> None:
    manifest = w3c.load_manifest()
    assert manifest["official_suite"]["repository"].startswith("https://github.com/w3c/")
    assert manifest["official_suite"]["node"] == "24"
    assert manifest["official_suite"]["npm"] == "11.11.0"
    assert w3c.DIGEST.fullmatch(manifest["official_suite"]["package_lock_sha256"])
    assert manifest["adapter"]["path"] == "/__test__/vc-api"
    assert manifest["exclusions"][0]["review_date"]


def test_npm_command_uses_the_windows_launcher_when_needed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(w3c.os, "name", "nt")
    assert w3c.npm_command() == "npm.cmd"
    monkeypatch.setattr(w3c.os, "name", "posix")
    assert w3c.npm_command() == "npm"


def test_w3c_test_command_uses_absolute_reporter_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mocha = tmp_path / "node_modules" / "mocha" / "bin" / "mocha.js"
    mocha.parent.mkdir(parents=True)
    mocha.write_text("", encoding="utf-8")
    monkeypatch.setattr(w3c.shutil, "which", lambda _name: "node")
    command = w3c.w3c_test_command(tmp_path)
    assert command[0] == "node"
    assert (tmp_path / "reports").as_posix() in command[command.index("--reporter-options") + 1]


def test_w3c_local_config_registers_the_real_issuer_and_verifiers(tmp_path: Path) -> None:
    output = tmp_path / "localConfig.cjs"
    w3c.write_local_config(output, "https://interop.example.test/__test__/vc-api")
    config = output.read_text(encoding="utf-8")
    assert "/credentials/issue" in config
    assert "/credentials/verify" in config
    assert "/presentations/verify" in config
    assert "issuers:" in config


def test_w3c_report_requires_an_executed_matrix_case(tmp_path: Path) -> None:
    report = tmp_path / "index.json"
    report.write_text(json.dumps({"matrices": [{"rows": [], "columns": []}]}), encoding="utf-8")
    assert not w3c.report_has_executed_cases(report)
    report.write_text(
        json.dumps({"matrices": [{"rows": [{"title": "case"}], "columns": ["ElevenID"]}]}), encoding="utf-8"
    )
    assert w3c.report_has_executed_cases(report)


def test_w3c_evidence_preserves_the_narrow_exclusion_and_immutable_stack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    suite = tmp_path / "suite"
    suite.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    (output / "result.json").write_text("{}", encoding="utf-8")
    stack = tmp_path / "stack-manifest.json"
    stack.write_text(
        json.dumps(
            {
                "schema": "marty.stack/v1",
                "release": "marty-ui@1.0.0",
                "components": [
                    {
                        "name": "marty-ui",
                        "artifacts": [
                            {
                                "type": "oci",
                                "uri": "ghcr.io/elevenid/marty-ui-oss/services",
                                "digest": "sha256:" + "a" * 64,
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(w3c, "revision", lambda _path: "a" * 40)
    w3c.write_evidence(output, w3c.load_manifest(), suite, "https://marty.test/__test__/vc-api", 1, stack)
    evidence = json.loads((output / "evidence.json").read_text(encoding="utf-8"))
    assert evidence["result"] == {"exit_code": 1, "passed": False}
    assert evidence["exclusions"][0]["capability"] == "JSON-LD Data Integrity eddsa-rdfc-2022"
    assert evidence["marty"]["stack_manifest"]["images"][0]["digest"] == "sha256:" + "a" * 64
