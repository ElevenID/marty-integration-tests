from __future__ import annotations

import importlib.util
import json
import os
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


def test_npm_command_uses_the_windows_launcher_when_needed(monkeypatch) -> None:
    monkeypatch.setattr(w3c.os, "name", "nt")
    assert w3c.npm_command() == "npm.cmd"
    monkeypatch.setattr(w3c.os, "name", "posix")
    assert w3c.npm_command() == "npm"


def test_w3c_test_command_uses_absolute_reporter_paths(tmp_path: Path, monkeypatch) -> None:
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
    report.write_text(json.dumps({"matrices": [{"rows": [{"title": "case"}], "columns": ["ElevenID"]}]}), encoding="utf-8")
    assert w3c.report_has_executed_cases(report)


def test_w3c_evidence_preserves_the_narrow_exclusion(tmp_path: Path, monkeypatch) -> None:
    suite = tmp_path / "suite"
    suite.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    (output / "result.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(w3c, "revision", lambda _path: "a" * 40)
    w3c.write_evidence(output, w3c.load_manifest(), suite, "https://marty.test/__test__/vc-api", 1)
    evidence = json.loads((output / "evidence.json").read_text(encoding="utf-8"))
    assert evidence["result"] == {"exit_code": 1, "passed": False}
    assert evidence["exclusions"][0]["capability"] == "JSON-LD Data Integrity eddsa-rdfc-2022"
