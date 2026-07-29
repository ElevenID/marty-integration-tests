from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "official_suite_checkout", ROOT / "scripts" / "official_suite_checkout.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load official suite checkout helper")
checkout = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checkout)


def test_all_suite_sources_are_exact_and_allowlisted() -> None:
    oidf_repository, oidf_commit = checkout.pinned_source("oidf")
    w3c_repository, w3c_commit = checkout.pinned_source("w3c")
    assert oidf_repository == "https://gitlab.com/openid/conformance-suite.git"
    assert w3c_repository == "https://github.com/w3c/vc-data-model-2.0-test-suite.git"
    assert len(oidf_commit) == len(w3c_commit) == 40
    oidf_manifest = json.loads((ROOT / "conformance" / "oidf-runner.json").read_text(encoding="utf-8"))
    w3c_manifest = json.loads((ROOT / "conformance" / "w3c-vc-data-model-v2.json").read_text(encoding="utf-8"))
    assert oidf_manifest["official_runner"]["source_policy"] == "unmodified"
    assert w3c_manifest["official_suite"]["source_policy"] == "unmodified"
    assert "compatibility_patch" not in w3c_manifest


def test_checkout_refuses_to_reuse_nonempty_directory(tmp_path: Path) -> None:
    (tmp_path / "existing").write_text("do not replace", encoding="utf-8")
    with pytest.raises(FileExistsError, match="non-empty"):
        checkout.checkout("w3c", tmp_path)


def test_checkout_verification_rejects_a_tracked_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Compliance Test"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "compliance@example.test"], cwd=tmp_path, check=True)
    source = tmp_path / "official-test.py"
    source.write_text("assert True\n", encoding="utf-8")
    subprocess.run(["git", "add", "official-test.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "fixture"], cwd=tmp_path, check=True, capture_output=True)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=tmp_path, text=True).strip()
    monkeypatch.setattr(checkout, "pinned_source", lambda _name: ("https://example.test/suite.git", commit))

    assert checkout.verify_checkout("oidf", tmp_path) == commit
    source.write_text("assert False\n", encoding="utf-8")

    with pytest.raises(ValueError, match="byte-for-byte clean"):
        checkout.verify_checkout("oidf", tmp_path)
