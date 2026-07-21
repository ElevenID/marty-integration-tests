from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "official-interoperability.yml"
PYTHON_LOCK = ROOT / "requirements" / "official-py312.lock"


def test_workflow_is_manual_and_uses_isolated_standard_runner_lanes() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "workflow_dispatch:" in text
    assert "schedule:" not in text
    assert "pull_request:" not in text
    assert "runs-on: ubuntu-latest" in text
    for lane in ("oid4vp-final", "haip", "w3c-v2", "eudi"):
        assert lane in text
    assert "fail-fast: false" in text


def test_workflow_attests_released_inputs_and_never_uploads_raw_evidence() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "official_stack_release.py materialize" in text
    assert 'gh attestation verify "oci://$reference"' in text
    assert "eudi_test_material.py generate" in text
    assert "eudi_test_material.py validate" in text
    verifier_material = text.split("- name: Generate disposable verifier material", 1)[1].split(
        "- name: Generate disposable operator credentials", 1
    )[0]
    assert "matrix.lane == 'eudi'" in verifier_material
    assert "haip_test_certificates.py" in verifier_material
    assert "sanitize_official_evidence.py" in text
    upload = text.split("- name: Upload sanitized evidence", 1)[1].split("- name: Enforce lane result", 1)[0]
    assert "work/sanitized/" in upload
    assert "work/evidence" not in upload
    assert "work/material" not in upload


def test_workflow_installs_only_frozen_verified_tooling() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "--require-hashes --only-binary=:all:" in text
    assert "requirements/official-py312.lock" in text
    assert "w3c_vc_conformance.py bootstrap-npm" in text
    assert "npm install --global" not in text
    assert "eudi_harness_provenance.py" in text
    assert "--harness-image-report work/eudi-harness-image.json" in text
    lock = PYTHON_LOCK.read_text(encoding="utf-8")
    requirements = [line for line in lock.splitlines() if line and not line.startswith(("#", " "))]
    assert requirements
    assert all("==" in requirement for requirement in requirements)
    assert "--hash=sha256:" in lock


def test_every_action_reference_is_a_full_commit_sha() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    references = re.findall(r"^\s*uses:\s*[^\s@]+@([^\s]+)", text, flags=re.MULTILINE)
    assert references
    assert all(re.fullmatch(r"[0-9a-f]{40}", reference) for reference in references)
