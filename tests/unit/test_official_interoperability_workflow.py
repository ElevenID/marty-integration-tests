from __future__ import annotations

import os
import re
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "official-interoperability.yml"
PYTHON_LOCK = ROOT / "requirements" / "official-py312.lock"


def test_native_runtime_attestation_has_step_scoped_read_only_auth() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    runtime = text.split("      - name: Run official lane\n", 1)[1].split(
        "      - name: Record locally built EUDI harness digest", 1
    )[0]
    assert re.search(r"        env:\n(?:          #.*\n)*          GH_TOKEN: \$\{\{ github.token \}\}\n", runtime)
    assert "official_interoperability_lane.py" in runtime
    job_environment = text.split("    env:\n", 1)[1].split("    steps:\n", 1)[0]
    assert "GH_TOKEN" not in job_environment
    permissions = text.split("\npermissions:\n", 1)[1].split("\nconcurrency:", 1)[0]
    assert permissions.strip()
    assert all(re.fullmatch(r"[a-z-]+: read", line.strip()) for line in permissions.splitlines() if line.strip())


@pytest.mark.parametrize(("overrides", "allowed"), [
    ({}, True),
    ({"GITHUB_REPOSITORY": "other/product"}, False),
    ({"GITHUB_REF": "refs/heads/feature"}, False),
    ({"LANE": "oid4vci-issuer"}, False),
    ({"CANDIDATE_ARTIFACT": "stack-release-official-candidate-98"}, False),
    ({"HARNESS_REVISION": "main"}, False),
    ({"CANDIDATE_MANIFEST_SHA256": "latest"}, False),
    ({"CANDIDATE_TAG": "v1.2.3;true"}, False),
    ({"CANDIDATE_ARTIFACT": "", "CANDIDATE_MANIFEST_SHA256": "",
      "CANDIDATE_TAG": "", "HARNESS_REVISION": "",
      "GITHUB_REPOSITORY": "ElevenID/marty-integration-tests"}, True),
    ({"CANDIDATE_ARTIFACT": "", "CANDIDATE_MANIFEST_SHA256": "",
      "CANDIDATE_TAG": "", "HARNESS_REVISION": ""}, False),
])
def test_actual_candidate_caller_guard(
    overrides: dict[str, str], allowed: bool,
) -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    step = text.split("      - name: Validate candidate caller before fetching source\n", 1)[1]
    script = textwrap.dedent(step.split("      - name: Checkout integration harness", 1)[0]
                             .split("        run: |\n", 1)[1])
    git_bash = Path("C:/Program Files/Git/bin/bash.exe")
    bash = str(git_bash) if os.name == "nt" and git_bash.is_file() else shutil.which("bash")
    assert bash, "Bash is required to execute the actual workflow caller guard"
    environment = {**os.environ, "GITHUB_REPOSITORY": "ElevenID/marty-ui",
                   "GITHUB_REF": "refs/heads/main", "GITHUB_RUN_ID": "99",
                   "CANDIDATE_ARTIFACT": "stack-release-official-candidate-99",
                   "CANDIDATE_MANIFEST_SHA256": "sha256:" + "a" * 64,
                   "CANDIDATE_TAG": "v1.2.3", "HARNESS_REVISION": "b" * 40,
                   "LANE": "all", **overrides}
    result = subprocess.run([bash, "--noprofile", "--norc"], input=script,
                            env=environment, text=True, capture_output=True, check=False)
    assert (result.returncode == 0) == allowed, result.stderr


def test_workflow_is_manual_and_monthly_with_isolated_standard_runner_lanes() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "workflow_dispatch:" in text
    assert "schedule:" in text
    assert text.count("cron:") == 1
    assert 'cron: "41 5 8 * *"' in text
    assert "github.event_name == 'schedule' || inputs.lane == 'all'" in text
    assert "inputs.lane || 'all'" in text
    assert "pull_request:" not in text
    assert "runs-on: ubuntu-24.04" in text
    for lane in (
        "oid4vci-issuer",
        "oid4vp-final",
        "oid4vp-url-query",
        "oid4vp-mdoc",
        "haip",
        "w3c-v2",
        "eudi",
    ):
        assert lane in text
    assert "fail-fast: false" in text


def test_workflow_attests_released_inputs_and_never_uploads_raw_evidence() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "official_stack_release.py materialize" in text
    assert 'gh attestation verify "oci://$reference"' in text
    assert "eudi_test_material.py generate" in text
    assert "eudi_test_material.py validate" in text
    assert 'admin_password="$(openssl rand -hex 32)!A1"' in text
    assert 'reviewer_password="$(openssl rand -hex 32)!B2"' in text
    verifier_material = text.split("- name: Prepare disposable verifier trust material", 1)[1].split(
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
    assert "Verify runner-provided released-stack browser" in text
    assert 'browser="$(command -v google-chrome)"' in text
    assert 'echo "MARTY_PLAYWRIGHT_BROWSER_CHANNEL=chrome" >> "$GITHUB_ENV"' in text
    assert "playwright install" not in text
    assert "matrix.lane == 'oid4vp-final'" in text
    assert "w3c_vc_conformance.py bootstrap-npm" in text
    assert "npm install --global" not in text
    assert "eudi_harness_provenance.py" in text
    assert "--harness-image-report work/eudi-harness-image.json" in text
    lock = PYTHON_LOCK.read_text(encoding="utf-8")
    requirements = [line for line in lock.splitlines() if line and not line.startswith(("#", " "))]
    assert requirements
    assert all("==" in requirement for requirement in requirements)
    # The pinned OIDF runner's scripts/requirements.txt imports pyparsing in
    # test_plan_parser.py before any official module can be created.
    assert any(requirement.startswith("pyparsing==") for requirement in requirements)
    assert "--hash=sha256:" in lock


def test_every_action_reference_is_a_full_commit_sha() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    references = re.findall(r"^\s*uses:\s*[^\s@]+@([^\s]+)", text, flags=re.MULTILINE)
    assert references
    assert all(re.fullmatch(r"[0-9a-f]{40}", reference) for reference in references)
