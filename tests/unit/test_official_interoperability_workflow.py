from __future__ import annotations

import os
import re
import shutil
import subprocess
import textwrap
import types
import sys
from pathlib import Path

import pytest
import yaml

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


def test_candidate_operator_is_authenticated_before_disposable_kms_mutation() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    operator = text.index("- name: Download exact candidate native operator")
    proof = text.index("- name: Download exact candidate operator provenance")
    admission = text.index("- name: Authenticate source-matched native operator before KMS mutation")
    bootstrap = text.index("- name: Bootstrap disposable KMS-only released stack")
    assert operator < proof < admission < bootstrap
    guarded = text[operator:bootstrap]
    assert guarded.count("if: inputs.candidate_artifact != ''") == 3
    assert "operator-catalog-amd64-${{ github.run_id }}" in guarded
    assert "operator-installer-provenance-amd64-${{ github.run_id }}" in guarded
    assert "verify_subject(binary, proof" in guarded
    assert "source_sha=os.environ['GITHUB_SHA']" in guarded
    assert "run_attempt=int(os.environ['GITHUB_RUN_ATTEMPT'])" in guarded
    assert "MARTY_DEPLOY_BIN_SHA256" in guarded
    assert "MARTY_DEPLOY_RELEASE_TAG" in guarded


@pytest.mark.parametrize(("identity_matches", "proof_accepted", "allowed"), [
    (True, True, True),
    (False, True, False),
    (True, False, False),
])
def test_actual_candidate_operator_admission_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    identity_matches: bool, proof_accepted: bool, allowed: bool,
) -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    step = next(item for item in workflow["jobs"]["run-lane"]["steps"]
                if item.get("name") == "Authenticate source-matched native operator before KMS mutation")
    script = step["run"].split("python - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    monkeypatch.chdir(tmp_path)
    binary = tmp_path / "work/candidate-operator/marty-deploy-linux-amd64"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"synthetic-native-operator")
    proof = tmp_path / "work/candidate-operator-proof/marty-deploy-linux-amd64.provenance.jsonl"
    proof.parent.mkdir(parents=True)
    proof.write_text("synthetic-proof")
    (tmp_path / "work/marty-ui/scripts").mkdir(parents=True)
    gh = tmp_path / "gh"
    gh.write_bytes(b"synthetic-verifier")
    environment = tmp_path / "github-env"
    for name, value in {"GITHUB_SHA": "a" * 40, "CANDIDATE_TAG": "v1.2.3",
                        "GITHUB_RUN_ID": "99", "GITHUB_RUN_ATTEMPT": "1",
                        "GITHUB_ENV": str(environment)}.items():
        monkeypatch.setenv(name, value)
    observed = {}

    def verify_subject(subject, bundle, **kwargs):
        observed.update(subject=subject, bundle=bundle, **kwargs)
        if not proof_accepted:
            raise ValueError("provenance rejected")

    module = types.ModuleType("verify_installer_provenance")
    module.verify_subject = verify_subject
    monkeypatch.setitem(sys.modules, "verify_installer_provenance", module)
    monkeypatch.setattr(shutil, "which", lambda name: str(gh) if name == "gh" else None)
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: types.SimpleNamespace(
        stdout=("a" * 40 + ":v1.2.3" if identity_matches else "wrong-source:v1.2.3") + "\n"))

    if allowed:
        exec(script, {"__name__": "__main__"})
        settings = dict(line.split("=", 1) for line in environment.read_text().splitlines())
        assert settings["MARTY_DEPLOY_BIN"] == str(binary)
        assert settings["MARTY_DEPLOY_BIN_SHA256"] == __import__("hashlib").sha256(binary.read_bytes()).hexdigest()
        assert settings["MARTY_DEPLOY_SOURCE_SHA"] == "a" * 40
        assert settings["MARTY_DEPLOY_RELEASE_TAG"] == "v1.2.3"
    else:
        with pytest.raises(ValueError):
            exec(script, {"__name__": "__main__"})
        assert not environment.exists()
    assert observed["subject"] == binary
    assert observed["bundle"] == proof
    assert observed["workflow"] == ".github/workflows/cd.yml"
    assert observed["run_id"] == 99 and observed["run_attempt"] == 1


@pytest.mark.parametrize(("overrides", "allowed"), [
    ({}, True),
    ({"GITHUB_REPOSITORY": "other/product"}, False),
    ({"GITHUB_REF": "refs/heads/feature"}, False),
    ({"LANE": "oid4vci-issuer"}, False),
    ({"CANDIDATE_ARTIFACT": "stack-release-official-candidate-98"}, False),
    ({"HARNESS_REVISION": "main"}, False),
    ({"CANDIDATE_MANIFEST_SHA256": "latest"}, False),
    ({"CANDIDATE_TAG": "v1.2.3;true"}, False),
    ({"COLLECT_ONLY": "true"}, True),
    ({"COLLECT_ONLY": "true", "REVIEW_RECIPIENT": ""}, True),
    # Candidate collection never consults or consumes a diagnostic recipient.
    ({"COLLECT_ONLY": "true", "REVIEW_RECIPIENT": "unused-diagnostic-setting"}, True),
    ({"CANDIDATE_ARTIFACT": "", "CANDIDATE_MANIFEST_SHA256": "",
      "CANDIDATE_TAG": "", "HARNESS_REVISION": "",
      "GITHUB_REPOSITORY": "ElevenID/marty-integration-tests"}, True),
    ({"CANDIDATE_ARTIFACT": "", "CANDIDATE_MANIFEST_SHA256": "",
      "CANDIDATE_TAG": "", "HARNESS_REVISION": "", "COLLECT_ONLY": "true",
      "GITHUB_REPOSITORY": "ElevenID/marty-integration-tests"}, False),
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
                   "LANE": "all", "COLLECT_ONLY": "false", "REVIEW_RECIPIENT": "", **overrides}
    result = subprocess.run([bash, "--noprofile", "--norc"], input=script,
                            env=environment, text=True, capture_output=True, check=False)
    assert (result.returncode == 0) == allowed, result.stderr


@pytest.mark.parametrize(("raw_exit", "collect", "summary", "upload", "allowed"), [
    ("0", "false", "success", "success", True),
    ("1", "false", "success", "success", False),
    ("1", "true", "success", "success", True),
    ("2", "true", "success", "success", True),  # Collection, never qualification.
    ("", "true", "success", "success", False),
    ("1", "true", "failure", "success", False),
    ("1", "true", "success", "skipped", False),
])
def test_actual_collection_mode_keeps_standalone_enforcement_and_requires_evidence(
    raw_exit: str, collect: str, summary: str, upload: str, allowed: bool,
) -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    step = text.split("      - name: Enforce lane result\n", 1)[1]
    script = textwrap.dedent(step.split("      - name: Erase disposable bootstrap authorities", 1)[0]
                             .split("        run: |\n", 1)[1])
    git_bash = Path("C:/Program Files/Git/bin/bash.exe")
    bash = str(git_bash) if os.name == "nt" and git_bash.is_file() else shutil.which("bash")
    assert bash
    result = subprocess.run([bash, "--noprofile", "--norc"], input=script,
                            env={**os.environ, "LANE_EXIT_CODE": raw_exit, "COLLECT_ONLY": collect,
                                 "SUMMARY_OUTCOME": summary, "UPLOAD_OUTCOME": upload},
                            text=True, capture_output=True, check=False)
    assert (result.returncode == 0) == allowed, result.stderr
    if collect == "true" and allowed:
        assert f"Official raw exit is {raw_exit}" in result.stdout


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
    upload = text.split("- name: Upload sanitized evidence", 1)[1].split(
        "- name: Install the digest-pinned private review encryptor", 1
    )[0]
    assert "work/sanitized/" in upload
    assert "work/evidence" not in upload
    assert "work/material" not in upload


def test_private_review_upload_is_ciphertext_only_and_never_an_identity_or_plaintext_export() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    upload = text.split("      - name: Upload only encrypted private review delivery\n", 1)[1].split(
        "      - name: Enforce lane result", 1
    )[0]
    paths = upload.split("          path: |\n", 1)[1].split("          if-no-files-found:", 1)[0]
    assert [line.strip() for line in paths.splitlines()] == [
        "work/review-delivery/${{ matrix.lane }}/review.tar.age",
        "work/review-delivery/${{ matrix.lane }}/review-delivery.json",
    ]
    assert "review-delivery.json" in upload.split("        uses:", 1)[0]
    encryption = text.split("      - name: Encrypt exact private review images and unchanged exports\n", 1)[1].split(
        "      - name: Upload only encrypted private review delivery", 1
    )[0]
    assert '--recipient "$REVIEW_RECIPIENT"' in encryption
    assert "identity" not in encryption
    assert "has_reviews == 'true'" in encryption


def test_private_diagnostic_delivery_is_only_an_explicit_standalone_opt_in() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    reusable = text.split("  workflow_call:", 1)[1].split("  schedule:", 1)[0]
    assert "review_recipient" not in reusable
    assert "vars.OFFICIAL_REVIEW_RECIPIENT" not in text
    recipient = next(line.strip() for line in text.splitlines() if line.strip().startswith("REVIEW_RECIPIENT:"))
    assert "github.event_name == 'workflow_dispatch'" in recipient
    assert "github.repository == 'ElevenID/marty-integration-tests'" in recipient
    assert "inputs.review_recipient || ''" in recipient
    caller = text.split("      - name: Validate candidate caller", 1)[1].split("      - name: Checkout", 1)[0]
    assert "REVIEW_RECIPIENT" not in caller


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
