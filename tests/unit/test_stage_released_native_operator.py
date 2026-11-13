from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import stage_released_native_operator as staging  # noqa: E402


@pytest.fixture
def context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    checkout = tmp_path / "source"
    (checkout / "scripts").mkdir(parents=True)
    verifier_source = b"# accepted verifier\n"
    verifier = checkout / "scripts/verify_installer_provenance.py"
    verifier.write_bytes(verifier_source)
    native = b"test-native-bytes"
    pin = {"repository": "ElevenID/marty-ui", "release_tag": "v1.1.274",
           "marty_commit": "c" * 40, "marty_checkout_commit": "c" * 40}
    inventory = {
        "schema": "elevenid.installer-inventory/v1", "repository": pin["repository"],
        "source_sha": pin["marty_commit"], "release_tag": pin["release_tag"], "platform": "linux/amd64",
        "build_run_id": 42418639332, "build_run_attempt": 1,
        "artifacts": [{"name": staging.OPERATOR, "size": len(native),
                       "sha256": hashlib.sha256(native).hexdigest()}],
    }
    state: dict[str, Any] = {
        "pin": pin, "checkout": checkout, "output": tmp_path / "staged",
        "inventory": inventory, "events": [], "checkout_head": pin["marty_commit"],
    }

    def run(command: list[str], **_kwargs: Any) -> SimpleNamespace:
        if command[0] == "git":
            return SimpleNamespace(stdout=(state["checkout_head"] + "\n") if "rev-parse" in command
                                   else verifier_source)
        assert command[:3] == [str(tmp_path / "gh"), "release", "download"]
        assert command[3] == pin["release_tag"]
        state["events"].append("download")
        output = state["output"]
        (output / staging.INVENTORY).write_text(json.dumps(inventory), encoding="utf-8")
        (output / staging.OPERATOR).write_bytes(native)
        for name in (staging.INVENTORY, staging.OPERATOR):
            for suffix in (".provenance.jsonl", ".sigstore.json"):
                (output / (name + suffix)).write_text("test-proof", encoding="ascii")
        if state.get("tamper_download"):
            (output / staging.OPERATOR).write_bytes(b"changed")
        return SimpleNamespace(returncode=0)

    def verify(subject: Path, _bundle: Path, **kwargs: Any) -> None:
        assert kwargs["cosign"] == tmp_path / "cosign"
        assert kwargs["source_sha"] == pin["marty_commit"]
        assert kwargs["workflow"] == ".github/workflows/cd.yml"
        assert kwargs["run_id"] == 42418639332
        assert kwargs["run_attempt"] == 1
        assert kwargs["signature_bundle"] == subject.with_name(subject.name + ".sigstore.json")
        state["events"].append("verify:" + subject.name)
        if state.get("rejected_subject") == subject.name:
            raise ValueError("invalid producer proof")
        if subject.name == staging.OPERATOR and state.get("tamper_after_verification"):
            subject.write_bytes(b"changed")

    def probe(binary: Path) -> str:
        assert state["events"][-2:] == ["verify:" + staging.INVENTORY, "verify:" + staging.OPERATOR]
        state["events"].append("execute")
        if state.get("tamper_during_probe"):
            binary.write_bytes(b"changed")
        return state.get("probe_identity", pin["marty_commit"] + ":" + pin["release_tag"])

    monkeypatch.setattr(staging.subprocess, "run", run)
    monkeypatch.setattr(staging.runpy, "run_path", lambda _path: {"verify_subject": verify})
    state["invoke"] = lambda: staging.stage(pin, checkout, state["output"],
                                             gh=tmp_path / "gh", cosign=tmp_path / "cosign", probe=probe)
    return state


def test_inventory_and_native_both_authenticate_before_execution(context: dict[str, Any]) -> None:
    environment = context["invoke"]()
    assert context["events"] == ["download", "verify:" + staging.INVENTORY, "verify:" + staging.OPERATOR, "execute"]
    assert environment == {
        "MARTY_DEPLOY_BIN": str(context["output"] / staging.OPERATOR),
        "MARTY_DEPLOY_BIN_SHA256": context["inventory"]["artifacts"][0]["sha256"],
        "MARTY_DEPLOY_SOURCE_SHA": "c" * 40, "MARTY_DEPLOY_RELEASE_TAG": "v1.1.274",
    }


@pytest.mark.parametrize("subject", [staging.INVENTORY, staging.OPERATOR])
def test_rejected_signature_or_provenance_never_executes(context: dict[str, Any], subject: str) -> None:
    context["rejected_subject"] = subject
    with pytest.raises(ValueError, match="invalid producer proof"):
        context["invoke"]()
    assert "execute" not in context["events"]


@pytest.mark.parametrize(("field", "value"), [
    ("source_sha", "d" * 40), ("release_tag", "v1.1.275"), ("platform", "linux/arm64"),
    ("repository", "foreign/repository"), ("build_run_id", True), ("build_run_attempt", 0),
])
def test_inventory_cannot_select_another_platform_or_producer(
    context: dict[str, Any], field: str, value: Any,
) -> None:
    context["inventory"][field] = value
    with pytest.raises(ValueError, match="reviewed platform"):
        context["invoke"]()
    assert context["events"] == ["download"]


@pytest.mark.parametrize("phase", ["tamper_download", "tamper_after_verification", "tamper_during_probe"])
def test_operator_changes_are_detected(context: dict[str, Any], phase: str) -> None:
    context[phase] = True
    with pytest.raises(ValueError, match="inventory|bytes changed"):
        context["invoke"]()
    assert ("execute" in context["events"]) is (phase == "tamper_during_probe")


def test_wrong_build_identity_is_not_exported(context: dict[str, Any]) -> None:
    context["probe_identity"] = "c" * 40 + ":v1.1.275"
    with pytest.raises(ValueError, match="build identity"):
        context["invoke"]()


def test_stale_output_is_not_reused(context: dict[str, Any]) -> None:
    context["output"].mkdir()
    with pytest.raises(FileExistsError):
        context["invoke"]()
    assert context["events"] == []


def test_checkout_and_verifier_must_match_reviewed_source(context: dict[str, Any]) -> None:
    context["checkout_head"] = "d" * 40
    with pytest.raises(ValueError, match="source"):
        context["invoke"]()
    context["checkout_head"] = "c" * 40
    (context["checkout"] / "scripts/verify_installer_provenance.py").write_text("changed", encoding="ascii")
    with pytest.raises(ValueError, match="verifier differs"):
        context["invoke"]()
    assert context["events"] == []


def test_windows_checkout_newlines_preserve_verifier_source(context: dict[str, Any]) -> None:
    (context["checkout"] / "scripts/verify_installer_provenance.py").write_bytes(b"# accepted verifier\r\n")
    assert context["invoke"]()["MARTY_DEPLOY_SOURCE_SHA"] == "c" * 40


@pytest.mark.parametrize(("filename", "bootstrap", "conditional"), [
    ("official-interoperability.yml", "Bootstrap disposable KMS-only released stack", True),
    ("public-tenant-boundary.yml", "Run ElevenID-owned public-boundary matrix", False),
])
def test_published_consumers_stage_verified_operator_before_mutation(
    filename: str, bootstrap: str, conditional: bool,
) -> None:
    path = Path(__file__).resolve().parents[2] / ".github/workflows" / filename
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    jobs = [job for job in workflow["jobs"].values() if any(
        step.get("name") == "Stage signed source-matched released native operator"
        for step in job.get("steps", [])
    )]
    assert len(jobs) == 1
    steps = jobs[0]["steps"]
    install_index = next(i for i, step in enumerate(steps)
                         if step.get("name") == "Install pinned published-operator signature verifier")
    stage_index = next(i for i, step in enumerate(steps)
                       if step.get("name") == "Stage signed source-matched released native operator")
    bootstrap_index = next(i for i, step in enumerate(steps) if step.get("name") == bootstrap)
    assert install_index < stage_index < bootstrap_index
    install, stage = steps[install_index], steps[stage_index]
    assert install["uses"] == "sigstore/cosign-installer@756fe2d284c7292c4e9b62c8a28f1e5629c59532"
    assert install["with"]["cosign-release"] == "v3.1.4"
    assert stage["env"] == {"GH_TOKEN": "$" + "{{ github.token }}"}
    assert "--pin conformance/stack-under-test.json" in stage["run"]
    assert "--marty-ui work/marty-ui" in stage["run"]
    assert "--github-env \"$GITHUB_ENV\"" in stage["run"]
    if conditional:
        assert install["if"] == stage["if"] == "inputs.candidate_artifact == ''"
    else:
        assert "if" not in stage
