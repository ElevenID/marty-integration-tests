"""Unit tests for the ElevenID-owned public tenant-boundary dispatcher."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "public_boundary_lane",
    SCRIPTS / "public_boundary_lane.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load public tenant-boundary lane")
lane = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lane)


def test_product_lane_selects_explicit_marty_only_compose_mode(
    tmp_path: Path,
) -> None:
    command = lane.compose_command(
        SimpleNamespace(
            run_id="product-boundary",
            marty_ui=tmp_path / "marty-ui",
        ),
        "up",
        marty_only=True,
    )

    assert "--marty-only" in command
    assert "--oidf" not in command
    assert "--eudi" not in command


def test_product_lane_local_build_is_explicit_and_non_default(
    tmp_path: Path,
) -> None:
    base = SimpleNamespace(
        run_id="product-boundary",
        marty_ui=tmp_path / "marty-ui",
    )
    assert "--local-build" not in lane.boundary_compose_command(base, "up")

    local = SimpleNamespace(**vars(base), local_build=True)
    assert lane.boundary_compose_command(local, "up")[-1] == "--local-build"


def test_local_source_commit_requires_exact_git_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = "a" * 40
    monkeypatch.setattr(
        lane.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, expected, ""),
    )
    assert lane.local_source_commit(tmp_path) == expected

    monkeypatch.setattr(
        lane.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "main", ""),
    )
    with pytest.raises(ValueError, match="exact Git commit"):
        lane.local_source_commit(tmp_path)


def test_public_session_uses_public_login_adapter_without_logging_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        observed["command"] = command
        observed.update(kwargs)
        return subprocess.CompletedProcess(command, 0, "browser-session\n", "")

    monkeypatch.setattr(lane.subprocess, "run", fake_run)
    result = lane.public_session(
        {"OIDF_MARTY_GATEWAY_URL": "https://marty.test"},
        email="reviewer@example.test",
        password="never-log-this",
    )

    assert result == "browser-session"
    assert observed["command"] == [sys.executable, str(lane.PUBLIC_LOGIN)]
    child_environment = observed["env"]
    assert isinstance(child_environment, dict)
    assert child_environment["OIDF_MARTY_OPERATOR_EMAIL"] == "reviewer@example.test"
    assert child_environment["OIDF_MARTY_OPERATOR_PASSWORD"] == "never-log-this"
    assert "never-log-this" not in str(observed["command"])


def test_public_session_rejects_failed_or_malformed_login(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        lane.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [],
            2,
            "",
            "public login failed",
        ),
    )
    with pytest.raises(RuntimeError, match="public OIDC login failed"):
        lane.public_session({}, email="reviewer@example.test", password="secret")

    monkeypatch.setattr(
        lane.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [],
            0,
            "two tokens\n",
            "",
        ),
    )
    with pytest.raises(RuntimeError, match="malformed"):
        lane.public_session({}, email="reviewer@example.test", password="secret")


def test_summary_labels_new_tenant_evidence_as_owned_not_official(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "stack-manifest.json"
    manifest.write_text(
        json.dumps({"release": "marty-ui@test"}) + "\n",
        encoding="utf-8",
    )
    output = tmp_path / "evidence"

    lane.write_summary(
        SimpleNamespace(stack_manifest=manifest, output_dir=output),
        {"marty_commit": "a" * 40},
        0,
    )

    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    assert summary["evidence_class"] == "elevenid-owned-product-security"
    assert summary["execution"] == {
        "mode": "immutable-release",
        "release_grade": True,
    }
    assert summary["official_suite_boundary"] == {
        "official_suite_invoked": False,
        "official_suite_source_modified": False,
        "claim": "This lane is not an official standards-compliance result.",
    }
    assert {
        "issuance transaction and revocation-status isolation",
        "issued-credential lifecycle and revocation isolation",
        "trust-profile ownership and mutation isolation",
        "issuer-entity and trust-profile relationship isolation",
        "applicant form-data and vetting isolation",
        "application evidence collection, deletion, revocation, and tenant isolation",
        "deployment-profile, lane, and device-assignment isolation",
        "wallet catalogue and organization-override isolation",
        "notification SSE delivery and subscription isolation",
        "ambiguous compatible issuer-profile rejection and recovery",
        "encrypted DIDComm v2 delivery with holder-key decryption",
        (
            "browser-driven issuance and verification through the shipped UI, "
            "including adversarial organization and policy substitution"
        ),
    } <= set(summary["coverage"])
    assert summary["test_source"]["additional_paths"] == [lane.DIDCOMM_TEST_PATH]
    assert summary["didcomm_interoperability"]["required"] is False
    assert summary["didcomm_interoperability"]["cross_implementation_decryption_passed"] is False


def test_owned_browser_lane_mutates_real_ui_requests_for_adversarial_checks() -> None:
    source = (
        ROOT / "tests" / "integration" / "gateway" / "test_two_organization_isolation.py"
    ).read_text(encoding="utf-8")

    assert 'page.route("**/approve", substitute_approval_organization, times=1)' in source
    assert 'pattern = "**/v1/flows/verify"' in source
    assert "presentation_policy_id=foreign_presentation_policy_id" in source
    assert "organization_id=foreign_organization_id" in source
    assert "substituted_approval.status in {403, 404}" in source
    assert "response.status in {403, 404, 422}" in source


def test_summary_records_only_executed_independent_didcomm_evidence(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "stack-manifest.json"
    manifest.write_text(json.dumps({"release": "marty-ui@test"}) + "\n", encoding="utf-8")
    output = tmp_path / "evidence"
    implementation = lane.independent_didcomm_record()
    implementation["required"] = True

    lane.write_summary(
        SimpleNamespace(stack_manifest=manifest, output_dir=output),
        {
            "marty_commit": "a" * 40,
            "didcomm_interoperability": implementation,
        },
        0,
    )

    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    interop = summary["didcomm_interoperability"]
    assert interop["cross_implementation_decryption_passed"] is True
    assert interop["implementation"] == {
        "repository": "https://github.com/notabene-id/go-didcomm.git",
        "release": "v0.4.0",
        "commit": "5ffd085c2b5088a639c1c0d3910d668887298ce5",
    }
    assert "independent go-didcomm decryption of Marty's released anoncrypt envelope" in summary["coverage"]


def test_local_summary_cannot_be_mistaken_for_release_evidence(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "stack-manifest.json"
    manifest.write_text(
        json.dumps({"release": "marty-ui@bootstrap"}) + "\n",
        encoding="utf-8",
    )
    output = tmp_path / "evidence"

    lane.write_summary(
        SimpleNamespace(
            stack_manifest=manifest,
            output_dir=output,
            local_build=True,
        ),
        {
            "marty_commit": "b" * 40,
            "bootstrap_marty_commit": "a" * 40,
        },
        0,
    )

    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    assert summary["execution"] == {
        "mode": "local-source-preflight",
        "release_grade": False,
    }
    assert summary["stack"]["marty_commit"] == "b" * 40
    assert summary["stack"]["bootstrap_marty_commit"] == "a" * 40


def test_execute_retains_owned_pytest_diagnostics_as_private_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "evidence"
    args = SimpleNamespace(output_dir=output)
    calls: list[tuple[list[str], Path | None]] = []
    execution_environment = {
        "MARTY_CONFORMANCE_ADMIN_EMAIL": "admin@example.test",
        "MARTY_CONFORMANCE_ADMIN_PASSWORD": "admin-secret",
        "MARTY_CONFORMANCE_REVIEWER_EMAIL": "reviewer@example.test",
        "MARTY_CONFORMANCE_REVIEWER_PASSWORD": "reviewer-secret",
    }

    monkeypatch.setattr(
        lane,
        "environment",
        lambda _args: (
            execution_environment,
            {"marty_commit": "a" * 40},
        ),
    )
    monkeypatch.setattr(
        lane,
        "boundary_compose_command",
        lambda _args, action: ["compose", action],
    )
    monkeypatch.setattr(lane, "wait_for_public_stack", lambda _environment: None)
    monkeypatch.setattr(
        lane,
        "public_session",
        lambda _environment, **_identity: "session",
    )
    monkeypatch.setattr(lane, "write_summary", lambda *_args: None)

    def fake_run(
        command: list[str],
        _environment: dict[str, str],
        *,
        capture: Path | None = None,
    ) -> int:
        calls.append((command, capture))
        return 0

    monkeypatch.setattr(lane, "run", fake_run)

    assert lane.execute(args) == 0
    pytest_calls = [capture for command, capture in calls if command[:3] == [sys.executable, "-m", "pytest"]]
    assert pytest_calls == [output / "private" / "pytest.log"]
    pytest_command = next(command for command, _capture in calls if command[:3] == [sys.executable, "-m", "pytest"])
    assert pytest_command[-2:] == [lane.TEST_PATH, lane.DIDCOMM_TEST_PATH]
    assert execution_environment["DIDCOMM_PRIVATE_AGENT_TESTS"] == "true"


def test_pytest_diagnostic_is_bounded_and_redacts_private_values(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    log = tmp_path / "pytest.log"
    log.write_text(
        "\n".join(
            [f"unrelated-{index}" for index in range(170)]
            + [
                "password=admin-secret",
                "session_id=session-secret",
                "FAILED test_delivery - connection refused",
            ]
        ),
        encoding="utf-8",
    )

    lane.emit_pytest_diagnostic(
        log,
        {
            "MARTY_CONFORMANCE_ADMIN_PASSWORD": "admin-secret",
            "MARTY_CONFORMANCE_REVIEWER_PASSWORD": "reviewer-secret",
            "MARTY_TEST_SESSION_ID": "session-secret",
            "MARTY_REVIEWER_TEST_SESSION_ID": "reviewer-session-secret",
        },
    )

    diagnostic = capsys.readouterr().err
    assert "FAILED test_delivery - connection refused" in diagnostic
    assert "admin-secret" not in diagnostic
    assert "session-secret" not in diagnostic
    assert "password=<redacted>" in diagnostic
    assert "session_id=<redacted>" in diagnostic
    assert "unrelated-0" not in diagnostic


def test_public_boundary_workflow_installs_manifest_pinned_didcomm_verifier() -> None:
    workflow = (Path(__file__).parents[2] / ".github" / "workflows" / "public-tenant-boundary.yml").read_text(
        encoding="utf-8"
    )

    assert "Install attested released DIDComm verifier" in workflow
    assert 'select(.name == "marty-core-python")' in workflow
    assert 'test "$repository" = "ElevenID/marty-core"' in workflow
    assert 'printf \'%s  %s\\n\' "${digest#sha256:}" "$wheel"' in workflow
    assert 'gh attestation verify "$wheel" --repo "$repository"' in workflow
    assert "--no-deps --no-index" in workflow
    assert "callable(_marty_rs.didcomm_decrypt)" in workflow


def test_public_boundary_workflow_builds_pinned_independent_didcomm_verifier() -> None:
    root = Path(__file__).parents[2]
    workflow = (root / ".github" / "workflows" / "public-tenant-boundary.yml").read_text(encoding="utf-8")
    manifest = json.loads((root / "conformance" / "didcomm-interoperability.json").read_text(encoding="utf-8"))
    implementation = manifest["independent_implementation"]

    assert "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16" in workflow
    assert "repository: notabene-id/go-didcomm" in workflow
    assert f"ref: {implementation['commit']}" in workflow
    assert 'go build -mod=readonly -trimpath -o "$verifier" ./cmd/didcomm' in workflow
    assert f"notabene-id/go-didcomm@{implementation['release']}#{implementation['commit']}" in workflow
    assert "DIDCOMM_INDEPENDENT_VERIFIER_REQUIRED=true" in workflow
