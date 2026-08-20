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
    released_command = lane.boundary_compose_command(base, "up")
    assert "--local-build" not in released_command
    assert released_command[-1] == "--didcomm-authcrypt"

    local = SimpleNamespace(**vars(base), local_build=True)
    local_command = lane.boundary_compose_command(local, "up")
    assert local_command[-2:] == ["--didcomm-authcrypt", "--local-build"]


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


def test_did_web_domain_and_authority_bind_the_same_non_default_https_port() -> None:
    assert lane.did_web_domain("marty-oidf.test", None) == "marty-oidf.test"
    assert lane.did_web_domain("marty-oidf.test", 443) == "marty-oidf.test"
    assert lane.did_web_domain("marty-oidf.test", 18443) == "marty-oidf.test:18443"
    assert lane.did_web_authority("marty-oidf.test", None) == "marty-oidf.test"
    assert lane.did_web_authority("marty-oidf.test", 443) == "marty-oidf.test"
    assert lane.did_web_authority("marty-oidf.test", 18443) == "marty-oidf.test%3A18443"


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
        (
            "normalized issuer relationships drive released verification decisions, "
            "including immediate under-review denial, trust-threshold denial, "
            "multi-accreditation evidence denial, and recovery"
        ),
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
    assert summary["test_source"]["additional_paths"] == [
        lane.DIDCOMM_TEST_PATH,
        lane.DIDCOMM_AUTHCRYPT_TEST_PATH,
    ]
    assert summary["didcomm_interoperability"]["required"] is False
    assert summary["didcomm_interoperability"]["cross_implementation_decryption_passed"] is False
    assert (
        summary["didcomm_interoperability"][
            "authcrypt_cross_implementation_decryption_passed"
        ]
        is False
    )


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


def test_owned_tenant_lane_exercises_multiple_accreditation_evidence() -> None:
    source = (
        ROOT / "tests" / "integration" / "gateway" / "test_two_organization_isolation.py"
    ).read_text(encoding="utf-8")

    assert '"accreditations": ["ISO27001", "FIPS140-2"]' in source
    assert '"required_accreditations": ["iso27001", "FIPS140-2"]' in source
    assert '"accreditation_body": "FIPS140-2"' in source
    assert '"accreditations": ["ISO27001"]' in source
    assert '"accreditations": ["FIPS140-2", "iso27001"]' in source
    assert '"Issuer accreditation is missing: fips140-2"' in source


def test_summary_records_only_executed_independent_didcomm_evidence(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "stack-manifest.json"
    manifest.write_text(json.dumps({"release": "marty-ui@test"}) + "\n", encoding="utf-8")
    output = tmp_path / "evidence"
    private = output / "private"
    private.mkdir(parents=True)
    (private / "pytest.xml").write_text(
        (
            '<testsuites><testsuite tests="2"><testcase classname="'
            f'{lane.DIDCOMM_TEST_CLASSNAME}" name="test_deliver_to_mock_agent"'
            ' /><testcase classname="'
            f'{lane.DIDCOMM_TEST_CLASSNAME}" '
            'name="test_deliver_authcrypt_with_managed_issuer" />'
            "</testsuite></testsuites>"
        ),
        encoding="utf-8",
    )
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
        "repository": "https://github.com/sicpa-dlab/didcomm-rust.git",
        "release": "v0.4.1",
        "commit": "9fd70993e9a6e5fd527058ecfe173ee066bcbc27",
    }
    assert "independent didcomm-rust decryption of Marty's released anoncrypt envelope" in summary["coverage"]
    assert summary["didcomm_interoperability"]["cross_implementation_tamper_rejection_passed"] is True
    assert interop["authcrypt_cross_implementation_decryption_passed"] is True
    assert interop["authcrypt_cross_implementation_tamper_rejection_passed"] is True
    assert interop["authcrypt_wrong_sender_key_fail_closed_passed"] is True
    assert any("wrapped-key tampering" in item for item in summary["coverage"])
    assert any("managed-issuer authcrypt envelope" in item for item in summary["coverage"])
    assert any("fails closed before transport" in item for item in summary["coverage"])


@pytest.mark.parametrize(
    "testcase_result",
    [
        "<failure />",
        "<error />",
        "<skipped />",
    ],
)
def test_summary_does_not_claim_failed_or_unexecuted_didcomm_evidence(
    tmp_path: Path,
    testcase_result: str,
) -> None:
    manifest = tmp_path / "stack-manifest.json"
    manifest.write_text(json.dumps({"release": "marty-ui@test"}) + "\n", encoding="utf-8")
    output = tmp_path / "evidence"
    private = output / "private"
    private.mkdir(parents=True)
    (private / "pytest.xml").write_text(
        (
            '<testsuites><testsuite><testcase classname="'
            f'{lane.DIDCOMM_TEST_CLASSNAME}" name="test_deliver_to_mock_agent">'
            f"{testcase_result}</testcase></testsuite></testsuites>"
        ),
        encoding="utf-8",
    )
    implementation = lane.independent_didcomm_record()
    implementation["required"] = True

    lane.write_summary(
        SimpleNamespace(stack_manifest=manifest, output_dir=output),
        {
            "marty_commit": "a" * 40,
            "didcomm_interoperability": implementation,
        },
        1,
    )

    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    interop = summary["didcomm_interoperability"]
    assert interop["cross_implementation_decryption_passed"] is False
    assert interop["cross_implementation_tamper_rejection_passed"] is False
    assert interop["authcrypt_cross_implementation_decryption_passed"] is False
    assert interop["authcrypt_wrong_sender_key_fail_closed_passed"] is False
    assert "independent didcomm-rust decryption of Marty's released anoncrypt envelope" not in summary["coverage"]


def test_summary_preserves_didcomm_success_when_an_unrelated_tenant_test_fails(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "stack-manifest.json"
    manifest.write_text(json.dumps({"release": "marty-ui@test"}) + "\n", encoding="utf-8")
    output = tmp_path / "evidence"
    private = output / "private"
    private.mkdir(parents=True)
    (private / "pytest.xml").write_text(
        (
            '<testsuites><testsuite failures="1" tests="3">'
            '<testcase classname="tests.integration.gateway.test_two_organization_isolation" '
            'name="test_two_principals_cannot_cross_tenant_product_boundaries"><failure /></testcase>'
            '<testcase classname="'
            f'{lane.DIDCOMM_TEST_CLASSNAME}" name="test_deliver_to_mock_agent" />'
            '<testcase classname="'
            f'{lane.DIDCOMM_TEST_CLASSNAME}" '
            'name="test_deliver_authcrypt_with_managed_issuer" />'
            "</testsuite></testsuites>"
        ),
        encoding="utf-8",
    )
    implementation = lane.independent_didcomm_record()
    implementation["required"] = True

    lane.write_summary(
        SimpleNamespace(stack_manifest=manifest, output_dir=output),
        {
            "marty_commit": "a" * 40,
            "didcomm_interoperability": implementation,
        },
        1,
    )

    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    assert summary["result"]["passed"] is False
    assert summary["didcomm_interoperability"]["cross_implementation_decryption_passed"] is True
    assert summary["didcomm_interoperability"]["cross_implementation_tamper_rejection_passed"] is True
    assert (
        summary["didcomm_interoperability"][
            "authcrypt_cross_implementation_decryption_passed"
        ]
        is True
    )


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
    args = SimpleNamespace(output_dir=output, run_id="unit-boundary")
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
    monkeypatch.setattr(
        lane,
        "trust_registry_fixture_command",
        lambda _args, action: ["registry-compose", action],
    )
    monkeypatch.setattr(
        lane,
        "trust_registry_control_url",
        lambda _args, _environment: "http://127.0.0.1:32100",
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
    assert pytest_command[-3:] == [
        lane.TEST_PATH,
        lane.DIDCOMM_TEST_PATH,
        lane.DIDCOMM_AUTHCRYPT_TEST_PATH,
    ]
    assert execution_environment["DIDCOMM_PRIVATE_AGENT_TESTS"] == "true"
    policy_file = Path(execution_environment["MARTY_DIDCOMM_TEST_POLICY_FILE"])
    assert policy_file.name == "didcomm-encryption-policy.json"
    assert not policy_file.exists(), "ephemeral sender custody must be removed after the lane"
    assert execution_environment["DIDCOMM_ENCRYPTION_POLICY_DIR"] == str(
        policy_file.parent
    )
    assert execution_environment["TRUST_REGISTRY_FIXTURE_REQUIRED"] == "true"
    assert execution_environment["TRUST_REGISTRY_FIXTURE_UID"].isdigit()
    assert execution_environment["TRUST_REGISTRY_FIXTURE_GID"].isdigit()
    assert execution_environment["TRUST_REGISTRY_FIXTURE_CONTROL_URL"] == (
        "http://127.0.0.1:32100"
    )


def test_registry_fixture_compose_is_project_scoped_and_immutable() -> None:
    args = SimpleNamespace(run_id="product-boundary")

    command = lane.trust_registry_fixture_command(args, "up")

    assert command == [
        "docker",
        "compose",
        "--project-name",
        "marty-conformance-product-boundary-trust-registry",
        "--file",
        str(lane.TRUST_REGISTRY_FIXTURE_COMPOSE),
        "up",
        "--detach",
        "--wait",
    ]
    compose = lane.TRUST_REGISTRY_FIXTURE_COMPOSE.read_text(encoding="utf-8")
    assert "${MARTY_SERVICES_IMAGE:" in compose
    assert "build:" not in compose
    assert '"127.0.0.1::8080"' in compose
    assert "external: true" in compose
    assert "TRUST_REGISTRY_FIXTURE_UID" in compose
    assert "TRUST_REGISTRY_FIXTURE_GID" in compose
    capabilities = compose.split("cap_add:", 1)[1].split("security_opt:", 1)[0]
    assert "DAC_OVERRIDE" not in capabilities
    assert "read_only: true" in compose
    assert "no-new-privileges:true" in compose
    assert "- ALL" in compose
    assert "NET_BIND_SERVICE" in compose


def test_failed_registry_start_is_diagnosed_and_cleaned_up(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "evidence"
    args = SimpleNamespace(output_dir=output, run_id="unit-boundary")
    calls: list[tuple[list[str], Path | None]] = []
    execution_environment = {
        "MARTY_CONFORMANCE_ADMIN_PASSWORD": "admin-secret",
        "MARTY_CONFORMANCE_REVIEWER_PASSWORD": "reviewer-secret",
    }
    monkeypatch.setattr(
        lane,
        "environment",
        lambda _args: (execution_environment, {"marty_commit": "a" * 40}),
    )
    monkeypatch.setattr(
        lane, "boundary_compose_command", lambda _args, action: ["compose", action]
    )
    monkeypatch.setattr(
        lane,
        "trust_registry_fixture_command",
        lambda _args, action: ["registry-compose", action],
    )
    monkeypatch.setattr(lane, "wait_for_public_stack", lambda _environment: None)
    monkeypatch.setattr(lane, "write_summary", lambda *_args: None)

    def fake_run(
        command: list[str],
        _environment: dict[str, str],
        *,
        capture: Path | None = None,
    ) -> int:
        calls.append((command, capture))
        if command == ["registry-compose", "up"]:
            return 1
        if command == ["registry-compose", "logs"] and capture is not None:
            capture.write_text("permission denied: admin-secret\n", encoding="utf-8")
        return 0

    monkeypatch.setattr(lane, "run", fake_run)

    with pytest.raises(RuntimeError, match="fixture failed to start"):
        lane.execute(args)

    assert (["registry-compose", "logs"], output / "private" / "trust-registry-fixture.log") in calls
    assert (["registry-compose", "down"], None) in calls
    diagnostic = capsys.readouterr().err
    assert "permission denied" in diagnostic
    assert "admin-secret" not in diagnostic
    assert "<redacted>" in diagnostic


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
    assert "callable(_marty_rs.didcomm_decrypt_authcrypt)" in workflow


def test_public_boundary_workflow_builds_pinned_independent_didcomm_verifier() -> None:
    root = Path(__file__).parents[2]
    workflow = (root / ".github" / "workflows" / "public-tenant-boundary.yml").read_text(encoding="utf-8")
    manifest = json.loads((root / "conformance" / "didcomm-interoperability.json").read_text(encoding="utf-8"))
    implementation = manifest["independent_implementation"]

    assert "dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4" in workflow
    assert 'toolchain: "1.97.1"' in workflow
    assert "cargo fetch --locked --manifest-path" in workflow
    assert "cargo build --locked --offline --release --manifest-path" in workflow
    assert f"sicpa-dlab/didcomm-rust@{implementation['release']}#{implementation['commit']}" in workflow
    assert f"didcomm-rust?rev={implementation['commit']}#{implementation['commit']}" in workflow
    assert "DIDCOMM_INDEPENDENT_VERIFIER_REQUIRED=true" in workflow
