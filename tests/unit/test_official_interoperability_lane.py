from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "official_interoperability_lane", ROOT / "scripts" / "official_interoperability_lane.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load official interoperability lane")
lane = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lane)
eudi_material = importlib.import_module("eudi_test_material")


def stack_binding_fixture(tmp_path: Path) -> tuple[Path, dict[str, object], dict[str, str]]:
    references = {
        "MARTY_UI_IMAGE": "ghcr.io/elevenid/marty-ui-oss/ui@sha256:" + "1" * 64,
        "MARTY_SERVICES_IMAGE": "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "2" * 64,
        "MARTY_MIGRATIONS_IMAGE": "ghcr.io/elevenid/marty-ui-oss/migrations@sha256:" + "3" * 64,
        "MARTY_ISSUANCE_IMAGE": "ghcr.io/elevenid/marty-credentials-issuance@sha256:" + "4" * 64,
    }
    manifest = tmp_path / "stack-manifest.json"
    artifacts = []
    for reference in references.values():
        uri, digest = reference.split("@", 1)
        artifacts.append({"type": "oci", "uri": uri, "digest": digest})
    manifest.write_text(
        json.dumps(
            {
                "schema": "marty.stack/v1",
                "release": "marty-ui@1.2.3",
                "components": [
                    {"name": "images", "artifacts": artifacts},
                    {
                        "name": "marty-core-python",
                        "repository": "ElevenID/marty-core",
                        "artifacts": [
                            {
                                "type": "python",
                                "uri": "https://github.com/ElevenID/marty-core/releases/download/v0.1.0/marty_rs.whl",
                                "digest": "sha256:" + "5" * 64,
                            }
                        ],
                    },
                    {
                        "name": "marty-verification-python",
                        "repository": "ElevenID/marty-core",
                        "artifacts": [
                            {
                                "type": "python",
                                "uri": "https://github.com/ElevenID/marty-core/releases/download/v0.1.0/marty_verification_py.whl",
                                "digest": "sha256:" + "7" * 64,
                            }
                        ],
                    },
                    {
                        "name": "marty-iso18013-python",
                        "repository": "ElevenID/marty-core",
                        "artifacts": [
                            {
                                "type": "python",
                                "uri": "https://github.com/ElevenID/marty-core/releases/download/v0.1.0/marty_iso18013.whl",
                                "digest": "sha256:" + "8" * 64,
                            }
                        ],
                    },
                    {
                        "name": "marty-common",
                        "repository": "ElevenID/Marty",
                        "artifacts": [
                            {
                                "type": "python",
                                "uri": "https://github.com/ElevenID/Marty/releases/download/v0.1.0/marty_common.whl",
                                "digest": "sha256:" + "6" * 64,
                            }
                        ],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    metadata: dict[str, object] = {
        "schema": "elevenid.official-stack-material/v1",
        "manifest_path": str(manifest.resolve()),
        "manifest_sha256": lane.file_sha256(manifest),
        "marty_commit": "a" * 40,
        "images": [{"reference": reference} for reference in references.values()],
    }
    base_images = json.loads((ROOT / "config" / "base-images.json").read_text(encoding="utf-8"))
    environment = {
        **references,
        "MARTY_RS_URI": "https://github.com/ElevenID/marty-core/releases/download/v0.1.0/marty_rs.whl",
        "MARTY_RS_DIGEST": "sha256:" + "5" * 64,
        "MARTY_VERIFICATION_URI": "https://github.com/ElevenID/marty-core/releases/download/v0.1.0/marty_verification_py.whl",
        "MARTY_VERIFICATION_DIGEST": "sha256:" + "7" * 64,
        "MARTY_ISO18013_URI": "https://github.com/ElevenID/marty-core/releases/download/v0.1.0/marty_iso18013.whl",
        "MARTY_ISO18013_DIGEST": "sha256:" + "8" * 64,
        "MARTY_COMMON_URI": "https://github.com/ElevenID/Marty/releases/download/v0.1.0/marty_common.whl",
        "MARTY_COMMON_DIGEST": "sha256:" + "6" * 64,
        "POSTGRES_IMAGE": base_images["postgres"],
        "REDIS_IMAGE": base_images["redis"],
    }
    return manifest, metadata, environment


def test_stack_environment_accepts_only_complete_digest_pins(tmp_path: Path) -> None:
    path = tmp_path / ".env.stack"
    artifact_repositories = {
        f"{prefix}_URI": repository
        for prefix, (_component, _artifact_type, repository) in lane.STACK_ARTIFACT_ENVIRONMENT.items()
    }
    path.write_text(
        "\n".join(
            (
                f"{name}=https://github.com/{artifact_repositories[name]}/releases/download/v0.1.0/{name.lower()}.whl"
                if name.endswith("_URI")
                else f"{name}=sha256:{index:064x}"
                if name.endswith("_DIGEST")
                else f"{name}=ghcr.io/elevenid/{name.lower()}@sha256:{index:064x}"
            )
            for index, name in enumerate(sorted(lane.STACK_ENV_KEYS), 1)
        ),
        encoding="utf-8",
    )
    assert set(lane.load_stack_environment(path)) == lane.STACK_ENV_KEYS
    path.write_text("MARTY_UI_IMAGE=ghcr.io/elevenid/ui:latest\n", encoding="utf-8")
    with pytest.raises(ValueError, match="sha256"):
        lane.load_stack_environment(path)


def test_keycloak_initializer_diagnostic_redacts_secret_values() -> None:
    value = "password=private-value token: abc123 Authorization is bearer-value session_id=opaque-cookie"
    redacted = lane.redact_initializer_log(value)
    assert "private-value" not in redacted
    assert "abc123" not in redacted
    assert "bearer-value" not in redacted
    assert "opaque-cookie" not in redacted
    assert redacted.count("<redacted>") == 4


def test_oid4vci_runtime_diagnostic_emits_only_fixed_categories(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    log = tmp_path / "compose.log"
    log.write_text(
        "proof verification failed: Key-attestation-bound proof has no resolved tenant issuer policy "
        "token=must-not-leak\n",
        encoding="utf-8",
    )

    lane.emit_oid4vci_runtime_diagnostic(log)

    output = capsys.readouterr().err
    assert "key-attestation-policy-unresolved" in output
    assert "must-not-leak" not in output
    assert "proof verification failed" not in output


def test_oid4vp_browser_runtime_diagnostic_emits_only_fixed_categories(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    log = tmp_path / "compose.log"
    log.write_text(
        "token=must-not-leak\n"
        "Issuer DID resolves to multiple active issuer profiles for the requested tuple\n"
        "POST /v1/flows/verify HTTP/1.1 500\n",
        encoding="utf-8",
    )

    lane.emit_oid4vp_browser_runtime_diagnostic(log)

    output = capsys.readouterr().err
    assert "issuer-did-ambiguous" in output
    assert "public-flow-http-500" in output
    assert "must-not-leak" not in output
    assert "multiple active issuer profiles" not in output


def test_oid4vp_browser_runtime_diagnostic_reports_unavailable_log(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lane.emit_oid4vp_browser_runtime_diagnostic(tmp_path / "missing.log")

    output = capsys.readouterr().err
    assert "categories=runtime-log-unavailable" in output


def test_keycloak_startup_diagnostic_includes_service_logs_and_redacts(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class Result:
        def __init__(self, stdout: str = "", stderr: str = "") -> None:
            self.stdout = stdout
            self.stderr = stderr

    calls: list[list[str]] = []

    def docker(command: list[str], **_kwargs: object) -> Result:
        calls.append(command)
        if command[1] == "ps":
            return Result("container-id\n" if command[-1].endswith("=keycloak") else "")
        return Result("Keycloak started with password=private-value\n")

    monkeypatch.setattr(lane.subprocess, "run", docker)

    lane.emit_keycloak_initializer_diagnostic("w3c-v2-1")

    output = capsys.readouterr().out
    assert "--- keycloak diagnostic (redacted) ---" in output
    assert "No keycloak-configurator container was created." in output
    assert "private-value" not in output
    assert "password=<redacted>" in output
    assert any(command[-1].endswith("=keycloak") for command in calls if command[1] == "ps")


def test_oidf_startup_failure_is_diagnosed_before_retained_projects_are_removed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[list[str]] = []
    events: list[str] = []

    def fake_run(command: list[str], _environment: dict[str, str], **_kwargs: object) -> int:
        calls.append(command)
        rendered = " ".join(command)
        if "official_suite_compose.py" in rendered and " up " in f" {rendered} ":
            return 17
        if "official_suite_compose.py" in rendered and " down " in f" {rendered} ":
            events.append("down")
        return 0

    monkeypatch.setattr(lane, "run", fake_run)
    monkeypatch.setattr(
        lane,
        "emit_keycloak_initializer_diagnostic",
        lambda run_id: events.append(f"diagnostic:{run_id}"),
    )
    args = SimpleNamespace(
        lane="oid4vp-final",
        marty_ui=tmp_path / "marty-ui",
        run_id="run-1",
        oidf_runner=tmp_path / "runner",
        haip_material=tmp_path / "haip",
        output_dir=tmp_path / "output",
        stack_manifest=tmp_path / "stack-manifest.json",
    )

    assert lane.run_oidf(args, {}) == 1
    assert events == ["diagnostic:run-1", "down"]
    up = calls[0]
    assert "--retain-on-up-failure" in up


def test_w3c_issuance_diagnostic_prints_only_redacted_error_lines(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class Result:
        def __init__(self, stdout: str = "", stderr: str = "") -> None:
            self.stdout = stdout
            self.stderr = stderr

    calls: list[list[str]] = []

    def docker(command: list[str], **_kwargs: object) -> Result:
        calls.append(command)
        if command[1] == "ps":
            return Result("issuance-container\n" if command[-1].endswith("=issuance") else "")
        return Result(
            "routine startup complete\n"
            "credential creation failed: session_id=opaque-cookie reason=remote signer unavailable\n"
        )

    monkeypatch.setattr(lane.subprocess, "run", docker)

    lane.emit_w3c_issuance_diagnostic("w3c-v2-1")

    output = capsys.readouterr().out
    assert "issuance W3C issuance diagnostic" in output
    assert "credential creation failed" in output
    assert "opaque-cookie" not in output
    assert "session_id=<redacted>" in output
    assert "routine startup complete" not in output
    assert any(command[-1].endswith("=presentation-policy") for command in calls if command[1] == "ps")
    assert ["docker", "logs", "--tail", "2000", "issuance-container"] in calls


def test_w3c_lane_emits_issuance_diagnostic_when_the_official_suite_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    args = SimpleNamespace(
        marty_ui=tmp_path,
        run_id="w3c-v2-1",
        w3c_suite=tmp_path / "w3c-suite",
        stack_manifest=tmp_path / "stack-manifest.json",
        output_dir=tmp_path / "evidence",
    )
    exit_codes = iter((0, 1, 0))
    diagnostics: list[str] = []

    monkeypatch.setattr(lane, "run", lambda *_args, **_kwargs: next(exit_codes))
    monkeypatch.setattr(lane, "wait_for_public_stack", lambda _environment: None)
    monkeypatch.setattr(
        lane,
        "bootstrap_fixtures",
        lambda *_args, **_kwargs: {
            "organization_id": "organization",
            "w3c_issuer_did": "did:web:marty-oidf.test:orgs:organization",
            "w3c_template_id": "template",
            "w3c_credential_policy_id": "credential-policy",
            "w3c_presentation_policy_id": "presentation-policy",
            "w3c_api_key_id": "api-key-id",
            "w3c_api_key": "mk_test_fixture",
        },
    )
    monkeypatch.setattr(lane, "emit_w3c_issuance_diagnostic", diagnostics.append)

    assert lane.run_w3c(args, {"OIDF_MARTY_GATEWAY_URL": "https://marty-oidf.test"}) == 1
    assert diagnostics == ["w3c-v2-1"]


def test_mdoc_runtime_diagnostic_reports_only_fixed_categories(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    log = tmp_path / "compose.log"
    log.write_text(
        "token=must-not-be-reported\n"
        "Policy evaluation denied because a required claim is missing\n"
        "issuer_signature_valid=false\n"
        "mDoc verification outcome device_auth_error_kind=device-signature-invalid\n"
        "mDoc verification outcome device_auth_error_kind=attacker-controlled-value\n",
        encoding="utf-8",
    )

    lane.emit_mdoc_runtime_diagnostic(log)

    output = capsys.readouterr().err
    assert "presentation-policy-denied" in output
    assert "required-claim-missing" in output
    assert "issuer-signature-invalid" in output
    assert "device-auth-error-kind-device-signature-invalid" in output
    assert "attacker-controlled-value" not in output
    assert "must-not-be-reported" not in output


def test_mdoc_runtime_diagnostic_reports_unavailable_log(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    lane.emit_mdoc_runtime_diagnostic(tmp_path / "missing.log")

    output = capsys.readouterr().err
    assert "categories=runtime-log-unavailable" in output


def test_material_environment_uses_private_generator_envelope(tmp_path: Path) -> None:
    for filename in (
        "tls.crt",
        "tls.key",
        "oidf-runner-tls.crt",
        "oidf-runner-tls.key",
        "root-ca.pem",
        "truststore.jks",
        "keystore.jks",
    ):
        (tmp_path / filename).write_text("fixture", encoding="utf-8")
    (tmp_path / "environment.json").write_text(
        json.dumps(
            {
                "schema": "elevenid.eudi-test-material/v1",
                "mode": "generated",
                "environment": {
                    "OIDF_PUBLIC_BASE_URL": "https://marty-oidf.test:18443",
                    "EUDI_VERIFIER_KEYSTORE_PASSWORD": "private-value",
                },
            }
        ),
        encoding="utf-8",
    )
    environment = lane.load_material_environment(tmp_path)
    assert environment["OIDF_TLS_CERT_DIR"] == str(tmp_path.resolve())
    assert environment["EUDI_VERIFIER_KEYSTORE_FILE"].endswith("keystore.jks")
    data = json.loads((tmp_path / "environment.json").read_text(encoding="utf-8"))
    data["environment"]["UNREVIEWED_SECRET"] = "no"
    (tmp_path / "environment.json").write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported keys"):
        lane.load_material_environment(tmp_path)


def test_material_environment_accepts_the_complete_generated_contract(tmp_path: Path) -> None:
    for filename in (
        "tls.crt",
        "tls.key",
        "oidf-runner-tls.crt",
        "oidf-runner-tls.key",
        "root-ca.pem",
        "truststore.jks",
        "keystore.jks",
    ):
        (tmp_path / filename).write_text("fixture", encoding="utf-8")
    environment = eudi_material._environment(
        tmp_path,
        hostname="marty-oidf.test",
        marty_port=18443,
        verifier_port=28091,
        wallet_kit_port=29090,
        store_password="store-password",
        key_password="key-password",
        truststore_password="trust-password",
        alias="eudi-verifier",
    )
    (tmp_path / "environment.json").write_text(
        json.dumps(
            {
                "schema": "elevenid.eudi-test-material/v1",
                "mode": "generated",
                "environment": environment,
            }
        ),
        encoding="utf-8",
    )

    loaded = lane.load_material_environment(tmp_path)

    assert set(environment) <= set(loaded)
    assert loaded[lane.OID4VP_TRUST_ANCHOR_FILE_ENV] == str((tmp_path / "root-ca.pem").resolve())


def test_stack_metadata_must_be_a_json_object(tmp_path: Path) -> None:
    path = tmp_path / "stack-metadata.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        lane.load_stack_metadata(path)


def test_stack_binding_accepts_only_the_attested_manifest_and_rendered_images(tmp_path: Path) -> None:
    manifest, metadata, environment = stack_binding_fixture(tmp_path)
    lane.validate_stack_binding(manifest, metadata, environment)


def test_stack_binding_rejects_a_different_evidence_manifest(tmp_path: Path) -> None:
    manifest, metadata, environment = stack_binding_fixture(tmp_path)
    copy = tmp_path / "evidence-manifest.json"
    copy.write_bytes(manifest.read_bytes())
    with pytest.raises(ValueError, match="metadata path"):
        lane.validate_stack_binding(copy, metadata, environment)


def test_stack_binding_rejects_manifest_tampering(tmp_path: Path) -> None:
    manifest, metadata, environment = stack_binding_fixture(tmp_path)
    manifest.write_text(manifest.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="metadata digest"):
        lane.validate_stack_binding(manifest, metadata, environment)


def test_stack_binding_rejects_a_deployed_image_not_in_evidence(tmp_path: Path) -> None:
    manifest, metadata, environment = stack_binding_fixture(tmp_path)
    environment["MARTY_UI_IMAGE"] = "ghcr.io/elevenid/marty-ui-oss/ui@sha256:" + "f" * 64
    with pytest.raises(ValueError, match="MARTY_UI_IMAGE"):
        lane.validate_stack_binding(manifest, metadata, environment)


def test_standard_verifier_config_reuses_generated_wallet_key_and_request_trust(
    tmp_path: Path,
) -> None:
    source = {
        "credential": {"signing_jwk": {"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "d": "d"}},
        "client": {"request_object_trust_anchor_pem": "test-root"},
    }
    (tmp_path / "marty-verifier-haip.json").write_text(json.dumps(source), encoding="utf-8")
    destination = lane.standard_verifier_config(tmp_path, "https://marty.test")
    config = json.loads(destination.read_text(encoding="utf-8"))
    assert config["alias"] == lane.OIDF_VERIFIER_ALIAS
    assert config["verifier"]["profile"] == "oid4vp-1.0-final"
    assert config["client"]["request_object_trust_anchor_pem"] == "test-root"
    assert config["browser"] == lane.VERIFICATION_EVIDENCE_BROWSER_AUTOMATION


def test_oidf_fixture_bootstrap_receives_the_private_runner_config_by_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[str] = []
    output_dir = tmp_path / "output"
    haip_material = tmp_path / "haip"
    haip_material.mkdir()

    def fake_run(command: list[str], _environment: dict[str, str], **_kwargs: object) -> int:
        captured.extend(command)
        destination = Path(command[command.index("--output") + 1])
        destination.parent.mkdir(parents=True)
        destination.write_text(
            json.dumps(
                {
                    "organization_id": "org-1",
                    "oid4vp_template_id": "template-1",
                    "oid4vp_policy_id": "policy-1",
                    "oid4vp_trust_profile_id": "trust-1",
                    "oid4vp_request_issuer_public_jwk": {
                        "kty": "EC",
                        "crv": "P-256",
                        "x": "public-x",
                        "y": "public-y",
                    },
                    "oid4vp_credential_issuer_public_jwk": {
                        "kty": "EC",
                        "crv": "P-256",
                        "x": "credential-public-x",
                        "y": "credential-public-y",
                    },
                }
            ),
            encoding="utf-8",
        )
        return 0

    monkeypatch.setattr(lane, "run", fake_run)
    args = SimpleNamespace(
        output_dir=output_dir,
        run_id="run-1",
        haip_material=haip_material,
    )

    result = lane.bootstrap_fixtures(
        args,
        {"OIDF_MARTY_GATEWAY_URL": "https://marty.test"},
        mode="oid4vp",
    )

    assert result["oid4vp_trust_profile_id"] == "trust-1"
    assert result["oid4vp_credential_issuer_public_jwk"] == {
        "kty": "EC",
        "crv": "P-256",
        "x": "credential-public-x",
        "y": "credential-public-y",
    }
    assert captured[captured.index("--oidf-runner-config") + 1] == str(haip_material / "marty-verifier-haip.json")


def test_oid4vci_fixture_bootstrap_accepts_public_configuration_fragment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(
        command: list[str],
        _environment: dict[str, str],
        **_kwargs: object,
    ) -> int:
        destination = Path(command[command.index("--output") + 1])
        destination.parent.mkdir(parents=True)
        destination.write_text(
            json.dumps(
                {
                    "organization_id": "org-1",
                    "oid4vci_template_id": "template-1",
                    "oid4vci_credential_configuration_id": "PID#sd-jwt",
                    "oid4vci_issuer_did": "did:web:marty.test:orgs:org-1",
                }
            ),
            encoding="utf-8",
        )
        return 0

    monkeypatch.setattr(lane, "run", fake_run)
    args = SimpleNamespace(
        output_dir=tmp_path / "output",
        run_id="run-1",
        haip_material=tmp_path / "haip",
    )

    result = lane.bootstrap_fixtures(
        args,
        {"OIDF_MARTY_GATEWAY_URL": "https://marty.test"},
        mode="oid4vci",
        oidf_key_attestation_trust_anchor=tmp_path / "attester-root.pem",
    )

    assert result["oid4vci_credential_configuration_id"] == "PID#sd-jwt"


def test_eudi_fixture_bootstrap_accepts_only_public_request_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(
        command: list[str],
        _environment: dict[str, str],
        **_kwargs: object,
    ) -> int:
        destination = Path(command[command.index("--output") + 1])
        destination.parent.mkdir(parents=True)
        destination.write_text(
            json.dumps(
                {
                    "organization_id": "org-1",
                    "eudi_issuer_did": "did:web:marty.test:orgs:org-1",
                    "eudi_request_issuer_did": "did:web:marty.test:orgs:org-1",
                    "eudi_request_issuer_public_jwk": {
                        "kty": "EC",
                        "crv": "P-256",
                        "x": "public-x",
                        "y": "public-y",
                    },
                    "eudi_passport_template_id": "passport-1",
                    "eudi_mdl_template_id": "mdl-1",
                    "eudi_open_badge_template_id": "badge-1",
                }
            ),
            encoding="utf-8",
        )
        return 0

    monkeypatch.setattr(lane, "run", fake_run)
    result = lane.bootstrap_fixtures(
        SimpleNamespace(
            output_dir=tmp_path / "output",
            run_id="run-1",
            haip_material=tmp_path / "haip",
        ),
        {"OIDF_MARTY_GATEWAY_URL": "https://marty.test"},
        mode="eudi",
        oidf_key_attestation_trust_anchor=tmp_path / "attester-root.pem",
    )

    assert result["eudi_request_issuer_public_jwk"] == {
        "kty": "EC",
        "crv": "P-256",
        "x": "public-x",
        "y": "public-y",
    }


def test_eudi_fixture_bootstrap_rejects_private_request_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(
        command: list[str],
        _environment: dict[str, str],
        **_kwargs: object,
    ) -> int:
        destination = Path(command[command.index("--output") + 1])
        destination.parent.mkdir(parents=True)
        destination.write_text(
            json.dumps(
                {
                    "organization_id": "org-1",
                    "eudi_request_issuer_public_jwk": {
                        "kty": "EC",
                        "crv": "P-256",
                        "x": "public-x",
                        "y": "public-y",
                        "d": "must-never-cross-custody-boundary",
                    },
                }
            ),
            encoding="utf-8",
        )
        return 0

    monkeypatch.setattr(lane, "run", fake_run)
    with pytest.raises(RuntimeError, match="invalid request-signing public JWK"):
        lane.bootstrap_fixtures(
            SimpleNamespace(
                output_dir=tmp_path / "output",
                run_id="run-1",
                haip_material=tmp_path / "haip",
            ),
            {"OIDF_MARTY_GATEWAY_URL": "https://marty.test"},
            mode="eudi",
            oidf_key_attestation_trust_anchor=tmp_path / "attester-root.pem",
        )


def test_fixture_bootstrap_rejects_control_characters(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(
        command: list[str],
        _environment: dict[str, str],
        **_kwargs: object,
    ) -> int:
        destination = Path(command[command.index("--output") + 1])
        destination.parent.mkdir(parents=True)
        destination.write_text(
            json.dumps({"organization_id": "org-1\nforged-log-entry"}),
            encoding="utf-8",
        )
        return 0

    monkeypatch.setattr(lane, "run", fake_run)
    args = SimpleNamespace(
        output_dir=tmp_path / "output",
        run_id="run-1",
        haip_material=tmp_path / "haip",
    )

    with pytest.raises(
        RuntimeError,
        match="oid4vci public fixture bootstrap returned invalid identifiers",
    ):
        lane.bootstrap_fixtures(
            args,
            {"OIDF_MARTY_GATEWAY_URL": "https://marty.test"},
            mode="oid4vci",
            oidf_key_attestation_trust_anchor=tmp_path / "attester-root.pem",
        )


def test_oid4vci_config_uses_disposable_public_fixture_ids(tmp_path: Path) -> None:
    key_attestation_jwks, root_path = lane.oidf_key_attestation_material(tmp_path)
    config, request = lane.oid4vci_issuer_config(
        tmp_path,
        "https://marty.test",
        {
            "organization_id": "org-1",
            "oid4vci_template_id": "template-1",
            "oid4vci_credential_configuration_id": "PID#sd-jwt",
            "oid4vci_issuer_did": "did:web:marty.test:orgs:org-1",
        },
        key_attestation_jwks,
    )

    data = json.loads(config.read_text(encoding="utf-8"))
    assert data["vci"] == {
        "credential_issuer_url": "https://marty.test/org/org-1",
        "authorization_server": "https://marty.test/org/org-1",
        "credential_configuration_id": "PID#sd-jwt",
        "credential_proof_type_hint": "jwt",
    }
    assert data["client"]["client_id"] == "marty-official-wallet-org-1"
    assert data["client2"]["client_id"] == "marty-official-wallet-2-org-1"
    attester = data["client_attestation"]["key_attestation_jwks"]["keys"][0]
    assert attester["alg"] == "ES256"
    assert attester["d"]
    assert len(attester["x5c"]) == 2
    if os.name != "nt":
        assert root_path.stat().st_mode & 0o777 == 0o600
    request_data = json.loads(request.read_text(encoding="utf-8"))
    assert request_data["claims"]["employee_id"] == "oidf-conformance"
    for runner_client, registered_client in zip(
        (data["client"], data["client2"]),
        request_data["authorized_clients"],
        strict=True,
    ):
        private_key = runner_client["jwks"]["keys"][0]
        public_key = registered_client["jwks"]["keys"][0]
        assert private_key["d"]
        assert "d" not in public_key
        assert public_key == {name: value for name, value in private_key.items() if name != "d"}
        assert registered_client["client_id"] == runner_client["client_id"]


def test_oidf_key_attestation_material_is_disposable_ca_bound(tmp_path: Path) -> None:
    jwks, root_path = lane.oidf_key_attestation_material(tmp_path)

    root = lane.x509.load_pem_x509_certificate(root_path.read_bytes())
    assert root.extensions.get_extension_for_class(lane.x509.BasicConstraints).value.ca is True
    key = jwks["keys"][0]
    leaf = lane.x509.load_der_x509_certificate(lane.base64.b64decode(key["x5c"][0]))
    assert leaf.issuer == root.subject
    assert leaf.extensions.get_extension_for_class(lane.x509.BasicConstraints).value.ca is False
    assert key["d"]


def test_oid4vci_lane_runs_official_plan_through_public_issuance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    official_command: list[str] = []
    suite_environment: dict[str, str] = {}

    def fake_run(
        command: list[str],
        environment: dict[str, str],
        **_kwargs: object,
    ) -> int:
        if "oidf_conformance.py" in " ".join(command):
            official_command.extend(command)
            suite_environment.update(environment)
        return 0

    monkeypatch.setattr(lane, "run", fake_run)
    monkeypatch.setattr(lane, "wait_for_public_stack", lambda _environment: None)
    monkeypatch.setattr(
        lane,
        "bootstrap_fixtures",
        lambda *_args, **_kwargs: {
            "organization_id": "org-1",
            "oid4vci_template_id": "template-1",
            "oid4vci_credential_configuration_id": "PID#sd-jwt",
            "oid4vci_issuer_did": "did:web:marty.test:orgs:org-1",
        },
    )
    args = SimpleNamespace(
        lane="oid4vci-issuer",
        marty_ui=tmp_path / "marty-ui",
        run_id="run-1",
        oidf_runner=tmp_path / "runner",
        output_dir=tmp_path / "output",
        stack_manifest=tmp_path / "stack-manifest.json",
    )

    assert (
        lane.run_oid4vci_issuer(
            args,
            {"OIDF_MARTY_GATEWAY_URL": "https://marty.test"},
        )
        == 0
    )
    assert official_command[official_command.index("--profile") + 1] == "oid4vci-issuer"
    assert "--allow-planned-profile" not in official_command
    assert suite_environment["OIDF_MARTY_ORGANIZATION_ID"] == "org-1"
    assert suite_environment["OIDF_MARTY_CREDENTIAL_TEMPLATE_ID"] == "template-1"
    assert suite_environment["OIDF_MARTY_ISSUER_DID"] == "did:web:marty.test:orgs:org-1"
    assert suite_environment["OIDF_ISSUANCE_COMMAND"].endswith("oidf_marty_public_issuance.py")
    assert "OIDF_ISSUANCE_API_KEY" not in suite_environment


def test_oidf_lane_binds_the_disposable_trust_profile_to_the_real_flow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suite_environment: dict[str, str] = {}
    compose_commands: list[list[str]] = []
    executed_commands: list[list[str]] = []

    def fake_run(command: list[str], environment: dict[str, str], **_kwargs: object) -> int:
        executed_commands.append(command)
        if "oidf_conformance.py" in " ".join(command):
            suite_environment.update(environment)
        elif "official_suite_compose.py" in " ".join(command):
            compose_commands.append(command)
        return 0

    monkeypatch.setattr(lane, "run", fake_run)
    monkeypatch.setattr(lane, "wait_for_public_stack", lambda _environment: None)
    monkeypatch.setattr(
        lane,
        "refresh_request_signing_certificate",
        lambda *_args: {"VERIFIER_X509_CERT_PEM": "request-certificate"},
    )
    monkeypatch.setattr(
        lane,
        "bootstrap_fixtures",
        lambda *_args, **_kwargs: {
            "organization_id": "org-1",
            "oid4vp_template_id": "template-1",
            "oid4vp_policy_id": "policy-1",
            "oid4vp_trust_profile_id": "trust-1",
            "oid4vp_issuer_did": "did:web:marty.test:orgs:org-1",
            "oid4vp_request_issuer_public_jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": "public-x",
                "y": "public-y",
            },
            "oid4vp_credential_issuer_public_jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": "credential-public-x",
                "y": "credential-public-y",
            },
            "browser_credential_template_id": "browser-credential-1",
            "browser_application_template_id": "browser-application-1",
            "browser_flow_id": "browser-flow-1",
        },
    )
    monkeypatch.setattr(
        lane,
        "standard_verifier_config",
        lambda _material, _gateway: tmp_path / "marty-verifier.json",
    )
    args = SimpleNamespace(
        lane="oid4vp-final",
        marty_ui=tmp_path / "marty-ui",
        run_id="run-1",
        oidf_runner=tmp_path / "runner",
        haip_material=tmp_path / "haip",
        output_dir=tmp_path / "output",
        stack_manifest=tmp_path / "stack-manifest.json",
    )

    assert lane.run_oidf(args, {"OIDF_MARTY_GATEWAY_URL": "https://marty.test"}) == 0
    assert suite_environment["OIDF_MARTY_ORGANIZATION_ID"] == "org-1"
    assert suite_environment["OIDF_MARTY_PRESENTATION_POLICY_ID"] == "policy-1"
    assert suite_environment["OIDF_MARTY_TRUST_PROFILE_ID"] == "trust-1"
    assert "OIDF_MARTY_ISSUER_PROFILE_ID" not in suite_environment
    assert suite_environment["OIDF_MARTY_ISSUER_DID"] == "did:web:marty.test:orgs:org-1"
    assert suite_environment["OIDF_MARTY_DYNAMIC_ISSUER_GOVERNANCE"] == "1"
    assert json.loads(suite_environment["OIDF_MARTY_OFFICIAL_SIGNER_PUBLIC_JWK"]) == {
        "kty": "EC",
        "crv": "P-256",
        "x": "credential-public-x",
        "y": "credential-public-y",
    }
    assert suite_environment["OIDF_MARTY_BROWSER_CREDENTIAL_TEMPLATE_ID"] == "browser-credential-1"
    assert suite_environment["OIDF_MARTY_BROWSER_APPLICATION_TEMPLATE_ID"] == "browser-application-1"
    assert suite_environment["OIDF_VERIFIER_REQUEST_METHOD"] == "request_uri_signed"
    assert suite_environment["OIDF_MARTY_FLOW_AUDIT_DIR"] == str(args.output_dir / "private" / "oidf-flow-audit")
    assert suite_environment["VERIFIER_X509_CERT_PEM"] == "request-certificate"
    browser_command = next(
        command for command in executed_commands if "oidf_marty_browser_smoke.py" in " ".join(command)
    )
    assert browser_command[browser_command.index("--output") + 1] == str(
        args.output_dir / "raw" / "browser" / "browser-evidence.json"
    )
    assert compose_commands
    assert all("--haip" in command for command in compose_commands)


def test_oidf_final_lane_emits_browser_runtime_diagnostic_after_browser_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    diagnostics: list[Path] = []
    sd_jwt_audits: list[tuple[Path, Path, Path]] = []

    def fake_run(command: list[str], _environment: dict[str, str], **_kwargs: object) -> int:
        if "oidf_marty_browser_smoke.py" in " ".join(command):
            return 2
        return 0

    monkeypatch.setattr(lane, "run", fake_run)
    monkeypatch.setattr(lane, "wait_for_public_stack", lambda _environment: None)
    monkeypatch.setattr(lane, "emit_oid4vp_browser_runtime_diagnostic", diagnostics.append)
    monkeypatch.setattr(
        lane,
        "audit_oidf_sd_jwt_diagnostics",
        lambda mapping, log, official: (
            sd_jwt_audits.append((mapping, log, official))
            or {
                "schema": "elevenid.oidf-sd-jwt-diagnostic-audit/v2",
                "source_policy": "unmodified",
                "modules": [],
            }
        ),
    )
    monkeypatch.setattr(lane, "refresh_request_signing_certificate", lambda *_args: {})
    monkeypatch.setattr(
        lane,
        "bootstrap_fixtures",
        lambda *_args, **_kwargs: {
            "organization_id": "org-1",
            "oid4vp_policy_id": "policy-1",
            "oid4vp_trust_profile_id": "trust-1",
            "oid4vp_issuer_did": "did:web:marty.test:orgs:org-1",
            "oid4vp_request_issuer_public_jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": "public-x",
                "y": "public-y",
            },
            "oid4vp_credential_issuer_public_jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": "credential-public-x",
                "y": "credential-public-y",
            },
            "browser_credential_template_id": "browser-credential-1",
            "browser_application_template_id": "browser-application-1",
        },
    )
    monkeypatch.setattr(
        lane,
        "standard_verifier_config",
        lambda _material, _gateway: tmp_path / "marty-verifier.json",
    )
    args = SimpleNamespace(
        lane="oid4vp-final",
        marty_ui=tmp_path / "marty-ui",
        run_id="run-1",
        oidf_runner=tmp_path / "runner",
        haip_material=tmp_path / "haip",
        output_dir=tmp_path / "output",
        stack_manifest=tmp_path / "stack-manifest.json",
    )

    assert lane.run_oidf(args, {"OIDF_MARTY_GATEWAY_URL": "https://marty.test"}) == 2
    assert diagnostics == [tmp_path / "output" / "private" / "compose.log"]
    assert sd_jwt_audits == [
        (
            tmp_path / "output" / "private" / "oidf-flow-audit",
            tmp_path / "output" / "private" / "compose.log",
            tmp_path
            / "output"
            / "raw"
            / "oid4vp-verifier"
            / "failure-diagnostics.json",
        )
    ]
    diagnostic_report = (
        tmp_path
        / "output"
        / "raw"
        / "oid4vp-verifier"
        / "oidf-sd-jwt-diagnostic-audit.json"
    )
    assert diagnostic_report.is_file()
    assert json.loads(diagnostic_report.read_text(encoding="utf-8"))["source_policy"] == "unmodified"


def test_oidf_url_query_lane_runs_the_exact_active_direct_query_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    official_command: list[str] = []
    suite_environment: dict[str, str] = {}

    def fake_run(
        command: list[str],
        environment: dict[str, str],
        **_kwargs: object,
    ) -> int:
        if "oidf_conformance.py" in " ".join(command):
            official_command.extend(command)
            suite_environment.update(environment)
        return 0

    monkeypatch.setattr(lane, "run", fake_run)
    monkeypatch.setattr(lane, "wait_for_public_stack", lambda _environment: None)
    discarded: list[Path] = []
    monkeypatch.setattr(lane, "discard_disposable_certificate_authority", discarded.append)
    monkeypatch.setattr(
        lane,
        "bootstrap_fixtures",
        lambda *_args, **_kwargs: {
            "organization_id": "org-1",
            "oid4vp_policy_id": "policy-1",
            "oid4vp_trust_profile_id": "trust-1",
            "oid4vp_issuer_did": "did:web:marty.test:orgs:org-1",
            "oid4vp_request_issuer_public_jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": "public-x",
                "y": "public-y",
            },
            "oid4vp_credential_issuer_public_jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": "credential-public-x",
                "y": "credential-public-y",
            },
        },
    )
    monkeypatch.setattr(
        lane,
        "standard_verifier_config",
        lambda _material, _gateway: tmp_path / "marty-verifier.json",
    )
    args = SimpleNamespace(
        lane="oid4vp-url-query",
        marty_ui=tmp_path / "marty-ui",
        run_id="run-1",
        oidf_runner=tmp_path / "runner",
        haip_material=tmp_path / "haip",
        output_dir=tmp_path / "output",
        stack_manifest=tmp_path / "stack-manifest.json",
    )

    assert (
        lane.run_oidf(
            args,
            {"OIDF_MARTY_GATEWAY_URL": "https://marty.test"},
        )
        == 0
    )
    assert official_command[official_command.index("--profile") + 1] == ("oid4vp-url-query-verifier")
    assert "--allow-planned-profile" not in official_command
    assert suite_environment["OIDF_MARTY_VERIFIER_PROFILE"] == "standard"
    assert suite_environment["OIDF_VERIFIER_REQUEST_METHOD"] == "url_query"
    assert suite_environment["OIDF_MARTY_ORGANIZATION_ID"] == "org-1"
    assert suite_environment["OIDF_MARTY_ISSUER_DID"] == ("did:web:marty.test:orgs:org-1")
    assert suite_environment["OIDF_MARTY_DYNAMIC_ISSUER_GOVERNANCE"] == "1"
    assert json.loads(suite_environment["OIDF_MARTY_OFFICIAL_SIGNER_PUBLIC_JWK"])["x"] == (
        "credential-public-x"
    )
    assert discarded == [tmp_path / "haip"]


def test_mdoc_fixture_bootstrap_receives_the_exact_runner_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command: list[str] = []
    output_dir = tmp_path / "output"
    haip_material = tmp_path / "haip"
    haip_material.mkdir()

    def fake_run(actual: list[str], _environment: dict[str, str], **_kwargs: object) -> int:
        command.extend(actual)
        destination = Path(actual[actual.index("--output") + 1])
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(
                {
                    "oid4vp_mdoc_policy_id": "policy-1",
                    "oid4vp_mdoc_trust_profile_id": "trust-1",
                    "oid4vp_mdoc_issuer_did": "did:web:marty.test:orgs:org-1",
                    "oid4vp_mdoc_request_issuer_public_jwk": {
                        "kty": "EC",
                        "crv": "P-256",
                        "x": "public-x",
                        "y": "public-y",
                    },
                }
            ),
            encoding="utf-8",
        )
        return 0

    monkeypatch.setattr(lane, "run", fake_run)
    args = SimpleNamespace(
        output_dir=output_dir,
        run_id="run-1",
        haip_material=haip_material,
        oidf_runner=tmp_path / "oidf-runner",
    )

    fixtures = lane.bootstrap_fixtures(
        args,
        {"OIDF_MARTY_GATEWAY_URL": "https://marty.test"},
        mode="oid4vp-mdoc",
    )

    assert fixtures["oid4vp_mdoc_policy_id"] == "policy-1"
    assert "--oidf-runner-config" not in command
    assert command[command.index("--oidf-runner-source") + 1] == str(tmp_path / "oidf-runner")


def test_oidf_mdoc_lane_selects_the_iso_mdl_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command: list[str] = []
    suite_environment: dict[str, str] = {}
    diagnostics: list[Path] = []

    def fake_run(actual: list[str], environment: dict[str, str], **_kwargs: object) -> int:
        if "oidf_conformance.py" in " ".join(actual):
            command.extend(actual)
            suite_environment.update(environment)
            return 1
        return 0

    monkeypatch.setattr(lane, "run", fake_run)
    monkeypatch.setattr(lane, "emit_mdoc_runtime_diagnostic", diagnostics.append)
    monkeypatch.setattr(lane, "wait_for_public_stack", lambda _environment: None)
    monkeypatch.setattr(lane, "refresh_request_signing_certificate", lambda *_args: {})
    monkeypatch.setattr(
        lane,
        "bootstrap_fixtures",
        lambda *_args, **_kwargs: {
            "organization_id": "org-1",
            "oid4vp_mdoc_policy_id": "mdoc-policy-1",
            "oid4vp_mdoc_trust_profile_id": "trust-1",
            "oid4vp_mdoc_issuer_did": "did:web:marty.test:orgs:org-1",
            "oid4vp_mdoc_request_issuer_public_jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": "public-x",
                "y": "public-y",
            },
        },
    )
    monkeypatch.setattr(
        lane,
        "standard_verifier_config",
        lambda _material, _gateway: tmp_path / "marty-verifier.json",
    )
    args = SimpleNamespace(
        lane="oid4vp-mdoc",
        marty_ui=tmp_path / "marty-ui",
        run_id="run-1",
        oidf_runner=tmp_path / "runner",
        haip_material=tmp_path / "haip",
        output_dir=tmp_path / "output",
        stack_manifest=tmp_path / "stack-manifest.json",
    )

    assert lane.run_oidf(args, {"OIDF_MARTY_GATEWAY_URL": "https://marty.test"}) == 1
    assert "oid4vp-mdoc-verifier" in command
    assert suite_environment["OIDF_MARTY_ORGANIZATION_ID"] == "org-1"
    assert suite_environment["OIDF_MARTY_PRESENTATION_POLICY_ID"] == "mdoc-policy-1"
    assert suite_environment["OIDF_MARTY_VERIFIER_PROFILE"] == "standard"
    assert "OIDF_MARTY_FLOW_AUDIT_DIR" not in suite_environment
    assert diagnostics == [tmp_path / "output" / "private" / "compose.log"]


def test_old_release_fails_before_any_compose_command(tmp_path: Path) -> None:
    args = type(
        "Args",
        (),
        {
            "lane": "eudi",
            "run_id": "run-1",
            "marty_ui": tmp_path / "marty-ui",
        },
    )()
    args.marty_ui.mkdir()
    with pytest.raises(ValueError, match="publish a fresh stack release"):
        lane.base_environment(args)


def test_base_environment_binds_eudi_vct_to_verified_gateway_origin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, metadata, stack_environment = stack_binding_fixture(tmp_path)
    marty_ui = tmp_path / "marty-ui"
    (marty_ui / "scripts").mkdir(parents=True)
    (marty_ui / "scripts" / "conformance_stack.py").write_text("# released launcher\n", encoding="utf-8")
    haip_material = tmp_path / "haip-material"
    haip_material.mkdir()
    monkeypatch.setattr(lane, "load_stack_metadata", lambda _path: metadata)
    monkeypatch.setattr(lane, "load_stack_environment", lambda _path: stack_environment)
    monkeypatch.setattr(
        lane,
        "load_material_environment",
        lambda _path: {"OIDF_PUBLIC_BASE_URL": "https://marty-oidf.test:18443"},
    )
    monkeypatch.setenv("MARTY_CONFORMANCE_ADMIN_PASSWORD", "admin-password")
    monkeypatch.setenv("MARTY_CONFORMANCE_REVIEWER_PASSWORD", "reviewer-password")
    args = SimpleNamespace(
        lane="eudi",
        run_id="run-1",
        marty_ui=marty_ui,
        stack_manifest=manifest,
        stack_metadata=tmp_path / "stack-metadata.json",
        stack_env=tmp_path / ".env.stack",
        material=tmp_path / "material",
        oidf_runner=None,
        w3c_suite=None,
        haip_material=haip_material,
    )

    environment, _ = lane.base_environment(args)

    assert environment["EUDI_TEST_VCT_ORIGIN"] == environment["OIDF_MARTY_GATEWAY_URL"]


def test_base_environment_rejects_loopback_request_uri_hostname(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, metadata, stack_environment = stack_binding_fixture(tmp_path)
    marty_ui = tmp_path / "marty-ui"
    (marty_ui / "scripts").mkdir(parents=True)
    (marty_ui / "scripts" / "conformance_stack.py").write_text(
        "# released launcher\n",
        encoding="utf-8",
    )
    haip_material = tmp_path / "haip-material"
    haip_material.mkdir()
    oidf_runner = tmp_path / "oidf-runner"
    oidf_runner.mkdir()
    monkeypatch.setattr(lane, "load_stack_metadata", lambda _path: metadata)
    monkeypatch.setattr(lane, "load_stack_environment", lambda _path: stack_environment)
    monkeypatch.setattr(
        lane,
        "load_material_environment",
        lambda _path: {"OIDF_PUBLIC_BASE_URL": "https://localhost:18443"},
    )
    args = SimpleNamespace(
        lane="oid4vp-final",
        run_id="run-1",
        marty_ui=marty_ui,
        stack_manifest=manifest,
        stack_metadata=tmp_path / "stack-metadata.json",
        stack_env=tmp_path / ".env.stack",
        material=tmp_path / "material",
        oidf_runner=oidf_runner,
        w3c_suite=None,
        haip_material=haip_material,
    )

    with pytest.raises(ValueError, match="non-loopback bridge hostname"):
        lane.base_environment(args)


def test_public_readiness_uses_generated_ca_and_exact_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    responses = iter(
        [
            type("Result", (), {"returncode": 22, "stdout": ""})(),
            type("Result", (), {"returncode": 0, "stdout": '{"status":"ready"}\n__MARTY_PUBLIC_HTTP_STATUS__:200\n'})(),
        ]
    )

    def fake_run(command: list[str], **_kwargs: object) -> object:
        calls.append(command)
        return next(responses)

    monotonic = iter([0.0, 1.0, 2.0])
    monkeypatch.setattr(lane.subprocess, "run", fake_run)
    monkeypatch.setattr(lane.time, "monotonic", lambda: next(monotonic))
    monkeypatch.setattr(lane.time, "sleep", lambda _seconds: None)
    lane.wait_for_public_stack(
        {
            "OIDF_MARTY_GATEWAY_URL": "https://marty-oidf.test:18443",
            "OIDF_MARTY_RESOLVE_IP": "127.0.0.1",
            "SSL_CERT_FILE": "/material/root-ca.pem",
        },
        timeout=5,
        poll=0,
    )
    assert "--cacert" in calls[0]
    assert "/material/root-ca.pem" in calls[0]
    assert "--noproxy" in calls[0]
    assert "marty-oidf.test" in calls[0]
    assert "--write-out" in calls[0]
    assert any("__MARTY_PUBLIC_HTTP_STATUS__:%{http_code}" in value for value in calls[0])
    assert "marty-oidf.test:18443:127.0.0.1" in calls[0]
    assert calls[0][-1] == "https://marty-oidf.test:18443/ready"


def test_public_readiness_disables_only_windows_revocation_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []
    response = type(
        "Result",
        (),
        {
            "returncode": 0,
            "stdout": '{"status":"ready"}\n__MARTY_PUBLIC_HTTP_STATUS__:200\n',
        },
    )()
    monkeypatch.setattr(lane.os, "name", "nt")
    monkeypatch.setattr(
        lane.subprocess,
        "run",
        lambda command, **_kwargs: calls.append(command) or response,
    )

    lane.wait_for_public_stack(
        {
            "OIDF_MARTY_GATEWAY_URL": "https://marty-oidf.test:18443",
            "OIDF_MARTY_RESOLVE_IP": "127.0.0.1",
            "SSL_CERT_FILE": "/material/root-ca.pem",
        }
    )

    assert "--cacert" in calls[0]
    assert "--ssl-no-revoke" in calls[0]
    assert calls[0][-1] == "https://marty-oidf.test:18443/ready"


def test_public_readiness_timeout_reports_only_service_states(monkeypatch: pytest.MonkeyPatch) -> None:
    response = type(
        "Result",
        (),
        {
            "returncode": 22,
            "stdout": (
                '{"status":"not_ready","services":{"issuance":{"status":"unreachable",'
                '"error":"secret-looking-detail"},"auth":{"status":"healthy"}}}'
            ),
        },
    )()
    monkeypatch.setattr(lane.subprocess, "run", lambda *_args, **_kwargs: response)
    monotonic = iter([0.0, 1.0])
    monkeypatch.setattr(lane.time, "monotonic", lambda: next(monotonic))
    monkeypatch.setattr(lane.time, "sleep", lambda _seconds: None)

    with pytest.raises(RuntimeError) as error:
        lane.wait_for_public_stack(
            {
                "OIDF_MARTY_GATEWAY_URL": "https://marty-oidf.test:18443",
                "SSL_CERT_FILE": "/material/root-ca.pem",
            },
            timeout=1,
            poll=0,
        )

    message = str(error.value)
    assert "auth=healthy" in message
    assert "issuance=unreachable" in message
    assert "secret-looking-detail" not in message


def test_public_proxy_diagnostics_are_fixed_categories_only() -> None:
    classes = lane.classify_public_proxy_diagnostics(
        "connect() failed (111: Connection refused) while connecting to upstream; "
        "upstream timed out; token=must-not-be-reported"
    )

    assert classes == ["upstream-connect", "upstream-timeout"]


def test_eudi_runtime_diagnostics_are_fixed_categories_only() -> None:
    classes = lane.classify_eudi_runtime_diagnostics(
        "SSLHandshakeException: PKIX path building failed; CredentialIssuerMetadata secret=must-not-be-reported"
    )

    assert classes == ["tls-trust", "metadata-deserialization"]


def test_eudi_runtime_diagnostics_identify_allowlisted_metadata_boundary_without_values() -> None:
    classes = lane.classify_eudi_runtime_diagnostics(
        "JsonDecodingException: Unexpected JSON token at credential_configurations_supported."
        "MobileDrivingLicense.proof_types_supported secret=must-not-be-reported"
    )

    assert classes == [
        "metadata-deserialization",
        "metadata-json-type-mismatch",
        "metadata-field-credential-configurations-supported",
        "metadata-field-proof-types",
    ]


@pytest.mark.parametrize(
    ("diagnostic", "category"),
    [
        ("Active issuer profile not found. secret=must-not-escape", "issuer-profile-not-found"),
        (
            "Issuer profile has an incomplete signing identity binding. secret=must-not-escape",
            "issuer-profile-binding-incomplete",
        ),
        (
            "Issuer-profile signer returned a different DID verification method",
            "issuer-profile-identity-mismatch",
        ),
        ("Signing algorithm must match the issuer profile binding.", "issuer-profile-algorithm-mismatch"),
        ("No mDoc namespace mapping is defined for doctype secret", "mdoc-namespace"),
        ("_mdoc_x5c[0] is not valid base64-encoded DER secret", "mdoc-certificate-chain"),
        ("Remote signing service returned no mDoc signature", "mdoc-signature-missing"),
        ("Invalid ES256 P1363 signature length for remote mDoc signing", "mdoc-signature-length"),
        ("Unsupported remote mDoc signature encoding secret", "mdoc-signature-encoding"),
        ("Remote mDoc signature is not valid DER ECDSA", "mdoc-signature-der"),
        ("mDoc claims must be a JSON object", "mdoc-claims"),
        ("oid4vci_prepare_mdoc failed with secret", "mdoc-prepare"),
        ("COSE serialization failed: secret", "mdoc-assemble"),
        (
            "Issuer-profile credential builder changed the reserved credential ID",
            "mdoc-credential-id-mismatch",
        ),
    ],
)
def test_eudi_runtime_diagnostics_identify_safe_mdoc_stage(
    diagnostic: str,
    category: str,
) -> None:
    assert category in lane.classify_eudi_runtime_diagnostics(diagnostic)


@pytest.mark.parametrize(
    ("diagnostic", "category"),
    [
        ("Verification error for sd-jwt: private detail", "marty-sd-jwt-verification"),
        ("DID resolution failed: private issuer", "marty-sd-jwt-issuer-key"),
        ("SD-JWT has no cnf.jwk for key binding", "marty-sd-jwt-holder-key"),
        ("Key Binding JWT is required when verifier context is supplied", "marty-sd-jwt-key-binding-required"),
        ("Key Binding JWT signature validation failed: private detail", "marty-sd-jwt-key-binding-signature"),
        (
            'SD-JWT verification failed: DeserializationError("InvalidSignature")',
            "marty-sd-jwt-signature",
        ),
        ("Key Binding JWT sd_hash does not bind this SD-JWT", "marty-sd-jwt-key-binding-sd-hash"),
        ("Invalid digest in KB-JWT", "marty-sd-jwt-key-binding-sd-hash"),
        ("Key Binding JWT audience does not match the verifier", "marty-sd-jwt-key-binding-audience"),
        ("invalid input: InvalidAudience", "marty-sd-jwt-key-binding-audience"),
        ("Key Binding JWT nonce does not match the request", "marty-sd-jwt-key-binding-nonce"),
        ("invalid input: Invalid nonce", "marty-sd-jwt-key-binding-nonce"),
        ("Key Binding JWT iat is outside the five-minute freshness window", "marty-sd-jwt-key-binding-freshness"),
        ("Missing required `iat` claim in KB-JWT", "marty-sd-jwt-key-binding-freshness"),
        ("invalid input: Invalid header type", "marty-sd-jwt-key-binding-header"),
        ("Cannot decode jwt: ExpiredSignature", "marty-sd-jwt-issuer-validity"),
        ("Disclosure hash was invalid: private detail", "marty-sd-jwt-disclosure"),
        ("Rust SD-JWT verification returned invalid JSON", "marty-sd-jwt-native-backend"),
        ("Device authentication signature invalid", "marty-mdoc-device-authentication"),
        ("Session transcript mismatch: private detail", "marty-mdoc-session-transcript"),
        ("Issuer signature validation failed", "marty-mdoc-issuer-signature"),
        ("Issuer certificate is not trusted", "marty-mdoc-issuer-trust"),
        ("Could not parse MSO: private detail", "marty-mdoc-parse"),
    ],
)
def test_eudi_runtime_diagnostics_identify_marty_verifier_stage_without_values(
    diagnostic: str,
    category: str,
) -> None:
    assert category in lane.classify_eudi_runtime_diagnostics(diagnostic)


def test_eudi_runtime_diagnostics_forward_allowlisted_mdoc_error_kind() -> None:
    classes = lane.classify_eudi_runtime_diagnostics(
        "mDoc verification outcome device_auth_error_kind=session-transcript-parse-failed"
    )

    assert "marty-mdoc-error-kind-session-transcript-parse-failed" in classes


def test_eudi_runtime_diagnostics_reject_unknown_mdoc_error_kind() -> None:
    classes = lane.classify_eudi_runtime_diagnostics(
        "mDoc verification outcome device_auth_error_kind=private-arbitrary-value"
    )

    assert "marty-mdoc-error-kind-private-arbitrary-value" not in classes


def test_eudi_runtime_diagnostic_never_prints_private_log_text(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    log = tmp_path / "compose.log"
    log.write_text(
        "UnknownHostException host.private token=must-not-be-reported",
        encoding="utf-8",
    )

    lane.emit_eudi_runtime_diagnostic(log)

    output = capsys.readouterr().err
    assert "hostname-resolution" in output
    assert "host.private" not in output
    assert "must-not-be-reported" not in output


def test_public_proxy_diagnostic_selects_exact_compose_service(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: object) -> object:
        calls.append(command)
        if command[:2] == ["docker", "ps"]:
            return type("Result", (), {"returncode": 0, "stdout": "proxy-id\n", "stderr": ""})()
        return type(
            "Result",
            (),
            {"returncode": 0, "stdout": "", "stderr": "connect() failed while connecting to upstream"},
        )()

    monkeypatch.setattr(lane.subprocess, "run", fake_run)
    lane.emit_public_proxy_diagnostic("marty-conformance-run-1", {})

    assert "label=com.docker.compose.project=marty-conformance-run-1" in calls[0]
    assert "label=com.docker.compose.service=oidf-tls-proxy" in calls[0]
    assert calls[1] == ["docker", "logs", "--tail", "250", "proxy-id"]
    assert "upstream-connect" in capsys.readouterr().out


def test_w3c_lane_uses_authenticated_public_vc_api(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    events: list[str] = []
    suite_environment: dict[str, str] = {}
    suite_command: list[str] = []
    lifecycle_environments: list[dict[str, str]] = []

    def fake_run(command: list[str], environment: dict[str, str], **_kwargs: object) -> int:
        if "conformance_stack.py" in " ".join(command):
            lifecycle_environments.append(dict(environment))
        if "w3c_vc_conformance.py" in " ".join(command):
            events.append("suite")
            suite_environment.update(environment)
            suite_command.extend(command)
        return 0

    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setattr(lane, "run", fake_run)
    monkeypatch.setattr(lane, "wait_for_public_stack", lambda _environment: events.append("ready"))
    monkeypatch.setattr(
        lane,
        "bootstrap_fixtures",
        lambda *_args, **_kwargs: {
            "organization_id": "00000000-0000-0000-0000-000000000001",
            "w3c_issuer_did": ("did:web:marty-oidf.test:orgs:00000000-0000-0000-0000-000000000001"),
            "w3c_template_id": "00000000-0000-0000-0000-000000000002",
            "w3c_credential_policy_id": "00000000-0000-0000-0000-000000000003",
            "w3c_presentation_policy_id": "00000000-0000-0000-0000-000000000004",
            "w3c_api_key_id": "00000000-0000-0000-0000-000000000005",
            "w3c_api_key": "mk_test_fixture",
        },
    )
    args = type(
        "Args",
        (),
        {
            "marty_ui": tmp_path / "marty-ui",
            "run_id": "run-1",
            "output_dir": tmp_path / "output",
            "w3c_suite": tmp_path / "w3c-suite",
            "stack_manifest": tmp_path / "stack-manifest.json",
        },
    )()

    assert lane.run_w3c(args, {"OIDF_MARTY_GATEWAY_URL": "https://marty-oidf.test:18443"}) == 0
    assert events == ["ready", "suite"]
    assert suite_environment["W3C_VC_API_KEY"] == "mk_test_fixture"
    assert suite_environment["RATE_LIMIT_RPM"] == lane.W3C_CONFORMANCE_RATE_LIMIT_RPM
    assert suite_environment["TOKEN_RATE_LIMIT"] == lane.W3C_CONFORMANCE_TOKEN_RATE_LIMIT
    assert suite_environment["VCDM_RELATED_RESOURCE_URLS"] == ("https://www.w3.org/ns/credentials/v2")
    assert lifecycle_environments
    assert all(
        environment["RATE_LIMIT_RPM"] == lane.W3C_CONFORMANCE_RATE_LIMIT_RPM for environment in lifecycle_environments
    )
    assert all(
        environment["TOKEN_RATE_LIMIT"] == lane.W3C_CONFORMANCE_TOKEN_RATE_LIMIT
        for environment in lifecycle_environments
    )
    assert all(
        environment["VCDM_RELATED_RESOURCE_URLS"] == "https://www.w3.org/ns/credentials/v2"
        for environment in lifecycle_environments
    )
    assert "https://marty-oidf.test:18443/v1/vc-api" in suite_command
    assert "--organization-id" in suite_command
    assert "--credential-template-id" in suite_command
    assert "--credential-policy-id" in suite_command
    assert "--presentation-policy-id" in suite_command
    assert "mk_test_fixture" not in suite_command
    assert "::add-mask::mk_test_fixture" in capsys.readouterr().out


def test_eudi_lane_starts_marty_haip_without_the_oidf_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []
    lifecycle_environments: list[dict[str, str]] = []
    suite_environment: dict[str, str] = {}
    certificate_calls: list[tuple[dict[str, str], dict[str, object]]] = []

    def fake_run(command: list[str], environment: dict[str, str], **_kwargs: object) -> int:
        commands.append(command)
        rendered = " ".join(command)
        if "official_suite_compose.py" in rendered:
            lifecycle_environments.append(dict(environment))
        if "eudi_reference_interop.py" in rendered:
            suite_environment.update(environment)
        return 0

    monkeypatch.setattr(lane, "run", fake_run)
    monkeypatch.setattr(lane, "wait_for_public_stack", lambda _environment: None)
    monkeypatch.setattr(
        lane,
        "bootstrap_fixtures",
        lambda *_args, **_kwargs: {
            "organization_id": "org-1",
            "eudi_issuer_did": "did:web:marty.test:orgs:org-1",
            "eudi_request_issuer_did": "did:web:marty.test:orgs:org-1",
            "eudi_request_issuer_public_jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": "public-x",
                "y": "public-y",
            },
            "eudi_passport_template_id": "passport-1",
            "eudi_mdl_template_id": "mdl-1",
            "eudi_open_badge_template_id": "badge-1",
        },
    )

    def issue_certificate(_path: Path, public_jwk: dict[str, str], **kwargs: object) -> dict[str, object]:
        certificate_calls.append((public_jwk, kwargs))
        return {
            "certificate_sha256": "sha256:certificate",
            "dns_names": "marty.test",
            "public_jwk": public_jwk,
        }

    monkeypatch.setattr(lane, "issue_verifier_certificate", issue_certificate)
    monkeypatch.setattr(
        lane,
        "load_verifier_environment",
        lambda _path: {
            "VERIFIER_X509_CERT_PEM": "certificate-chain",
            lane.OID4VP_TRUST_ANCHOR_FILE_ENV: "/haip/request-object-root.pem",
        },
    )
    args = SimpleNamespace(
        marty_ui=tmp_path / "marty-ui",
        run_id="run-1",
        output_dir=tmp_path / "output",
        haip_material=tmp_path / "haip-material",
        stack_manifest=tmp_path / "stack-manifest.json",
    )

    assert (
        lane.run_eudi(
            args,
            {
                "OIDF_MARTY_GATEWAY_URL": "https://marty.test",
                "EUDI_VERIFIER_PUBLIC_URL": "https://verifier.test",
                "EUDI_WALLET_KIT_URL": "http://wallet-kit:9090",
            },
        )
        == 0
    )

    lifecycle_commands = [command for command in commands if "official_suite_compose.py" in " ".join(command)]
    assert len(lifecycle_commands) == 3
    for command in lifecycle_commands:
        assert "--eudi" in command
        assert "--haip" in command
        assert "--haip-material" in command
        assert "--oidf" not in command
    assert len(lifecycle_environments) == 3
    refresh_commands = [command for command in commands if "conformance_stack.py" in " ".join(command)]
    assert len(refresh_commands) == 1
    assert refresh_commands[0][-3:] == ["--haip", "--resume", "up"]
    legacy_private_key_name = "VERIFIER_" + "SIGNING_KEY_PEM"
    assert all(legacy_private_key_name not in item for item in lifecycle_environments)
    assert all("VERIFIER_X509_CERT_PEM" not in item for item in lifecycle_environments)
    assert suite_environment[lane.OID4VP_TRUST_ANCHOR_FILE_ENV] == "/haip/request-object-root.pem"
    assert suite_environment["VERIFIER_X509_CERT_PEM"] == "certificate-chain"
    assert suite_environment["TEST_ORG_ID"] == "org-1"
    assert suite_environment["EUDI_TEST_OPEN_BADGE_TEMPLATE_ID"] == "badge-1"
    assert "EUDI_TEST_ISSUER_PROFILE_ID" not in suite_environment
    assert suite_environment["EUDI_TEST_ISSUER_DID"] == "did:web:marty.test:orgs:org-1"
    assert "EUDI_TEST_REQUEST_ISSUER_PROFILE_ID" not in suite_environment
    assert suite_environment["EUDI_TEST_REQUEST_ISSUER_DID"] == "did:web:marty.test:orgs:org-1"
    assert not any("KMS" in name or "KEY_REFERENCE" in name for name in suite_environment)
    assert certificate_calls == [
        (
            {
                "kty": "EC",
                "crv": "P-256",
                "x": "public-x",
                "y": "public-y",
            },
            {
                "gateway_url": "https://marty.test",
                "replace_existing": True,
            },
        )
    ]


def test_w3c_lane_cleans_up_a_partial_initial_start(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    commands: list[list[str]] = []
    keycloak_diagnostics: list[str] = []
    issuance_diagnostics: list[str] = []

    def fake_run(command: list[str], _environment: dict[str, str], **_kwargs: object) -> int:
        commands.append(command)
        return 1 if command[-1] == "up" else 0

    monkeypatch.setattr(lane, "run", fake_run)
    monkeypatch.setattr(
        lane,
        "emit_keycloak_initializer_diagnostic",
        keycloak_diagnostics.append,
    )
    monkeypatch.setattr(
        lane,
        "emit_w3c_issuance_diagnostic",
        issuance_diagnostics.append,
    )
    args = SimpleNamespace(marty_ui=tmp_path / "marty-ui", run_id="run-1")

    assert lane.run_w3c(args, {}) == 1
    assert commands[-1][-1] == "down"
    assert keycloak_diagnostics == ["run-1"]
    assert issuance_diagnostics == ["run-1"]


def test_w3c_lane_diagnoses_fixture_bootstrap_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    diagnostics: list[str] = []
    commands: list[list[str]] = []

    def fake_run(command: list[str], _environment: dict[str, str], **_kwargs: object) -> int:
        commands.append(command)
        return 0

    monkeypatch.setattr(lane, "run", fake_run)
    monkeypatch.setattr(lane, "wait_for_public_stack", lambda _environment: None)
    monkeypatch.setattr(
        lane,
        "bootstrap_fixtures",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("w3c public fixture bootstrap failed with exit code 2")
        ),
    )
    monkeypatch.setattr(lane, "emit_w3c_issuance_diagnostic", diagnostics.append)
    args = SimpleNamespace(
        marty_ui=tmp_path / "marty-ui",
        run_id="w3c-bootstrap-1",
        w3c_suite=tmp_path / "w3c-suite",
        stack_manifest=tmp_path / "stack-manifest.json",
        output_dir=tmp_path / "evidence",
    )

    with pytest.raises(RuntimeError, match="fixture bootstrap failed"):
        lane.run_w3c(
            args,
            {"OIDF_MARTY_GATEWAY_URL": "https://marty-oidf.test:18443"},
        )

    assert diagnostics == ["w3c-bootstrap-1"]
    assert commands[-1][-1] == "down"
