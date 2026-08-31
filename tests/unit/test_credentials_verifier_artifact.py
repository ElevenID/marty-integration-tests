from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "credentials_verifier_artifact",
    ROOT / "scripts" / "credentials_verifier_artifact.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load credentials verifier artifact helper")
artifact = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifact)


def valid_pin() -> dict[str, object]:
    return {
        "schema": artifact.PIN_SCHEMA,
        "state": "ready",
        "repository": artifact.EXPECTED_REPOSITORY,
        "release_tag": "v1.2.3",
        "version": "1.2.3",
        "commit": "a" * 40,
        "source_ref": "refs/heads/main",
        "image": {
            "uri": artifact.EXPECTED_IMAGE_URI,
            "digest": "sha256:" + "b" * 64,
        },
        "sbom": {
            "asset": "marty-credentials-verification.spdx.json",
            "digest": "sha256:" + "c" * 64,
        },
    }


def valid_rust_pin() -> dict[str, object]:
    return {
        "schema": artifact.RUST_PIN_SCHEMA,
        "state": "ready",
        "repository": artifact.RUST_REPOSITORY,
        "release_tag": "v1.2.3",
        "version": "1.2.3",
        "commit": "a" * 40,
        "source_ref": "refs/tags/v1.2.3",
        "image": {
            "uri": artifact.RUST_IMAGE_URI,
            "digest": "sha256:" + "b" * 64,
        },
        "sbom": {
            "asset": "marty-ui-services-sbom.cdx.json",
            "digest": "sha256:" + "c" * 64,
        },
    }


def known_ineligible_failure() -> dict[str, object]:
    return {
        "id": artifact.KNOWN_INELIGIBLE_FAILURE_ID,
        "message": artifact.KNOWN_INELIGIBLE_FAILURE_MESSAGE,
        "transient_retry": {
            "message": artifact.KNOWN_INELIGIBLE_TRANSIENT_MESSAGE,
            "max_attempts": artifact.KNOWN_INELIGIBLE_MAX_ATTEMPTS,
        },
    }


def write_pin(path: Path, value: dict[str, object] | None = None) -> Path:
    path.write_text(json.dumps(value or valid_pin()), encoding="utf-8")
    return path


def valid_sbom() -> dict[str, object]:
    return {
        "spdxVersion": "SPDX-2.3",
        "name": artifact.EXPECTED_IMAGE_URI,
        "packages": [
            {
                "name": artifact.EXPECTED_IMAGE_URI,
                "versionInfo": "sha256:" + "b" * 64,
            },
            {"name": "marty-rs", "versionInfo": "0.1.46"},
            {"name": "marty-verification-py", "versionInfo": "0.1.46"},
        ],
    }


def valid_rust_sbom() -> dict[str, object]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "component": {
                "type": "container",
                "name": artifact.RUST_IMAGE_URI,
                "version": "sha256:" + "b" * 64,
            }
        },
        "components": [],
    }


def test_repository_pin_is_ready_exact_and_immutable(tmp_path: Path) -> None:
    pin = artifact.load_pin(write_pin(tmp_path / "pin.json"))

    assert artifact.image_reference(pin) == (artifact.EXPECTED_IMAGE_URI + "@sha256:" + "b" * 64)
    assert pin["release_tag"] == "v1.2.3"
    assert pin["commit"] == "a" * 40


def test_default_pin_preserves_oracle_and_stale_rust_candidate_is_ineligible() -> None:
    oracle = artifact.load_pin()

    assert artifact.DEFAULT_PIN.name == "credentials-verifier-oracle.json"
    assert oracle["release_tag"] == "v0.1.71"
    assert oracle["commit"] == "94f19ad369e7e41883f2aa3d77656ce561bb6534"
    assert oracle["image"]["digest"] == ("sha256:fcec33e259c2d7856606f434e5c9830e392e820a548ab7a6ff4bd4afb3395b3b")

    with pytest.raises(ValueError, match="artifact pin must be ready"):
        artifact.load_pin(ROOT / "config" / "credentials-verifier-under-test.json")

    rejected = artifact.load_pin(
        ROOT / "config" / "credentials-verifier-under-test.json",
        expected_state="ineligible",
    )
    assert rejected["release_tag"] == "v1.1.208"
    assert rejected["commit"] == "7c8fa31500acd8f2ec589781232c444fe81dd22e"
    assert rejected["expected_failure"] == known_ineligible_failure()


def test_ineligible_pin_still_validates_every_immutable_coordinate(tmp_path: Path) -> None:
    pin = valid_rust_pin()
    pin["state"] = "ineligible"
    pin["expected_failure"] = known_ineligible_failure()
    pin["image"]["digest"] = "mutable"  # type: ignore[index]

    with pytest.raises(ValueError, match="image digest"):
        artifact.load_pin(
            write_pin(tmp_path / "rejected.json", pin),
            expected_state="ineligible",
        )


def test_workflow_runs_oracle_and_exact_known_negative_control() -> None:
    workflow = (ROOT / ".github" / "workflows" / "credentials-verifier-artifact.yml").read_text(encoding="utf-8")

    assert "pin: config/credentials-verifier-oracle.json" in workflow
    assert "pin: config/credentials-verifier-under-test.json" in workflow
    assert "state: ineligible" in workflow
    assert "mode: expected-failure" in workflow
    assert 'validate-pin --pin "$PIN_FILE" --state "$PIN_STATE"' in workflow
    assert "run-expected-failure" in workflow
    assert workflow.count('--pin "$PIN_FILE"') == 4


def test_sbom_is_bound_to_pinned_image_and_native_packages(tmp_path: Path) -> None:
    path = tmp_path / "verification.spdx.json"
    path.write_text(json.dumps(valid_sbom()), encoding="utf-8")

    value = artifact.validate_sbom(path, valid_pin())

    assert value["name"] == artifact.EXPECTED_IMAGE_URI


def test_rust_pin_and_cyclonedx_sbom_are_bound_to_canonical_services_image(tmp_path: Path) -> None:
    pin_path = write_pin(tmp_path / "rust-pin.json", valid_rust_pin())
    pin = artifact.load_pin(pin_path)
    sbom_path = tmp_path / "services.cdx.json"
    sbom_path.write_text(json.dumps(valid_rust_sbom()), encoding="utf-8")

    value = artifact.validate_sbom(sbom_path, pin)

    assert artifact.artifact_target(pin) is artifact.RUST_TARGET
    assert artifact.image_reference(pin) == artifact.RUST_IMAGE_URI + "@sha256:" + "b" * 64
    assert value["metadata"]["component"]["version"] == pin["image"]["digest"]


def test_migration_commands_preserve_each_images_runtime_contract() -> None:
    rust = artifact._migration_command(
        "rust-image@sha256:digest",
        artifact.RUST_TARGET,
        "verification-network",
        "postgresql://database",
    )
    legacy = artifact._migration_command(
        "python-image@sha256:digest",
        artifact.LEGACY_TARGET,
        "verification-network",
        "postgresql://database",
    )

    assert rust[-4:] == [
        "--entrypoint",
        "/app/services/entrypoint.sh",
        "rust-image@sha256:digest",
        "migrate",
    ]
    assert "SERVICE_NAME=verification" in rust
    assert legacy[-4:] == [
        "python-image@sha256:digest",
        "python",
        "manage_migrations.py",
        "upgrade",
    ]
    assert "--entrypoint" not in legacy


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value.update(name="attacker/image"), "unexpected image"),
        (
            lambda value: value["packages"][0].update(versionInfo="sha256:" + "d" * 64),
            "not bound",
        ),
        (
            lambda value: value.update(packages=value["packages"][:2]),
            "missing required native",
        ),
    ],
)
def test_sbom_rejects_wrong_subject_or_missing_native_package(
    tmp_path: Path,
    mutate: object,
    message: str,
) -> None:
    value = valid_sbom()
    mutate(value)  # type: ignore[operator]
    path = tmp_path / "verification.spdx.json"
    path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        artifact.validate_sbom(path, valid_pin())


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("state",), "awaiting_release", "must be ready"),
        (("repository",), "attacker/example", "does not match its schema"),
        (("release_tag",), "v1.2.3-rc.1", "stable SemVer"),
        (("source_ref",), "refs/tags/v1.2.3", "attested release source"),
        (("image", "uri"), artifact.EXPECTED_IMAGE_URI + ":latest", "unexpected verification image URI"),
        (("image", "digest"), "sha256:" + "B" * 64, "image digest"),
        (("sbom", "digest"), "sha256:" + "d" * 63, "SBOM digest"),
    ],
)
def test_pin_rejects_mutable_or_unreviewed_inputs(
    tmp_path: Path,
    path: tuple[str, ...],
    value: object,
    message: str,
) -> None:
    pin = valid_pin()
    target = pin
    for part in path[:-1]:
        target = target[part]  # type: ignore[assignment,index]
    target[path[-1]] = value  # type: ignore[index]

    with pytest.raises(ValueError, match=message):
        artifact.load_pin(write_pin(tmp_path / "pin.json", pin))


def test_governance_binds_key_to_exact_org_profiles_and_artifact() -> None:
    pin = valid_pin()
    governance = artifact.build_governance(
        pin,
        "ephemeral-api-key",
        "123e4567-e89b-42d3-a456-426614174000",
        "did:web:issuer.integration.invalid",
        vds_only_api_key="vds-only-api-key",
        oid4vp_only_api_key="oid4vp-only-api-key",
    )

    assert governance["component"] == {
        "component_id": "marty-credentials",
        "version": "1.2.3",
        "artifact_digest": "sha256:" + "b" * 64,
        "adapter_id": "verification-service",
        "adapter_version": "1.0.0",
    }
    assert governance["policies"][0]["content"]["required_checks"] == [
        "credential.proof",
        "issuer.trust",
    ]
    assert governance["policies"][1]["content"] == {
        "verifier_id": "did:web:verifier.integration.invalid",
        "presentation_definition_digest": artifact.canonical_digest(artifact.presentation_definition()),
        "required_checks": artifact.OID4VP_REQUIRED_CHECKS,
    }
    assert governance["trust_profiles"][0]["content"] == {
        "trusted_issuers": ["did:web:issuer.integration.invalid"],
        "allow_public_did_fallback": False,
    }
    assert set(governance["clients"][0]["purposes"]) == {
        artifact.SESSION_PURPOSE,
        artifact.DIRECT_PURPOSE,
        artifact.VDS_PURPOSE,
    }
    assert set(governance["clients"][1]["purposes"]) == {artifact.VDS_PURPOSE}
    assert set(governance["clients"][2]["purposes"]) == {
        artifact.SESSION_PURPOSE,
        artifact.DIRECT_PURPOSE,
    }
    assert "ephemeral-api-key" not in json.dumps(governance)
    assert "vds-only-api-key" not in json.dumps(governance)
    assert "oid4vp-only-api-key" not in json.dumps(governance)


def test_missing_required_check_fixture_is_self_consistent() -> None:
    governance = artifact.build_governance(
        valid_pin(),
        "ephemeral-api-key",
        "123e4567-e89b-42d3-a456-426614174000",
        "did:web:issuer.integration.invalid",
    )
    invalid = artifact.invalid_governance_missing_required_check(governance)
    policy = invalid["policies"][0]

    assert policy["content"]["required_checks"] == ["credential.proof"]
    assert policy["content_digest"] == artifact.canonical_digest(policy["content"])


def test_vds_fixture_uses_public_jwk_and_separate_private_key() -> None:
    issuer = "did:web:issuer.integration.invalid"
    private_key, jwk, method_id = artifact.make_vds_key_material(issuer)

    assert set(jwk) == {"kty", "crv", "alg", "x", "y", "kid"}
    assert "d" not in jwk
    assert method_id == f"{issuer}#vdsnc-key"
    assert private_key.public_key().public_numbers().x.to_bytes(32, "big") == __import__("base64").urlsafe_b64decode(
        jwk["x"] + "=="
    )


def test_oid4vp_fixture_is_nonce_audience_bound_and_contains_no_private_jwk() -> None:
    token = artifact.make_oid4vp_jwt("n" * 43, "did:web:verifier.integration.invalid")
    header_segment, payload_segment, signature_segment = token.split(".")
    header = json.loads(base64.urlsafe_b64decode(header_segment + "=="))
    payload = json.loads(base64.urlsafe_b64decode(payload_segment + "=="))

    assert header["alg"] == "EdDSA"
    assert set(header["jwk"]) == {"kty", "crv", "x"}
    assert payload["nonce"] == "n" * 43
    assert payload["aud"] == "did:web:verifier.integration.invalid"
    assert payload["exp"] > payload["iat"]
    assert len(base64.urlsafe_b64decode(signature_segment + "==")) == 64

    nonce_less = artifact.make_oid4vp_jwt(None, "did:web:verifier.integration.invalid")
    nonce_less_payload_segment = nonce_less.split(".")[1]
    nonce_less_payload = json.loads(base64.urlsafe_b64decode(nonce_less_payload_segment + "=="))
    assert "nonce" not in nonce_less_payload


def test_canonical_projection_requires_exact_vds_check_floor() -> None:
    value = {
        "decision": "PASS",
        "overall_result": "PASS",
        "valid": True,
        "canonical_result": {
            "verification_id": "verification:fixture",
            "decision": "PASS",
            "valid": True,
            "processing_status": "COMPLETED",
            "context": {"transaction_id": "transaction:fixture"},
            "checks": [
                {"check_id": "credential.proof", "outcome": "PASSED"},
                {"check_id": "issuer.trust", "outcome": "PASSED"},
            ],
        },
    }
    value["verification_method"] = "w3c_vc"
    value["canonical_result"]["input_digest"] = "sha256:" + "a" * 64
    assert (
        artifact._assert_canonical(
            value,
            decision="PASS",
            expected_input_digest="sha256:" + "a" * 64,
            expected_verification_method="w3c_vc",
        )
        == value["canonical_result"]
    )

    value["verification_method"] = "jwt_vp"
    with pytest.raises(ValueError, match="verification method projection changed"):
        artifact._assert_canonical(value, decision="PASS", expected_verification_method="w3c_vc")
    value["verification_method"] = "w3c_vc"

    value["canonical_result"]["input_digest"] = "sha256:" + "b" * 64
    with pytest.raises(ValueError, match="canonical input digest changed"):
        artifact._assert_canonical(value, decision="PASS", expected_input_digest="sha256:" + "a" * 64)
    value["canonical_result"]["input_digest"] = "sha256:" + "a" * 64

    value["canonical_result"]["checks"].pop()
    with pytest.raises(ValueError, match="canonical check count changed"):
        artifact._assert_canonical(value, decision="PASS")

    value["decision"] = "FAIL"
    value["overall_result"] = "FAIL"
    value["valid"] = False
    value["canonical_result"] = {
        "verification_id": "verification:fixture",
        "decision": "FAIL",
        "valid": False,
        "processing_status": "COMPLETED",
        "context": {"transaction_id": "transaction:fixture"},
        "checks": [
            {"check_id": "credential.proof", "outcome": "PASSED"},
            {"check_id": "issuer.trust", "outcome": "PASSED"},
        ],
    }
    with pytest.raises(ValueError, match="no failing check"):
        artifact._assert_canonical(value, decision="FAIL")

    value["canonical_result"]["checks"][0]["outcome"] = "FAILED"
    assert artifact._assert_canonical(value, decision="FAIL") == value["canonical_result"]

    value["decision"] = "INDETERMINATE"
    value["overall_result"] = "INDETERMINATE"
    value["canonical_result"]["decision"] = "INDETERMINATE"
    value["canonical_result"]["checks"][0]["outcome"] = "PASSED"
    assert (
        artifact._assert_canonical(
            value,
            decision="INDETERMINATE",
            expected_passed_checks={"credential.proof", "issuer.trust"},
        )
        == value["canonical_result"]
    )


@pytest.mark.parametrize(
    ("decision", "projection"),
    [
        ("PASS", artifact.VDS_PASS_CHECK_PROJECTION),
        ("FAIL", artifact.VDS_FAIL_CHECK_PROJECTION),
    ],
)
def test_vds_projection_requires_exact_outcomes_and_codes(
    decision: str,
    projection: dict[str, tuple[str, str]],
) -> None:
    value = {
        "decision": decision,
        "overall_result": decision,
        "valid": decision == "PASS",
        "canonical_result": {
            "verification_id": "verification:fixture",
            "decision": decision,
            "valid": decision == "PASS",
            "processing_status": "COMPLETED",
            "context": {"transaction_id": "transaction:fixture"},
            "checks": [
                {"check_id": check_id, "outcome": outcome, "code": code}
                for check_id, (outcome, code) in projection.items()
            ],
        },
    }

    artifact._assert_canonical(value, decision=decision, expected_check_projection=projection)

    value["canonical_result"]["checks"][0]["code"] = "WRONG_FAILURE_CATEGORY"
    with pytest.raises(ValueError, match="canonical check projection changed"):
        artifact._assert_canonical(value, decision=decision, expected_check_projection=projection)


def test_session_projection_requires_exact_shape_binding_and_nonce_lifecycle() -> None:
    value = {
        "id": "session-1",
        "organization_id": "org-1",
        "verifier_did": "did:web:verifier.integration.invalid",
        "status": "pending",
        "request_uri": "oid4vp://request?session_id=session-1",
        "nonce": "n" * 43,
        "expires_at": "2026-08-31T15:00:00+00:00",
        "created_at": "2026-08-31T14:50:00+00:00",
    }

    artifact._assert_session(
        value,
        organization_id="org-1",
        expected_status="pending",
        nonce_present=True,
    )

    value["status"] = "failed"
    value["nonce"] = ""
    artifact._assert_session(
        value,
        organization_id="org-1",
        expected_status="failed",
        nonce_present=False,
    )

    value["unexpected"] = True
    with pytest.raises(ValueError, match="session response shape changed"):
        artifact._assert_session(
            value,
            organization_id="org-1",
            expected_status="failed",
            nonce_present=False,
        )


def test_session_result_limits_legacy_transaction_id_to_the_frozen_oracle() -> None:
    value = {
        "decision": "FAIL",
        "overall_result": "FAIL",
        "valid": False,
        "canonical_result": {
            "verification_id": "verification:session-1",
            "decision": "FAIL",
            "valid": False,
            "processing_status": "COMPLETED",
            "context": {"transaction_id": "session-1"},
            "checks": [{"check_id": check, "outcome": "FAILED"} for check in artifact.OID4VP_REQUIRED_CHECKS],
        },
    }

    artifact._assert_session_result(value, "session-1", artifact.LEGACY_TARGET)
    with pytest.raises(ValueError, match="approved compatibility correction"):
        artifact._assert_session_result(value, "session-1", artifact.RUST_TARGET)

    value["canonical_result"]["context"]["transaction_id"] = "transaction:session-1"
    artifact._assert_session_result(value, "session-1", artifact.RUST_TARGET)

    value["canonical_result"]["context"]["transaction_id"] = "transaction:unrelated"
    with pytest.raises(ValueError, match="canonical transaction ID changed") as error:
        artifact._assert_session_result(value, "session-1", artifact.RUST_TARGET)
    assert str(error.value) != artifact.KNOWN_INELIGIBLE_FAILURE_MESSAGE


def test_expected_failure_runner_accepts_only_the_bound_regression(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pin = valid_rust_pin()
    pin["state"] = "ineligible"
    pin["expected_failure"] = known_ineligible_failure()
    evidence_path = tmp_path / "negative-control.json"
    calls = 0

    def reject(*_args: object, **_kwargs: object) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ValueError(artifact.KNOWN_INELIGIBLE_TRANSIENT_MESSAGE)
        raise ValueError(artifact.KNOWN_INELIGIBLE_FAILURE_MESSAGE)

    monkeypatch.setattr(artifact, "run_artifact_test", reject)
    evidence = artifact.run_expected_failure(
        pin,
        evidence_path,
        provenance_verified=True,
    )

    assert evidence["status"] == "expected_failure_observed"
    assert evidence["failure_id"] == artifact.KNOWN_INELIGIBLE_FAILURE_ID
    assert evidence["attempts"] == 2
    assert evidence["transient_readiness_failures"] == 1
    assert json.loads(evidence_path.read_text(encoding="utf-8")) == evidence

    def wrong_failure(*_args: object, **_kwargs: object) -> None:
        raise ValueError("different failure")

    monkeypatch.setattr(artifact, "run_artifact_test", wrong_failure)
    with pytest.raises(ValueError, match="unexpected reason"):
        artifact.run_expected_failure(pin, evidence_path, provenance_verified=True)

    def transient_failure(*_args: object, **_kwargs: object) -> None:
        raise ValueError(artifact.KNOWN_INELIGIBLE_TRANSIENT_MESSAGE)

    monkeypatch.setattr(artifact, "run_artifact_test", transient_failure)
    with pytest.raises(ValueError, match="exhausted bounded readiness retries"):
        artifact.run_expected_failure(pin, evidence_path, provenance_verified=True)
    assert not evidence_path.exists()

    def unexpected_pass(_pin: object, private_path: Path, **_kwargs: object) -> dict[str, str]:
        private_path.write_text('{"status":"passed"}\n', encoding="utf-8")
        return {"status": "passed"}

    monkeypatch.setattr(artifact, "run_artifact_test", unexpected_pass)
    with pytest.raises(ValueError, match="unexpectedly passed"):
        artifact.run_expected_failure(pin, evidence_path, provenance_verified=True)
    assert not evidence_path.exists()


def test_health_requires_the_real_native_diagnostic_contract() -> None:
    value = {
        "status": "healthy",
        "native_backend": {
            "available": True,
            "module": "_marty_rs",
            "version": "0.1.46",
            "missing_capabilities": [],
            "error": None,
        },
    }

    artifact._assert_health(value, artifact.LEGACY_TARGET)

    value["native_backend"]["missing_capabilities"] = ["vds_nc_verify"]
    with pytest.raises(ValueError, match="missing required native capabilities"):
        artifact._assert_health(value, artifact.LEGACY_TARGET)


def test_rust_health_requires_canonical_backend_identity() -> None:
    value = {
        "status": "healthy",
        "service": "verification",
        "native_backend": {
            "available": True,
            "module": "marty-verification-service",
            "version": "1.2.3",
            "missing_capabilities": [],
            "error": None,
        },
    }

    artifact._assert_health(value, artifact.RUST_TARGET)

    value["native_backend"]["module"] = "_marty_rs"
    with pytest.raises(ValueError, match="canonical Rust service"):
        artifact._assert_health(value, artifact.RUST_TARGET)


def test_vds_fixture_is_language_neutral_and_uses_standard_signature_base64() -> None:
    issuer = "did:web:issuer.integration.invalid"
    private_key, _jwk, method_id = artifact.make_vds_key_material(issuer)

    barcode = artifact.make_vds_barcode(issuer, method_id, private_key)
    header, payload_json, signature = barcode.split("~")
    payload = json.loads(payload_json)

    assert header == "DC03USA"
    assert payload["_vds"] == {
        "version": "1.0",
        "documentType": "CMC",
        "issuerId": issuer,
        "keyId": method_id,
        "algorithm": "ES256",
    }
    assert artifact.canonical_json(payload).decode("utf-8") == payload_json
    assert len(__import__("base64").b64decode(signature, validate=True)) == 64


def test_vds_private_material_covers_submitted_barcode_and_decoded_claim_sentinels() -> None:
    issuer = "did:web:issuer.integration.invalid"
    private_key, _jwk, method_id = artifact.make_vds_key_material(issuer)
    barcode = artifact.make_vds_barcode(issuer, method_id, private_key)
    tampered = barcode.rsplit("~", 1)[0] + "~" + base64.b64encode(bytes(64)).decode("ascii")

    material = artifact._vds_private_material(tampered)

    assert material[0] == tampered
    assert barcode not in material
    for sentinel in ("dateOfBirth", "documentNumber", "givenNames", "surname", "19900102", "X123456", "ADA", "EXAMPLE"):
        assert sentinel in material
        with pytest.raises(ValueError, match="retained private"):
            artifact._assert_private_material_absent({"decoded": sentinel}, material)
    with pytest.raises(ValueError, match="retained private"):
        artifact._assert_private_material_absent({"submitted": tampered}, material)


def test_expired_terminal_row_requires_complete_minimization(monkeypatch: pytest.MonkeyPatch) -> None:
    row = {
        "status": "expired",
        "presentation_data": None,
        "verified_claims": None,
        "verification_evidence": {"policy": "fixture"},
        "nonce": None,
        "submission_sha256": None,
        "processing_token_sha256": None,
        "processing_started_at": None,
        "processing_expires_at": None,
    }
    monkeypatch.setattr(artifact, "_session_row", lambda _postgres, _session_id: row)

    artifact._assert_expired_row_minimized("postgres", "session", ["sensitive-holder-claim"])

    for field, retained, message in (
        ("presentation_data", "sensitive-holder-claim", "retained raw presentation"),
        ("verified_claims", {"claim": "sensitive-holder-claim"}, "retained raw verified claims"),
        ("nonce", "retained-nonce", "nonce was retained"),
        ("submission_sha256", "unexpected-digest", "rejected submission digest"),
        ("processing_token_sha256", "unexpected-token", "processing_token_sha256 was not cleared"),
    ):
        original = row[field]
        row[field] = retained
        with pytest.raises(ValueError, match=message):
            artifact._assert_expired_row_minimized("postgres", "session", ["sensitive-holder-claim"])
        row[field] = original


def test_malformed_terminal_row_rejects_raw_submission_retention(monkeypatch: pytest.MonkeyPatch) -> None:
    presentation = "header.payload.signature"
    digest = __import__("hashlib").sha256(presentation.encode("utf-8")).hexdigest()
    row = {
        "status": "failed",
        "presentation_data": None,
        "verified_claims": {},
        "verification_evidence": {"submission_sha256": digest},
        "nonce": None,
        "submission_sha256": digest,
        "processing_token_sha256": None,
        "processing_started_at": None,
        "processing_expires_at": None,
    }
    monkeypatch.setattr(artifact, "_session_row", lambda _postgres, _session_id: row)

    artifact._assert_terminal_row_minimized("postgres", "session", presentation, [presentation])

    row["verification_evidence"]["raw_submission"] = presentation
    with pytest.raises(ValueError, match="retained private"):
        artifact._assert_terminal_row_minimized("postgres", "session", presentation, [presentation])


def test_private_material_guard_rejects_retention() -> None:
    artifact._assert_private_material_absent({"decision": "PASS"}, ["secret-value"])
    with pytest.raises(ValueError, match="retained private"):
        artifact._assert_private_material_absent({"evidence": "secret-value"}, ["secret-value"])


def test_health_wait_fails_immediately_when_container_exits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def not_running(arguments: list[str], *, label: str, timeout: int = 60) -> str:
        assert arguments[:3] == ["docker", "inspect", "--format"]
        assert label == "inspect verification service"
        assert timeout == 60
        return "false"

    monkeypatch.setattr(artifact, "_run", not_running)

    with pytest.raises(artifact.ArtifactRuntimeError, match="exited before becoming healthy"):
        artifact._wait_for_health("http://127.0.0.1:8006", "verifier-under-test")
