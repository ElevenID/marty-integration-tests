from __future__ import annotations

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
    assert governance["trust_profiles"][0]["content"] == {
        "trusted_issuers": ["did:web:issuer.integration.invalid"],
        "allow_public_did_fallback": False,
    }
    assert "ephemeral-api-key" not in json.dumps(governance)


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


def test_canonical_projection_requires_exact_vds_check_floor() -> None:
    value = {
        "decision": "PASS",
        "overall_result": "PASS",
        "valid": True,
        "canonical_result": {
            "decision": "PASS",
            "valid": True,
            "processing_status": "COMPLETED",
            "checks": [
                {"check_id": "credential.proof", "outcome": "PASSED"},
                {"check_id": "issuer.trust", "outcome": "PASSED"},
            ],
        },
    }
    assert artifact._assert_canonical(value, decision="PASS") == value["canonical_result"]

    value["canonical_result"]["checks"].pop()
    with pytest.raises(ValueError, match="exactly two checks"):
        artifact._assert_canonical(value, decision="PASS")

    value["decision"] = "FAIL"
    value["overall_result"] = "FAIL"
    value["valid"] = False
    value["canonical_result"] = {
        "decision": "FAIL",
        "valid": False,
        "processing_status": "COMPLETED",
        "checks": [
            {"check_id": "credential.proof", "outcome": "PASSED"},
            {"check_id": "issuer.trust", "outcome": "PASSED"},
        ],
    }
    with pytest.raises(ValueError, match="no failing check"):
        artifact._assert_canonical(value, decision="FAIL")

    value["canonical_result"]["checks"][0]["outcome"] = "FAILED"
    assert artifact._assert_canonical(value, decision="FAIL") == value["canonical_result"]


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
