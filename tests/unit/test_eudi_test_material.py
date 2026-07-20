"""Tests for disposable EUDI TLS and Java-store material."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "eudi_test_material",
    ROOT / "scripts" / "eudi_test_material.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load EUDI material helper")
material = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(material)


def fake_java_stores(**values: object) -> None:
    output = values["output_dir"]
    assert isinstance(output, Path)
    for name in (material.EUDI_KEYSTORE_FILE, material.TRUSTSTORE_FILE):
        path = output / name
        path.write_bytes(f"fake-{name}".encode())
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def generated(tmp_path: Path, **options: object) -> Path:
    output = tmp_path / "material"
    material.generate_material(
        output,
        keytool=Path(__file__),
        java_store_builder=fake_java_stores,
        **options,
    )
    return output


def certificates(path: Path) -> list[x509.Certificate]:
    return [x509.load_pem_x509_certificate(value) for value in material.PEM_CERTIFICATE.findall(path.read_bytes())]


def test_generate_writes_short_lived_tls_chain_eudi_access_cert_and_private_environment(tmp_path: Path) -> None:
    output = generated(tmp_path, now=datetime.now(UTC))
    tls_leaf, root = certificates(output / material.TLS_CERTIFICATE_FILE)
    eudi_leaf, eudi_root = certificates(output / material.EUDI_CERTIFICATE_FILE)
    tls_key = serialization.load_pem_private_key((output / material.TLS_KEY_FILE).read_bytes(), password=None)

    assert isinstance(tls_key, ec.EllipticCurvePrivateKey)
    assert isinstance(tls_key.curve, ec.SECP256R1)
    assert tls_key.public_key().public_numbers() == tls_leaf.public_key().public_numbers()
    assert isinstance(eudi_leaf.public_key(), ec.EllipticCurvePublicKey)
    assert isinstance(eudi_leaf.public_key().curve, ec.SECP521R1)
    assert root == eudi_root
    root.public_key().verify(
        tls_leaf.signature,
        tls_leaf.tbs_certificate_bytes,
        ec.ECDSA(tls_leaf.signature_hash_algorithm),
    )
    root.public_key().verify(
        eudi_leaf.signature,
        eudi_leaf.tbs_certificate_bytes,
        ec.ECDSA(eudi_leaf.signature_hash_algorithm),
    )
    assert tls_leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert root.extensions.get_extension_for_class(x509.BasicConstraints).value == x509.BasicConstraints(
        ca=True,
        path_length=0,
    )
    assert ExtendedKeyUsageOID.SERVER_AUTH in tls_leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert tls_leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
        x509.DNSName
    ) == [material.DEFAULT_HOSTNAME]

    document = json.loads((output / material.ENVIRONMENT_FILE).read_text(encoding="utf-8"))
    environment = document["environment"]
    assert document["schema"] == material.SCHEMA
    assert document["mode"] == "generated"
    assert environment["OIDF_PUBLIC_BASE_URL"] == "https://marty-oidf.test:8443"
    assert environment["OIDF_INTERNAL_TLS_PORT"] == "8443"
    assert environment["OIDF_CONFORMANCE_BRIDGE_ALIAS"] == material.DEFAULT_HOSTNAME
    assert environment["EUDI_WALLET_TESTER_PUBLIC_URL"] == "https://marty-oidf.test:25051"
    assert environment["EUDI_VERIFIER_PUBLIC_URL"] == "https://marty-oidf.test:28091"
    assert environment["EUDI_VERIFIER_KEYSTORE_ALIAS"] == "access_certificate"
    assert environment["EUDI_VERIFIER_SIGNING_ALGORITHM"] == "ES512"
    assert environment["EUDI_VERIFIER_CLIENT_ID_PREFIX"] == "x509_san_dns"
    assert environment["EUDI_VERIFIER_ORIGINAL_CLIENT_ID"] == material.DEFAULT_HOSTNAME
    assert environment["EUDI_TEST_MATERIAL_MODE"] == "generated"

    report_text = (output / material.REPORT_FILE).read_text(encoding="utf-8")
    for secret_name in (
        "EUDI_VERIFIER_KEYSTORE_PASSWORD",
        "EUDI_VERIFIER_KEY_PASSWORD",
        "EUDI_TLS_TRUSTSTORE_PASSWORD",
    ):
        assert environment[secret_name] not in report_text
    assert not any(path.suffix == ".p12" for path in output.rglob("*"))
    assert not any("root" in path.name and "key" in path.name for path in output.iterdir())
    if os.name != "nt":
        assert stat.S_IMODE((output / material.TLS_KEY_FILE).stat().st_mode) == 0o600
        assert stat.S_IMODE((output / material.ENVIRONMENT_FILE).stat().st_mode) == 0o600


def test_generated_environment_passes_tls_validation_without_keytool(tmp_path: Path) -> None:
    output = generated(tmp_path)
    mode, environment = material.load_environment_manifest(output)
    report = material.validate_environment(environment, validate_java=False)

    assert mode == "generated"
    assert report["mode"] == "generated"
    assert report["eudi_access_certificate_sha256"].startswith("sha256:")


def test_external_contract_requires_a_docker_host_reachable_wallet_kit_url(tmp_path: Path) -> None:
    output = generated(tmp_path)
    _mode, environment = material.load_environment_manifest(output)
    environment.pop("EUDI_WALLET_KIT_URL")

    with pytest.raises(ValueError, match="EUDI_WALLET_KIT_URL"):
        material.validate_environment_contract(environment)


def test_validation_rejects_public_hostname_not_covered_by_tls_san(tmp_path: Path) -> None:
    output = generated(tmp_path)
    _mode, environment = material.load_environment_manifest(output)
    environment["EUDI_VERIFIER_PUBLIC_URL"] = "https://other.test:28091"

    with pytest.raises(ValueError, match="SAN"):
        material.validate_environment(environment, validate_java=False)


def test_generation_refuses_overwrite_and_invalid_service_contracts(tmp_path: Path) -> None:
    output = generated(tmp_path)
    key_before = (output / material.TLS_KEY_FILE).read_bytes()
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        material.generate_material(
            output,
            keytool=Path(__file__),
            java_store_builder=fake_java_stores,
        )
    assert (output / material.TLS_KEY_FILE).read_bytes() == key_before

    with pytest.raises(ValueError, match="distinct"):
        material.generate_material(
            tmp_path / "duplicate-ports",
            marty_port=8443,
            wallet_tester_port=8443,
            keytool=Path(__file__),
            java_store_builder=fake_java_stores,
        )
    with pytest.raises(ValueError, match="DNS hostname"):
        material.generate_material(
            tmp_path / "ip-hostname",
            hostname="127.0.0.1",
            keytool=Path(__file__),
            java_store_builder=fake_java_stores,
        )


def test_complete_external_material_paths_take_precedence_but_partial_pair_fails(tmp_path: Path) -> None:
    output = generated(tmp_path)
    external = {
        "OIDF_TLS_CERT_DIR": "C:/secure/external-tls",
        "EUDI_VERIFIER_KEYSTORE_FILE": "C:/secure/external-verifier.jks",
        "UNRELATED": "preserved",
    }
    mode, environment = material.merged_material_environment(output, external)
    assert mode == "external"
    assert environment["EUDI_TEST_MATERIAL_MODE"] == "external"
    assert environment["OIDF_TLS_CERT_DIR"] == external["OIDF_TLS_CERT_DIR"]

    with pytest.raises(ValueError, match="both external"):
        material.merged_material_environment(output, {"OIDF_TLS_CERT_DIR": external["OIDF_TLS_CERT_DIR"]})


def test_exported_generated_values_remain_authoritative(tmp_path: Path) -> None:
    output = generated(tmp_path)
    _mode, generated_environment = material.load_environment_manifest(output)
    stale = dict(generated_environment)
    stale.update(
        {
            "EUDI_TEST_MATERIAL_MODE": "generated",
            "EUDI_VERIFIER_KEYSTORE_PASSWORD": "stale-password",
            "EUDI_TLS_TRUSTSTORE_PASSWORD": "stale-truststore-password",
            "SSL_CERT_FILE": "stale-root.pem",
            "PATH": "preserved-process-path",
        }
    )

    mode, environment = material.merged_material_environment(output, stale)

    assert mode == "generated"
    assert environment["EUDI_TEST_MATERIAL_MODE"] == "generated"
    assert environment["EUDI_VERIFIER_KEYSTORE_PASSWORD"] == generated_environment["EUDI_VERIFIER_KEYSTORE_PASSWORD"]
    assert environment["EUDI_TLS_TRUSTSTORE_PASSWORD"] == generated_environment["EUDI_TLS_TRUSTSTORE_PASSWORD"]
    assert environment["SSL_CERT_FILE"] == generated_environment["SSL_CERT_FILE"]
    assert environment["PATH"] == "preserved-process-path"


def test_stable_cli_uses_output_and_material_options() -> None:
    generate = material.parser().parse_args(["generate", "--output", "material"])
    validate = material.parser().parse_args(["validate", "--material", "material"])
    assert generate.output_dir == Path("material")
    assert validate.material_dir == Path("material")


@pytest.mark.skipif(material.find_keytool() is None, reason="JDK keytool is not installed")
def test_real_keytool_jks_round_trip(tmp_path: Path) -> None:
    output = tmp_path / "material"
    report = material.generate_material(output)
    _mode, environment = material.load_environment_manifest(output)
    validated = material.validate_environment(environment)
    assert validated["eudi_access_certificate_sha256"] == report["eudi_access_certificate_sha256"]
