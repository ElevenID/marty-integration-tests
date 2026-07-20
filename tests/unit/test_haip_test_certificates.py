"""Tests for disposable HAIP verifier and official-runner material."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "haip_test_certificates",
    ROOT / "scripts" / "haip_test_certificates.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load HAIP certificate generator")
certificates = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(certificates)
OIDF_SPEC = importlib.util.spec_from_file_location(
    "oidf_conformance_for_haip_material",
    ROOT / "scripts" / "oidf_conformance.py",
)
if OIDF_SPEC is None or OIDF_SPEC.loader is None:
    raise RuntimeError("could not load OIDF conformance helper")
oidf = importlib.util.module_from_spec(OIDF_SPEC)
OIDF_SPEC.loader.exec_module(oidf)


def generated(tmp_path: Path, name: str = "material") -> Path:
    output = tmp_path / name
    certificates.generate_material(
        output,
        gateway_url="https://verifier.example:8443",
        now=datetime(2026, 7, 20, tzinfo=UTC),
    )
    return output


def parsed_bundle(path: Path) -> list[x509.Certificate]:
    data = path.read_bytes()
    return [x509.load_pem_x509_certificate(value) for value in certificates.PEM_CERTIFICATE.findall(data)]


def test_generate_material_writes_matching_p256_chain_and_ready_config(tmp_path: Path) -> None:
    output = tmp_path / "material"
    report = certificates.generate_material(
        output,
        gateway_url="https://verifier.example:8443",
        now=datetime(2026, 7, 20, tzinfo=UTC),
    )

    key = serialization.load_pem_private_key(
        (output / certificates.KEY_FILE).read_bytes(),
        password=None,
    )
    leaf, root = parsed_bundle(output / certificates.CERTIFICATE_FILE)
    trust_anchor = x509.load_pem_x509_certificate((output / certificates.TRUST_ANCHOR_FILE).read_bytes())
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert isinstance(key.curve, ec.SECP256R1)
    assert leaf.public_key().public_numbers() == key.public_key().public_numbers()
    assert trust_anchor == root
    root.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm))

    leaf_constraints = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value
    root_constraints = root.extensions.get_extension_for_class(x509.BasicConstraints).value
    leaf_usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    root_usage = root.extensions.get_extension_for_class(x509.KeyUsage).value
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert (leaf_constraints.ca, root_constraints.ca, root_constraints.path_length) == (False, True, 0)
    assert leaf_usage.digital_signature
    assert not leaf_usage.key_cert_sign
    assert root_usage.key_cert_sign
    assert root_usage.crl_sign
    assert san.get_values_for_type(x509.DNSName) == ["verifier.example"]

    config_path = output / certificates.CONFIG_FILE
    config = json.loads(config_path.read_text(encoding="utf-8"))
    assert config["verifier"] == {
        "gateway_url": "https://verifier.example:8443",
        "profile": "oid4vp-haip-1.0",
    }
    assert config["client"]["request_object_trust_anchor_pem"] == (output / certificates.TRUST_ANCHOR_FILE).read_text(
        encoding="ascii"
    )
    credential_jwk = config["credential"]["signing_jwk"]
    assert set(credential_jwk) == {"kty", "crv", "x", "y", "d"}
    assert (credential_jwk["x"], credential_jwk["y"]) != (
        certificates._base64url(key.public_key().public_numbers().x.to_bytes(32, "big")),
        certificates._base64url(key.public_key().public_numbers().y.to_bytes(32, "big")),
    )
    assert report["certificate_sha256"] == f"sha256:{leaf.fingerprint(hashes.SHA256()).hex()}"
    assert set(report) == {
        "certificate_sha256",
        "config_path",
        "config_sha256",
        "dns_names",
        "gateway_url",
        "not_after",
        "signing_key_path",
        "trust_anchor_path",
        "trust_anchor_sha256",
        "verifier_certificate_path",
    }
    assert "BEGIN PRIVATE KEY" not in json.dumps(report)
    oidf.validate_config(config_path, "oid4vp-haip-verifier")
    if os.name != "nt":
        assert stat.S_IMODE((output / certificates.KEY_FILE).stat().st_mode) == 0o600
        assert stat.S_IMODE(config_path.stat().st_mode) == 0o600


def test_generated_material_is_short_lived_and_refuses_overwrite(tmp_path: Path) -> None:
    output = generated(tmp_path)
    key_before = (output / certificates.KEY_FILE).read_bytes()
    leaf = parsed_bundle(output / certificates.CERTIFICATE_FILE)[0]
    not_after = (
        leaf.not_valid_after_utc if hasattr(leaf, "not_valid_after_utc") else leaf.not_valid_after.replace(tzinfo=UTC)
    )
    assert not_after == datetime(2026, 7, 21, tzinfo=UTC)

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        certificates.generate_material(output)
    assert (output / certificates.KEY_FILE).read_bytes() == key_before


def test_loader_rejects_a_certificate_from_a_different_pair(tmp_path: Path) -> None:
    first = generated(tmp_path, "first")
    second = generated(tmp_path, "second")
    mismatched_certificate = (second / certificates.CERTIFICATE_FILE).read_text(encoding="ascii")
    with pytest.raises(ValueError, match="does not match"):
        certificates.validate_verifier_environment(
            (first / certificates.KEY_FILE).read_text(encoding="ascii"),
            mismatched_certificate,
        )
