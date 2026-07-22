"""Tests for disposable HAIP trust material and issuer-profile certification."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("haip_test_certificates", ROOT / "scripts" / "haip_test_certificates.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load HAIP certificate generator")
certificates = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(certificates)
OIDF_SPEC = importlib.util.spec_from_file_location(
    "oidf_conformance_for_haip_material", ROOT / "scripts" / "oidf_conformance.py"
)
if OIDF_SPEC is None or OIDF_SPEC.loader is None:
    raise RuntimeError("could not load OIDF conformance helper")
oidf = importlib.util.module_from_spec(OIDF_SPEC)
OIDF_SPEC.loader.exec_module(oidf)


def public_jwk(key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
    numbers = key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": certificates._base64url(numbers.x.to_bytes(32, "big")),
        "y": certificates._base64url(numbers.y.to_bytes(32, "big")),
    }


def parsed_bundle(path: Path) -> list[x509.Certificate]:
    data = path.read_bytes()
    return [x509.load_pem_x509_certificate(value) for value in certificates.PEM_CERTIFICATE.findall(data)]


def test_prepare_then_certify_uses_only_issuer_profile_public_key(tmp_path: Path) -> None:
    output = tmp_path / "material"
    prepared = certificates.generate_material(
        output,
        gateway_url="https://verifier.example:8443",
        now=datetime(2026, 7, 20, tzinfo=UTC),
    )
    assert not (output / certificates.CERTIFICATE_FILE).exists()
    assert (output / certificates.AUTHORITY_KEY_FILE).exists()
    verifier_key = ec.generate_private_key(ec.SECP256R1())
    issued = certificates.issue_verifier_certificate(
        output,
        public_jwk(verifier_key),
        gateway_url="https://verifier.example:8443",
        now=datetime(2026, 7, 20, tzinfo=UTC),
    )

    leaf, root = parsed_bundle(output / certificates.CERTIFICATE_FILE)
    trust_anchor = x509.load_pem_x509_certificate((output / certificates.TRUST_ANCHOR_FILE).read_bytes())
    assert leaf.public_key().public_numbers() == verifier_key.public_key().public_numbers()
    assert trust_anchor == root
    root.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm))
    assert not (output / certificates.AUTHORITY_KEY_FILE).exists()

    leaf_usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert leaf_usage.digital_signature
    assert not leaf_usage.key_cert_sign
    assert san.get_values_for_type(x509.DNSName) == ["verifier.example"]
    assert issued["certificate_sha256"] == f"sha256:{leaf.fingerprint(hashes.SHA256()).hex()}"
    assert "certificate_sha256" not in prepared
    assert "signing_key_path" not in prepared

    config_path = output / certificates.CONFIG_FILE
    config = json.loads(config_path.read_text(encoding="utf-8"))
    assert config["client"]["request_object_trust_anchor_pem"] == (output / certificates.TRUST_ANCHOR_FILE).read_text(
        encoding="ascii"
    )
    assert set(config["credential"]["signing_jwk"]) == {"kty", "crv", "x", "y", "d"}
    oidf.validate_config(config_path, "oid4vp-haip-verifier")
    if os.name != "nt":
        assert stat.S_IMODE(config_path.stat().st_mode) == 0o600


def test_certificate_is_short_lived_and_refuses_overwrite(tmp_path: Path) -> None:
    output = tmp_path / "material"
    certificates.generate_material(output, gateway_url="https://verifier.example:8443")
    jwk = public_jwk(ec.generate_private_key(ec.SECP256R1()))
    certificates.issue_verifier_certificate(
        output,
        jwk,
        gateway_url="https://verifier.example:8443",
        now=datetime(2026, 7, 20, tzinfo=UTC),
    )
    leaf = parsed_bundle(output / certificates.CERTIFICATE_FILE)[0]
    not_after = leaf.not_valid_after_utc
    assert not_after == datetime(2026, 7, 21, tzinfo=UTC)
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        certificates.issue_verifier_certificate(output, jwk)


def test_validation_rejects_a_certificate_for_another_profile_key(tmp_path: Path) -> None:
    output = tmp_path / "material"
    certificates.generate_material(output, gateway_url="https://verifier.example:8443")
    first = public_jwk(ec.generate_private_key(ec.SECP256R1()))
    second = public_jwk(ec.generate_private_key(ec.SECP256R1()))
    certificates.issue_verifier_certificate(output, first, gateway_url="https://verifier.example:8443")
    certificate = (output / certificates.CERTIFICATE_FILE).read_text(encoding="ascii")
    with pytest.raises(ValueError, match="does not match the issuer profile"):
        certificates.validate_verifier_environment(certificate, second)


def test_private_jwk_is_rejected_as_profile_identity(tmp_path: Path) -> None:
    output = tmp_path / "material"
    certificates.generate_material(output)
    private = certificates._private_jwk(ec.generate_private_key(ec.SECP256R1()))
    with pytest.raises(ValueError, match="only a public"):
        certificates.issue_verifier_certificate(output, private)
