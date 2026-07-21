"""Tests for the disposable mdoc DSC used by the official EUDI lane."""

from __future__ import annotations

import base64
from datetime import UTC, datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from tests.integration.gateway.helpers.mdoc_test_certificate import (
    create_disposable_mdoc_certificate_chain,
    p256_public_key_from_jwk,
)


def _b64url(value: int) -> str:
    return base64.urlsafe_b64encode(value.to_bytes(32, "big")).rstrip(b"=").decode("ascii")


def _public_jwk(key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
    numbers = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": _b64url(numbers.x), "y": _b64url(numbers.y), "kid": "kms-key"}


def test_certificate_wraps_real_kms_public_key_and_has_valid_chain() -> None:
    kms_key = ec.generate_private_key(ec.SECP256R1())
    material = create_disposable_mdoc_certificate_chain(
        _public_jwk(kms_key),
        organization_id="org-test",
        now=datetime(2026, 7, 21, 12, tzinfo=UTC),
    )
    leaf = x509.load_pem_x509_certificate(material.leaf_pem.encode("ascii"))
    root = x509.load_pem_x509_certificate(material.chain_pem.encode("ascii"))

    assert leaf.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ) == kms_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    root.public_key().verify(
        leaf.signature,
        leaf.tbs_certificate_bytes,
        ec.ECDSA(leaf.signature_hash_algorithm),
    )
    assert leaf.fingerprint(hashes.SHA256()).hex() == material.leaf_sha256
    assert root.fingerprint(hashes.SHA256()).hex() == material.trust_anchor_sha256


def test_jwk_parser_rejects_private_material_and_non_p256_keys() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    private_jwk = {**_public_jwk(key), "d": "secret"}
    with pytest.raises(ValueError, match="private key material"):
        p256_public_key_from_jwk(private_jwk)

    with pytest.raises(ValueError, match="EC P-256"):
        p256_public_key_from_jwk({**_public_jwk(key), "crv": "P-384"})
