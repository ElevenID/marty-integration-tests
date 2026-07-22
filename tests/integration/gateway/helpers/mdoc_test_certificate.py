"""Disposable document-signer certificate material for interoperability tests.

The leaf certificate wraps the public key exported by the production signing
service.  Its private key remains in OpenBao/KMS; only the disposable test CA
private key exists in the test process.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


@dataclass(frozen=True)
class MdocCertificateMaterial:
    leaf_pem: str
    chain_pem: str
    leaf_sha256: str
    trust_anchor_sha256: str


def _base64url_coordinate(value: Any, *, name: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError(f"mDoc signing JWK {name} must be unpadded base64url")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except Exception as exc:
        raise ValueError(f"mDoc signing JWK {name} is invalid base64url") from exc
    if len(decoded) != 32:
        raise ValueError(f"mDoc signing JWK {name} must be a 32-byte P-256 coordinate")
    return decoded


def p256_public_key_from_jwk(jwk: dict[str, Any]) -> ec.EllipticCurvePublicKey:
    """Strictly convert the public ES256 JWK returned by the gateway."""
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("mDoc signing JWK must be an EC P-256 public key")
    if any(secret in jwk for secret in ("d", "p", "q", "dp", "dq", "qi", "k")):
        raise ValueError("mDoc signing JWK unexpectedly contains private key material")
    x = int.from_bytes(_base64url_coordinate(jwk.get("x"), name="x"), "big")
    y = int.from_bytes(_base64url_coordinate(jwk.get("y"), name="y"), "big")
    try:
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    except ValueError as exc:
        raise ValueError("mDoc signing JWK is not a point on P-256") from exc


def create_disposable_issuer_certificate_chain(
    jwk: dict[str, Any],
    *,
    organization_id: str,
    profile_label: str = "issuer",
    now: datetime | None = None,
) -> MdocCertificateMaterial:
    """Issue a short-lived certificate for a profile's real KMS public key."""
    checked_at = (now or datetime.now(UTC)).astimezone(UTC)
    signer_public_key = p256_public_key_from_jwk(jwk)
    ca_private_key = ec.generate_private_key(ec.SECP256R1())
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"ElevenID EUDI test CA {organization_id}")])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(checked_at - timedelta(minutes=5))
        .not_valid_after(checked_at + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_private_key.public_key()), critical=False)
        .sign(ca_private_key, hashes.SHA256())
    )
    leaf_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Marty {profile_label} {organization_id}")])
    leaf_certificate = (
        x509.CertificateBuilder()
        .subject_name(leaf_subject)
        .issuer_name(ca_certificate.subject)
        .public_key(signer_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(checked_at - timedelta(minutes=5))
        .not_valid_after(checked_at + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(signer_public_key), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()), critical=False)
        .sign(ca_private_key, hashes.SHA256())
    )
    leaf_pem = leaf_certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
    chain_pem = ca_certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return MdocCertificateMaterial(
        leaf_pem=leaf_pem,
        chain_pem=chain_pem,
        leaf_sha256=leaf_certificate.fingerprint(hashes.SHA256()).hex(),
        trust_anchor_sha256=ca_certificate.fingerprint(hashes.SHA256()).hex(),
    )


def create_disposable_mdoc_certificate_chain(
    jwk: dict[str, Any],
    *,
    organization_id: str,
    now: datetime | None = None,
) -> MdocCertificateMaterial:
    """Backward-compatible mdoc-specific name for the generic profile helper."""

    return create_disposable_issuer_certificate_chain(
        jwk,
        organization_id=organization_id,
        profile_label="mdoc DSC",
        now=now,
    )
