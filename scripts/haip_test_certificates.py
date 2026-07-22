#!/usr/bin/env python3
"""Prepare a disposable HAIP trust root and certify Marty's KMS-backed DID key.

Marty request objects are signed through an issuer profile. This helper never
creates or receives that private key: after Marty starts, it issues a short-lived
certificate for the profile's public DID JWK. A distinct credential-signing JWK
belongs only to the disposable official test runner.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import stat
import sys
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

AUTHORITY_KEY_FILE = "root-ca-key.pem"
CERTIFICATE_FILE = "verifier-cert.pem"
TRUST_ANCHOR_FILE = "root-ca.pem"
CONFIG_FILE = "marty-verifier-haip.json"
PREPARED_FILES = (AUTHORITY_KEY_FILE, TRUST_ANCHOR_FILE, CONFIG_FILE)
DEFAULT_GATEWAY_URL = "https://marty-oidf.test:8443"
MAX_VALIDITY_HOURS = 168
PEM_CERTIFICATE = re.compile(rb"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----")
OID4VP_TRUST_ANCHOR_FILE_ENV = "EUDI_OID4VP_TRUST_ANCHOR_FILE"


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _private_jwk(key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
    numbers = key.private_numbers()
    size = (key.curve.key_size + 7) // 8
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _base64url(numbers.public_numbers.x.to_bytes(size, "big")),
        "y": _base64url(numbers.public_numbers.y.to_bytes(size, "big")),
        "d": _base64url(numbers.private_value.to_bytes(size, "big")),
    }


def _public_key_from_jwk(jwk: dict[str, object]) -> ec.EllipticCurvePublicKey:
    private_parameters = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
    if (
        jwk.get("kty") != "EC"
        or jwk.get("crv") != "P-256"
        or not isinstance(jwk.get("x"), str)
        or not isinstance(jwk.get("y"), str)
        or private_parameters.intersection(jwk)
    ):
        raise ValueError("issuer profile must expose only a public P-256 JWK")

    def decode_coordinate(name: str) -> int:
        value = str(jwk[name])
        try:
            raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        except (ValueError, TypeError) as exc:
            raise ValueError(f"issuer profile JWK {name} coordinate is invalid") from exc
        if len(raw) != 32:
            raise ValueError(f"issuer profile JWK {name} coordinate must be 32 bytes")
        return int.from_bytes(raw, "big")

    try:
        return ec.EllipticCurvePublicNumbers(
            decode_coordinate("x"), decode_coordinate("y"), ec.SECP256R1()
        ).public_key()
    except ValueError as exc:
        raise ValueError("issuer profile JWK is not a valid P-256 public key") from exc


def _gateway_hostname(gateway_url: str) -> str:
    parsed = urlparse(gateway_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("gateway URL must be an absolute HTTPS URL without user information")
    return parsed.hostname


def _validate_dns_names(values: list[str]) -> list[str]:
    names = list(dict.fromkeys(value.strip().lower() for value in values))
    if not names or any(
        not name
        or len(name) > 253
        or not all(
            label
            and len(label) <= 63
            and label[0].isalnum()
            and label[-1].isalnum()
            and all(character.isalnum() or character == "-" for character in label)
            for label in name.split(".")
        )
        for name in names
    ):
        raise ValueError("DNS names must contain valid dot-separated hostname labels")
    return names


def _write_private(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
    except Exception:
        path.unlink(missing_ok=True)
        raise
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def _write_public(path: Path, data: bytes) -> None:
    with path.open("xb") as output:
        output.write(data)


def _fingerprint(certificate: x509.Certificate) -> str:
    return f"sha256:{certificate.fingerprint(hashes.SHA256()).hex()}"


def generate_material(
    output_dir: Path,
    *,
    gateway_url: str = DEFAULT_GATEWAY_URL,
    dns_names: list[str] | None = None,
    valid_hours: int = 24,
    now: datetime | None = None,
) -> dict[str, object]:
    """Generate a verifier certificate chain and ready official-runner config."""
    if not 1 <= valid_hours <= MAX_VALIDITY_HOURS:
        raise ValueError(f"validity must be between 1 and {MAX_VALIDITY_HOURS} hours")
    hostname = _gateway_hostname(gateway_url)
    names = _validate_dns_names(dns_names or [hostname])
    targets = {name: output_dir / name for name in PREPARED_FILES}
    existing = [path for path in targets.values() if path.exists()]
    if existing:
        raise FileExistsError("refusing to overwrite HAIP material: " + ", ".join(map(str, existing)))

    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    current = current.astimezone(UTC)
    not_before = current - timedelta(minutes=5)
    leaf_not_after = current + timedelta(hours=valid_hours)
    root_not_after = leaf_not_after + timedelta(hours=1)

    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ElevenID disposable conformance"),
            x509.NameAttribute(NameOID.COMMON_NAME, "ElevenID HAIP disposable root"),
        ]
    )
    root_certificate = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(root_not_after)
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
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    credential_key = ec.generate_private_key(ec.SECP256R1())
    authority_key_pem = root_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    root_pem = root_certificate.public_bytes(serialization.Encoding.PEM)
    runner_config = {
        "credential": {"signing_jwk": _private_jwk(credential_key)},
        "client": {"request_object_trust_anchor_pem": root_pem.decode("ascii")},
        "verifier": {"gateway_url": gateway_url, "profile": "oid4vp-haip-1.0"},
    }
    config_bytes = (json.dumps(runner_config, indent=2, sort_keys=True) + "\n").encode("utf-8")

    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    created: list[Path] = []
    try:
        _write_private(targets[AUTHORITY_KEY_FILE], authority_key_pem)
        created.append(targets[AUTHORITY_KEY_FILE])
        _write_public(targets[TRUST_ANCHOR_FILE], root_pem)
        created.append(targets[TRUST_ANCHOR_FILE])
        _write_private(targets[CONFIG_FILE], config_bytes)
        created.append(targets[CONFIG_FILE])
    except Exception:
        for path in created:
            path.unlink(missing_ok=True)
        raise

    return {
        "config_path": str(targets[CONFIG_FILE].resolve()),
        "config_sha256": f"sha256:{sha256(config_bytes).hexdigest()}",
        "dns_names": names,
        "gateway_url": gateway_url,
        "not_after": leaf_not_after.isoformat(),
        "trust_anchor_path": str(targets[TRUST_ANCHOR_FILE].resolve()),
        "trust_anchor_sha256": _fingerprint(root_certificate),
    }


def issue_verifier_certificate(
    material_dir: Path,
    public_jwk: dict[str, object],
    *,
    gateway_url: str = DEFAULT_GATEWAY_URL,
    dns_names: list[str] | None = None,
    valid_hours: int = 24,
    now: datetime | None = None,
) -> dict[str, str]:
    """Issue a leaf for an issuer profile public key, then destroy the test CA key."""
    if not 1 <= valid_hours <= MAX_VALIDITY_HOURS:
        raise ValueError(f"validity must be between 1 and {MAX_VALIDITY_HOURS} hours")
    hostname = _gateway_hostname(gateway_url)
    names = _validate_dns_names(dns_names or [hostname])
    certificate_path = material_dir / CERTIFICATE_FILE
    if certificate_path.exists():
        raise FileExistsError(f"refusing to overwrite HAIP certificate: {certificate_path}")
    authority_key_path = material_dir / AUTHORITY_KEY_FILE
    trust_anchor_path = material_dir / TRUST_ANCHOR_FILE
    try:
        authority_key = serialization.load_pem_private_key(authority_key_path.read_bytes(), password=None)
        root_certificate = x509.load_pem_x509_certificate(trust_anchor_path.read_bytes())
    except (OSError, ValueError) as exc:
        raise ValueError("prepared HAIP authority material is missing or invalid") from exc
    if not isinstance(authority_key, ec.EllipticCurvePrivateKey) or not isinstance(authority_key.curve, ec.SECP256R1):
        raise ValueError("prepared HAIP authority key must be P-256")
    if root_certificate.public_key().public_numbers() != authority_key.public_key().public_numbers():
        raise ValueError("prepared HAIP authority certificate does not match its key")
    verifier_public_key = _public_key_from_jwk(public_jwk)
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    current = current.astimezone(UTC)
    leaf_certificate = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ElevenID disposable conformance"),
                    x509.NameAttribute(NameOID.COMMON_NAME, hostname),
                ]
            )
        )
        .issuer_name(root_certificate.subject)
        .public_key(verifier_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(current - timedelta(minutes=5))
        .not_valid_after(current + timedelta(hours=valid_hours))
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
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name) for name in names]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(verifier_public_key), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(authority_key.public_key()), critical=False)
        .sign(authority_key, hashes.SHA256())
    )
    bundle = leaf_certificate.public_bytes(serialization.Encoding.PEM) + trust_anchor_path.read_bytes()
    _write_public(certificate_path, bundle)
    authority_key_path.unlink()
    return {
        "certificate_sha256": _fingerprint(leaf_certificate),
        "dns_names": ",".join(names),
        "verifier_certificate_path": str(certificate_path.resolve()),
    }


def validate_verifier_environment(certificate_pem: str, public_jwk: dict[str, object] | None = None) -> dict[str, str]:
    """Validate the public certificate consumed by Marty's HAIP profile."""
    try:
        encoded_certificates = certificate_pem.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("HAIP verifier certificate bundle must be PEM") from exc
    certificates = [x509.load_pem_x509_certificate(value) for value in PEM_CERTIFICATE.findall(encoded_certificates)]
    if not certificates:
        raise ValueError("HAIP verifier certificate bundle contains no PEM certificate")
    leaf = certificates[0]
    public_key = leaf.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP256R1):
        raise ValueError("HAIP verifier leaf certificate must contain a P-256 public key")
    if public_jwk is not None and public_key.public_numbers() != _public_key_from_jwk(public_jwk).public_numbers():
        raise ValueError("HAIP verifier certificate does not match the issuer profile DID key")
    try:
        basic_constraints = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value
        key_usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("HAIP verifier leaf certificate requires BasicConstraints and KeyUsage") from exc
    if basic_constraints.ca or not key_usage.digital_signature:
        raise ValueError("HAIP verifier leaf certificate must be a non-CA digital-signature certificate")
    return {
        "VERIFIER_X509_CERT_PEM": certificate_pem,
    }


def validate_oid4vp_trust_anchor(certificate_pem: str, trust_anchor_pem: str) -> str:
    """Require the separately trusted root to terminate the verifier bundle."""
    try:
        certificate_bundle = certificate_pem.encode("ascii")
        trust_anchor_bytes = trust_anchor_pem.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("HAIP request-object trust anchor must be PEM") from exc
    certificates = [x509.load_pem_x509_certificate(value) for value in PEM_CERTIFICATE.findall(certificate_bundle)]
    anchors = [x509.load_pem_x509_certificate(value) for value in PEM_CERTIFICATE.findall(trust_anchor_bytes)]
    if not anchors:
        raise ValueError("HAIP request-object trust-anchor file contains no PEM certificate")
    for anchor in anchors:
        try:
            constraints = anchor.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound as exc:
            raise ValueError("HAIP request-object trust anchors require BasicConstraints") from exc
        if not constraints.ca:
            raise ValueError("HAIP request-object trust-anchor file must contain only CA certificates")
    if not certificates or not any(
        certificates[-1].fingerprint(hashes.SHA256()) == anchor.fingerprint(hashes.SHA256()) for anchor in anchors
    ):
        raise ValueError("HAIP verifier certificate bundle must end at the request-object trust anchor")
    return trust_anchor_pem


def load_verifier_environment(material_dir: Path) -> dict[str, str]:
    """Load generated verifier material and its independent wallet trust anchor."""
    certificate_path = material_dir / CERTIFICATE_FILE
    trust_anchor_path = material_dir / TRUST_ANCHOR_FILE
    try:
        certificate_pem = certificate_path.read_text(encoding="ascii")
        trust_anchor_pem = trust_anchor_path.read_text(encoding="ascii")
    except FileNotFoundError as exc:
        raise ValueError(f"HAIP material is incomplete: {exc.filename}") from exc
    environment = validate_verifier_environment(certificate_pem)
    validate_oid4vp_trust_anchor(certificate_pem, trust_anchor_pem)
    environment[OID4VP_TRUST_ANCHOR_FILE_ENV] = str(trust_anchor_path.resolve())
    return environment


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--output-dir", type=Path, required=True)
    result.add_argument("--gateway-url", default=DEFAULT_GATEWAY_URL)
    result.add_argument("--dns-name", action="append", dest="dns_names")
    result.add_argument("--valid-hours", type=int, default=24)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    report = generate_material(
        args.output_dir,
        gateway_url=args.gateway_url,
        dns_names=args.dns_names,
        valid_hours=args.valid_hours,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        print(f"HAIP material error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
