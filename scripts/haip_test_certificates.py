#!/usr/bin/env python3
"""Generate short-lived HAIP material for disposable conformance runs.

The verifier certificate/key pair signs Marty's request objects. A distinct
credential-signing JWK is written into the official runner configuration.
Only public fingerprints and output paths are printed; private values remain
in files with owner-only permissions.
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

KEY_FILE = "verifier-key.pem"
CERTIFICATE_FILE = "verifier-cert.pem"
TRUST_ANCHOR_FILE = "root-ca.pem"
CONFIG_FILE = "marty-verifier-haip.json"
OUTPUT_FILES = (KEY_FILE, CERTIFICATE_FILE, TRUST_ANCHOR_FILE, CONFIG_FILE)
DEFAULT_GATEWAY_URL = "https://marty-oidf.test:8443"
MAX_VALIDITY_HOURS = 168
PEM_CERTIFICATE = re.compile(rb"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----")


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
    targets = {name: output_dir / name for name in OUTPUT_FILES}
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
                encipher_only=None,
                decipher_only=None,
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

    verifier_key = ec.generate_private_key(ec.SECP256R1())
    leaf_name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ElevenID disposable conformance"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ]
    )
    leaf_certificate = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(root_name)
        .public_key(verifier_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(leaf_not_after)
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
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in names]),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(verifier_key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    credential_key = ec.generate_private_key(ec.SECP256R1())
    verifier_key_pem = verifier_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    leaf_pem = leaf_certificate.public_bytes(serialization.Encoding.PEM)
    root_pem = root_certificate.public_bytes(serialization.Encoding.PEM)
    certificate_bundle = leaf_pem + root_pem
    runner_config = {
        "credential": {"signing_jwk": _private_jwk(credential_key)},
        "client": {"request_object_trust_anchor_pem": root_pem.decode("ascii")},
        "verifier": {"gateway_url": gateway_url, "profile": "oid4vp-haip-1.0"},
    }
    config_bytes = (json.dumps(runner_config, indent=2, sort_keys=True) + "\n").encode("utf-8")

    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    created: list[Path] = []
    try:
        _write_private(targets[KEY_FILE], verifier_key_pem)
        created.append(targets[KEY_FILE])
        _write_public(targets[CERTIFICATE_FILE], certificate_bundle)
        created.append(targets[CERTIFICATE_FILE])
        _write_public(targets[TRUST_ANCHOR_FILE], root_pem)
        created.append(targets[TRUST_ANCHOR_FILE])
        _write_private(targets[CONFIG_FILE], config_bytes)
        created.append(targets[CONFIG_FILE])
    except Exception:
        for path in created:
            path.unlink(missing_ok=True)
        raise

    return {
        "certificate_sha256": _fingerprint(leaf_certificate),
        "config_path": str(targets[CONFIG_FILE].resolve()),
        "config_sha256": f"sha256:{sha256(config_bytes).hexdigest()}",
        "dns_names": names,
        "gateway_url": gateway_url,
        "not_after": leaf_not_after.isoformat(),
        "signing_key_path": str(targets[KEY_FILE].resolve()),
        "trust_anchor_path": str(targets[TRUST_ANCHOR_FILE].resolve()),
        "trust_anchor_sha256": _fingerprint(root_certificate),
        "verifier_certificate_path": str(targets[CERTIFICATE_FILE].resolve()),
    }


def validate_verifier_environment(key_pem: str, certificate_pem: str) -> dict[str, str]:
    """Validate the exact PEM pair consumed by Marty's HAIP profile."""
    try:
        key = serialization.load_pem_private_key(key_pem.encode("ascii"), password=None)
    except (UnicodeEncodeError, ValueError) as exc:
        raise ValueError("HAIP verifier signing key must be unencrypted PEM") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("HAIP verifier signing key must be an unencrypted P-256 private key")
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
    if public_key.public_numbers() != key.public_key().public_numbers():
        raise ValueError("HAIP verifier certificate does not match its signing key")
    try:
        basic_constraints = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value
        key_usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("HAIP verifier leaf certificate requires BasicConstraints and KeyUsage") from exc
    if basic_constraints.ca or not key_usage.digital_signature:
        raise ValueError("HAIP verifier leaf certificate must be a non-CA digital-signature certificate")
    return {
        "VERIFIER_SIGNING_KEY_PEM": key_pem,
        "VERIFIER_X509_CERT_PEM": certificate_pem,
    }


def load_verifier_environment(material_dir: Path) -> dict[str, str]:
    """Load and validate generated verifier material for Marty's flow service."""
    key_path = material_dir / KEY_FILE
    certificate_path = material_dir / CERTIFICATE_FILE
    try:
        key_pem = key_path.read_text(encoding="ascii")
        certificate_pem = certificate_path.read_text(encoding="ascii")
    except FileNotFoundError as exc:
        raise ValueError(f"HAIP material is incomplete: {exc.filename}") from exc
    return validate_verifier_environment(key_pem, certificate_pem)


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
