#!/usr/bin/env python3
"""Generate or validate TLS and Java stores for disposable EUDI runs.

Generated material is deliberately separate from production and certification
material.  The resulting environment manifest is consumed by the official
suite lifecycle without changing any protocol endpoint or internal service
route.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

SCHEMA = "elevenid.eudi-test-material/v1"
REPORT_SCHEMA = "elevenid.eudi-test-material-report/v1"
TLS_KEY_FILE = "tls.key"
TLS_CERTIFICATE_FILE = "tls.crt"
ROOT_CA_FILE = "root-ca.pem"
TRUSTSTORE_FILE = "truststore.jks"
EUDI_KEYSTORE_FILE = "keystore.jks"
EUDI_CERTIFICATE_FILE = "eudi-verifier-cert.pem"
ENVIRONMENT_FILE = "environment.json"
REPORT_FILE = "report.json"
OUTPUT_FILES = (
    TLS_KEY_FILE,
    TLS_CERTIFICATE_FILE,
    ROOT_CA_FILE,
    TRUSTSTORE_FILE,
    EUDI_KEYSTORE_FILE,
    EUDI_CERTIFICATE_FILE,
    ENVIRONMENT_FILE,
    REPORT_FILE,
)
PEM_CERTIFICATE = re.compile(rb"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----")
DNS_NAME = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$"
)
DEFAULT_HOSTNAME = "marty-oidf.test"
DEFAULT_PORTS = {
    "marty": 8443,
    "wallet_tester": 25051,
    "verifier": 28091,
    "wallet_kit": 29090,
}
DEFAULT_ALIAS = "access_certificate"
TRUSTSTORE_ALIAS = "elevenid-conformance-root"
MAX_VALIDITY_HOURS = 168
MATERIAL_PATH_VARIABLES = ("OIDF_TLS_CERT_DIR", "EUDI_VERIFIER_KEYSTORE_FILE")
REQUIRED_ENVIRONMENT = (
    "OIDF_PUBLIC_BASE_URL",
    "OIDF_TLS_HOST_PORT",
    "OIDF_INTERNAL_TLS_PORT",
    "OIDF_CONFORMANCE_BRIDGE_ALIAS",
    "OIDF_TLS_CERT_DIR",
    "EUDI_WALLET_TESTER_PUBLIC_URL",
    "EUDI_WALLET_TESTER_TLS_HOST_PORT",
    "EUDI_VERIFIER_PUBLIC_URL",
    "EUDI_VERIFIER_TLS_HOST_PORT",
    "EUDI_WALLET_KIT_HOST_PORT",
    "EUDI_WALLET_KIT_URL",
    "EUDI_VERIFIER_KEYSTORE_FILE",
    "EUDI_VERIFIER_KEYSTORE_TYPE",
    "EUDI_VERIFIER_KEYSTORE_PASSWORD",
    "EUDI_VERIFIER_KEYSTORE_ALIAS",
    "EUDI_VERIFIER_KEY_PASSWORD",
    "EUDI_VERIFIER_SIGNING_ALGORITHM",
    "EUDI_VERIFIER_CLIENT_ID_PREFIX",
    "EUDI_VERIFIER_ORIGINAL_CLIENT_ID",
    "EUDI_TLS_TRUSTSTORE_PASSWORD",
    "EUDI_TLS_TRUSTSTORE_ALIAS",
)


def _certificate_not_before(certificate: x509.Certificate) -> datetime:
    value: datetime | None = getattr(certificate, "not_valid_before_utc", None)
    return value if value is not None else certificate.not_valid_before.replace(tzinfo=UTC)


def _certificate_not_after(certificate: x509.Certificate) -> datetime:
    value: datetime | None = getattr(certificate, "not_valid_after_utc", None)
    return value if value is not None else certificate.not_valid_after.replace(tzinfo=UTC)


def _fingerprint(certificate: x509.Certificate) -> str:
    return f"sha256:{certificate.fingerprint(hashes.SHA256()).hex()}"


def _file_sha256(path: Path) -> str:
    return f"sha256:{sha256(path.read_bytes()).hexdigest()}"


def _secret() -> str:
    return secrets.token_urlsafe(32)


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


def _dns_name(value: str, field: str) -> str:
    normalized = value.strip().lower().rstrip(".")
    if not DNS_NAME.fullmatch(normalized):
        raise ValueError(f"{field} must be a valid DNS hostname")
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        return normalized
    raise ValueError(f"{field} must be a DNS hostname, not an IP address")


def _port(value: int, field: str) -> int:
    if not 1 <= value <= 65535:
        raise ValueError(f"{field} must be between 1 and 65535")
    return value


def _https_origin(value: str, field: str) -> tuple[str, str, int]:
    parsed = urlparse(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise ValueError(f"{field} must be an absolute HTTPS origin without credentials, path, query, or fragment")
    hostname = parsed.hostname.lower()
    port = parsed.port or 443
    return f"https://{hostname}:{port}" if port != 443 else f"https://{hostname}", hostname, port


def _http_origin(value: str, field: str) -> tuple[str, str, int]:
    parsed = urlparse(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise ValueError(f"{field} must be an absolute HTTP(S) origin without credentials, path, query, or fragment")
    hostname = parsed.hostname.lower()
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    default_port = 443 if parsed.scheme == "https" else 80
    origin = f"{parsed.scheme}://{hostname}:{port}" if port != default_port else f"{parsed.scheme}://{hostname}"
    return origin, hostname, port


def _parse_certificates(data: bytes, field: str) -> list[x509.Certificate]:
    certificates = [x509.load_pem_x509_certificate(item) for item in PEM_CERTIFICATE.findall(data)]
    if not certificates:
        raise ValueError(f"{field} contains no PEM certificate")
    return certificates


def _signer_verifies(issuer: x509.Certificate, subject: x509.Certificate) -> None:
    public_key = issuer.public_key()
    hash_algorithm = subject.signature_hash_algorithm
    if hash_algorithm is None:
        raise ValueError("certificate chain uses an unsupported signature algorithm")
    parameters = getattr(subject, "signature_algorithm_parameters", None)
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        algorithm = parameters if isinstance(parameters, ec.ECDSA) else ec.ECDSA(hash_algorithm)
        public_key.verify(subject.signature, subject.tbs_certificate_bytes, algorithm)
        return
    if isinstance(public_key, rsa.RSAPublicKey):
        signature_padding = parameters if isinstance(parameters, padding.AsymmetricPadding) else padding.PKCS1v15()
        public_key.verify(
            subject.signature,
            subject.tbs_certificate_bytes,
            signature_padding,
            hash_algorithm,
        )
        return
    raise ValueError("certificate chain uses an unsupported issuer key")


def _require_current(certificate: x509.Certificate, field: str, now: datetime) -> None:
    if not _certificate_not_before(certificate) <= now <= _certificate_not_after(certificate):
        raise ValueError(f"{field} is not currently valid")


def _root_certificate(
    private_key: ec.EllipticCurvePrivateKey,
    now: datetime,
    valid_hours: int,
) -> x509.Certificate:
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ElevenID disposable conformance"),
            x509.NameAttribute(NameOID.COMMON_NAME, "ElevenID EUDI disposable root"),
        ]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=valid_hours + 1))
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
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )


def _leaf_certificate(
    private_key: ec.EllipticCurvePrivateKey,
    root_key: ec.EllipticCurvePrivateKey,
    root: x509.Certificate,
    now: datetime,
    valid_hours: int,
    *,
    common_name: str,
    dns_names: Sequence[str],
    server_auth: bool,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ElevenID disposable conformance"),
                    x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                ]
            )
        )
        .issuer_name(root.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=valid_hours))
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
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in dns_names]),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
    )
    if server_auth:
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    return builder.sign(root_key, hashes.SHA256())


def find_keytool(explicit: Path | None = None) -> Path | None:
    """Locate keytool without relying on a shell-specific executable suffix."""
    if explicit is not None:
        candidate = explicit.resolve()
        return candidate if candidate.is_file() else None
    java_home = os.environ.get("JAVA_HOME", "").strip()
    if java_home:
        for name in ("keytool.exe", "keytool"):
            candidate = Path(java_home) / "bin" / name
            if candidate.is_file():
                return candidate.resolve()
    command = shutil.which("keytool")
    return Path(command).resolve() if command else None


def _run_keytool(
    keytool: Path,
    arguments: Sequence[str],
    passwords: Mapping[str, str],
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.update(passwords)
    completed = subprocess.run(
        [str(keytool), *arguments],
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise ValueError(f"keytool failed: {detail[:500]}")
    return completed


def _expected_curve(signing_algorithm: str) -> type[ec.EllipticCurve]:
    curves: dict[str, type[ec.EllipticCurve]] = {
        "ES256": ec.SECP256R1,
        "ES384": ec.SECP384R1,
        "ES512": ec.SECP521R1,
    }
    try:
        return curves[signing_algorithm]
    except KeyError as exc:
        raise ValueError("EUDI verifier signing algorithm must be ES256, ES384, or ES512") from exc


def _validate_java_stores(
    *,
    keytool: Path,
    keystore: Path,
    keystore_type: str,
    store_password: str,
    key_password: str,
    alias: str,
    truststore: Path,
    truststore_password: str,
    truststore_alias: str,
    expected_root: x509.Certificate,
    signing_algorithm: str,
) -> tuple[x509.Certificate, list[x509.Certificate]]:
    check_password = _secret()
    password_environment = {
        "EUDI_SOURCE_STORE_PASSWORD": store_password,
        "EUDI_SOURCE_KEY_PASSWORD": key_password,
        "EUDI_CHECK_STORE_PASSWORD": check_password,
        "EUDI_TRUSTSTORE_PASSWORD": truststore_password,
    }
    with tempfile.TemporaryDirectory(prefix="elevenid-eudi-store-check-") as temporary:
        temporary_path = Path(temporary)
        exported_store = temporary_path / "entry.p12"
        exported_root = temporary_path / "root.pem"
        _run_keytool(
            keytool,
            [
                "-importkeystore",
                "-noprompt",
                "-srckeystore",
                str(keystore),
                "-srcstoretype",
                keystore_type,
                "-srcstorepass:env",
                "EUDI_SOURCE_STORE_PASSWORD",
                "-srckeypass:env",
                "EUDI_SOURCE_KEY_PASSWORD",
                "-srcalias",
                alias,
                "-destkeystore",
                str(exported_store),
                "-deststoretype",
                "PKCS12",
                "-deststorepass:env",
                "EUDI_CHECK_STORE_PASSWORD",
                "-destkeypass:env",
                "EUDI_CHECK_STORE_PASSWORD",
                "-destalias",
                alias,
            ],
            password_environment,
        )
        private_key, leaf, additional = pkcs12.load_key_and_certificates(
            exported_store.read_bytes(),
            check_password.encode("ascii"),
        )
        if private_key is None or leaf is None:
            raise ValueError("EUDI verifier keystore alias is not a private-key entry")
        expected_curve = _expected_curve(signing_algorithm)
        if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(private_key.curve, expected_curve):
            raise ValueError(f"EUDI verifier keystore key is incompatible with {signing_algorithm}")
        leaf_public_key = leaf.public_key()
        if not isinstance(leaf_public_key, ec.EllipticCurvePublicKey):
            raise ValueError("EUDI verifier keystore certificate does not contain an EC public key")
        if private_key.public_key().public_numbers() != leaf_public_key.public_numbers():
            raise ValueError("EUDI verifier keystore certificate does not match its private key")
        chain = list(additional or [])
        if not chain:
            raise ValueError("EUDI verifier access certificate must have a non-self-signed chain")
        if chain[-1].fingerprint(hashes.SHA256()) != expected_root.fingerprint(hashes.SHA256()):
            raise ValueError("EUDI verifier access-certificate chain does not end at root-ca.pem")
        for subject, issuer in zip([leaf, *chain[:-1]], chain, strict=True):
            if subject.issuer != issuer.subject:
                raise ValueError("EUDI verifier access-certificate chain issuer names do not match")
            _signer_verifies(issuer, subject)
        current = datetime.now(UTC)
        _require_current(leaf, "EUDI verifier access certificate", current)
        for index, certificate in enumerate(chain, start=1):
            _require_current(certificate, f"EUDI verifier access-certificate chain item {index}", current)

        _run_keytool(
            keytool,
            [
                "-exportcert",
                "-rfc",
                "-keystore",
                str(truststore),
                "-storetype",
                "JKS",
                "-storepass:env",
                "EUDI_TRUSTSTORE_PASSWORD",
                "-alias",
                truststore_alias,
                "-file",
                str(exported_root),
            ],
            password_environment,
        )
        actual_root = x509.load_pem_x509_certificate(exported_root.read_bytes())
        if actual_root.fingerprint(hashes.SHA256()) != expected_root.fingerprint(hashes.SHA256()):
            raise ValueError("Java truststore root does not match root-ca.pem")
        return leaf, chain


def _build_java_stores(
    *,
    keytool: Path,
    output_dir: Path,
    private_key: ec.EllipticCurvePrivateKey,
    certificate: x509.Certificate,
    root: x509.Certificate,
    store_password: str,
    key_password: str,
    alias: str,
    truststore_password: str,
    truststore_alias: str,
) -> None:
    source_password = _secret()
    keystore = output_dir / EUDI_KEYSTORE_FILE
    truststore = output_dir / TRUSTSTORE_FILE
    password_environment = {
        "EUDI_SOURCE_STORE_PASSWORD": source_password,
        "EUDI_DESTINATION_STORE_PASSWORD": store_password,
        "EUDI_DESTINATION_KEY_PASSWORD": key_password,
        "EUDI_TRUSTSTORE_PASSWORD": truststore_password,
    }
    with tempfile.TemporaryDirectory(prefix=".eudi-store-", dir=output_dir) as temporary:
        source = Path(temporary) / "access.p12"
        source.write_bytes(
            pkcs12.serialize_key_and_certificates(
                alias.encode("ascii"),
                private_key,
                certificate,
                [root],
                serialization.BestAvailableEncryption(source_password.encode("ascii")),
            )
        )
        source.chmod(stat.S_IRUSR | stat.S_IWUSR)
        _run_keytool(
            keytool,
            [
                "-importkeystore",
                "-noprompt",
                "-srckeystore",
                str(source),
                "-srcstoretype",
                "PKCS12",
                "-srcstorepass:env",
                "EUDI_SOURCE_STORE_PASSWORD",
                "-srcalias",
                alias,
                "-destkeystore",
                str(keystore),
                "-deststoretype",
                "JKS",
                "-deststorepass:env",
                "EUDI_DESTINATION_STORE_PASSWORD",
                "-destkeypass:env",
                "EUDI_DESTINATION_KEY_PASSWORD",
                "-destalias",
                alias,
            ],
            password_environment,
        )
        _run_keytool(
            keytool,
            [
                "-importcert",
                "-noprompt",
                "-trustcacerts",
                "-alias",
                truststore_alias,
                "-file",
                str(output_dir / ROOT_CA_FILE),
                "-keystore",
                str(truststore),
                "-storetype",
                "JKS",
                "-storepass:env",
                "EUDI_TRUSTSTORE_PASSWORD",
            ],
            password_environment,
        )
    keystore.chmod(stat.S_IRUSR | stat.S_IWUSR)
    truststore.chmod(stat.S_IRUSR | stat.S_IWUSR)
    _validate_java_stores(
        keytool=keytool,
        keystore=keystore,
        keystore_type="JKS",
        store_password=store_password,
        key_password=key_password,
        alias=alias,
        truststore=truststore,
        truststore_password=truststore_password,
        truststore_alias=truststore_alias,
        expected_root=root,
        signing_algorithm="ES512",
    )


def _environment(
    output_dir: Path,
    *,
    hostname: str,
    marty_port: int,
    wallet_tester_port: int,
    verifier_port: int,
    wallet_kit_port: int,
    store_password: str,
    key_password: str,
    truststore_password: str,
    alias: str,
) -> dict[str, str]:
    marty_origin = f"https://{hostname}:{marty_port}"
    wallet_tester_origin = f"https://{hostname}:{wallet_tester_port}"
    verifier_origin = f"https://{hostname}:{verifier_port}"
    root = output_dir / ROOT_CA_FILE
    return {
        "EUDI_TEST_MATERIAL_MODE": "generated",
        "EUDI_TEST_CA_FILE": str(root),
        "SSL_CERT_FILE": str(root),
        "OIDF_PUBLIC_BASE_URL": marty_origin,
        "OIDF_TLS_HOST_PORT": str(marty_port),
        "OIDF_INTERNAL_TLS_PORT": str(marty_port),
        "OIDF_CONFORMANCE_BRIDGE_ALIAS": hostname,
        "OIDF_TLS_CERT_DIR": str(output_dir),
        "OIDF_MARTY_RESOLVE_IP": "127.0.0.1",
        "EUDI_WALLET_TESTER_PUBLIC_URL": wallet_tester_origin,
        "EUDI_WALLET_TESTER_TLS_HOST_PORT": str(wallet_tester_port),
        "EUDI_VERIFIER_PUBLIC_URL": verifier_origin,
        "EUDI_VERIFIER_TLS_HOST_PORT": str(verifier_port),
        "EUDI_WALLET_KIT_HOST_PORT": str(wallet_kit_port),
        "EUDI_WALLET_KIT_URL": f"http://127.0.0.1:{wallet_kit_port}",
        "EUDI_VERIFIER_KEYSTORE_FILE": str(output_dir / EUDI_KEYSTORE_FILE),
        "EUDI_VERIFIER_KEYSTORE_TYPE": "JKS",
        "EUDI_VERIFIER_KEYSTORE_PASSWORD": store_password,
        "EUDI_VERIFIER_KEYSTORE_ALIAS": alias,
        "EUDI_VERIFIER_KEY_PASSWORD": key_password,
        "EUDI_VERIFIER_SIGNING_ALGORITHM": "ES512",
        "EUDI_VERIFIER_CLIENT_ID_PREFIX": "x509_san_dns",
        "EUDI_VERIFIER_ORIGINAL_CLIENT_ID": hostname,
        "EUDI_TLS_TRUSTSTORE_PASSWORD": truststore_password,
        "EUDI_TLS_TRUSTSTORE_ALIAS": TRUSTSTORE_ALIAS,
    }


def generate_material(
    output_dir: Path,
    *,
    hostname: str = DEFAULT_HOSTNAME,
    marty_port: int = DEFAULT_PORTS["marty"],
    wallet_tester_port: int = DEFAULT_PORTS["wallet_tester"],
    verifier_port: int = DEFAULT_PORTS["verifier"],
    wallet_kit_port: int = DEFAULT_PORTS["wallet_kit"],
    valid_hours: int = 24,
    keytool: Path | None = None,
    now: datetime | None = None,
    java_store_builder: Callable[..., None] = _build_java_stores,
) -> dict[str, Any]:
    """Generate local material without persisting the root private key."""
    hostname = _dns_name(hostname, "hostname")
    ports = {
        "marty": _port(marty_port, "Marty port"),
        "wallet_tester": _port(wallet_tester_port, "wallet tester port"),
        "verifier": _port(verifier_port, "verifier port"),
        "wallet_kit": _port(wallet_kit_port, "wallet kit port"),
    }
    if len(set(ports.values())) != len(ports):
        raise ValueError("generated service ports must be distinct")
    if not 1 <= valid_hours <= MAX_VALIDITY_HOURS:
        raise ValueError(f"validity must be between 1 and {MAX_VALIDITY_HOURS} hours")
    selected_keytool = find_keytool(keytool)
    if selected_keytool is None:
        raise ValueError("keytool is required; install a JDK 17 or newer and set JAVA_HOME")

    output_dir = output_dir.resolve()
    targets = [output_dir / name for name in OUTPUT_FILES]
    existing = list(output_dir.iterdir()) if output_dir.is_dir() else [path for path in targets if path.exists()]
    if existing:
        raise FileExistsError("refusing to overwrite EUDI material: " + ", ".join(map(str, existing)))
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    current = current.astimezone(UTC)
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = _root_certificate(root_key, current, valid_hours)
    tls_key = ec.generate_private_key(ec.SECP256R1())
    tls_certificate = _leaf_certificate(
        tls_key,
        root_key,
        root,
        current,
        valid_hours,
        common_name=hostname,
        dns_names=[hostname],
        server_auth=True,
    )
    eudi_key = ec.generate_private_key(ec.SECP521R1())
    eudi_certificate = _leaf_certificate(
        eudi_key,
        root_key,
        root,
        current,
        valid_hours,
        common_name=hostname,
        dns_names=[hostname],
        server_auth=False,
    )
    store_password = _secret()
    key_password = _secret()
    truststore_password = _secret()
    environment = _environment(
        output_dir,
        hostname=hostname,
        marty_port=ports["marty"],
        wallet_tester_port=ports["wallet_tester"],
        verifier_port=ports["verifier"],
        wallet_kit_port=ports["wallet_kit"],
        store_password=store_password,
        key_password=key_password,
        truststore_password=truststore_password,
        alias=DEFAULT_ALIAS,
    )
    try:
        _write_private(
            output_dir / TLS_KEY_FILE,
            tls_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        _write_public(
            output_dir / TLS_CERTIFICATE_FILE,
            tls_certificate.public_bytes(serialization.Encoding.PEM) + root.public_bytes(serialization.Encoding.PEM),
        )
        _write_public(output_dir / ROOT_CA_FILE, root.public_bytes(serialization.Encoding.PEM))
        _write_public(
            output_dir / EUDI_CERTIFICATE_FILE,
            eudi_certificate.public_bytes(serialization.Encoding.PEM) + root.public_bytes(serialization.Encoding.PEM),
        )
        java_store_builder(
            keytool=selected_keytool,
            output_dir=output_dir,
            private_key=eudi_key,
            certificate=eudi_certificate,
            root=root,
            store_password=store_password,
            key_password=key_password,
            alias=DEFAULT_ALIAS,
            truststore_password=truststore_password,
            truststore_alias=TRUSTSTORE_ALIAS,
        )
        environment_document = {"schema": SCHEMA, "mode": "generated", "environment": environment}
        _write_private(
            output_dir / ENVIRONMENT_FILE,
            (json.dumps(environment_document, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )
        report = {
            "schema": REPORT_SCHEMA,
            "mode": "generated",
            "hostname": hostname,
            "urls": {
                "gateway": environment["OIDF_PUBLIC_BASE_URL"],
                "wallet_tester": environment["EUDI_WALLET_TESTER_PUBLIC_URL"],
                "verifier": environment["EUDI_VERIFIER_PUBLIC_URL"],
                "wallet_kit": environment["EUDI_WALLET_KIT_URL"],
            },
            "not_after": _certificate_not_after(tls_certificate).isoformat(),
            "tls_certificate_sha256": _fingerprint(tls_certificate),
            "root_ca_sha256": _fingerprint(root),
            "eudi_access_certificate_sha256": _fingerprint(eudi_certificate),
            "files": {
                name: _file_sha256(output_dir / name)
                for name in (
                    TLS_CERTIFICATE_FILE,
                    ROOT_CA_FILE,
                    TRUSTSTORE_FILE,
                    EUDI_KEYSTORE_FILE,
                    EUDI_CERTIFICATE_FILE,
                )
            },
        }
        _write_public(output_dir / REPORT_FILE, (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        return report
    except Exception:
        for path in reversed(targets):
            path.unlink(missing_ok=True)
        raise


def load_environment_manifest(material_dir: Path) -> tuple[str, dict[str, str]]:
    path = material_dir.resolve() / ENVIRONMENT_FILE
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"EUDI material manifest is missing: {path}") from exc
    if not isinstance(document, dict):
        raise ValueError("EUDI material manifest must be a JSON object")
    if document.get("schema") != SCHEMA or document.get("mode") not in {"generated", "external"}:
        raise ValueError("unsupported EUDI material manifest")
    values = document.get("environment")
    if not isinstance(values, dict) or any(
        not isinstance(key, str) or not isinstance(value, str) for key, value in values.items()
    ):
        raise ValueError("EUDI material environment must contain string keys and values")
    return str(document["mode"]), dict(values)


def merged_material_environment(material_dir: Path, external: Mapping[str, str]) -> tuple[str, dict[str, str]]:
    """Load generated values unless a complete external material pair is present."""
    present_paths = [name for name in MATERIAL_PATH_VARIABLES if external.get(name, "").strip()]
    if present_paths and len(present_paths) != len(MATERIAL_PATH_VARIABLES):
        raise ValueError("set both external OIDF_TLS_CERT_DIR and EUDI_VERIFIER_KEYSTORE_FILE, or neither")
    declared_mode = external.get("EUDI_TEST_MATERIAL_MODE", "").strip()
    if declared_mode not in {"", "generated", "external"}:
        raise ValueError("EUDI_TEST_MATERIAL_MODE must be generated or external")
    # A workflow may already have exported the generated manifest. Keep its
    # generated identity so remote-daemon safety cannot be bypassed merely by
    # exporting both generated paths.
    if len(present_paths) == len(MATERIAL_PATH_VARIABLES) and declared_mode != "generated":
        environment = dict(external)
        environment["EUDI_TEST_MATERIAL_MODE"] = "external"
        return "external", environment
    mode, generated = load_environment_manifest(material_dir)
    # Preserve process essentials such as PATH and Docker configuration, but
    # make every generated contract value authoritative. Stale ambient
    # passwords, aliases, URLs, and trust roots must not corrupt a fresh run.
    environment = dict(external)
    environment.update(generated)
    environment["EUDI_TEST_MATERIAL_MODE"] = mode
    return mode, environment


def validate_environment_contract(environment: Mapping[str, str]) -> dict[str, Any]:
    """Validate URL, port, identity, and store metadata without reading files."""
    missing = [name for name in REQUIRED_ENVIRONMENT if not environment.get(name, "").strip()]
    if missing:
        raise ValueError("missing EUDI material environment: " + ", ".join(missing))
    gateway, gateway_host, gateway_port = _https_origin(environment["OIDF_PUBLIC_BASE_URL"], "OIDF_PUBLIC_BASE_URL")
    wallet_tester, wallet_host, wallet_port = _https_origin(
        environment["EUDI_WALLET_TESTER_PUBLIC_URL"],
        "EUDI_WALLET_TESTER_PUBLIC_URL",
    )
    verifier, verifier_host, verifier_port = _https_origin(
        environment["EUDI_VERIFIER_PUBLIC_URL"],
        "EUDI_VERIFIER_PUBLIC_URL",
    )
    wallet_kit, _wallet_kit_host, wallet_kit_url_port = _http_origin(
        environment["EUDI_WALLET_KIT_URL"],
        "EUDI_WALLET_KIT_URL",
    )
    alias_host = _dns_name(environment["OIDF_CONFORMANCE_BRIDGE_ALIAS"], "OIDF_CONFORMANCE_BRIDGE_ALIAS")
    if alias_host != gateway_host:
        raise ValueError("OIDF_CONFORMANCE_BRIDGE_ALIAS must equal the OIDF public hostname")
    expected_ports = {
        "OIDF_TLS_HOST_PORT": gateway_port,
        "OIDF_INTERNAL_TLS_PORT": gateway_port,
        "EUDI_WALLET_TESTER_TLS_HOST_PORT": wallet_port,
        "EUDI_VERIFIER_TLS_HOST_PORT": verifier_port,
    }
    for name, expected in expected_ports.items():
        try:
            actual = int(environment[name])
        except ValueError as exc:
            raise ValueError(f"{name} must be an integer") from exc
        if actual != expected:
            raise ValueError(f"{name} must equal the port in its public URL")
    try:
        wallet_kit_port = _port(int(environment["EUDI_WALLET_KIT_HOST_PORT"]), "wallet kit port")
    except ValueError as exc:
        raise ValueError("EUDI_WALLET_KIT_HOST_PORT must be an integer between 1 and 65535") from exc
    if wallet_kit_port != wallet_kit_url_port:
        raise ValueError("EUDI_WALLET_KIT_HOST_PORT must equal the port in EUDI_WALLET_KIT_URL")
    published_ports = [gateway_port, wallet_port, verifier_port, wallet_kit_port]
    if len(published_ports) != len(set(published_ports)):
        raise ValueError("EUDI and Marty published ports must be distinct")
    _expected_curve(environment["EUDI_VERIFIER_SIGNING_ALGORITHM"])
    if environment["EUDI_VERIFIER_CLIENT_ID_PREFIX"] not in {"pre-registered", "x509_san_dns", "x509_hash"}:
        raise ValueError("EUDI verifier client ID prefix is unsupported")
    return {
        "gateway": gateway,
        "gateway_host": gateway_host,
        "gateway_port": gateway_port,
        "wallet_tester": wallet_tester,
        "wallet_host": wallet_host,
        "wallet_port": wallet_port,
        "verifier": verifier,
        "verifier_host": verifier_host,
        "verifier_port": verifier_port,
        "wallet_kit_port": wallet_kit_port,
        "wallet_kit": wallet_kit,
    }


def validate_environment(
    environment: Mapping[str, str],
    *,
    keytool: Path | None = None,
    validate_java: bool = True,
) -> dict[str, Any]:
    contract = validate_environment_contract(environment)
    gateway = contract["gateway"]
    gateway_host = contract["gateway_host"]
    wallet_tester = contract["wallet_tester"]
    wallet_host = contract["wallet_host"]
    verifier = contract["verifier"]
    verifier_host = contract["verifier_host"]

    certificate_dir = Path(environment["OIDF_TLS_CERT_DIR"]).resolve()
    key_path = certificate_dir / TLS_KEY_FILE
    certificate_path = certificate_dir / TLS_CERTIFICATE_FILE
    root_path = certificate_dir / ROOT_CA_FILE
    truststore_path = certificate_dir / TRUSTSTORE_FILE
    keystore_path = Path(environment["EUDI_VERIFIER_KEYSTORE_FILE"]).resolve()
    generated_access_path = certificate_dir / EUDI_CERTIFICATE_FILE
    paths = [key_path, certificate_path, root_path, truststore_path, keystore_path]
    if environment.get("EUDI_TEST_MATERIAL_MODE") == "generated":
        paths.append(generated_access_path)
    for path in paths:
        if not path.is_file():
            raise ValueError(f"required EUDI material file is missing: {path}")

    private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    certificates = _parse_certificates(certificate_path.read_bytes(), TLS_CERTIFICATE_FILE)
    leaf = certificates[0]
    if private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ) != leaf.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ):
        raise ValueError("TLS certificate does not match tls.key")
    now = datetime.now(UTC)
    _require_current(leaf, "TLS certificate", now)
    try:
        usage = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("TLS certificate requires serverAuth and subjectAltName extensions") from exc
    if ExtendedKeyUsageOID.SERVER_AUTH not in usage:
        raise ValueError("TLS certificate is not valid for server authentication")
    dns_names = set(san.get_values_for_type(x509.DNSName))
    required_names = {gateway_host, wallet_host, verifier_host}
    if not required_names <= dns_names:
        raise ValueError("TLS certificate SAN does not cover every public HTTPS hostname")
    root = x509.load_pem_x509_certificate(root_path.read_bytes())
    if len(certificates) < 2 or certificates[-1].fingerprint(hashes.SHA256()) != root.fingerprint(hashes.SHA256()):
        raise ValueError("tls.crt must contain a leaf-first chain ending at root-ca.pem")
    try:
        root_constraints = root.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("root-ca.pem requires a CA BasicConstraints extension") from exc
    if not root_constraints.ca:
        raise ValueError("root-ca.pem is not a CA certificate")
    for index, certificate in enumerate(certificates[1:], start=1):
        _require_current(certificate, f"TLS certificate chain item {index}", now)
        try:
            constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound as exc:
            raise ValueError("every TLS issuer certificate requires a CA BasicConstraints extension") from exc
        if not constraints.ca:
            raise ValueError("TLS certificate chain contains a non-CA issuer")
    for subject, issuer in zip(certificates, certificates[1:], strict=False):
        if subject.issuer != issuer.subject:
            raise ValueError("TLS certificate chain issuer names do not match")
        _signer_verifies(issuer, subject)

    eudi_leaf: x509.Certificate | None = None
    generated_access_leaf: x509.Certificate | None = None
    if environment.get("EUDI_TEST_MATERIAL_MODE") == "generated":
        access_certificates = _parse_certificates(generated_access_path.read_bytes(), EUDI_CERTIFICATE_FILE)
        generated_access_leaf = access_certificates[0]
        if len(access_certificates) < 2 or access_certificates[-1].fingerprint(hashes.SHA256()) != root.fingerprint(
            hashes.SHA256()
        ):
            raise ValueError("eudi-verifier-cert.pem must contain a leaf-first chain ending at root-ca.pem")
        _require_current(generated_access_leaf, "EUDI verifier access certificate", now)
        for subject, issuer in zip(access_certificates, access_certificates[1:], strict=False):
            if subject.issuer != issuer.subject:
                raise ValueError("EUDI verifier access-certificate chain issuer names do not match")
            _signer_verifies(issuer, subject)
    if validate_java:
        selected_keytool = find_keytool(keytool)
        if selected_keytool is None:
            raise ValueError("keytool is required to validate EUDI Java stores")
        eudi_leaf, _chain = _validate_java_stores(
            keytool=selected_keytool,
            keystore=keystore_path,
            keystore_type=environment["EUDI_VERIFIER_KEYSTORE_TYPE"],
            store_password=environment["EUDI_VERIFIER_KEYSTORE_PASSWORD"],
            key_password=environment["EUDI_VERIFIER_KEY_PASSWORD"],
            alias=environment["EUDI_VERIFIER_KEYSTORE_ALIAS"],
            truststore=truststore_path,
            truststore_password=environment["EUDI_TLS_TRUSTSTORE_PASSWORD"],
            truststore_alias=environment["EUDI_TLS_TRUSTSTORE_ALIAS"],
            expected_root=root,
            signing_algorithm=environment["EUDI_VERIFIER_SIGNING_ALGORITHM"],
        )
        if eudi_leaf.issuer == eudi_leaf.subject:
            raise ValueError("EUDI verifier access certificate cannot be self-signed")
        if generated_access_leaf is not None and eudi_leaf.fingerprint(
            hashes.SHA256()
        ) != generated_access_leaf.fingerprint(hashes.SHA256()):
            raise ValueError("EUDI verifier keystore certificate does not match eudi-verifier-cert.pem")
        try:
            eudi_san = eudi_leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        except x509.ExtensionNotFound as exc:
            raise ValueError("EUDI verifier access certificate requires a subjectAltName extension") from exc
        if environment.get("EUDI_VERIFIER_CLIENT_ID_PREFIX") == "x509_san_dns" and (
            environment.get("EUDI_VERIFIER_ORIGINAL_CLIENT_ID") not in eudi_san.get_values_for_type(x509.DNSName)
        ):
            raise ValueError("EUDI verifier original client ID is absent from its access certificate SAN")

    return {
        "schema": REPORT_SCHEMA,
        "mode": environment.get("EUDI_TEST_MATERIAL_MODE", "external"),
        "urls": {
            "gateway": gateway,
            "wallet_tester": wallet_tester,
            "verifier": verifier,
            "wallet_kit": environment.get("EUDI_WALLET_KIT_URL", ""),
        },
        "tls_certificate_sha256": _fingerprint(leaf),
        "root_ca_sha256": _fingerprint(root),
        "eudi_access_certificate_sha256": (
            _fingerprint(eudi_leaf or generated_access_leaf) if (eudi_leaf or generated_access_leaf) else "not-checked"
        ),
        "not_after": _certificate_not_after(leaf).isoformat(),
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="command", required=True)
    generate = subparsers.add_parser("generate")
    generate.add_argument("--output", "--output-dir", dest="output_dir", type=Path, required=True)
    generate.add_argument("--hostname", default=DEFAULT_HOSTNAME)
    generate.add_argument("--marty-port", type=int, default=DEFAULT_PORTS["marty"])
    generate.add_argument("--wallet-tester-port", type=int, default=DEFAULT_PORTS["wallet_tester"])
    generate.add_argument("--verifier-port", type=int, default=DEFAULT_PORTS["verifier"])
    generate.add_argument("--wallet-kit-port", type=int, default=DEFAULT_PORTS["wallet_kit"])
    generate.add_argument("--valid-hours", type=int, default=24)
    generate.add_argument("--keytool", type=Path)
    validate = subparsers.add_parser("validate")
    validate.add_argument(
        "--material",
        "--material-dir",
        dest="material_dir",
        type=Path,
        help="generated material directory; otherwise read environment",
    )
    validate.add_argument("--keytool", type=Path)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "generate":
        report = generate_material(
            args.output_dir,
            hostname=args.hostname,
            marty_port=args.marty_port,
            wallet_tester_port=args.wallet_tester_port,
            verifier_port=args.verifier_port,
            wallet_kit_port=args.wallet_kit_port,
            valid_hours=args.valid_hours,
            keytool=args.keytool,
        )
    else:
        environment: Mapping[str, str]
        if args.material_dir:
            _mode, environment = load_environment_manifest(args.material_dir)
        else:
            environment = os.environ
        report = validate_environment(environment, keytool=args.keytool)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        print(f"EUDI material error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
