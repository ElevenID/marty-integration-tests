"""Explicit isolated reference-verifier registration, never a national registration.

The registrar has its own internal PKI and non-exportable Transit signing key.
Only the public registration record/certificates/JWT leave OpenBao. Consumers
must validate this trusted bootstrap record, rather than trust embedded x5c.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

MAX_LIFETIME = 8 * 3600
REGISTRATION_FILE = "eudi-registration.json"
REGISTRATION_ENV = "EUDI_VERIFIER_REGISTRATION_RECORD_FILE"


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def transit_jws_signature(value: object) -> bytes:
    """OpenBao JWS mode returns unpadded URL-safe Base64 after its version prefix."""
    if not isinstance(value, str) or not re.fullmatch(r"vault:v1:[A-Za-z0-9_-]{86}", value):
        raise ValueError("registration fixture Transit JWS encoding is invalid")
    encoded = value.removeprefix("vault:v1:")
    signature = base64.urlsafe_b64decode(encoded + "==")
    if len(signature) != 64 or b64url(signature) != encoded:
        raise ValueError("registration fixture Transit JWS encoding is not canonical")
    return signature


def record_for(run_id: str, verifier_origin: str) -> dict[str, Any]:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", run_id):
        raise ValueError("registration fixture run id is invalid")
    parsed = urlsplit(verifier_origin)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
        or not re.fullmatch(r"[a-z0-9.-]+", parsed.hostname)
        or not 1 <= (parsed.port or 443) <= 65535
    ):
        raise ValueError("registration fixture verifier origin is invalid")
    # This immutable synthetic test purpose authorizes exact query attributes,
    # not issuers, wallet trust, production access or arbitrary over-asking.
    return {
        "schema": "elevenid.isolated-eudi-registration/v1",
        "scope": "ISOLATED_REFERENCE_FIXTURE_ONLY_NOT_NATIONAL_REGISTRATION",
        "registrar": f"urn:elevenid:fixture:{run_id}:registrar",
        "subject": f"urn:elevenid:fixture:{run_id}:reference-verifier",
        "verifier_origin": verifier_origin,
        "client_id": f"x509_san_dns:{parsed.hostname}",
        "intended_use_id": "1",
        "purpose": [{"lang": "en", "value": "Isolated interoperability using synthetic credentials only"}],
        "credentials": [
            {
                "format": "mso_mdoc",
                "meta": {"doctype_value": "eu.europa.ec.eudi.pid.1"},
                "claim": [
                    {"path": ["eu.europa.ec.eudi.pid.1", field]}
                    for field in ["family_name", "given_name", "age_over_18"]
                ],
            },
            {
                "format": "mso_mdoc",
                "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
                "claim": [
                    {"path": ["org.iso.18013.5.1", field]} for field in ["family_name", "given_name", "birth_date"]
                ],
            },
            {
                "format": "dc+sd-jwt",
                "meta": {
                    "vct_values": [
                        "https://marty.example/credentials/open_badge",
                        "https://beta.elevenidllc.com/credentials/open_badge",
                        "urn:credential:open_badge",
                    ]
                },
                "claim": [{"path": ["given_name"]}, {"path": ["family_name"]}],
            },
        ],
    }


def validate_bundle(bundle: dict[str, Any], run_id: str, verifier_origin: str, now: datetime | None = None) -> str:
    """Authenticate a locally governed bootstrap bundle, not remote x5c claims."""
    now = now or datetime.now(UTC)
    if set(bundle) != {"registration_record", "registration_jwt", "registrar_root_certificate"}:
        raise ValueError("registration fixture bundle shape is invalid")
    record = record_for(run_id, verifier_origin)
    if bundle.get("registration_record") != record:
        raise ValueError("registration fixture record binding is invalid")
    token = bundle.get("registration_jwt")
    if not isinstance(token, str) or len(token) > 131072:
        raise ValueError("registration fixture JWT is invalid")
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("registration fixture JWT is invalid")

    def decode(value: str) -> bytes:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("registration fixture JWT contains duplicate members")
            result[key] = value
        return result

    header, claims = (json.loads(decode(value), object_pairs_hook=unique_object) for value in parts[:2])
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise ValueError("registration fixture JWT objects are invalid")
    if header.get("typ") != "rc-wrp+jwt" or header.get("alg") != "ES256" or set(header) != {"typ", "alg", "x5c"}:
        raise ValueError("registration fixture JWT header is invalid")
    chain = header.get("x5c")
    if not isinstance(chain, list) or len(chain) != 2:
        raise ValueError("registration fixture certificate chain is invalid")
    leaf, root = [x509.load_der_x509_certificate(base64.b64decode(value, validate=True)) for value in chain]
    trusted_root = x509.load_pem_x509_certificate(bundle["registrar_root_certificate"].encode("ascii"))
    if root.public_bytes(serialization.Encoding.DER) != trusted_root.public_bytes(serialization.Encoding.DER):
        raise ValueError("registration fixture registrar root differs from the governed bundle")
    root.verify_directly_issued_by(root)
    leaf.verify_directly_issued_by(root)
    if (
        not root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        or leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    ):
        raise ValueError("registration fixture certificate roles are invalid")
    usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    if (
        not usage.digital_signature
        or usage.key_cert_sign
        or leaf.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value != "registrar.fixture.invalid"
    ):
        raise ValueError("registration fixture signer role is invalid")
    public = leaf.public_key()
    if not isinstance(public, ec.EllipticCurvePublicKey) or not isinstance(public.curve, ec.SECP256R1):
        raise ValueError("registration fixture signer is not P-256")
    signature = decode(parts[2])
    if len(signature) != 64:
        raise ValueError("registration fixture signature has invalid length")
    public.verify(
        encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")),
        f"{parts[0]}.{parts[1]}".encode("ascii"),
        ec.ECDSA(hashes.SHA256()),
    )
    expected = {
        "iss": record["registrar"],
        "sub": record["subject"],
        "name": "Isolated reference-verifier fixture (not a national registration)",
        "intended_use_id": "1",
        "purpose": record["purpose"],
        "credentials": record["credentials"],
        "verifier_client_id": record["client_id"],
        "verifier_origin": verifier_origin,
        "fixture_record_sha256": hashlib.sha256(canonical(record)).hexdigest(),
        "fixture_only": True,
    }
    if any(claims.get(name) != value for name, value in expected.items()) or set(claims) != {*expected, "iat", "exp"}:
        raise ValueError("registration fixture claims differ from the governed record")
    iat, exp = claims.get("iat"), claims.get("exp")
    if (
        type(iat) is not int
        or type(exp) is not int
        or not iat <= int(now.timestamp()) < exp
        or not 0 < exp - iat <= MAX_LIFETIME
    ):
        raise ValueError("registration fixture JWT validity is invalid")
    for certificate in (leaf, root):
        if (
            certificate.not_valid_before_utc.timestamp() > iat
            or certificate.not_valid_after_utc.timestamp() < exp
            or not certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc
        ):
            raise ValueError("registration fixture certificate validity is invalid")
    return token


def provision(
    bao: Any, run_id: str, verifier_origin: str, *, provision_key: Any, scoped_signer: Any, authority: str
) -> dict[str, Any]:
    """Called only in the newly admitted disposable bootstrap, before root retirement."""
    record = record_for(run_id, verifier_origin)
    mount = f"fixture-registration-{secrets.token_hex(8)}"
    name = f"fixture-registration-{secrets.token_hex(8)}"
    public_pem = provision_key(bao, name, "isolated registration")
    public_key = serialization.load_pem_public_key(public_pem.encode("ascii"))
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP256R1):
        raise ValueError("registration fixture remote key is not P-256")
    csr_pem = bao.request("POST", f"transit/keys/{name}/csr", {"version": 1})["data"]["csr"]
    csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))

    def encoding(key: ec.EllipticCurvePublicKey) -> bytes:
        return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    csr_key = csr.public_key()
    if (
        not csr.is_signature_valid
        or not isinstance(csr_key, ec.EllipticCurvePublicKey)
        or encoding(csr_key) != encoding(public_key)
    ):
        raise ValueError("registration fixture CSR does not match the remote key")
    bao.request("POST", f"sys/mounts/{mount}", {"type": "pki"})
    generated = bao.request(
        "POST",
        f"{mount}/root/generate/internal",
        {
            "common_name": "Isolated interoperability registrar - not a national authority",
            "ttl": "8h",
            "key_type": "ec",
            "key_bits": 256,
        },
    )["data"]
    if "private_key" in generated:
        raise ValueError("registration fixture root key was exported")
    root_pem = generated["certificate"]
    bao.request(
        "POST",
        f"{mount}/roles/registration",
        {
            "allowed_domains": ["registrar.fixture.invalid"],
            "allow_bare_domains": True,
            "allow_subdomains": False,
            "server_flag": False,
            "client_flag": False,
            "key_type": "ec",
            "key_bits": 256,
            "max_ttl": "8h",
            "key_usage": ["DigitalSignature"],
            "basic_constraints_valid_for_non_ca": True,
            "use_csr_common_name": False,
            "use_csr_sans": False,
        },
    )
    applied_role = bao.request("GET", f"{mount}/roles/registration").get("data", {})
    if applied_role.get("basic_constraints_valid_for_non_ca") is not True:
        raise ValueError("registration fixture explicit end-entity certificate role was not applied")
    issued = bao.request(
        "POST",
        f"{mount}/sign/registration",
        {
            "csr": csr_pem,
            "common_name": "registrar.fixture.invalid",
            "ttl": "7h50m",
        },
    )["data"]
    if "private_key" in issued:
        raise ValueError("registration fixture signer key was exported")
    leaf = x509.load_pem_x509_certificate(issued["certificate"].encode("ascii"))
    root = x509.load_pem_x509_certificate(root_pem.encode("ascii"))
    leaf_key = leaf.public_key()
    if not isinstance(leaf_key, ec.EllipticCurvePublicKey) or encoding(leaf_key) != encoding(public_key):
        raise ValueError("registration fixture certificate does not match remote custody")
    now = int(datetime.now(UTC).timestamp())
    claims = {
        "iss": record["registrar"],
        "sub": record["subject"],
        "iat": now,
        "exp": min(
            now + MAX_LIFETIME, int(leaf.not_valid_after_utc.timestamp()), int(root.not_valid_after_utc.timestamp())
        ),
        "name": "Isolated reference-verifier fixture (not a national registration)",
        "intended_use_id": "1",
        "purpose": record["purpose"],
        "credentials": record["credentials"],
        "verifier_client_id": record["client_id"],
        "verifier_origin": verifier_origin,
        "fixture_record_sha256": hashlib.sha256(canonical(record)).hexdigest(),
        "fixture_only": True,
    }
    header = {
        "typ": "rc-wrp+jwt",
        "alg": "ES256",
        "x5c": [
            base64.b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode("ascii")
            for certificate in (leaf, root)
        ],
    }
    signing_input = f"{b64url(canonical(header))}.{b64url(canonical(claims))}"
    token = scoped_signer(
        bao, name, f"fixture-registration-{secrets.token_hex(8)}", authority, b"isolated-registrar-custody-proof"
    )
    signed = bao.request(
        "POST",
        f"transit/sign/{name}",
        {
            "key_version": 1,
            "input": base64.b64encode(signing_input.encode("ascii")).decode("ascii"),
            "hash_algorithm": "sha2-256",
            "marshaling_algorithm": "jws",
            "prehashed": False,
        },
        token=token,
    )["data"]["signature"]
    signature = transit_jws_signature(signed)
    bundle = {
        "registration_record": record,
        "registrar_root_certificate": root_pem,
        "registration_jwt": f"{signing_input}.{b64url(signature)}",
    }
    validate_bundle(bundle, run_id, verifier_origin)
    return bundle


def load_bootstrap_configuration(
    path: Path, digest: str, run_id: str, verifier_origin: str, *, client_id_prefix: str, original_client_id: str
) -> str:
    """Load only the exact public bytes pinned by our private bootstrap env.

    All fixture writers belong to the controller until teardown. The bundle's
    embedded CA is not an external trust source; this provenance gate is required.
    """
    hostname = urlsplit(verifier_origin).hostname
    if client_id_prefix != "x509_san_dns" or original_client_id != hostname:
        raise ValueError("registration fixture client identity differs from the running verifier")
    if os.name != "posix" or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("registration fixture provenance is unavailable")
    parent = path.parent.lstat()
    if (
        not path.is_absolute()
        or path.name != REGISTRATION_FILE
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        raise ValueError("registration fixture directory custody is invalid")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or not 0 < before.st_size <= 262144
            or stat.S_IMODE(before.st_mode) not in {0o600, 0o444}
        ):
            raise ValueError("registration fixture file custody is invalid")
        content = os.read(descriptor, 262145)
        if len(content) != before.st_size or os.read(descriptor, 1):
            raise ValueError("registration fixture read was incomplete")
        if hashlib.sha256(content).hexdigest() != digest:
            raise ValueError("registration fixture bytes differ from their bootstrap pin")

        def identity(value: os.stat_result) -> tuple[int, ...]:
            return (
                value.st_dev,
                value.st_ino,
                value.st_uid,
                value.st_mode,
                value.st_nlink,
                value.st_size,
                value.st_mtime_ns,
                value.st_ctime_ns,
            )

        if identity(os.fstat(descriptor)) != identity(before) or identity(path.lstat()) != identity(before):
            raise ValueError("registration fixture changed during loading")
        if identity(path.parent.lstat()) != identity(parent):
            raise ValueError("registration fixture directory changed during loading")
    finally:
        os.close(descriptor)
    bundle = json.loads(content)
    token = validate_bundle(bundle, run_id, verifier_origin)
    return json.dumps(
        {
            "verifier": {
                "intendedUses": [
                    {
                        "id": "1",
                        "description": "Isolated interoperability using synthetic credentials only",
                        "registrationCertificate": token,
                    }
                ]
            }
        },
        separators=(",", ":"),
    )
