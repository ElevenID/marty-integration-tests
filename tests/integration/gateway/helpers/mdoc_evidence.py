"""Strict, independent evidence checks for ISO 18013-5 issuer-signed mdocs."""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import re
from collections.abc import Mapping
from datetime import UTC, date, datetime, timedelta
from typing import Any

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

_MDOC_TEXT = re.compile(r"[A-Za-z0-9_+/=-]+")
_COSE_ALGORITHMS: dict[int, tuple[type[ec.EllipticCurve], hashes.HashAlgorithm, int]] = {
    -7: (ec.SECP256R1, hashes.SHA256(), 32),
    -35: (ec.SECP384R1, hashes.SHA384(), 48),
}


def _decode_base64(text: str) -> bytes:
    if not text or text != text.strip() or _MDOC_TEXT.fullmatch(text) is None:
        raise ValueError("mDoc credential is not strict base64/base64url text")
    if "=" in text[:-2] or len(text.rstrip("=")) % 4 == 1:
        raise ValueError("mDoc credential has invalid base64 padding")
    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.b64decode(padded, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("mDoc credential is not valid base64/base64url") from exc


def _decode_cbor_exact(raw: bytes, *, label: str) -> Any:
    stream = io.BytesIO(raw)
    try:
        value = cbor2.CBORDecoder(stream).decode()
    except (cbor2.CBORDecodeError, ValueError) as exc:
        raise ValueError(f"{label} is not valid CBOR: {exc}") from exc
    if stream.read(1):
        raise ValueError(f"{label} contains trailing CBOR data")
    return value


def _require_map(value: Any, *, label: str) -> dict[Any, Any]:
    # cbor2 6 can expose CBOR maps as immutable Mapping implementations.
    # Materialize a local copy so all later shape checks are independent of
    # the decoder's Python container choices.
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be a CBOR map")
    return dict(value)


def _as_utc_datetime(value: Any, *, label: str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, cbor2.CBORTag) and value.tag == 0 and isinstance(value.value, str):
        parsed = datetime.fromisoformat(value.value.replace("Z", "+00:00"))
    else:
        raise ValueError(f"{label} must be a tagged RFC 3339 date-time")
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(UTC)


def _comparable_claim(value: Any) -> Any:
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, cbor2.CBORTag) and value.tag == 1004:
        return value.value
    if isinstance(value, (list, tuple)):
        return [_comparable_claim(item) for item in value]
    if isinstance(value, Mapping):
        return {key: _comparable_claim(item) for key, item in value.items()}
    return value


def _x5chain(header: dict[Any, Any]) -> list[bytes]:
    raw_chain = header.get(33)
    if isinstance(raw_chain, bytes):
        return [raw_chain]
    if isinstance(raw_chain, (list, tuple)) and raw_chain and all(isinstance(item, bytes) for item in raw_chain):
        return list(raw_chain)
    raise ValueError("mDoc issuerAuth protected header must contain a non-empty x5chain")


def _verify_cose_signature(
    *,
    protected_bytes: bytes,
    unprotected: dict[Any, Any],
    payload: bytes,
    signature: bytes,
    now: datetime,
) -> tuple[x509.Certificate, list[x509.Certificate], int]:
    protected = _require_map(
        _decode_cbor_exact(protected_bytes, label="COSE protected header"), label="COSE protected header"
    )
    algorithm = protected.get(1)
    if algorithm not in _COSE_ALGORITHMS:
        raise ValueError(f"unsupported mDoc COSE algorithm: {algorithm!r}")
    if 33 in unprotected:
        raise ValueError("mDoc x5chain must be integrity-protected")

    certificates: list[x509.Certificate] = []
    for index, der in enumerate(_x5chain(protected)):
        try:
            certificates.append(x509.load_der_x509_certificate(der))
        except ValueError as exc:
            raise ValueError(f"mDoc x5chain certificate {index} is invalid DER") from exc

    _verify_certificate_chain(certificates, now=now)
    leaf = certificates[0]

    curve_type, hash_algorithm, coordinate_size = _COSE_ALGORITHMS[algorithm]
    public_key = leaf.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, curve_type):
        raise ValueError("mDoc document-signer certificate key does not match the COSE algorithm")
    if len(signature) != coordinate_size * 2:
        raise ValueError("mDoc COSE signature has the wrong raw ECDSA length")

    r = int.from_bytes(signature[:coordinate_size], "big")
    s = int.from_bytes(signature[coordinate_size:], "big")
    signature_der = encode_dss_signature(r, s)
    sig_structure = cbor2.dumps(["Signature1", protected_bytes, b"", payload])
    try:
        public_key.verify(signature_der, sig_structure, ec.ECDSA(hash_algorithm))
    except Exception as exc:
        raise ValueError("mDoc issuerAuth COSE signature is invalid") from exc

    return leaf, certificates, algorithm


def _verify_certificate_signature(
    certificate: x509.Certificate,
    issuer_public_key: Any,
) -> None:
    if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
        issuer_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            ec.ECDSA(certificate.signature_hash_algorithm),
        )
    elif isinstance(issuer_public_key, rsa.RSAPublicKey):
        algorithm_parameters = certificate.signature_algorithm_parameters
        signature_padding = (
            algorithm_parameters if isinstance(algorithm_parameters, padding.AsymmetricPadding) else padding.PKCS1v15()
        )
        issuer_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            signature_padding,
            certificate.signature_hash_algorithm,
        )
    elif isinstance(issuer_public_key, dsa.DSAPublicKey):
        issuer_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            certificate.signature_hash_algorithm,
        )
    elif isinstance(issuer_public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        issuer_public_key.verify(certificate.signature, certificate.tbs_certificate_bytes)
    else:
        raise ValueError("mDoc x5chain uses an unsupported certificate issuer key")


def _verify_certificate_chain(certificates: list[x509.Certificate], *, now: datetime) -> None:
    for index, certificate in enumerate(certificates):
        if certificate.not_valid_before_utc > now or certificate.not_valid_after_utc <= now:
            label = "document-signer" if index == 0 else f"chain certificate {index}"
            raise ValueError(f"mDoc {label} certificate is not currently valid")

    for index, (child, parent) in enumerate(zip(certificates, certificates[1:], strict=False)):
        if child.issuer != parent.subject:
            raise ValueError(f"mDoc x5chain certificate {index} issuer does not match its parent")
        try:
            constraints = parent.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound as exc:
            raise ValueError(f"mDoc x5chain parent certificate {index + 1} lacks CA constraints") from exc
        if not constraints.ca:
            raise ValueError(f"mDoc x5chain parent certificate {index + 1} is not a CA")
        try:
            _verify_certificate_signature(child, parent.public_key())
        except Exception as exc:
            raise ValueError(f"mDoc x5chain certificate {index} signature is invalid") from exc

    chain_tail = certificates[-1]
    if len(certificates) > 1 and chain_tail.issuer == chain_tail.subject:
        try:
            _verify_certificate_signature(chain_tail, chain_tail.public_key())
        except Exception as exc:
            raise ValueError("mDoc x5chain self-signed trust anchor is invalid") from exc


def validate_issuer_signed_mdoc(
    credential: str,
    *,
    expected_doc_type: str,
    expected_namespace: str,
    expected_claims: dict[str, Any],
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate the actual OID4VCI ``IssuerSigned`` bytes and return evidence metadata.

    This deliberately does not trust the credential-configuration identifier
    returned by the wallet harness. It parses the credential itself, verifies
    the document-signer COSE signature, binds every disclosed item to the MSO
    digest table, checks validity, and compares the expected production claims.
    """
    checked_at = (now or datetime.now(UTC)).astimezone(UTC)
    issuer_signed = _require_map(
        _decode_cbor_exact(_decode_base64(credential), label="mDoc credential"),
        label="mDoc IssuerSigned",
    )
    if set(issuer_signed) != {"nameSpaces", "issuerAuth"}:
        raise ValueError("OID4VCI mso_mdoc credential must be a bare IssuerSigned structure")

    namespaces = _require_map(issuer_signed["nameSpaces"], label="mDoc nameSpaces")
    if set(namespaces) != {expected_namespace}:
        raise ValueError(f"mDoc namespaces do not match {expected_namespace!r}")
    raw_items = namespaces[expected_namespace]
    if not isinstance(raw_items, (list, tuple)) or not raw_items:
        raise ValueError("mDoc namespace must contain IssuerSignedItemBytes")

    item_bytes_by_digest: dict[int, bytes] = {}
    claims: dict[str, Any] = {}
    for index, tagged_item in enumerate(raw_items):
        if (
            not isinstance(tagged_item, cbor2.CBORTag)
            or tagged_item.tag != 24
            or not isinstance(tagged_item.value, bytes)
        ):
            raise ValueError(f"mDoc item {index} must be tag-24 encoded CBOR bytes")
        item = _require_map(
            _decode_cbor_exact(tagged_item.value, label=f"mDoc item {index}"),
            label=f"mDoc item {index}",
        )
        if set(item) != {"digestID", "random", "elementIdentifier", "elementValue"}:
            raise ValueError(f"mDoc item {index} has an invalid IssuerSignedItem shape")
        digest_id = item["digestID"]
        salt = item["random"]
        element = item["elementIdentifier"]
        if not isinstance(digest_id, int) or isinstance(digest_id, bool) or digest_id < 0:
            raise ValueError(f"mDoc item {index} has an invalid digestID")
        if digest_id in item_bytes_by_digest:
            raise ValueError(f"mDoc item {index} reuses digestID {digest_id}")
        if not isinstance(salt, bytes) or len(salt) < 16:
            raise ValueError(f"mDoc item {index} has insufficient digest salt")
        if not isinstance(element, str) or not element or element in claims:
            raise ValueError(f"mDoc item {index} has an invalid or duplicate elementIdentifier")
        item_bytes_by_digest[digest_id] = tagged_item.value
        claims[element] = item["elementValue"]

    issuer_auth = issuer_signed["issuerAuth"]
    if isinstance(issuer_auth, cbor2.CBORTag):
        if issuer_auth.tag != 18:
            raise ValueError("mDoc issuerAuth must use COSE_Sign1 tag 18")
        issuer_auth = issuer_auth.value
    # cbor2 6 decodes CBOR arrays as tuples by default.  COSE_Sign1 is an
    # array in the wire format, so validation must accept either Python
    # sequence representation rather than coupling evidence verification to
    # one decoder release.
    if not isinstance(issuer_auth, (list, tuple)) or len(issuer_auth) != 4:
        raise ValueError("mDoc issuerAuth must be a four-element COSE_Sign1")
    protected_bytes, unprotected, payload, signature = issuer_auth
    if not isinstance(protected_bytes, bytes) or not protected_bytes:
        raise ValueError("mDoc COSE protected header must be non-empty bytes")
    unprotected = _require_map(unprotected, label="COSE unprotected header")
    if not isinstance(payload, bytes) or not payload or not isinstance(signature, bytes) or not signature:
        raise ValueError("mDoc COSE payload and signature must be non-empty bytes")

    leaf, certificates, algorithm = _verify_cose_signature(
        protected_bytes=protected_bytes,
        unprotected=unprotected,
        payload=payload,
        signature=signature,
        now=checked_at,
    )

    mso = _require_map(
        _decode_cbor_exact(payload, label="mDoc MobileSecurityObject"), label="mDoc MobileSecurityObject"
    )
    if mso.get("version") != "1.0" or mso.get("digestAlgorithm") != "SHA-256":
        raise ValueError("mDoc MSO must use version 1.0 and SHA-256")
    if mso.get("docType") != expected_doc_type:
        raise ValueError(f"mDoc MSO docType does not match {expected_doc_type!r}")

    all_digests = _require_map(mso.get("valueDigests"), label="mDoc valueDigests")
    if set(all_digests) != {expected_namespace}:
        raise ValueError("mDoc MSO digest namespaces do not match IssuerSigned")
    expected_digests = _require_map(all_digests[expected_namespace], label="mDoc namespace digests")
    if set(expected_digests) != set(item_bytes_by_digest):
        raise ValueError("mDoc MSO digest IDs do not exactly cover IssuerSigned items")
    for digest_id, item_bytes in item_bytes_by_digest.items():
        digest = expected_digests[digest_id]
        if not isinstance(digest, bytes) or digest != hashlib.sha256(item_bytes).digest():
            raise ValueError(f"mDoc MSO digest mismatch for digestID {digest_id}")

    validity = _require_map(mso.get("validityInfo"), label="mDoc validityInfo")
    signed = _as_utc_datetime(validity.get("signed"), label="mDoc signed time")
    valid_from = _as_utc_datetime(validity.get("validFrom"), label="mDoc validFrom time")
    valid_until = _as_utc_datetime(validity.get("validUntil"), label="mDoc validUntil time")
    if signed > checked_at + timedelta(minutes=5) or valid_from > checked_at + timedelta(minutes=5):
        raise ValueError("mDoc validity begins in the future")
    if valid_until <= checked_at or signed > valid_until or valid_from > valid_until:
        raise ValueError("mDoc validity period is invalid or expired")

    comparable_claims = {name: _comparable_claim(value) for name, value in claims.items()}
    comparable_expected = {name: _comparable_claim(value) for name, value in expected_claims.items()}
    missing = sorted(set(comparable_expected) - set(comparable_claims))
    mismatched = sorted(
        name
        for name, value in comparable_expected.items()
        if name in comparable_claims and comparable_claims[name] != value
    )
    if missing or mismatched:
        raise ValueError(f"mDoc claims do not match issuance input (missing={missing}, mismatched={mismatched})")

    return {
        "doc_type": expected_doc_type,
        "namespace": expected_namespace,
        "claims": comparable_claims,
        "cose_algorithm": algorithm,
        "certificate_sha256": leaf.fingerprint(hashes.SHA256()).hex(),
        "certificate_chain_length": len(certificates),
        "certificate_chain_sha256": [certificate.fingerprint(hashes.SHA256()).hex() for certificate in certificates],
        "valid_until": valid_until.isoformat(),
    }
