"""Regression tests proving the EUDI mdoc sentinel cannot pass on opaque bytes."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from tests.integration.gateway.helpers.mdoc_evidence import validate_issuer_signed_mdoc

DOC_TYPE = "org.iso.18013.5.1.mDL"
NAMESPACE = "org.iso.18013.5.1"
NOW = datetime(2026, 7, 21, 12, tzinfo=UTC)
CLAIMS = {
    "given_name": "Erika",
    "family_name": "Mustermann",
    "birth_date": "1986-03-15",
}


def _encoded_mdoc() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    ca_key = ec.generate_private_key(ec.SECP256R1())
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "EUDI test document CA")])
    root = (
        x509.CertificateBuilder()
        .subject_name(issuer)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "EUDI test document signer")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    items: list[cbor2.CBORTag] = []
    digests: dict[int, bytes] = {}
    for digest_id, (name, value) in enumerate(CLAIMS.items()):
        encoded_value = cbor2.CBORTag(1004, value) if name == "birth_date" else value
        item_bytes = cbor2.dumps(
            {
                "digestID": digest_id,
                "random": bytes([digest_id + 1]) * 32,
                "elementIdentifier": name,
                "elementValue": encoded_value,
            }
        )
        items.append(cbor2.CBORTag(24, item_bytes))
        digests[digest_id] = hashlib.sha256(item_bytes).digest()

    mso = cbor2.dumps(
        {
            "version": "1.0",
            "digestAlgorithm": "SHA-256",
            "valueDigests": {NAMESPACE: digests},
            "docType": DOC_TYPE,
            "validityInfo": {
                "signed": cbor2.CBORTag(0, (NOW - timedelta(minutes=1)).isoformat()),
                "validFrom": cbor2.CBORTag(0, (NOW - timedelta(minutes=1)).isoformat()),
                "validUntil": cbor2.CBORTag(0, (NOW + timedelta(days=30)).isoformat()),
            },
        }
    )
    protected = cbor2.dumps(
        {
            1: -7,
            33: [
                certificate.public_bytes(serialization.Encoding.DER),
                root.public_bytes(serialization.Encoding.DER),
            ],
        }
    )
    to_be_signed = cbor2.dumps(["Signature1", protected, b"", mso])
    signature_der = key.sign(to_be_signed, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(signature_der)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    issuer_signed = {
        "nameSpaces": {NAMESPACE: items},
        "issuerAuth": cbor2.CBORTag(18, [protected, {}, mso, signature]),
    }
    return base64.urlsafe_b64encode(cbor2.dumps(issuer_signed)).rstrip(b"=").decode("ascii")


def _validate(credential: str) -> dict[str, object]:
    return validate_issuer_signed_mdoc(
        credential,
        expected_doc_type=DOC_TYPE,
        expected_namespace=NAMESPACE,
        expected_claims=CLAIMS,
        now=NOW,
    )


def _mutate(credential: str, operation: Callable[[dict[str, Any]], None]) -> str:
    decoded = cbor2.loads(base64.urlsafe_b64decode(credential + "=" * (-len(credential) % 4)))
    operation(decoded)
    return base64.urlsafe_b64encode(cbor2.dumps(decoded)).rstrip(b"=").decode("ascii")


def test_valid_mdoc_proves_signature_digests_validity_and_claims() -> None:
    evidence = _validate(_encoded_mdoc())
    assert evidence["doc_type"] == DOC_TYPE
    assert evidence["cose_algorithm"] == -7
    assert evidence["claims"] == CLAIMS
    assert evidence["certificate_chain_length"] == 2
    assert len(evidence["certificate_chain_sha256"]) == 2


def test_opaque_long_text_cannot_satisfy_mdoc_evidence() -> None:
    opaque = base64.urlsafe_b64encode(cbor2.dumps("x" * 1000)).decode("ascii")
    with pytest.raises(ValueError, match="IssuerSigned"):
        _validate(opaque)


def test_tampered_mdoc_signature_cannot_satisfy_evidence() -> None:
    def tamper(value: dict[str, Any]) -> None:
        cose = value["issuerAuth"].value
        cose[3] = bytes([cose[3][0] ^ 1]) + cose[3][1:]

    with pytest.raises(ValueError, match="COSE signature is invalid"):
        _validate(_mutate(_encoded_mdoc(), tamper))


def test_tampered_issuer_signed_item_cannot_satisfy_digest_evidence() -> None:
    def tamper(value: dict[str, Any]) -> None:
        items = value["nameSpaces"][NAMESPACE]
        item = items[0]
        decoded_item = cbor2.loads(item.value)
        decoded_item["elementValue"] = "Mallory"
        items[0] = cbor2.CBORTag(24, cbor2.dumps(decoded_item))

    with pytest.raises(ValueError, match="digest mismatch"):
        _validate(_mutate(_encoded_mdoc(), tamper))


def test_configuration_format_label_is_not_an_input_to_validation() -> None:
    evidence = _validate(_encoded_mdoc())
    assert "format" not in evidence
