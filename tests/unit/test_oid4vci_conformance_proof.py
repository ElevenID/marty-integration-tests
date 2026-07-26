"""Cryptographic regression tests for the ported OID4VCI issuer suite."""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from tests.integration import test_oid4vci_issuer_conformance as conformance


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))


def _base58btc_decode(value: str) -> bytes:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    number = 0
    for character in value:
        number = (number * 58) + alphabet.index(character)
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return (b"\0" * (len(value) - len(value.lstrip("1")))) + decoded


def test_valid_proof_is_signed_by_the_did_key_in_its_header() -> None:
    private_key = ed25519.Ed25519PrivateKey.generate()
    proof = conformance._build_proof_jwt(
        "https://issuer.example",
        "nonce-1",
        holder_key=private_key,
    )
    header_segment, payload_segment, signature_segment = proof.split(".")
    header = json.loads(_decode(header_segment))
    payload = json.loads(_decode(payload_segment))

    expected_did = conformance._holder_did(private_key)
    did_key_bytes = _base58btc_decode(expected_did.removeprefix("did:key:z"))
    assert did_key_bytes[:2] == bytes((0xED, 0x01))
    assert did_key_bytes[2:] == private_key.public_key().public_bytes_raw()
    assert header == {
        "alg": "EdDSA",
        "typ": "openid4vci-proof+jwt",
        "kid": f"{expected_did}#{expected_did}",
    }
    assert payload["iss"] == expected_did
    assert payload["aud"] == "https://issuer.example"
    assert payload["nonce"] == "nonce-1"
    private_key.public_key().verify(
        _decode(signature_segment),
        f"{header_segment}.{payload_segment}".encode(),
    )


def test_corrupted_proof_signature_is_not_valid() -> None:
    private_key = ed25519.Ed25519PrivateKey.generate()
    proof = conformance._build_proof_jwt(
        "https://issuer.example",
        "nonce-1",
        holder_key=private_key,
    )
    header_segment, payload_segment, signature_segment = proof.split(".")
    signature = bytearray(_decode(signature_segment))
    signature[0] ^= 0x01

    with pytest.raises(InvalidSignature):
        private_key.public_key().verify(
            bytes(signature),
            f"{header_segment}.{payload_segment}".encode(),
        )
