"""Owned DIDComm fixtures shared by public-boundary integration tests."""

from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58btc_encode(value: bytes) -> str:
    number = int.from_bytes(value, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = _BASE58_ALPHABET[remainder] + encoded
    leading_zeroes = len(value) - len(value.lstrip(b"\0"))
    return (_BASE58_ALPHABET[0] * leading_zeroes) + encoded


def make_did_peer_2_with_service(endpoint: str) -> tuple[str, bytes]:
    """Create a method-2 peer DID with an X25519 key and DIDComm service."""
    private_key = x25519.X25519PrivateKey.generate()
    private_key_bytes = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_key_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    key_multibase = "z" + _base58btc_encode(bytes((0xEC, 0x01)) + public_key_bytes)
    service = {
        "id": "#didcomm-1",
        "type": "DIDCommMessaging",
        "serviceEndpoint": endpoint,
    }
    service_b64 = base64.urlsafe_b64encode(json.dumps(service, separators=(",", ":")).encode()).rstrip(b"=").decode()
    return f"did:peer:2.E{key_multibase}.S{service_b64}", private_key_bytes
