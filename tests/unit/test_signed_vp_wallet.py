"""The test wallet signs a VP with its issuance key, without claiming VC validity."""

from __future__ import annotations

import base64
import json
from types import SimpleNamespace

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from tests.integration.gateway.helpers import oid4vc_wallet_client as wallet_module


def _decode_segment(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _jwt_parts(token: str) -> tuple[dict, dict, bytes, bytes]:
    header, payload, signature = token.split(".")
    return (
        json.loads(_decode_segment(header)),
        json.loads(_decode_segment(payload)),
        f"{header}.{payload}".encode(),
        _decode_segment(signature),
    )


def _verify_es256(token: str, public_key: ec.EllipticCurvePublicKey) -> tuple[dict, dict]:
    header, payload, signing_input, signature = _jwt_parts(token)
    assert len(signature) == 64
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    public_key.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(hashes.SHA256()))
    return header, payload


@pytest.mark.asyncio
async def test_signed_vp_reuses_issuance_proof_key_and_binds_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wallet = wallet_module.OID4VCIWalletClient(issuer_base_url="http://127.0.0.1:1")
    other_wallet = wallet_module.OID4VCIWalletClient(issuer_base_url="http://127.0.0.1:1")
    try:
        monkeypatch.setattr(wallet_module, "time", SimpleNamespace(time=lambda: 1_800_000_000))
        issuance_proof = wallet_module._build_proof_jwt(wallet._private_key, "https://issuer.example", "issuer-nonce")
        credential = "credential.payload.signature"  # Opaque fixture, not verified by this helper.
        presentation = wallet.build_signed_jwt_vp(
            credential,
            nonce="343s$FSFDa-",
            audience="did:web:verifier.example",
            lifetime_seconds=120,
        )
        proof_header, _ = _verify_es256(issuance_proof, wallet._private_key.public_key())
        header, payload = _verify_es256(presentation, wallet._private_key.public_key())
        assert header == {"typ": "vp+jwt", "alg": "ES256", "jwk": proof_header["jwk"]}
        assert set(header["jwk"]) == {"kty", "crv", "x", "y"}
        assert header["jwk"]["crv"] == "P-256"
        assert payload["nonce"] == "343s$FSFDa-"
        assert payload["aud"] == "did:web:verifier.example"
        assert (payload["iat"], payload["nbf"], payload["exp"]) == (
            1_800_000_000,
            1_800_000_000,
            1_800_000_120,
        )
        assert payload["vp"]["verifiableCredential"] == [credential]
        assert payload["vp"]["holder"] == payload["iss"]
        assert payload["iss"].startswith("did:jwk:")
        encoded_jwk = payload["iss"].removeprefix("did:jwk:")
        assert json.loads(_decode_segment(encoded_jwk)) == header["jwk"]
        with pytest.raises(InvalidSignature):
            _verify_es256(presentation, other_wallet._private_key.public_key())
        parts = presentation.split(".")
        tampered_payload = wallet_module._b64url_encode(b'{"nonce":"changed"}')
        tampered = f"{parts[0]}.{tampered_payload}.{parts[2]}"
        with pytest.raises(InvalidSignature):
            _verify_es256(tampered, wallet._private_key.public_key())
    finally:
        await wallet.close()
        await other_wallet.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("credential", "nonce", "audience", "lifetime"),
    [
        ("", "nonce", "audience", 300),
        ("not-a-jwt", "nonce", "audience", 300),
        ("a..c", "nonce", "audience", 300),
        ("a.b.c.d", "nonce", "audience", 300),
        ("a.b.c=", "nonce", "audience", 300),
        ("a.b.é", "nonce", "audience", 300),
        ("a." + "b" * 1_000_000 + ".c", "nonce", "audience", 300),
        (["a.b.c"], "nonce", "audience", 300),
        ("a.b.c", "", "audience", 300),
        ("a.b.c", "   ", "audience", 300),
        ("a.b.c", None, "audience", 300),
        ("a.b.c", "n" * 257, "audience", 300),
        ("a.b.c", "nonce", "", 300),
        ("a.b.c", "nonce", "   ", 300),
        ("a.b.c", "nonce", None, 300),
        ("a.b.c", "nonce", "a" * 2049, 300),
        ("a.b.c", "nonce", "audience", 0),
        ("a.b.c", "nonce", "audience", -1),
        ("a.b.c", "nonce", "audience", 301),
        ("a.b.c", "nonce", "audience", True),
        ("a.b.c", "nonce", "audience", 1.5),
        ("a.b.c", "nonce", "audience", "300"),
    ],
    ids=[
        "empty-credential", "not-compact", "empty-segment", "extra-segment",
        "padding", "non-ascii", "oversize-credential", "credential-list",
        "empty-nonce", "blank-nonce", "null-nonce", "oversize-nonce",
        "empty-audience", "blank-audience", "null-audience", "oversize-audience",
        "zero-lifetime", "negative-lifetime", "oversize-lifetime", "bool-lifetime",
        "float-lifetime", "string-lifetime",
    ],
)
async def test_signed_vp_requires_one_compact_credential_and_bounded_server_inputs(
    credential: str, nonce: str | None, audience: str | None, lifetime: int
) -> None:
    wallet = wallet_module.OID4VCIWalletClient(issuer_base_url="http://127.0.0.1:1")
    try:
        with pytest.raises(ValueError, match="required|nonce|audience|lifetime"):
            wallet.build_signed_jwt_vp(credential, nonce=nonce, audience=audience, lifetime_seconds=lifetime)
    finally:
        await wallet.close()


@pytest.mark.asyncio
async def test_signed_vp_rejects_non_p256_wallet_key() -> None:
    wallet = wallet_module.OID4VCIWalletClient(issuer_base_url="http://127.0.0.1:1")
    try:
        wallet._private_key = ec.generate_private_key(ec.SECP384R1())
        with pytest.raises(ValueError, match="P-256"):
            wallet.build_signed_jwt_vp("a.b.c", nonce="nonce", audience="audience")
    finally:
        await wallet.close()


def test_issuance_proof_rejects_non_p256_key() -> None:
    with pytest.raises(ValueError, match="P-256"):
        wallet_module._build_proof_jwt(
            ec.generate_private_key(ec.SECP384R1()),
            "https://issuer.example",
            "issuer-nonce",
        )
