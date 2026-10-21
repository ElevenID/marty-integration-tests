"""The headless wallet must present SD-JWT with its issuance-bound holder key."""

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from tests.integration.gateway.helpers.marty_wallet_client import MartyHeadlessWalletClient


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decoded(segment: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(segment + "==="))


def credential_for(holder_key: ec.EllipticCurvePrivateKey) -> str:
    public = holder_key.public_key().public_numbers()
    confirmation = {
        "kty": "EC", "crv": "P-256",
        "x": b64(public.x.to_bytes(32, "big")),
        "y": b64(public.y.to_bytes(32, "big")),
    }
    issuer = ".".join((
        b64(json.dumps({"alg": "ES256", "typ": "dc+sd-jwt"}).encode()),
        b64(json.dumps({"cnf": {"jwk": confirmation}}).encode()),
        "issuer-signature",
    ))
    return issuer + "~disclosure~"


def test_sd_jwt_key_binding_signs_hash_nonce_and_public_client_id() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    credential = credential_for(key)
    audience = "x509_hash:public-verifier-client"
    presentation = MartyHeadlessWalletClient()._build_vp_token(
        credential, "challenge-123", audience, key,
    )
    assert presentation.startswith(credential)
    header_segment, payload_segment, signature_segment = presentation.split("~")[-1].split(".")
    assert decoded(header_segment) == {"typ": "kb+jwt", "alg": "ES256"}
    claims = decoded(payload_segment)
    assert claims["aud"] == audience
    assert claims["nonce"] == "challenge-123"
    assert claims["sd_hash"] == b64(hashlib.sha256(credential.encode()).digest())
    signature = base64.urlsafe_b64decode(signature_segment + "===")
    der = encode_dss_signature(
        int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    )
    key.public_key().verify(
        der, f"{header_segment}.{payload_segment}".encode(), ec.ECDSA(hashes.SHA256())
    )


def test_sd_jwt_refuses_wrong_or_missing_holder_key_and_context() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    credential = credential_for(key)
    wallet = MartyHeadlessWalletClient()
    with pytest.raises(ValueError, match="confirmation key differs"):
        wallet._build_vp_token(
            credential, "nonce", "verifier", ec.generate_private_key(ec.SECP256R1())
        )
    for nonce, audience, holder in (("nonce", "verifier", None),
                                     ("", "verifier", key),
                                     ("nonce", "", key)):
        with pytest.raises(ValueError, match="holder key and verifier context"):
            wallet._build_vp_token(credential, nonce, audience, holder)


def test_plain_jwt_keeps_presentation_envelope() -> None:
    plain = "header.payload.signature"
    presentation = MartyHeadlessWalletClient()._build_vp_token(
        plain, "challenge-123", "verifier",
    )
    header, payload, _ = presentation.split(".")
    assert decoded(header)["typ"] == "vp+jwt"
    assert decoded(payload)["nonce"] == "challenge-123"
    assert decoded(payload)["vp"]["verifiableCredential"] == [plain]
