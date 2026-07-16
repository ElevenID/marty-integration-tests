#!/usr/bin/env python3
"""Generate static conformance test fixtures for OID4VC / OID4VP tests.

Produces a corpus of JSON, JWT, and JWK files consumed by:
  - marty-integration-tests (Python pytest conformance suite)
  - marty-verifier          (Rust integration tests)
  - marty-authenticator     (Flutter/Dart conformance tests)

Usage:
    python generate_fixtures.py

All output files are written to this directory.  The outputs are deterministic
(same key seed → same files) so the git diff is stable.

Key constants used across all three test suites:
  VERIFIER_ID = "https://verifier.example.com"
  ISSUER_URL  = "https://issuer.example.com"
  NONCE       = "n-0S6_WzA2Mj"
  HOLDERS DID  derived from HOLDER_KEY_SEED
"""

from __future__ import annotations

import base64
import json
import os
import struct

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Constants (must stay in sync with Rust and Dart tests)
# ---------------------------------------------------------------------------

VERIFIER_ID = "https://verifier.example.com"
ISSUER_URL = "https://issuer.example.com"
NONCE = "n-0S6_WzA2Mj"

# Deterministic key seed (32 bytes) — NOT secret, for tests only.
HOLDER_KEY_SEED = bytes(range(1, 33))  # 0x01 … 0x20

# Far-future expiry for static fixtures (year ~2286, unix ts 9999999999)
FAR_FUTURE_EXP = 9999999999


# ---------------------------------------------------------------------------
# Ed25519 helpers (requires `cryptography` package)
# ---------------------------------------------------------------------------

def _load_crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
        return Ed25519PrivateKey, Encoding, PublicFormat, PrivateFormat, NoEncryption
    except ImportError as e:
        raise SystemExit(
            "The 'cryptography' package is required.\n"
            "Install with:  pip install cryptography\n"
            f"Error: {e}"
        )


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _base58_encode(data: bytes) -> str:
    ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = int.from_bytes(data, "big")
    result = []
    while num > 0:
        num, rem = divmod(num, 58)
        result.append(ALPHABET[rem : rem + 1])
    for byte in data:
        if byte == 0:
            result.append(ALPHABET[0:1])
        else:
            break
    return b"".join(reversed(result)).decode("ascii")


def _build_did_key(pub_bytes: bytes) -> str:
    multicodec = b"\xed\x01" + pub_bytes
    return f"did:key:z{_base58_encode(multicodec)}"


def _sign_jwt(header: dict, payload: dict, private_key) -> str:
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = private_key.sign(signing_input)
    return f"{h}.{p}.{_b64url(sig)}"


# ---------------------------------------------------------------------------
# Fixture generators
# ---------------------------------------------------------------------------

def gen_holder_key(private_key, pub_bytes: bytes, did: str) -> dict:
    """JWK with both public and private components (test-only, never ship)."""
    Ed25519PrivateKey, Encoding, PublicFormat, PrivateFormat, NoEncryption = _load_crypto()
    pri_bytes = private_key.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64url(pub_bytes),
        "d": _b64url(pri_bytes),
        "kid": f"{did}#{did.split(':')[-1]}",
        "_comment": "Deterministic test-only key. Seed: bytes 1..32. NOT for production.",
    }


def gen_issuer_metadata_final() -> dict:
    """OID4VCI 1.0 Final §12.2.2 — minimal conformant issuer metadata."""
    return {
        "credential_issuer": ISSUER_URL,
        "credential_endpoint": f"{ISSUER_URL}/credential",
        "nonce_endpoint": f"{ISSUER_URL}/nonce",
        "deferred_credential_endpoint": f"{ISSUER_URL}/deferred",
        "notification_endpoint": f"{ISSUER_URL}/notification",
        "authorization_servers": [ISSUER_URL],
        "display": [{"name": "Conformance Test Issuer", "locale": "en-US"}],
        "credential_configurations_supported": {
            "UniversityDegree_jwt_vc_json": {
                "format": "jwt_vc_json",
                "scope": "UniversityDegree",
                "cryptographic_binding_methods_supported": ["did:key", "did:web"],
                "credential_signing_alg_values_supported": ["EdDSA", "ES256"],
                "display": [{"name": "University Degree", "locale": "en-US"}],
                "credential_definition": {
                    "type": ["VerifiableCredential", "UniversityDegreeCredential"],
                    "credentialSubject": {
                        "given_name": {"display": [{"name": "Given Name", "locale": "en-US"}]},
                        "family_name": {"display": [{"name": "Family Name", "locale": "en-US"}]},
                        "degree": {"display": [{"name": "Degree", "locale": "en-US"}]},
                    },
                },
            },
            "UniversityDegree_dc_sd_jwt": {
                "format": "dc+sd-jwt",
                "vct": "https://credentials.example.com/university_degree",
                "scope": "UniversityDegree_sd_jwt",
                "cryptographic_binding_methods_supported": ["did:key"],
                "credential_signing_alg_values_supported": ["EdDSA"],
                "display": [{"name": "University Degree (SD-JWT)", "locale": "en-US"}],
                "claims": {
                    "given_name": {"display": [{"name": "Given Name", "locale": "en-US"}]},
                    "family_name": {"display": [{"name": "Family Name", "locale": "en-US"}]},
                },
            },
        },
    }


def gen_issuer_metadata_legacy() -> dict:
    """OID4VCI draft-era metadata using `vc+sd-jwt` instead of `dc+sd-jwt`."""
    meta = gen_issuer_metadata_final()
    # Swap the Final format key for the draft-era key
    sd_jwt_config = meta["credential_configurations_supported"].pop("UniversityDegree_dc_sd_jwt")
    sd_jwt_config["format"] = "vc+sd-jwt"
    meta["credential_configurations_supported"]["UniversityDegree_vc_sd_jwt"] = sd_jwt_config
    # Remove Final-only endpoints
    meta.pop("nonce_endpoint", None)
    meta.pop("deferred_credential_endpoint", None)
    meta.pop("notification_endpoint", None)
    return meta


def gen_oauth_as_metadata() -> dict:
    """RFC 8414 OAuth Authorization Server metadata."""
    return {
        "issuer": ISSUER_URL,
        "token_endpoint": f"{ISSUER_URL}/token",
        "grant_types_supported": [
            "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "authorization_code",
        ],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
        "pre-authorized_grant_anonymous_access_supported": True,
    }


def gen_credential_offer_preauth() -> dict:
    """OID4VCI §11 — pre-authorized code offer."""
    return {
        "credential_issuer": ISSUER_URL,
        "credential_configuration_ids": ["UniversityDegree_jwt_vc_json"],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "SplxlOBeZQQYbYS6WxSbIA",
                "tx_code": {
                    "length": 6,
                    "input_mode": "numeric",
                    "description": "Please enter the PIN sent to your email.",
                },
            }
        },
    }


def gen_credential_offer_by_ref() -> dict:
    """OID4VCI §11.3 — offer-by-reference variant."""
    return {
        "credential_offer_uri": f"{ISSUER_URL}/offers/abc123",
    }


def gen_token_response() -> dict:
    """OID4VCI §7 — token endpoint response."""
    return {
        "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.dGVzdA.dGVzdA",
        "token_type": "Bearer",
        "expires_in": 86400,
    }


def gen_nonce_response() -> dict:
    """OID4VCI 1.0 Final §7.2 — nonce endpoint response."""
    return {
        "c_nonce": "fGFF7UkhLa",
    }


def gen_credential_response_jwt_vc() -> dict:
    """OID4VCI §8 — JWT-VC credential response."""
    return {
        "format": "jwt_vc_json",
        "credentials": [
            "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9."
            "eyJpc3MiOiJkaWQ6a2V5Ono2TWtpc3N1ZXIiLCJzdWIiOiJkaWQ6a2V5Ono2TWtob2xkZXIiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVW5pdmVyc2l0eURlZ3JlZUNyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiZ2l2ZW5fbmFtZSI6IkNvbmZvcm1hbmNlIiwiZmFtaWx5X25hbWUiOiJUZXN0IiwiZGVncmVlIjoiQlNjIENvbXB1dGVyIFNjaWVuY2UifX19."
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ],
    }


def gen_credential_response_sd_jwt() -> dict:
    """OID4VCI §8 — SD-JWT VC credential response."""
    return {
        "format": "dc+sd-jwt",
        "credentials": [
            "eyJhbGciOiJFZERTQSIsInR5cCI6InZjK3NkLWp3dCJ9."
            "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsInZjdCI6Imh0dHBzOi8vY3JlZGVudGlhbHMuZXhhbXBsZS5jb20vdW5pdmVyc2l0eV9kZWdyZWUiLCJfc2RfYWxnIjoic2hhLTI1NiIsIl9zZCI6WyJBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSJdfQ."
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ],
    }


def gen_credential_response_mdoc() -> dict:
    """OID4VCI §8 — mDoc (ISO 18013-5) credential response."""
    # Minimal CBOR IssuerSigned stub (base64url-encoded)
    stub_cbor_b64 = _b64url(b"\xa1" + b"\x00" * 31)  # CBOR map with one entry, stub
    return {
        "format": "mso_mdoc",
        "credentials": [stub_cbor_b64],
    }


def gen_presentation_definition() -> dict:
    """DIF Presentation Exchange v2 presentation definition."""
    return {
        "id": "pd-conformance-test",
        "name": "OID4VP Conformance Test",
        "purpose": "Verify University Degree for conformance testing",
        "input_descriptors": [
            {
                "id": "university_degree",
                "name": "University Degree Credential",
                "purpose": "We need your degree credential",
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.vc.type", "$.type"],
                            "filter": {
                                "type": "array",
                                "contains": {"const": "UniversityDegreeCredential"},
                            },
                        }
                    ]
                },
            }
        ],
    }


def gen_presentation_submission() -> dict:
    """DIF Presentation Exchange v2 — submission matching gen_presentation_definition()."""
    return {
        "id": "ps-conformance-test",
        "definition_id": "pd-conformance-test",
        "descriptor_map": [
            {
                "id": "university_degree",
                "format": "jwt_vp",
                "path": "$",
                "path_nested": {
                    "id": "university_degree",
                    "format": "jwt_vc",
                    "path": "$.vp.verifiableCredential[0]",
                },
            }
        ],
    }


def gen_presentation_request(pd: dict) -> dict:
    """OID4VP 1.0 Final §5 — authorization request with embedded PD."""
    return {
        "response_type": "vp_token",
        "client_id": VERIFIER_ID,
        "client_id_scheme": "redirect_uri",
        "nonce": NONCE,
        "response_mode": "direct_post",
        "response_uri": f"{VERIFIER_ID}/callback",
        "state": "test-state-abc",
        "presentation_definition": pd,
    }


def gen_vp_token_jwt(private_key, pub_bytes: bytes, did: str) -> str:
    """Build a properly signed VP JWT for the conformance tests.

    Uses:
      - aud  = VERIFIER_ID
      - nonce = NONCE (from presentation_request.json)
      - exp  = FAR_FUTURE_EXP (year ~2286 — will not expire in any reasonable lifetime)
      - jwk  embedded in header (required by VerificationEngine.verify_vp_token)
    """
    x = _b64url(pub_bytes)
    kid = f"{did}#{did.split(':')[-1]}"
    header = {
        "alg": "EdDSA",
        "typ": "JWT",
        "kid": kid,
        "jwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x,
        },
    }
    payload = {
        "iss": did,
        "sub": did,
        "aud": VERIFIER_ID,
        "iat": 1741824000,  # 2025-03-13 00:00:00 UTC — fixed for determinism
        "exp": FAR_FUTURE_EXP,
        "nonce": NONCE,
        "vp": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "verifiableCredential": [
                {
                    "@context": ["https://www.w3.org/2018/credentials/v1"],
                    "type": ["VerifiableCredential", "UniversityDegreeCredential"],
                    "credentialSubject": {
                        "given_name": "Conformance",
                        "family_name": "Test",
                        "degree": "BSc Computer Science",
                    },
                }
            ],
        },
    }
    return _sign_jwt(header, payload, private_key)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    Ed25519PrivateKey, Encoding, PublicFormat, PrivateFormat, NoEncryption = _load_crypto()

    # Generate deterministic holder keypair
    private_key = Ed25519PrivateKey.from_private_bytes(HOLDER_KEY_SEED)
    pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    did = _build_did_key(pub_bytes)

    print(f"Holder DID: {did}")
    print(f"Output dir: {OUTPUT_DIR}\n")

    files: dict[str, object] = {
        "holder_key.json":                  gen_holder_key(private_key, pub_bytes, did),
        "issuer_metadata.json":             gen_issuer_metadata_final(),
        "issuer_metadata_legacy.json":      gen_issuer_metadata_legacy(),
        "oauth_as_metadata.json":           gen_oauth_as_metadata(),
        "credential_offer_preauth.json":    gen_credential_offer_preauth(),
        "credential_offer_by_ref.json":     gen_credential_offer_by_ref(),
        "token_response.json":              gen_token_response(),
        "nonce_response.json":              gen_nonce_response(),
        "credential_response_jwt_vc.json":  gen_credential_response_jwt_vc(),
        "credential_response_sd_jwt.json":  gen_credential_response_sd_jwt(),
        "credential_response_mdoc.json":    gen_credential_response_mdoc(),
        "presentation_definition.json":     gen_presentation_definition(),
        "presentation_submission.json":     gen_presentation_submission(),
    }

    pd = gen_presentation_definition()
    files["presentation_request.json"] = gen_presentation_request(pd)

    vp_token = gen_vp_token_jwt(private_key, pub_bytes, did)
    files["vp_token_jwt.txt"] = vp_token

    for name, content in files.items():
        path = os.path.join(OUTPUT_DIR, name)
        if isinstance(content, str):
            with open(path, "w") as f:
                f.write(content)
        else:
            with open(path, "w") as f:
                json.dump(content, f, indent=2)
                f.write("\n")  # trailing newline
        print(f"  wrote {name}")

    print(f"\nGenerated {len(files)} fixture files.")
    print(f"Holder DID (for Rust/Dart tests): {did}")
    print(f"Nonce (for Rust/Dart tests):       {NONCE}")
    print(f"Verifier ID (for Rust tests):      {VERIFIER_ID}")


if __name__ == "__main__":
    main()
