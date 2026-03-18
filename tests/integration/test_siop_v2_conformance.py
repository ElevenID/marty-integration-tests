"""SIOPv2 (Self-Issued OpenID Provider v2) Draft 13 — Conformance Tests.

All tests target the gateway (GATEWAY_BASE, port 8000).
These tests cover SIOPv2 discovery, authentication request, and self-issued
ID token validation as specified in SIOPv2 Draft 13.

Since Marty acts as a Verifier/RP (not a self-issued OP), these tests
verify that the gateway/verifier correctly constructs SIOPv2 auth requests
and validates incoming self-issued ID tokens. All 7 tests are expected to
FAIL until SIOPv2 is implemented.

References:
  SIOPv2 Draft 13: https://openid.net/specs/openid-connect-self-issued-v2-1_0-13.html

Run standalone:
    SESSION_ID=<cookie> ORG_ID=<org> \\
        python -m tests.integration.test_siop_v2_conformance

Run via pytest:
    pytest tests/integration/test_siop_v2_conformance.py -v
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any


# ============================================================================
# Config
# ============================================================================

GATEWAY_BASE = os.environ.get("GATEWAY_BASE", "http://localhost:8000")
SESSION_ID = os.environ.get("SESSION_ID", "")
ORG_ID = os.environ.get("ORG_ID", "default")

# Holder DID used to construct self-issued ID tokens in tests
HOLDER_DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
HOLDER_JWK = {
    "kty": "OKP", "crv": "Ed25519",
    "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
}


def setup_module(_module=None) -> None:
    """Auto-acquire SESSION_ID if not set in the environment."""
    global SESSION_ID
    if not SESSION_ID:
        try:
            import asyncio
            import sys
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
            from tests.integration.gateway.helpers.auth_helper import AuthHelper
            SESSION_ID = asyncio.run(AuthHelper().get_session_id())
            os.environ["SESSION_ID"] = SESSION_ID
        except Exception as exc:
            import sys as _sys
            print(f"  ⚠️  Could not auto-acquire SESSION_ID: {exc}", file=_sys.stderr)


# ============================================================================
# HTTP helper
# ============================================================================

@dataclass
class HttpResult:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body)

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


def http(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    json_body: Any = None,
    timeout: int = 30,
) -> HttpResult:
    hdrs = dict(headers or {})
    data = None
    if json_body is not None:
        data = json.dumps(json_body).encode()
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            return HttpResult(resp.status, dict(resp.headers), body)
    except urllib.error.HTTPError as e:
        body = e.read() if hasattr(e, "read") else b""
        return HttpResult(e.code, dict(e.headers) if hasattr(e, "headers") else {}, body)


# ============================================================================
# Results tracker
# ============================================================================

@dataclass
class Results:
    _ok: list[str] = field(default_factory=list)
    _fail: list[tuple[str, str]] = field(default_factory=list)

    def ok(self, name: str) -> None:
        self._ok.append(name)
        print(f"  PASS  {name}")

    def fail(self, name: str, reason: str = "") -> None:
        self._fail.append((name, reason))
        print(f"  FAIL  {name}")
        if reason:
            print(f"        {reason}")

    def summary(self) -> bool:
        print(f"\n{'=' * 70}")
        print(f"SIOPv2 Conformance: {len(self._ok)} passed, {len(self._fail)} failed")
        if self._fail:
            print("\nFailed checks (missing features):")
            for name, reason in self._fail:
                print(f"  - {name}: {reason}")
        return len(self._fail) == 0


R = Results()


# ============================================================================
# Helpers
# ============================================================================

def _session_headers() -> dict[str, str]:
    sid = SESSION_ID or os.environ.get("SESSION_ID", "")
    if not sid:
        raise RuntimeError("SESSION_ID env var required for admin gateway calls.")
    return {"Cookie": f"sessionId={sid}"}


def _build_siop_id_token(
    iss: str,
    sub: str,
    aud: str,
    nonce: str,
    *,
    sub_jwk: dict | None = None,
    iat_offset: int = 0,
) -> str:
    """Build a self-issued ID token JWT (dummy signature).

    SIOPv2 §11: sub MUST equal iss, iss MUST be 'https://self-issued.me/v2'.
    sub_jwk (or sub_id_token_hint) identifies the holder's public key.
    """
    header = {"alg": "EdDSA", "typ": "JWT", "kid": f"{iss}#key-1"}
    payload: dict[str, Any] = {
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "iat": int(time.time()) + iat_offset,
        "exp": int(time.time()) + iat_offset + 300,
        "nonce": nonce,
    }
    if sub_jwk is not None:
        payload["sub_jwk"] = sub_jwk
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    sig = base64.urlsafe_b64encode(b"\x00" * 64).rstrip(b"=").decode()
    return f"{h}.{p}.{sig}"


# ============================================================================
# Tests
# ============================================================================

def test_siop_discovery_well_known():
    """SIOPv2 Draft 13 §6.1: RP publishes its own metadata at /.well-known/openid-configuration.

    The RP (Verifier/gateway) MUST advertise subject_types_supported including
    'pairwise' and 'public', and id_token_signing_alg_values_supported.
    For SIOPv2: subject_syntax_types_supported MUST include 'urn:ietf:params:oauth:jwk-thumbprint'
    or a DID method.
    This test WILL FAIL if SIOPv2 metadata is not published.
    """
    print("\n--- SIOPv2 §6.1: RP / Verifier Discovery ---")
    resp = http("GET", f"{GATEWAY_BASE}/.well-known/openid-configuration")
    if resp.status != 200:
        R.fail("siop_discovery.endpoint_available",
               f"SIOPv2 Draft 13 §6.1: /.well-known/openid-configuration not at {GATEWAY_BASE} "
               f"(status {resp.status}). SIOPv2 RP metadata not published — not implemented.")
        return
    R.ok("siop_discovery.endpoint_available")

    meta = resp.json()

    # subject_syntax_types_supported (SIOPv2-specific, §6.1)
    ssts = meta.get("subject_syntax_types_supported")
    if isinstance(ssts, list) and len(ssts) > 0:
        R.ok("siop_discovery.subject_syntax_types_supported")
        jwk_thumb = "urn:ietf:params:oauth:jwk-thumbprint"
        if jwk_thumb in ssts or any(s.startswith("did:") for s in ssts):
            R.ok("siop_discovery.valid_subject_syntax_type")
        else:
            R.fail("siop_discovery.valid_subject_syntax_type",
                   f"SIOPv2 §6.1: subject_syntax_types_supported MUST include jwk-thumbprint "
                   f"or a DID method, got {ssts}")
    else:
        R.fail("siop_discovery.subject_syntax_types_supported",
               "SIOPv2 Draft 13 §6.1: subject_syntax_types_supported MUST be present "
               "and non-empty in RP metadata (not implemented)")

    # id_token_signing_alg_values_supported
    algs = meta.get("id_token_signing_alg_values_supported")
    if isinstance(algs, list) and len(algs) > 0:
        R.ok("siop_discovery.id_token_signing_alg_values_supported")
    else:
        R.fail("siop_discovery.id_token_signing_alg_values_supported",
               "SIOPv2 Draft 13 §6.1: id_token_signing_alg_values_supported MUST be present")


def test_siop_auth_request_structure():
    """SIOPv2 Draft 13 §9: Authorization Request for self-issued authentication.

    The RP's authorization request for SIOPv2 MUST include:
    - scope: openid
    - response_type: id_token
    - client_id: RP's client identifier
    - nonce: anti-replay
    - Claims requesting sub_jwk or id_token_hint
    This test WILL FAIL if SIOPv2 auth requests are not supported.
    """
    print("\n--- SIOPv2 §9: Authentication Request ---")
    # Check if gateway has a SIOPv2 auth initiation endpoint
    # SIOPv2 auth goes through the OID4VP-like flow but with response_type=id_token
    try:
        resp = http(
            "POST",
            f"{GATEWAY_BASE}/v1/flows/verify",
            headers=_session_headers(),
            json_body={"organization_id": ORG_ID, "response_type": "id_token"},
        )
    except RuntimeError as e:
        R.fail("siop_auth_request.create", str(e))
        return

    if resp.status not in (200, 201):
        R.fail("siop_auth_request.create",
               f"SIOPv2 Draft 13 §9: could not create SIOPv2 auth session: {resp.status} {resp.text}. "
               "SIOPv2 authentication flow not implemented.")
        return
    R.ok("siop_auth_request.create")

    session = resp.json()
    instance_id = session.get("instance_id") or session.get("id")
    if not instance_id:
        R.fail("siop_auth_request.instance_id", f"no instance_id in {list(session.keys())}")
        return

    req_resp = http("GET", f"{GATEWAY_BASE}/v1/flows/instances/{instance_id}/request")
    if req_resp.status != 200:
        R.fail("siop_auth_request.fetch_request", f"status {req_resp.status}")
        return

    # The request endpoint returns a signed JWT; decode the payload without verifying signature
    content_type = req_resp.headers.get("Content-Type", "")
    if "jwt" in content_type or ";" not in content_type and req_resp.body.count(b".") >= 2:
        # JWT: decode the payload (second segment)
        try:
            jwt_str = req_resp.body.decode("utf-8", errors="replace").strip()
            _payload_b64 = jwt_str.split(".")[1]
            _payload_b64 += "=" * (4 - len(_payload_b64) % 4)
            req_obj = json.loads(base64.urlsafe_b64decode(_payload_b64))
        except Exception as exc:
            R.fail("siop_auth_request.fetch_request", f"Could not decode request JWT: {exc}")
            return
    else:
        try:
            req_obj = req_resp.json()
        except Exception as exc:
            R.fail("siop_auth_request.fetch_request", f"Could not parse request object: {exc}")
            return
    rt = req_obj.get("response_type")
    if rt == "id_token":
        R.ok("siop_auth_request.response_type_id_token")
    else:
        R.fail("siop_auth_request.response_type_id_token",
               f"SIOPv2 Draft 13 §9: response_type MUST be id_token for SIOPv2, got {rt!r}")

    scope = req_obj.get("scope", "")
    if "openid" in scope:
        R.ok("siop_auth_request.scope_openid")
    else:
        R.fail("siop_auth_request.scope_openid",
               f"SIOPv2 Draft 13 §9: scope MUST include 'openid', got {scope!r}")


def test_siop_id_token_iss_sub_must_match():
    """SIOPv2 Draft 13 §11: In self-issued ID token, iss MUST equal sub.

    Submitting a self-issued ID token where iss != sub MUST be rejected.
    This test WILL FAIL if SIOPv2 is not implemented.
    """
    print("\n--- SIOPv2 §11: iss MUST equal sub ---")
    # Construct a token where iss != sub (violation)
    bad_id_token = _build_siop_id_token(
        iss="https://self-issued.me/v2",
        sub="did:key:someotherdid",  # iss != sub — MUST be rejected
        aud=GATEWAY_BASE,
        nonce="test-nonce-123",
        sub_jwk=HOLDER_JWK,
    )

    # Try submitting to a verification session
    resp = http(
        "POST",
        f"{GATEWAY_BASE}/v1/flows/siop/submit",
        json_body={"id_token": bad_id_token},
    )
    if resp.status == 400:
        R.ok("siop_id_token.iss_equals_sub_enforced")
    elif resp.status == 404:
        R.fail("siop_id_token.iss_equals_sub_enforced",
               "SIOPv2 Draft 13 §11: No SIOPv2 submission endpoint at /v1/flows/siop/submit. "
               "SIOPv2 not implemented.")
    else:
        R.fail("siop_id_token.iss_equals_sub_enforced",
               f"SIOPv2 Draft 13 §11: iss != sub MUST be rejected with 400, got {resp.status}")


def test_siop_id_token_sub_jwk():
    """SIOPv2 Draft 13 §11: sub_jwk MUST be present for jwk-thumbprint subject syntax.

    The sub claim MUST be the JWK Thumbprint (RFC 7638) of the public key in sub_jwk.
    This test WILL FAIL if SIOPv2 is not implemented.
    """
    print("\n--- SIOPv2 §11: sub_jwk and JWK Thumbprint ---")
    # Compute a dummy JWK thumbprint for the holder key
    jwk_canonical = json.dumps(
        {"crv": "Ed25519", "kty": "OKP", "x": HOLDER_JWK["x"]}, sort_keys=True
    ).encode()
    import hashlib
    thumbprint = base64.urlsafe_b64encode(hashlib.sha256(jwk_canonical).digest()).rstrip(b"=").decode()

    token_with_sub_jwk = _build_siop_id_token(
        iss="https://self-issued.me/v2",
        sub=thumbprint,
        aud=GATEWAY_BASE,
        nonce="test-nonce-456",
        sub_jwk=HOLDER_JWK,
    )

    resp = http(
        "POST",
        f"{GATEWAY_BASE}/v1/flows/siop/submit",
        json_body={"id_token": token_with_sub_jwk},
    )
    if resp.status in (200, 201, 204):
        R.ok("siop_id_token.sub_jwk_accepted")
    elif resp.status == 400:
        # Could be nonce mismatch or other validation — not necessarily sub_jwk rejection
        R.fail("siop_id_token.sub_jwk_accepted",
               f"SIOPv2 Draft 13 §11: sub_jwk token rejected: {resp.text}")
    elif resp.status == 404:
        R.fail("siop_id_token.sub_jwk_accepted",
               "SIOPv2 Draft 13 §11: SIOPv2 submission endpoint not found — not implemented")
    else:
        R.fail("siop_id_token.sub_jwk_accepted",
               f"Unexpected status {resp.status}: {resp.text}")


def test_siop_issuer_value():
    """SIOPv2 Draft 13 §11: iss in self-issued token MUST be 'https://self-issued.me/v2'.

    Submit a token with an invalid iss — MUST be rejected.
    This test WILL FAIL if SIOPv2 is not implemented.
    """
    print("\n--- SIOPv2 §11: iss MUST be https://self-issued.me/v2 ---")
    bad_iss_token = _build_siop_id_token(
        iss="https://not-self-issued.example.com",  # Wrong iss
        sub="https://not-self-issued.example.com",
        aud=GATEWAY_BASE,
        nonce="test-nonce-789",
    )

    resp = http(
        "POST",
        f"{GATEWAY_BASE}/v1/flows/siop/submit",
        json_body={"id_token": bad_iss_token},
    )
    if resp.status == 400:
        R.ok("siop_id_token.invalid_iss_rejected")
    elif resp.status == 404:
        R.fail("siop_id_token.invalid_iss_rejected",
               "SIOPv2 Draft 13 §11: SIOPv2 not implemented — no submission endpoint")
    else:
        R.fail("siop_id_token.invalid_iss_rejected",
               f"SIOPv2 Draft 13 §11: invalid iss MUST be rejected with 400, got {resp.status}")


def test_siop_nonce_validation():
    """SIOPv2 Draft 13 §9 + §11: nonce in ID token MUST match request nonce.

    Submit ID token with wrong nonce — MUST be rejected (replay protection).
    This test WILL FAIL if SIOPv2 is not implemented.
    """
    print("\n--- SIOPv2 §9 + §11: nonce validation ---")
    bad_nonce_token = _build_siop_id_token(
        iss="https://self-issued.me/v2",
        sub="https://self-issued.me/v2",
        aud=GATEWAY_BASE,
        nonce="wrong-nonce-that-was-never-issued",
        sub_jwk=HOLDER_JWK,
    )

    resp = http(
        "POST",
        f"{GATEWAY_BASE}/v1/flows/siop/submit",
        json_body={"id_token": bad_nonce_token},
    )
    if resp.status == 400:
        R.ok("siop_id_token.nonce_validated")
    elif resp.status == 404:
        R.fail("siop_id_token.nonce_validated",
               "SIOPv2 nonce validation not testable — SIOPv2 not implemented")
    else:
        R.fail("siop_id_token.nonce_validated",
               f"SIOPv2 Draft 13 §11: wrong nonce MUST be rejected with 400, got {resp.status}")


def test_siop_cross_device_flow():
    """SIOPv2 Draft 13 §9: Cross-device SIOPv2 flow via QR code / deep link.

    Check if the gateway supports a cross-device SIOPv2 initiation that returns
    an openid:// URI for wallet scanning.
    This test WILL FAIL if SIOPv2 cross-device flow is not implemented.
    """
    print("\n--- SIOPv2 §9: Cross-device flow ---")
    resp = http(
        "POST",
        f"{GATEWAY_BASE}/v1/flows/siop",
        headers=_session_headers(),
        json_body={"organization_id": ORG_ID},
    )
    if resp.status in (200, 201):
        body = resp.json()
        # Should return an openid:// URI for wallet scanning
        request_uri = body.get("request_uri") or body.get("siop_uri") or body.get("openid_uri")
        if request_uri and (request_uri.startswith("openid://") or request_uri.startswith("openid4vp://")):
            R.ok("siop_cross_device.openid_uri_returned")
        elif request_uri:
            R.ok(f"siop_cross_device.uri_returned [{request_uri[:60]}]")
        else:
            R.fail("siop_cross_device.openid_uri_returned",
                   f"SIOPv2 Draft 13 §9: expected openid:// URI in response, got {list(body.keys())}")
    elif resp.status == 404:
        R.fail("siop_cross_device.endpoint_available",
               "SIOPv2 Draft 13 §9: No SIOPv2 endpoint at /v1/flows/siop — not implemented")
    else:
        R.fail("siop_cross_device.endpoint_available",
               f"SIOPv2 Draft 13 §9: unexpected {resp.status}: {resp.text}")


# ============================================================================
# Runner
# ============================================================================

def main() -> None:
    print("=" * 70)
    print("SIOPv2 (Self-Issued OpenID Provider v2 Draft 13) Conformance Tests")
    print(f"Target: {GATEWAY_BASE}")
    print("NOTE: All tests below are expected to FAIL — SIOPv2 not yet implemented.")
    print("=" * 70)

    try:
        resp = http("GET", f"{GATEWAY_BASE}/health")
        if resp.status != 200:
            print(f"FATAL: gateway not healthy: {resp.status} {resp.text}")
            sys.exit(1)
    except Exception as e:
        print(f"FATAL: gateway unreachable at {GATEWAY_BASE}: {e}")
        sys.exit(1)
    print("Gateway healthy ✓\n")

    test_siop_discovery_well_known()
    test_siop_auth_request_structure()
    test_siop_id_token_iss_sub_must_match()
    test_siop_id_token_sub_jwk()
    test_siop_issuer_value()
    test_siop_nonce_validation()
    test_siop_cross_device_flow()

    all_pass = R.summary()
    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
