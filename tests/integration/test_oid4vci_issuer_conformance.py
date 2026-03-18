#!/usr/bin/env python3
"""OID4VCI Issuer Conformance Test Suite.

Tests the Marty issuance service through the API gateway (port 8000) against the
OpenID for Verifiable Credential Issuance (OID4VCI) specification:
  - OID4VCI 1.0 Final (openid-4-verifiable-credential-issuance-1_0)
  - RFC 8414 (OAuth 2.0 Authorization Server Metadata)
  - RFC 6749 (OAuth 2.0 error response format)

All wallet-facing calls (token, credential, nonce, offers) route through the
gateway without authentication (the gateway treats these as public, exactly
as real wallets would). Admin setup calls (POST /v1/issuance to create a
transaction) require a Keycloak session cookie.

Test naming mirrors the OIDF conformance suite:
  https://gitlab.com/openid/conformance-suite (packages: vci10issuer/)

Can be run directly:
    SESSION_ID=<value> ORG_ID=<uuid> python3 tests/integration/test_oid4vci_issuer_conformance.py

Or via pytest:
    SESSION_ID=<value> ORG_ID=<uuid> pytest tests/integration/test_oid4vci_issuer_conformance.py -v -m conformance
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone, timedelta

# ---------------------------------------------------------------------------
# Configuration
# All calls go through the gateway.  The gateway is the public entry point
# that wallets talk to — never directly at the backend service ports.
# ---------------------------------------------------------------------------

GATEWAY_BASE = os.environ.get("GATEWAY_BASE", "http://localhost:8000")
# Keep ISSUANCE_BASE as a deprecated alias so any existing local scripts still
# work, but it is no longer used inside this file.
ORG_ID = os.environ.get("ORG_ID", "22222222-2222-2222-2222-222222222222")
CREDENTIAL_TEMPLATE_ID = os.environ.get("CREDENTIAL_TEMPLATE_ID", "")
# SESSION_ID — Keycloak session cookie for admin-facing gateway endpoints.
# Obtain with:  python -c "import asyncio; from tests.integration.gateway.helpers.auth_helper import AuthHelper; print(asyncio.run(AuthHelper().get_session_id()))"
SESSION_ID = os.environ.get("SESSION_ID", "")
ISSUER_BASE_URL = os.environ.get("ISSUER_BASE_URL", f"{GATEWAY_BASE}/org/{ORG_ID}")


def _localize_url(url: str) -> str:
    """Replace an external host in a metadata URL with GATEWAY_BASE for local testing."""
    parsed = urllib.parse.urlparse(url)
    gateway = urllib.parse.urlparse(GATEWAY_BASE)
    return parsed._replace(scheme=gateway.scheme, netloc=gateway.netloc).geturl()


def setup_module(_module=None) -> None:
    """Auto-acquire SESSION_ID if not set in the environment."""
    global SESSION_ID
    if not SESSION_ID:
        try:
            import asyncio
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
            from tests.integration.gateway.helpers.auth_helper import AuthHelper
            SESSION_ID = asyncio.run(AuthHelper().get_session_id())
            os.environ["SESSION_ID"] = SESSION_ID
        except Exception as exc:
            print(f"  ⚠️  Could not auto-acquire SESSION_ID: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only)
# ---------------------------------------------------------------------------

class HttpResult:
    def __init__(self, status: int, headers: dict[str, str], body: bytes):
        self.status = status
        self.headers = headers
        self.body = body

    @property
    def text(self) -> str:
        try:
            return self.body.decode("utf-8")
        except Exception:
            return repr(self.body[:2000])

    def json(self):
        return json.loads(self.text)


def http(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    json_body=None,
    form_body: dict[str, str] | None = None,
    timeout: int = 30,
) -> HttpResult:
    hdrs = dict(headers or {})
    data = None
    if json_body is not None:
        data = json.dumps(json_body).encode()
        hdrs.setdefault("Content-Type", "application/json")
    elif form_body is not None:
        data = urllib.parse.urlencode(form_body).encode()
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            return HttpResult(resp.status, dict(resp.headers), body)
    except urllib.error.HTTPError as e:
        body = e.read() if hasattr(e, "read") else b""
        return HttpResult(e.code, dict(e.headers) if hasattr(e, "headers") else {}, body)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _session_headers() -> dict[str, str]:
    """Return Cookie header with sessionId for admin-facing gateway endpoints.

    Admin endpoints (e.g. POST /v1/issuance to create a transaction) require
    a valid Keycloak session cookie.  Wallet-facing endpoints (token, credential,
    nonce, offers) are public and need no auth.
    """
    sid = SESSION_ID or os.environ.get("SESSION_ID", "")
    if not sid:
        raise RuntimeError(
            "SESSION_ID env var is required for admin gateway calls.\n"
            "Obtain it with:\n"
            "  python -c \"import asyncio; "
            "from tests.integration.gateway.helpers.auth_helper import AuthHelper; "
            "print(asyncio.run(AuthHelper().get_session_id()))\""
        )
    return {"Cookie": f"sessionId={sid}"}


def _initiate_issuance(
    org_id: str = ORG_ID,
    claims: dict | None = None,
    credential_template_id: str | None = None,
) -> dict:
    """Create a fresh issuance transaction via the gateway (admin endpoint).

    POST /v1/issuance — requires sessionId cookie.
    The gateway proxies this to the issuance service /v1/issuance/initiate.
    Returns the JSON response which contains pre_auth_code and credential_offer_uri.
    """
    body: dict = {
        "organization_id": org_id,
        "claims": claims or {"given_name": "Conformance", "family_name": "Test"},
    }
    tmpl_id = credential_template_id or CREDENTIAL_TEMPLATE_ID
    if tmpl_id:
        body["credential_template_id"] = tmpl_id
    resp = http(
        "POST",
        f"{GATEWAY_BASE}/v1/issuance",
        headers=_session_headers(),
        json_body=body,
    )
    assert resp.status == 200, f"initiate failed: {resp.status} {resp.text}"
    return resp.json()


def _exchange_token(pre_auth_code: str) -> dict:
    """Exchange a pre-authorized code for an access token.

    POST /v1/issuance/token — public wallet-facing endpoint, no auth needed.
    """
    resp = http(
        "POST",
        f"{GATEWAY_BASE}/v1/issuance/token",
        form_body={
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": pre_auth_code,
        },
    )
    assert resp.status == 200, f"token exchange failed: {resp.status} {resp.text}"
    return resp.json()


def _call_nonce_endpoint(access_token: str | None = None) -> HttpResult:
    """POST /v1/issuance/nonce — OID4VCI 1.0 Final §7.

    Returns a fresh c_nonce. When called with an access_token the server
    also updates the stored c_nonce for that credential transaction so that
    the proof JWT will pass nonce validation at the credential endpoint.
    """
    headers = {}
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"
    return http("POST", f"{GATEWAY_BASE}/v1/issuance/nonce", json_body={}, headers=headers)


def _build_proof_jwt(
    issuer_url: str,
    nonce: str,
    *,
    holder_kid: str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    typ: str = "openid4vci-proof+jwt",
    alg: str = "EdDSA",
    bad_nonce: str | None = None,
    bad_aud: str | None = None,
    iat_offset: int = 0,
) -> str:
    """Build a mock proof JWT.

    This creates a *structurally valid* JWT with the correct header/payload
    fields but a dummy signature (since the server doesn't verify signatures
    yet). Once signature verification is added this helper will need real
    Ed25519 signing.
    """
    header = {
        "alg": alg,
        "typ": typ,
        "kid": holder_kid,
    }
    payload = {
        "iss": holder_kid.split("#")[0],
        "aud": bad_aud if bad_aud is not None else issuer_url,
        "iat": int(time.time()) + iat_offset,
        "nonce": bad_nonce if bad_nonce is not None else nonce,
    }
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    # Dummy 64-byte Ed25519-shaped signature
    sig = base64.urlsafe_b64encode(b"\x00" * 64).rstrip(b"=").decode()
    return f"{h}.{p}.{sig}"


def _issue_credential(
    access_token: str,
    proof_jwt: str,
    *,
    format: str = "jwt_vc_json",
    use_v1_proofs: bool = True,
    credential_identifier: str | None = None,
    credential_configuration_id: str | None = None,
) -> HttpResult:
    """Call the credential endpoint with a proof.

    POST /v1/issuance/credential — public wallet-facing endpoint.
    OID4VCI 1.0 Final §8: supports both `proofs` (Final) and legacy `proof` (Draft).
    """
    body: dict = {"format": format}
    if credential_identifier is not None:
        body["credential_identifier"] = credential_identifier
    if credential_configuration_id is not None:
        body["credential_configuration_id"] = credential_configuration_id
    if use_v1_proofs:
        body["proofs"] = {"jwt": [proof_jwt]}
    else:
        body["proof"] = {"proof_type": "jwt", "jwt": proof_jwt}
    return http(
        "POST",
        f"{GATEWAY_BASE}/v1/issuance/credential",
        headers={"Authorization": f"Bearer {access_token}"},
        json_body=body,
    )


def _full_flow(
    *,
    org_id: str = ORG_ID,
    claims: dict | None = None,
    use_v1_proofs: bool = True,
) -> tuple[dict, dict, HttpResult]:
    """Run the full initiate → token → credential flow. Returns (initiate, token, credential_resp)."""
    tx = _initiate_issuance(org_id=org_id, claims=claims)
    tok = _exchange_token(tx["pre_auth_code"])
    proof = _build_proof_jwt(ISSUER_BASE_URL, tok["nonce"])
    cred_resp = _issue_credential(tok["access_token"], proof, use_v1_proofs=use_v1_proofs)
    return tx, tok, cred_resp


# ============================================================================
# Test Results Tracker
# ============================================================================

class Results:
    def __init__(self):
        self.passed: list[str] = []
        self.failed: list[tuple[str, str]] = []
        self.skipped: list[tuple[str, str]] = []

    def ok(self, name: str):
        self.passed.append(name)
        print(f"  ✅ {name}")

    def fail(self, name: str, reason: str):
        self.failed.append((name, reason))
        print(f"  ❌ {name}: {reason}")

    def skip(self, name: str, reason: str):
        self.skipped.append((name, reason))
        print(f"  ⏭️  {name}: {reason}")

    def summary(self) -> bool:
        total = len(self.passed) + len(self.failed) + len(self.skipped)
        print(f"\n{'='*70}")
        print(f"RESULTS: {len(self.passed)} passed, {len(self.failed)} failed, {len(self.skipped)} skipped / {total} total")
        if self.failed:
            print("\nFAILURES:")
            for name, reason in self.failed:
                print(f"  ❌ {name}: {reason}")
        if self.skipped:
            print("\nSKIPPED:")
            for name, reason in self.skipped:
                print(f"  ⏭️  {name}: {reason}")
        print(f"{'='*70}")
        return len(self.failed) == 0


R = Results()


# ============================================================================
# §12.2 — Credential Issuer Metadata
# ============================================================================

def test_issuer_metadata():
    """OID4VCI §12.2.2: Issuer Metadata well-known endpoint."""
    print("\n--- §12.2 Credential Issuer Metadata ---")

    # 1. Global metadata available
    resp = http("GET", f"{GATEWAY_BASE}/.well-known/openid-credential-issuer")
    if resp.status != 200:
        R.fail("metadata_available", f"status {resp.status}")
        return
    R.ok("metadata_available")
    meta = resp.json()

    # 2. Required field: credential_issuer
    if "credential_issuer" in meta:
        R.ok("has_credential_issuer")
    else:
        R.fail("has_credential_issuer", "missing credential_issuer")

    # 3. Required field: credential_endpoint
    if "credential_endpoint" in meta:
        R.ok("has_credential_endpoint")
    else:
        R.fail("has_credential_endpoint", "missing credential_endpoint")

    # 4. credential_configurations_supported MUST be present
    ccs = meta.get("credential_configurations_supported")
    if ccs and isinstance(ccs, dict) and len(ccs) > 0:
        R.ok("has_credential_configurations_supported")
    else:
        R.fail("has_credential_configurations_supported", f"missing or empty: {ccs!r}")

    # 5. Each config MUST have format
    if ccs:
        all_have_format = all("format" in v for v in ccs.values())
        if all_have_format:
            R.ok("configs_have_format")
        else:
            R.fail("configs_have_format", "some configs missing 'format'")

    # 6. Each config SHOULD have proof_types_supported
    if ccs:
        all_have_proof = all("proof_types_supported" in v for v in ccs.values())
        if all_have_proof:
            R.ok("configs_have_proof_types_supported")
        else:
            R.fail("configs_have_proof_types_supported", "some configs missing 'proof_types_supported'")

    # 7. token_endpoint present (not required by spec but expected when issuer == AS)
    if "token_endpoint" in meta:
        R.ok("has_token_endpoint")
    else:
        R.fail("has_token_endpoint", "missing token_endpoint (expected when issuer == AS)")

    # 8. Content-Type should be application/json
    ct = resp.headers.get("Content-Type", resp.headers.get("content-type", ""))
    if "application/json" in ct:
        R.ok("metadata_content_type_json")
    else:
        R.fail("metadata_content_type_json", f"expected application/json, got {ct!r}")


def test_issuer_metadata_per_org():
    """OID4VCI §12.2.2 insertion rule: per-org metadata."""
    print("\n--- §12.2 Per-Org Metadata (insertion rule) ---")

    resp = http("GET", f"{GATEWAY_BASE}/.well-known/openid-credential-issuer/org/{ORG_ID}")
    if resp.status != 200:
        R.fail("per_org_metadata_available", f"status {resp.status}")
        return
    R.ok("per_org_metadata_available")
    meta = resp.json()

    # credential_issuer should include org path
    ci = meta.get("credential_issuer", "")
    if f"/org/{ORG_ID}" in ci:
        R.ok("per_org_credential_issuer_includes_org")
    else:
        R.fail("per_org_credential_issuer_includes_org", f"got {ci!r}")

    # credential_configurations_supported should reflect org's types
    ccs = meta.get("credential_configurations_supported", {})
    if isinstance(ccs, dict) and len(ccs) > 0:
        R.ok("per_org_has_configs")
    else:
        R.fail("per_org_has_configs", f"empty or missing: {ccs!r}")


# ============================================================================
# RFC 8414 — OAuth AS Metadata
# ============================================================================

def test_oauth_as_metadata():
    """RFC 8414: OAuth Authorization Server Metadata."""
    print("\n--- RFC 8414 OAuth AS Metadata ---")

    # Global
    resp = http("GET", f"{GATEWAY_BASE}/.well-known/oauth-authorization-server")
    if resp.status != 200:
        R.fail("as_metadata_available", f"status {resp.status}")
        return
    R.ok("as_metadata_available")
    meta = resp.json()

    # Required: issuer
    if "issuer" in meta:
        R.ok("as_has_issuer")
    else:
        R.fail("as_has_issuer", "missing")

    # Required: token_endpoint
    if "token_endpoint" in meta:
        R.ok("as_has_token_endpoint")
    else:
        R.fail("as_has_token_endpoint", "missing")

    # grant_types_supported should include pre-authorized_code
    gts = meta.get("grant_types_supported", [])
    pre_auth_grant = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    if pre_auth_grant in gts:
        R.ok("as_supports_pre_auth_code_grant")
    else:
        R.fail("as_supports_pre_auth_code_grant", f"grant_types_supported: {gts}")

    # If authorization_code is advertised, there SHOULD be an authorization_endpoint
    if "authorization_code" in gts:
        if "authorization_endpoint" in meta:
            R.ok("as_auth_code_has_auth_endpoint")
        else:
            R.fail("as_auth_code_has_auth_endpoint",
                   "authorization_code grant advertised but no authorization_endpoint")

    # Per-org
    resp2 = http("GET", f"{GATEWAY_BASE}/.well-known/oauth-authorization-server/org/{ORG_ID}")
    if resp2.status == 200:
        R.ok("per_org_as_metadata_available")
        meta2 = resp2.json()
        issuer2 = meta2.get("issuer", "")
        if f"/org/{ORG_ID}" in issuer2:
            R.ok("per_org_as_issuer_includes_org")
        else:
            R.fail("per_org_as_issuer_includes_org", f"got {issuer2!r}")
    else:
        R.fail("per_org_as_metadata_available", f"status {resp2.status}")


# ============================================================================
# §7.2 — Token Endpoint (Pre-Authorized Code Grant)
# ============================================================================

def test_token_endpoint_happy_path():
    """OID4VCI §7.2: Token exchange with pre-authorized code."""
    print("\n--- §7.2 Token Endpoint ---")

    tx = _initiate_issuance()
    resp = http(
        "POST",
        f"{GATEWAY_BASE}/v1/issuance/token",
        form_body={
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": tx["pre_auth_code"],
        },
    )
    if resp.status != 200:
        R.fail("token_happy_path", f"status {resp.status}: {resp.text}")
        return
    tok = resp.json()
    R.ok("token_happy_path")

    # access_token present
    if tok.get("access_token"):
        R.ok("token_has_access_token")
    else:
        R.fail("token_has_access_token", "missing")

    # token_type = Bearer
    if tok.get("token_type", "").lower() == "bearer":
        R.ok("token_type_bearer")
    else:
        R.fail("token_type_bearer", f"got {tok.get('token_type')!r}")

    # expires_in present and > 0
    if isinstance(tok.get("expires_in"), int) and tok["expires_in"] > 0:
        R.ok("token_has_expires_in")
    else:
        R.fail("token_has_expires_in", f"got {tok.get('expires_in')!r}")

    # nonce present (for proof of possession)
    if tok.get("nonce"):
        R.ok("token_has_nonce")
    else:
        R.fail("token_has_nonce", f"missing nonce")

    # content-type should be application/json
    ct = resp.headers.get("Content-Type", resp.headers.get("content-type", ""))
    if "application/json" in ct:
        R.ok("token_content_type_json")
    else:
        R.fail("token_content_type_json", f"expected application/json, got {ct!r}")


def test_token_endpoint_errors():
    """OID4VCI: Token endpoint error handling."""
    print("\n--- §7.2 Token Endpoint Error Handling ---")

    # 1. Missing grant_type
    resp = http(
        "POST",
        f"{GATEWAY_BASE}/v1/issuance/token",
        form_body={"pre-authorized_code": "anything"},
    )
    if resp.status == 422 or resp.status == 400:
        R.ok("token_err_missing_grant_type")
    else:
        R.fail("token_err_missing_grant_type", f"expected 400/422, got {resp.status}")

    # 2. Unsupported grant_type → should be 400 with error=unsupported_grant_type (RFC 6749 §5.2)
    resp = http(
        "POST",
        f"{GATEWAY_BASE}/v1/issuance/token",
        form_body={
            "grant_type": "authorization_code",
            "pre-authorized_code": "anything",
        },
    )
    if resp.status == 400:
        R.ok("token_err_unsupported_grant_type_status")
        body = resp.json()
        # RFC 6749 §5.2: error response MUST include "error" field
        if "error" in body:
            R.ok("token_err_rfc6749_error_field")
        else:
            R.fail("token_err_rfc6749_error_field",
                   f"response missing 'error' field (RFC 6749 §5.2). Got: {body}")
    else:
        R.fail("token_err_unsupported_grant_type_status", f"expected 400, got {resp.status}")

    # 3. Invalid pre-authorized code → 400
    resp = http(
        "POST",
        f"{GATEWAY_BASE}/v1/issuance/token",
        form_body={
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": "invalid-code-that-does-not-exist",
        },
    )
    if resp.status == 400:
        R.ok("token_err_invalid_pre_auth_code")
    else:
        R.fail("token_err_invalid_pre_auth_code", f"expected 400, got {resp.status}")

    # 4. Replay: same pre-auth code used twice → second should fail
    tx = _initiate_issuance()
    _exchange_token(tx["pre_auth_code"])
    resp = http(
        "POST",
        f"{GATEWAY_BASE}/v1/issuance/token",
        form_body={
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": tx["pre_auth_code"],
        },
    )
    if resp.status == 400:
        R.ok("token_err_replay_pre_auth_code")
    else:
        R.fail("token_err_replay_pre_auth_code", f"expected 400 on replay, got {resp.status}")


# ============================================================================
# §8 — Credential Endpoint
# ============================================================================

def test_credential_endpoint_happy_path():
    """OID4VCI §8: Credential issuance with v1 proofs format."""
    print("\n--- §8 Credential Endpoint ---")

    tx = _initiate_issuance()
    tok = _exchange_token(tx["pre_auth_code"])
    proof = _build_proof_jwt(ISSUER_BASE_URL, tok["nonce"])
    resp = _issue_credential(tok["access_token"], proof, use_v1_proofs=True)

    if resp.status != 200:
        R.fail("credential_happy_path", f"status {resp.status}: {resp.text}")
        return
    R.ok("credential_happy_path")
    cred = resp.json()

    # credential field present and is a string (JWT)
    c = cred.get("credential")
    if isinstance(c, str) and c.count(".") >= 2:
        R.ok("credential_is_jwt_string")
    else:
        R.fail("credential_is_jwt_string", f"not a JWT string: {str(c)[:80]}")

    # Validate JWT structure: header.payload.signature
    if isinstance(c, str) and c.count(".") >= 2:
        parts = c.split(".")
        try:
            hdr_b64 = parts[0] + "=" * ((-len(parts[0])) % 4)
            hdr = json.loads(base64.urlsafe_b64decode(hdr_b64))
            if hdr.get("alg") in ("EdDSA", "ES256"):
                R.ok("credential_jwt_alg_valid")
            else:
                R.fail("credential_jwt_alg_valid", f"alg={hdr.get('alg')}")

            payload_b64 = parts[1] + "=" * ((-len(parts[1])) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            # VC-JWT: must have "vc" claim
            if "vc" in payload:
                R.ok("credential_jwt_has_vc_claim")
                vc = payload["vc"]
                # vc.type should include VerifiableCredential
                vc_type = vc.get("type", [])
                if "VerifiableCredential" in vc_type:
                    R.ok("credential_vc_type_includes_VerifiableCredential")
                else:
                    R.fail("credential_vc_type_includes_VerifiableCredential", f"type={vc_type}")
                # vc.credentialSubject should have claims
                cs = vc.get("credentialSubject", {})
                if cs:
                    R.ok("credential_has_subject_claims")
                else:
                    R.fail("credential_has_subject_claims", "credentialSubject empty")
            else:
                R.fail("credential_jwt_has_vc_claim", "payload missing 'vc' key")

            # iss should be a DID
            iss = payload.get("iss", "")
            if iss.startswith("did:"):
                R.ok("credential_iss_is_did")
            else:
                R.fail("credential_iss_is_did", f"iss={iss!r}")

            # sub should be holder DID (from proof)
            sub = payload.get("sub", "")
            if sub.startswith("did:"):
                R.ok("credential_sub_is_holder_did")
            else:
                R.fail("credential_sub_is_holder_did", f"sub={sub!r}")

        except Exception as e:
            R.fail("credential_jwt_parse", f"failed to parse JWT: {e}")

    # Content-Type should be application/json
    ct = resp.headers.get("Content-Type", resp.headers.get("content-type", ""))
    if "application/json" in ct:
        R.ok("credential_content_type_json")
    else:
        R.fail("credential_content_type_json", f"got {ct!r}")


def test_credential_endpoint_legacy_proof():
    """OID4VCI draft compat: legacy proof format (proof_type + jwt)."""
    print("\n--- §8 Credential Endpoint (legacy proof) ---")

    tx = _initiate_issuance()
    tok = _exchange_token(tx["pre_auth_code"])
    proof = _build_proof_jwt(ISSUER_BASE_URL, tok["nonce"])
    resp = _issue_credential(tok["access_token"], proof, use_v1_proofs=False)

    if resp.status == 200:
        R.ok("credential_legacy_proof_accepted")
        cred = resp.json()
        if isinstance(cred.get("credential"), str):
            R.ok("credential_legacy_proof_returns_jwt")
        else:
            R.fail("credential_legacy_proof_returns_jwt", f"got {type(cred.get('credential'))}")
    else:
        R.fail("credential_legacy_proof_accepted", f"status {resp.status}: {resp.text}")


def test_credential_endpoint_errors():
    """OID4VCI §8: Credential endpoint error handling."""
    print("\n--- §8 Credential Endpoint Error Handling ---")

    # 1. Missing Authorization header → 401
    resp = http(
        "POST",
        f"{GATEWAY_BASE}/v1/issuance/credential",
        json_body={"format": "jwt_vc_json"},
    )
    if resp.status == 401:
        R.ok("credential_err_no_auth_401")
    else:
        R.fail("credential_err_no_auth_401", f"expected 401, got {resp.status}")

    # 2. Invalid Bearer token → 401
    resp = http(
        "POST",
        f"{GATEWAY_BASE}/v1/issuance/credential",
        headers={"Authorization": "Bearer invalid-token-xxx"},
        json_body={"format": "jwt_vc_json"},
    )
    if resp.status == 401:
        R.ok("credential_err_invalid_token_401")
    else:
        R.fail("credential_err_invalid_token_401", f"expected 401, got {resp.status}")

    # 3. Token used twice (credential already issued) → should fail
    tx = _initiate_issuance()
    tok = _exchange_token(tx["pre_auth_code"])
    proof1 = _build_proof_jwt(ISSUER_BASE_URL, tok["nonce"])
    resp1 = _issue_credential(tok["access_token"], proof1)
    assert resp1.status == 200, f"first credential issuance failed: {resp1.status}"
    # Second use should fail
    proof2 = _build_proof_jwt(ISSUER_BASE_URL, tok["nonce"])
    resp2 = _issue_credential(tok["access_token"], proof2)
    if resp2.status == 400:
        R.ok("credential_err_token_replay")
    else:
        R.fail("credential_err_token_replay", f"expected 400 on second use, got {resp2.status}")


# ============================================================================
# §11 — Credential Offer
# ============================================================================

def test_credential_offer():
    """OID4VCI §11: Credential offer structure."""
    print("\n--- §11 Credential Offer ---")

    tx = _initiate_issuance()
    offer_uri = tx.get("credential_offer_uri", "")

    # 1. Offer URI has correct scheme
    if offer_uri.startswith("openid-credential-offer://"):
        R.ok("offer_uri_scheme")
    else:
        R.fail("offer_uri_scheme", f"expected openid-credential-offer://, got {offer_uri[:40]}")

    # 2. Parse offer from URI
    parsed = urllib.parse.urlparse(offer_uri)
    params = urllib.parse.parse_qs(parsed.query)

    offer_json_str = params.get("credential_offer", [None])[0]
    offer_uri_ref = params.get("credential_offer_uri", [None])[0]

    offer = None
    if offer_json_str:
        try:
            offer = json.loads(offer_json_str)
            R.ok("offer_inline_parseable")
        except json.JSONDecodeError as e:
            R.fail("offer_inline_parseable", f"invalid JSON: {e}")
    elif offer_uri_ref:
        # By-reference: fetch the offer
        resp = http("GET", offer_uri_ref)
        if resp.status == 200:
            offer = resp.json()
            R.ok("offer_by_reference_fetchable")
        else:
            R.fail("offer_by_reference_fetchable", f"status {resp.status}")
    else:
        R.fail("offer_has_credential_offer_param", "no credential_offer or credential_offer_uri param")
        return

    if not offer:
        return

    # 3. Required: credential_issuer
    if "credential_issuer" in offer:
        R.ok("offer_has_credential_issuer")
    else:
        R.fail("offer_has_credential_issuer", "missing")

    # 4. Required: credential_configuration_ids (list)
    ccids = offer.get("credential_configuration_ids")
    if isinstance(ccids, list) and len(ccids) > 0:
        R.ok("offer_has_credential_configuration_ids")
    else:
        R.fail("offer_has_credential_configuration_ids", f"got {ccids!r}")

    # 5. Required: grants
    grants = offer.get("grants", {})
    pre_auth_grant = grants.get("urn:ietf:params:oauth:grant-type:pre-authorized_code")
    if pre_auth_grant:
        R.ok("offer_has_pre_auth_grant")
        if "pre-authorized_code" in pre_auth_grant:
            R.ok("offer_grant_has_pre_auth_code")
        else:
            R.fail("offer_grant_has_pre_auth_code", "missing pre-authorized_code in grant")
    else:
        R.fail("offer_has_pre_auth_grant", "missing pre-authorized_code grant")

    # 6. Offer by-reference endpoint (GET /v1/issuance/offers/{tx_id})
    tx_id = tx.get("id")
    if tx_id:
        resp = http("GET", f"{GATEWAY_BASE}/v1/issuance/offers/{tx_id}")
        if resp.status == 200:
            ref_offer = resp.json()
            if "credential_issuer" in ref_offer and "credential_configuration_ids" in ref_offer:
                R.ok("offer_by_reference_valid")
            else:
                R.fail("offer_by_reference_valid", f"missing fields: {list(ref_offer.keys())}")
        else:
            R.fail("offer_by_reference_valid", f"status {resp.status}")


# ============================================================================
# §8.2 — Proof of Possession (Key Binding)
# ============================================================================

def test_proof_extraction():
    """OID4VCI §8.2: Proof of Possession — holder DID extraction."""
    print("\n--- §8.2 Proof of Possession ---")

    # Holder DID should appear as 'sub' in the issued VC.
    # Use a real valid Ed25519 did:key (different from the default to confirm binding).
    holder_kid = "did:key:z6Mkep5MgDkUqeGpHFhMKzDWwLRG8W8GMKJhPuPuULJQrLiy#z6Mkep5MgDkUqeGpHFhMKzDWwLRG8W8GMKJhPuPuULJQrLiy"
    expected_did = "did:key:z6Mkep5MgDkUqeGpHFhMKzDWwLRG8W8GMKJhPuPuULJQrLiy"

    tx = _initiate_issuance()
    tok = _exchange_token(tx["pre_auth_code"])
    proof = _build_proof_jwt(ISSUER_BASE_URL, tok["nonce"], holder_kid=holder_kid)
    resp = _issue_credential(tok["access_token"], proof)

    if resp.status != 200:
        R.fail("proof_holder_did_extracted", f"status {resp.status}")
        return

    cred = resp.json()
    jwt_str = cred.get("credential", "")
    parts = jwt_str.split(".")
    if len(parts) < 2:
        R.fail("proof_holder_did_extracted", "not a JWT")
        return

    payload_b64 = parts[1] + "=" * ((-len(parts[1])) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    sub = payload.get("sub", "")
    if sub == expected_did:
        R.ok("proof_holder_did_extracted")
    else:
        R.fail("proof_holder_did_extracted", f"expected sub={expected_did!r}, got {sub!r}")


# ============================================================================
# Full End-to-End Flow
# ============================================================================

def test_full_e2e_flow():
    """Complete OID4VCI flow: initiate → offer → metadata → token → credential."""
    print("\n--- Full E2E OID4VCI Flow ---")

    # 1. Initiate
    claims = {"given_name": "Alice", "family_name": "Conformance", "document_number": "E2E-001"}
    tx = _initiate_issuance(claims=claims)
    R.ok("e2e_initiate")

    # 2. Parse offer URI
    offer_uri = tx["credential_offer_uri"]
    parsed = urllib.parse.urlparse(offer_uri)
    params = urllib.parse.parse_qs(parsed.query)
    offer = json.loads(params["credential_offer"][0])

    # 3. Resolve metadata from credential_issuer
    issuer = offer["credential_issuer"]
    # Extract org_id from issuer URL (e.g. https://host/org/<id>)
    org_path = urllib.parse.urlparse(issuer).path
    # Metadata request goes to the issuer's well-known
    meta_url = f"{GATEWAY_BASE}/.well-known/openid-credential-issuer"
    if "/org/" in org_path:
        meta_url = f"{GATEWAY_BASE}/.well-known/openid-credential-issuer{org_path}"
    meta_resp = http("GET", meta_url)
    if meta_resp.status == 200:
        R.ok("e2e_metadata_fetch")
    else:
        R.fail("e2e_metadata_fetch", f"status {meta_resp.status}")
        return

    # 4. Token exchange
    pre_auth_code = offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
    tok = _exchange_token(pre_auth_code)
    R.ok("e2e_token_exchange")

    # 5. Issue credential
    proof = _build_proof_jwt(ISSUER_BASE_URL, tok["nonce"])
    cred_resp = _issue_credential(tok["access_token"], proof)
    if cred_resp.status == 200:
        R.ok("e2e_credential_issued")
        cred = cred_resp.json()
        jwt_str = cred["credential"]
        parts = jwt_str.split(".")
        payload_b64 = parts[1] + "=" * ((-len(parts[1])) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        # Verify claims appear in credential
        cs = payload.get("vc", {}).get("credentialSubject", {})
        if cs.get("given_name") == "Alice":
            R.ok("e2e_claims_in_credential")
        else:
            R.fail("e2e_claims_in_credential", f"credentialSubject: {cs}")
    else:
        R.fail("e2e_credential_issued", f"status {cred_resp.status}: {cred_resp.text}")


# ============================================================================
# Metadata Consistency
# ============================================================================

def test_metadata_consistency():
    """Cross-validate issuer metadata and OAuth AS metadata."""
    print("\n--- Metadata Consistency ---")

    issuer_resp = http("GET", f"{GATEWAY_BASE}/.well-known/openid-credential-issuer")
    as_resp = http("GET", f"{GATEWAY_BASE}/.well-known/oauth-authorization-server")

    if issuer_resp.status != 200 or as_resp.status != 200:
        R.fail("metadata_consistency_available", f"issuer={issuer_resp.status}, as={as_resp.status}")
        return

    issuer_meta = issuer_resp.json()
    as_meta = as_resp.json()

    # Token endpoints should match
    issuer_te = issuer_meta.get("token_endpoint", "")
    as_te = as_meta.get("token_endpoint", "")
    if issuer_te == as_te:
        R.ok("metadata_token_endpoints_match")
    else:
        R.fail("metadata_token_endpoints_match", f"issuer={issuer_te!r}, as={as_te!r}")

    # grant_types_supported should not advertise unimplemented grants
    gts = as_meta.get("grant_types_supported", [])
    if "authorization_code" in gts:
        # If auth_code is advertised, authorization_endpoint should exist
        if "authorization_endpoint" in as_meta:
            R.ok("metadata_auth_code_consistent")
        else:
            R.fail("metadata_auth_code_consistent",
                   "authorization_code in grant_types_supported but no authorization_endpoint")
    else:
        R.ok("metadata_auth_code_consistent")


# ============================================================================
# NEW: OIDF-Mirrored Tests (OID4VCI 1.0 Final)
# All tests below route through the gateway (GATEWAY_BASE) and mirror the
# OIDF conformance suite module names from vci10issuer/.
# ============================================================================


# ---------------------------------------------------------------------------
# A. Metadata — OIDF: VCIIssuerMetadataTest conditions
# ---------------------------------------------------------------------------

def test_issuer_metadata_required_fields():
    """OID4VCI-1FINAL §12.2.3: Required metadata fields present and valid.

    OIDF: VCIIssuerMetadataTest
    Validates: credential_issuer (MUST be URL), credential_configurations_supported
    (MUST be object), credential_endpoint (MUST be URL).
    Also checks for Final-spec endpoints: nonce_endpoint (§7),
    deferred_credential_endpoint (§9), notification_endpoint (§11).
    """
    print("\n--- VCIIssuerMetadataTest: Required Fields (§12.2.3) ---")
    resp = http("GET", f"{GATEWAY_BASE}/.well-known/openid-credential-issuer/org/{ORG_ID}")
    assert resp.status == 200, f"metadata not available: {resp.status}"
    meta = resp.json()

    # credential_issuer MUST be a URL
    ci = meta.get("credential_issuer", "")
    if ci.startswith(("http://", "https://")):
        R.ok("VCIIssuerMetadataTest.credential_issuer_is_url")
    else:
        R.fail("VCIIssuerMetadataTest.credential_issuer_is_url",
               f"OID4VCI-1FINAL §12.2.3: credential_issuer MUST be URL, got {ci!r}")

    # credential_endpoint MUST be a URL
    ce = meta.get("credential_endpoint", "")
    if ce.startswith(("http://", "https://")):
        R.ok("VCIIssuerMetadataTest.credential_endpoint_is_url")
    else:
        R.fail("VCIIssuerMetadataTest.credential_endpoint_is_url",
               f"OID4VCI-1FINAL §12.2.3: credential_endpoint MUST be URL, got {ce!r}")

    # credential_configurations_supported MUST be an object
    ccs = meta.get("credential_configurations_supported")
    if isinstance(ccs, dict) and len(ccs) > 0:
        R.ok("VCIIssuerMetadataTest.credential_configurations_supported_is_object")
    else:
        R.fail("VCIIssuerMetadataTest.credential_configurations_supported_is_object",
               f"OID4VCI-1FINAL §12.2.3: MUST be non-empty object, got {type(ccs).__name__}")

    # nonce_endpoint presence (FINAL spec §7 — replaces c_nonce in token response)
    if "nonce_endpoint" in meta:
        ne = meta["nonce_endpoint"]
        if ne.startswith(("http://", "https://")):
            R.ok("VCIIssuerMetadataTest.nonce_endpoint_is_url")
        else:
            R.fail("VCIIssuerMetadataTest.nonce_endpoint_is_url",
                   f"OID4VCI-1FINAL §7: nonce_endpoint MUST be URL, got {ne!r}")
    else:
        R.fail("VCIIssuerMetadataTest.nonce_endpoint_present",
               "OID4VCI-1FINAL §7: nonce_endpoint MUST be present (Final spec — not implemented)")

    # deferred_credential_endpoint (§9 — optional but expected for certification)
    if "deferred_credential_endpoint" in meta:
        R.ok("VCIIssuerMetadataTest.deferred_credential_endpoint_present")
    else:
        R.fail("VCIIssuerMetadataTest.deferred_credential_endpoint_present",
               "OID4VCI-1FINAL §9: deferred_credential_endpoint not present (missing feature)")

    # notification_endpoint (§11 — optional but expected for certification)
    if "notification_endpoint" in meta:
        R.ok("VCIIssuerMetadataTest.notification_endpoint_present")
    else:
        R.fail("VCIIssuerMetadataTest.notification_endpoint_present",
               "OID4VCI-1FINAL §11: notification_endpoint not present (missing feature)")


def test_issuer_metadata_credential_configurations_format():
    """OID4VCI-1FINAL Appendix A: format field in each credential configuration.

    OIDF: VCIIssuerMetadataTest
    Each config MUST have `format`. Valid Final-spec values: jwt_vc_json, ldp_vc,
    mso_mdoc, dc+sd-jwt. Reports if Draft convention (vc+sd-jwt) is used instead.
    """
    print("\n--- VCIIssuerMetadataTest: Format Fields (Appendix A) ---")
    resp = http("GET", f"{GATEWAY_BASE}/.well-known/openid-credential-issuer/org/{ORG_ID}")
    assert resp.status == 200, f"metadata not available: {resp.status}"
    meta = resp.json()
    ccs = meta.get("credential_configurations_supported", {})

    FINAL_FORMATS = {"jwt_vc_json", "ldp_vc", "mso_mdoc", "dc+sd-jwt"}
    DRAFT_FORMATS = {"vc+sd-jwt", "jwt_vc"}

    observed_formats: set[str] = set()
    missing_format = []
    for key, cfg in ccs.items():
        fmt = cfg.get("format")
        if fmt is None:
            missing_format.append(key)
        else:
            observed_formats.add(fmt)

    if missing_format:
        R.fail("VCIIssuerMetadataTest.all_configs_have_format",
               f"OID4VCI-1FINAL Appendix A: configs missing format: {missing_format}")
    else:
        R.ok("VCIIssuerMetadataTest.all_configs_have_format")

    draft_detected = observed_formats & DRAFT_FORMATS
    if draft_detected:
        R.fail("VCIIssuerMetadataTest.format_ids_are_final_spec",
               f"OID4VCI-1FINAL Appendix A: Draft format IDs detected: {draft_detected}. "
               f"Final spec uses dc+sd-jwt, not vc+sd-jwt")
    else:
        R.ok("VCIIssuerMetadataTest.format_ids_are_final_spec")


def test_issuer_metadata_authorization_servers():
    """OID4VCI-1FINAL §12.2.3: authorization_servers array, if present, each URI resolvable.

    OIDF: VCIIssuerMetadataTest
    If absent, credential issuer URL itself is the authorization server.
    """
    print("\n--- VCIIssuerMetadataTest: authorization_servers (§12.2.3) ---")
    resp = http("GET", f"{GATEWAY_BASE}/.well-known/openid-credential-issuer/org/{ORG_ID}")
    assert resp.status == 200, f"metadata not available: {resp.status}"
    meta = resp.json()

    auth_servers = meta.get("authorization_servers")
    if auth_servers is None:
        # Issuer itself is the AS — check that token_endpoint is present
        if "token_endpoint" in meta:
            R.ok("VCIIssuerMetadataTest.as_self_has_token_endpoint")
        else:
            R.fail("VCIIssuerMetadataTest.as_self_has_token_endpoint",
                   "OID4VCI-1FINAL §12.2.3: No authorization_servers and no token_endpoint in issuer metadata")
    else:
        # Each entry MUST be a URL
        for uri in auth_servers:
            if isinstance(uri, str) and uri.startswith(("http://", "https://")):
                R.ok(f"VCIIssuerMetadataTest.auth_server_uri_valid[{uri[:40]}]")
            else:
                R.fail(f"VCIIssuerMetadataTest.auth_server_uri_valid",
                       f"OID4VCI-1FINAL §12.2.3: authorization_servers entry must be URL, got {uri!r}")


# ---------------------------------------------------------------------------
# B. Nonce Endpoint — OIDF: AbstractVCIIssuerTestModule.afterNonceEndpointResponse()
# ---------------------------------------------------------------------------

def test_nonce_endpoint_happy_path():
    """OID4VCI-1FINAL §7.1-§7.2: Nonce endpoint happy path.

    OIDF: AbstractVCIIssuerTestModule (nonce endpoint step)
    POST to nonce_endpoint: response MUST be 200, Content-Type application/json,
    MUST contain c_nonce string. Cache-Control MUST include no-store.
    """
    print("\n--- §7 Nonce Endpoint Happy Path ---")
    resp = _call_nonce_endpoint()
    if resp.status != 200:
        R.fail("nonce_endpoint.happy_path",
               f"OID4VCI-1FINAL §7.1: POST to nonce_endpoint MUST return 200, got {resp.status}: {resp.text}")
        return
    R.ok("nonce_endpoint.happy_path")

    body = resp.json()
    c_nonce = body.get("c_nonce")
    if isinstance(c_nonce, str) and len(c_nonce) > 0:
        R.ok("nonce_endpoint.c_nonce_present")
    else:
        R.fail("nonce_endpoint.c_nonce_present",
               f"OID4VCI-1FINAL §7.2: response MUST contain c_nonce string, got {c_nonce!r}")

    ct = resp.headers.get("content-type", resp.headers.get("Content-Type", ""))
    if "application/json" in ct:
        R.ok("nonce_endpoint.content_type_json")
    else:
        R.fail("nonce_endpoint.content_type_json",
               f"OID4VCI-1FINAL §7.2: Content-Type MUST be application/json, got {ct!r}")

    cc = resp.headers.get("cache-control", resp.headers.get("Cache-Control", ""))
    if "no-store" in cc:
        R.ok("nonce_endpoint.cache_control_no_store")
    else:
        R.fail("nonce_endpoint.cache_control_no_store",
               f"OID4VCI-1FINAL §7.2: Cache-Control MUST include no-store, got {cc!r}")


def test_nonce_endpoint_nonce_uniqueness():
    """OID4VCI-1FINAL §7.2: Two consecutive nonce requests MUST return different c_nonce values.

    OIDF: AbstractVCIIssuerTestModule (nonce uniqueness check)
    """
    print("\n--- §7 Nonce Uniqueness ---")
    resp1 = _call_nonce_endpoint()
    resp2 = _call_nonce_endpoint()

    if resp1.status != 200 or resp2.status != 200:
        R.fail("nonce_endpoint.uniqueness",
               f"OID4VCI-1FINAL §7.2: nonce endpoint not available ({resp1.status}, {resp2.status})")
        return

    n1 = resp1.json().get("c_nonce", "")
    n2 = resp2.json().get("c_nonce", "")

    if n1 and n2 and n1 != n2:
        R.ok("nonce_endpoint.uniqueness")
    elif n1 == n2:
        R.fail("nonce_endpoint.uniqueness",
               f"OID4VCI-1FINAL §7.2: nonce MUST be unique per request, but got same value twice: {n1!r}")
    else:
        R.fail("nonce_endpoint.uniqueness",
               f"OID4VCI-1FINAL §7.2: could not retrieve c_nonce from both responses")


# ---------------------------------------------------------------------------
# C. Credential Endpoint — OIDF: VCIIssuerHappyFlow
# ---------------------------------------------------------------------------

def test_issuer_happy_flow():
    """Full OID4VCI 1.0 Final happy flow including nonce endpoint.

    OIDF: VCIIssuerHappyFlow
    initiate → offer → metadata → token → nonce endpoint → credential with proofs object.
    OID4VCI-1FINAL §8.3: response MUST be 200, Content-Type application/json.
    Detects Draft (credential string) vs Final (credentials array) convention.
    """
    print("\n--- VCIIssuerHappyFlow (§8.3) ---")
    tx = _initiate_issuance()
    tok = _exchange_token(tx["pre_auth_code"])

    # Prefer nonce from nonce endpoint (Final spec), fall back to token response (Draft).
    # Pass the access_token so the server updates the stored c_nonce for this transaction,
    # ensuring the proof nonce matches what the server expects at the credential endpoint.
    nonce_resp = _call_nonce_endpoint(access_token=tok.get("access_token"))
    if nonce_resp.status == 200:
        nonce = nonce_resp.json().get("c_nonce", tok.get("nonce", ""))
        R.ok("VCIIssuerHappyFlow.nonce_from_nonce_endpoint")
    else:
        nonce = tok.get("nonce") or tok.get("c_nonce", "")
        R.fail("VCIIssuerHappyFlow.nonce_from_nonce_endpoint",
               "OID4VCI-1FINAL §7: nonce endpoint not available, fell back to token response nonce")

    proof = _build_proof_jwt(ISSUER_BASE_URL, nonce)
    resp = _issue_credential(tok["access_token"], proof, use_v1_proofs=True)

    if resp.status != 200:
        R.fail("VCIIssuerHappyFlow.credential_response_200",
               f"OID4VCI-1FINAL §8.3: MUST return 200, got {resp.status}: {resp.text}")
        return
    R.ok("VCIIssuerHappyFlow.credential_response_200")

    body = resp.json()
    # Detect Final (credentials array) vs Draft (credential string)
    if "credentials" in body and isinstance(body["credentials"], list):
        R.ok("VCIIssuerHappyFlow.response_uses_final_credentials_array")
    elif "credential" in body:
        R.fail("VCIIssuerHappyFlow.response_uses_final_credentials_array",
               "OID4VCI-1FINAL §8.3: response uses Draft 'credential' string instead of Final 'credentials' array")
    else:
        R.fail("VCIIssuerHappyFlow.response_uses_final_credentials_array",
               f"OID4VCI-1FINAL §8.3: no 'credentials' or 'credential' in response: {list(body.keys())}")


def test_issuer_happy_flow_additional_requests():
    """Multiple credential requests in same session (nonce rotation).

    OIDF: VCIIssuerHappyFlowAdditionalRequests
    After first credential, request same credential again with fresh nonce from
    nonce endpoint. OID4VCI-1FINAL §7 & §8: nonce MUST rotate between requests.
    """
    print("\n--- VCIIssuerHappyFlowAdditionalRequests ---")
    tx = _initiate_issuance()
    tok = _exchange_token(tx["pre_auth_code"])
    nonce = tok.get("nonce") or tok.get("c_nonce", "")

    # First request
    proof1 = _build_proof_jwt(ISSUER_BASE_URL, nonce)
    resp1 = _issue_credential(tok["access_token"], proof1)
    if resp1.status != 200:
        R.fail("VCIIssuerHappyFlowAdditionalRequests.first_request",
               f"status {resp1.status}: {resp1.text}")
        return
    R.ok("VCIIssuerHappyFlowAdditionalRequests.first_request")

    # Check for new nonce via nonce endpoint (Final spec §7)
    nonce_resp = _call_nonce_endpoint()
    if nonce_resp.status == 200:
        new_nonce = nonce_resp.json().get("c_nonce", "")
        if new_nonce and new_nonce != nonce:
            R.ok("VCIIssuerHappyFlowAdditionalRequests.nonce_rotated")
        else:
            R.fail("VCIIssuerHappyFlowAdditionalRequests.nonce_rotated",
                   f"OID4VCI-1FINAL §7: nonce did not rotate (old={nonce!r}, new={new_nonce!r})")
    else:
        R.fail("VCIIssuerHappyFlowAdditionalRequests.nonce_rotated",
               "OID4VCI-1FINAL §7: nonce endpoint unavailable — cannot validate nonce rotation")


def test_issuer_happy_flow_sd_jwt():
    """OID4VCI 1.0 Final happy flow requesting dc+sd-jwt (or vc+sd-jwt) format.

    OIDF: VCIIssuerHappyFlow (sd-jwt variant)
    OID4VCI-1FINAL Appendix A.3: format id is dc+sd-jwt (Final) or vc+sd-jwt (Draft).
    SD-JWT VC MUST have: iss (HTTPS URI), iat, vct. Header typ MUST be vc+sd-jwt.
    """
    print("\n--- VCIIssuerHappyFlow (dc+sd-jwt) ---")
    meta_resp = http("GET", f"{GATEWAY_BASE}/.well-known/openid-credential-issuer/org/{ORG_ID}")
    if meta_resp.status != 200:
        R.fail("VCIIssuerHappyFlow.sd_jwt.metadata", f"status {meta_resp.status}")
        return
    meta = meta_resp.json()
    ccs = meta.get("credential_configurations_supported", {})

    sd_jwt_format = None
    for config_id, cfg in ccs.items():
        fmt = cfg.get("format", "")
        if fmt in ("dc+sd-jwt", "vc+sd-jwt"):
            sd_jwt_format = fmt
            break

    if sd_jwt_format is None:
        R.fail("VCIIssuerHappyFlow.sd_jwt.format_in_metadata",
               "OID4VCI-1FINAL Appendix A.3: No dc+sd-jwt or vc+sd-jwt format in credential_configurations_supported")
        return
    R.ok(f"VCIIssuerHappyFlow.sd_jwt.format_in_metadata [{sd_jwt_format}]")

    tx = _initiate_issuance()
    tok = _exchange_token(tx["pre_auth_code"])
    nonce = tok.get("nonce") or tok.get("c_nonce", "")
    proof = _build_proof_jwt(ISSUER_BASE_URL, nonce)
    resp = _issue_credential(tok["access_token"], proof, format=sd_jwt_format)

    if resp.status != 200:
        R.fail("VCIIssuerHappyFlow.sd_jwt.issued", f"status {resp.status}: {resp.text}")
        return
    R.ok("VCIIssuerHappyFlow.sd_jwt.issued")

    body = resp.json()
    sd_jwt_str = body.get("credential") or (body.get("credentials", [None])[0] if "credentials" in body else None)
    if sd_jwt_str is None:
        R.fail("VCIIssuerHappyFlow.sd_jwt.credential_in_response", "no credential field")
        return

    # SD-JWT has ~ separators or is a plain JWT; validate header
    core_jwt = sd_jwt_str.split("~")[0] if "~" in sd_jwt_str else sd_jwt_str
    parts = core_jwt.split(".")
    if len(parts) >= 2:
        try:
            hdr_b64 = parts[0] + "=" * ((-len(parts[0])) % 4)
            hdr = json.loads(base64.urlsafe_b64decode(hdr_b64))
            if hdr.get("typ") == "vc+sd-jwt":
                R.ok("VCIIssuerHappyFlow.sd_jwt.typ_header")
            else:
                R.fail("VCIIssuerHappyFlow.sd_jwt.typ_header",
                       f"SD-JWT VC spec: typ MUST be vc+sd-jwt, got {hdr.get('typ')!r}")
        except Exception as e:
            R.fail("VCIIssuerHappyFlow.sd_jwt.parse", f"failed to parse SD-JWT header: {e}")
    else:
        R.fail("VCIIssuerHappyFlow.sd_jwt.parse", "not a JWT structure")


def test_issuer_happy_flow_mso_mdoc():
    """OID4VCI 1.0 Final happy flow requesting mso_mdoc format.

    OIDF: VCIIssuerHappyFlow (mdoc variant)
    OID4VCI-1FINAL Appendix A.2: response contains unpadded base64url-encoded
    IssuerSigned CBOR structure.
    """
    print("\n--- VCIIssuerHappyFlow (mso_mdoc) ---")
    meta_resp = http("GET", f"{GATEWAY_BASE}/.well-known/openid-credential-issuer/org/{ORG_ID}")
    if meta_resp.status != 200:
        R.fail("VCIIssuerHappyFlow.mdoc.metadata", f"status {meta_resp.status}")
        return
    meta = meta_resp.json()
    ccs = meta.get("credential_configurations_supported", {})

    has_mdoc = any(v.get("format") == "mso_mdoc" for v in ccs.values())
    if not has_mdoc:
        R.fail("VCIIssuerHappyFlow.mdoc.format_in_metadata",
               "OID4VCI-1FINAL Appendix A.2: mso_mdoc not in credential_configurations_supported")
        return
    R.ok("VCIIssuerHappyFlow.mdoc.format_in_metadata")

    tx = _initiate_issuance()
    tok = _exchange_token(tx["pre_auth_code"])
    nonce = tok.get("nonce") or tok.get("c_nonce", "")
    proof = _build_proof_jwt(ISSUER_BASE_URL, nonce)
    resp = _issue_credential(tok["access_token"], proof, format="mso_mdoc")

    if resp.status != 200:
        R.fail("VCIIssuerHappyFlow.mdoc.issued",
               f"OID4VCI-1FINAL Appendix A.2: mso_mdoc issuance MUST succeed, got {resp.status}: {resp.text}")
        return
    R.ok("VCIIssuerHappyFlow.mdoc.issued")

    body = resp.json()
    mdoc_b64 = body.get("credential") or (body.get("credentials", [None])[0] if "credentials" in body else None)
    if isinstance(mdoc_b64, str):
        try:
            raw = base64.urlsafe_b64decode(mdoc_b64 + "==")
            if len(raw) > 0:
                R.ok("VCIIssuerHappyFlow.mdoc.base64url_decodeable")
            else:
                R.fail("VCIIssuerHappyFlow.mdoc.base64url_decodeable", "decoded to empty bytes")
        except Exception as e:
            R.fail("VCIIssuerHappyFlow.mdoc.base64url_decodeable",
                   f"OID4VCI-1FINAL Appendix A.2: MUST be base64url-encoded CBOR: {e}")
    else:
        R.fail("VCIIssuerHappyFlow.mdoc.credential_in_response",
               f"no credential string in response: {list(body.keys())}")


# ---------------------------------------------------------------------------
# D. Negative Tests — mirroring OIDF negative test modules
# ---------------------------------------------------------------------------

def test_issuer_fail_on_invalid_nonce():
    """Send credential request with deliberately wrong nonce in JWT proof.

    OIDF: VCIIssuerFailOnInvalidNonce
    OID4VCI-1FINAL Appendix F.4: Issuer MUST verify nonce matches issued c_nonce.
    Expect HTTP 400 with error response.
    """
    print("\n--- VCIIssuerFailOnInvalidNonce (Appendix F.4) ---")
    tx = _initiate_issuance()
    tok = _exchange_token(tx["pre_auth_code"])
    proof = _build_proof_jwt(ISSUER_BASE_URL, "this-is-not-the-nonce")
    resp = _issue_credential(tok["access_token"], proof)
    if resp.status == 400:
        R.ok("VCIIssuerFailOnInvalidNonce")
        body = resp.json()
        if "error" in body:
            R.ok("VCIIssuerFailOnInvalidNonce.rfc6749_error_field")
        else:
            R.fail("VCIIssuerFailOnInvalidNonce.rfc6749_error_field",
                   f"RFC 6749 §5.2: error response MUST have 'error' field, got: {body}")
    else:
        R.fail("VCIIssuerFailOnInvalidNonce",
               f"OID4VCI-1FINAL Appendix F.4: invalid nonce MUST be rejected with 400, got {resp.status}: {resp.text}")


def test_issuer_fail_on_replay_nonce():
    """Use same nonce twice — second request MUST fail.

    OIDF: VCIIssuerFailOnReplayNonce
    OID4VCI-1FINAL §7: nonce is single-use.
    """
    print("\n--- VCIIssuerFailOnReplayNonce (§7) ---")
    tx = _initiate_issuance()
    tok = _exchange_token(tx["pre_auth_code"])
    nonce = tok.get("nonce") or tok.get("c_nonce", "")

    proof1 = _build_proof_jwt(ISSUER_BASE_URL, nonce)
    resp1 = _issue_credential(tok["access_token"], proof1)
    if resp1.status != 200:
        R.fail("VCIIssuerFailOnReplayNonce.first_request_succeeds",
               f"first request should succeed: {resp1.status}")
        return
    R.ok("VCIIssuerFailOnReplayNonce.first_request_succeeds")

    # Replay: use the same nonce again with a new token
    tx2 = _initiate_issuance()
    tok2 = _exchange_token(tx2["pre_auth_code"])
    proof2 = _build_proof_jwt(ISSUER_BASE_URL, nonce)  # same nonce, new token
    resp2 = _issue_credential(tok2["access_token"], proof2)
    if resp2.status == 400:
        R.ok("VCIIssuerFailOnReplayNonce.replay_rejected")
    else:
        R.fail("VCIIssuerFailOnReplayNonce.replay_rejected",
               f"OID4VCI-1FINAL §7: replayed nonce MUST be rejected with 400, got {resp2.status}")


def test_issuer_fail_on_invalid_jwt_proof_signature():
    """Send JWT proof with corrupted signature — issuer MUST reject.

    OIDF: VCIIssuerFailOnInvalidJwtProofSignature
    OID4VCI-1FINAL Appendix F.4: Issuer MUST verify proof signature.
    NOTE: dummy signatures are used throughout this suite. If the server currently
    doesn't verify signatures, this test will FAIL — exposing the missing feature.
    """
    print("\n--- VCIIssuerFailOnInvalidJwtProofSignature (Appendix F.4) ---")
    tx = _initiate_issuance()
    tok = _exchange_token(tx["pre_auth_code"])
    nonce = tok.get("nonce") or tok.get("c_nonce", "")

    header = {"alg": "EdDSA", "typ": "openid4vci-proof+jwt", "kid": "did:key:z6MkBad#z6MkBad"}
    payload = {"iss": "did:key:z6MkBad", "aud": ISSUER_BASE_URL, "iat": int(time.time()), "nonce": nonce}
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    bad_sig = base64.urlsafe_b64encode(b"\xff" * 64).rstrip(b"=").decode()
    bad_proof = f"{h}.{p}.{bad_sig}"

    resp = _issue_credential(tok["access_token"], bad_proof)
    if resp.status == 400:
        R.ok("VCIIssuerFailOnInvalidJwtProofSignature")
    else:
        R.fail("VCIIssuerFailOnInvalidJwtProofSignature",
               f"OID4VCI-1FINAL Appendix F.4: invalid signature MUST be rejected with 400, "
               f"got {resp.status}. NOTE: server likely not verifying signatures yet.")


def test_issuer_fail_on_missing_proof():
    """Send credential request without any proof — issuer MUST reject.

    OIDF: VCIIssuerFailOnMissingProof
    OID4VCI-1FINAL §8.2: If credential config has proof_types_supported,
    issuer MUST reject request with no proof with HTTP 400.
    """
    print("\n--- VCIIssuerFailOnMissingProof (§8.2) ---")
    tx = _initiate_issuance()
    tok = _exchange_token(tx["pre_auth_code"])

    resp = http(
        "POST",
        f"{GATEWAY_BASE}/v1/issuance/credential",
        headers={"Authorization": f"Bearer {tok['access_token']}"},
        json_body={"format": "jwt_vc_json"},
    )
    if resp.status == 400:
        R.ok("VCIIssuerFailOnMissingProof")
    else:
        R.fail("VCIIssuerFailOnMissingProof",
               f"OID4VCI-1FINAL §8.2: missing proof MUST return 400, got {resp.status}: {resp.text}")


def test_issuer_fail_on_unknown_credential_configuration_id():
    """Send credential request with unknown credential_configuration_id.

    OIDF: VCIIssuerFailOnUnknownCredentialConfigurationId
    OID4VCI-1FINAL §8.2: Issuer MUST reject with 400 if
    credential_configuration_id is not in credential_configurations_supported.
    """
    print("\n--- VCIIssuerFailOnUnknownCredentialConfigurationId (§8.2) ---")
    tx = _initiate_issuance()
    tok = _exchange_token(tx["pre_auth_code"])
    nonce = tok.get("nonce") or tok.get("c_nonce", "")
    proof = _build_proof_jwt(ISSUER_BASE_URL, nonce)

    resp = _issue_credential(
        tok["access_token"], proof,
        credential_configuration_id="this-does-not-exist-xyz",
    )
    if resp.status == 400:
        R.ok("VCIIssuerFailOnUnknownCredentialConfigurationId")
    else:
        R.fail("VCIIssuerFailOnUnknownCredentialConfigurationId",
               f"OID4VCI-1FINAL §8.2: unknown credential_configuration_id MUST return 400, "
               f"got {resp.status}: {resp.text}")


def test_issuer_fail_on_unknown_credential_identifier():
    """Send credential request with unknown credential_identifier.

    OIDF: VCIIssuerFailOnUnknownCredentialIdentifier
    OID4VCI-1FINAL §8.2: Issuer MUST reject unknown credential_identifier with 400.
    """
    print("\n--- VCIIssuerFailOnUnknownCredentialIdentifier (§8.2) ---")
    tx = _initiate_issuance()
    tok = _exchange_token(tx["pre_auth_code"])
    nonce = tok.get("nonce") or tok.get("c_nonce", "")
    proof = _build_proof_jwt(ISSUER_BASE_URL, nonce)

    resp = _issue_credential(
        tok["access_token"], proof,
        credential_identifier="identifier-that-does-not-exist-9999",
    )
    if resp.status == 400:
        R.ok("VCIIssuerFailOnUnknownCredentialIdentifier")
    else:
        R.fail("VCIIssuerFailOnUnknownCredentialIdentifier",
               f"OID4VCI-1FINAL §8.2: unknown credential_identifier MUST return 400, "
               f"got {resp.status}: {resp.text}")


def test_issuer_fail_on_access_token_in_query():
    """Access token sent as query param instead of Authorization header MUST be rejected.

    OIDF: VCIIssuerFailOnRequestWithAccessTokenInQuery
    RFC 6750 §2.3 / OID4VCI-1FINAL §8: NOT RECOMMENDED; SHOULD reject with 400 or 401.
    """
    print("\n--- VCIIssuerFailOnRequestWithAccessTokenInQuery (RFC 6750 §2.3) ---")
    tx = _initiate_issuance()
    tok = _exchange_token(tx["pre_auth_code"])
    nonce = tok.get("nonce") or tok.get("c_nonce", "")
    proof = _build_proof_jwt(ISSUER_BASE_URL, nonce)

    body = {"format": "jwt_vc_json", "proofs": {"jwt": [proof]}}
    url = f"{GATEWAY_BASE}/v1/issuance/credential?access_token={tok['access_token']}"
    resp = http("POST", url, json_body=body)
    if resp.status in (400, 401):
        R.ok("VCIIssuerFailOnRequestWithAccessTokenInQuery")
    else:
        R.fail("VCIIssuerFailOnRequestWithAccessTokenInQuery",
               f"RFC 6750 §2.3: access token in query SHOULD be rejected with 400/401, "
               f"got {resp.status}")


# ---------------------------------------------------------------------------
# E. Deferred Credential — OID4VCI-1FINAL §9
# ---------------------------------------------------------------------------

def test_deferred_credential_endpoint():
    """POST to deferred_credential_endpoint with transaction_id.

    OID4VCI-1FINAL §9.1: Response MUST be 200 with credential or 202 (pending).
    §9.3: interval REQUIRED when still pending.
    This test WILL FAIL if deferred credential endpoint is not implemented.
    """
    print("\n--- §9 Deferred Credential Endpoint ---")
    meta_resp = http("GET", f"{GATEWAY_BASE}/.well-known/openid-credential-issuer/org/{ORG_ID}")
    if meta_resp.status != 200:
        R.fail("deferred_credential.endpoint_in_metadata", f"metadata status {meta_resp.status}")
        return
    meta = meta_resp.json()
    deferred_ep = meta.get("deferred_credential_endpoint")
    if not deferred_ep:
        R.fail("deferred_credential.endpoint_in_metadata",
               "OID4VCI-1FINAL §9: deferred_credential_endpoint not in metadata (not implemented)")
        return
    R.ok("deferred_credential.endpoint_in_metadata")

    tx = _initiate_issuance()
    tok = _exchange_token(tx["pre_auth_code"])
    nonce = tok.get("nonce") or tok.get("c_nonce", "")
    proof = _build_proof_jwt(ISSUER_BASE_URL, nonce)

    issue_resp = _issue_credential(tok["access_token"], proof)
    if issue_resp.status == 202:
        txn_id = issue_resp.json().get("transaction_id")
        if not txn_id:
            R.fail("deferred_credential.transaction_id_in_202",
                   "OID4VCI-1FINAL §9.1: 202 response MUST contain transaction_id")
            return
        R.ok("deferred_credential.transaction_id_in_202")

        deferred_resp = http(
            "POST",
            deferred_ep,
            headers={"Authorization": f"Bearer {tok['access_token']}"},
            json_body={"transaction_id": txn_id},
        )
        if deferred_resp.status in (200, 202):
            R.ok("deferred_credential.poll_accepted")
        else:
            R.fail("deferred_credential.poll_accepted",
                   f"OID4VCI-1FINAL §9.1: deferred endpoint MUST return 200 or 202, "
                   f"got {deferred_resp.status}: {deferred_resp.text}")
    elif issue_resp.status == 200:
        R.ok("deferred_credential.synchronous_fallback")
    else:
        R.fail("deferred_credential.issue_failed",
               f"OID4VCI-1FINAL §9: credential endpoint returned {issue_resp.status}: {issue_resp.text}")


# ---------------------------------------------------------------------------
# F. Notification Endpoint — OID4VCI-1FINAL §11
# ---------------------------------------------------------------------------

def test_notification_endpoint_credential_accepted():
    """POST notification_id + event=credential_accepted to notification endpoint.

    OIDF: VCIIssuerHappyFlow (notification step)
    OID4VCI-1FINAL §11.1-§11.2: Response MUST be 2xx (204 recommended).
    This test WILL FAIL if notification endpoint is not implemented.
    """
    print("\n--- §11 Notification Endpoint (credential_accepted) ---")
    meta_resp = http("GET", f"{GATEWAY_BASE}/.well-known/openid-credential-issuer/org/{ORG_ID}")
    if meta_resp.status != 200:
        R.fail("notification_endpoint.in_metadata", f"metadata status {meta_resp.status}")
        return
    notif_ep = meta_resp.json().get("notification_endpoint")
    if not notif_ep:
        R.fail("notification_endpoint.in_metadata",
               "OID4VCI-1FINAL §11: notification_endpoint not in metadata (not implemented)")
        return
    R.ok("notification_endpoint.in_metadata")
    notif_ep = _localize_url(notif_ep)

    tx = _initiate_issuance()
    tok = _exchange_token(tx["pre_auth_code"])
    nonce = tok.get("nonce") or tok.get("c_nonce", "")
    proof = _build_proof_jwt(ISSUER_BASE_URL, nonce)
    issue_resp = _issue_credential(tok["access_token"], proof)
    if issue_resp.status != 200:
        R.fail("notification_endpoint.credential_accepted.prereq",
               f"credential issuance failed: {issue_resp.status}")
        return

    notif_id = issue_resp.json().get("notification_id")
    if not notif_id:
        R.fail("notification_endpoint.notification_id_in_response",
               "OID4VCI-1FINAL §11: credential response MUST contain notification_id when endpoint is available")
        return
    R.ok("notification_endpoint.notification_id_in_response")

    notif_resp = http(
        "POST",
        notif_ep,
        headers={"Authorization": f"Bearer {tok['access_token']}"},
        json_body={"notification_id": notif_id, "event": "credential_accepted"},
    )
    if 200 <= notif_resp.status < 300:
        R.ok("notification_endpoint.credential_accepted")
    else:
        R.fail("notification_endpoint.credential_accepted",
               f"OID4VCI-1FINAL §11.2: notification MUST return 2xx, got {notif_resp.status}: {notif_resp.text}")


def test_notification_endpoint_credential_deleted():
    """POST event=credential_deleted to notification endpoint.

    OID4VCI-1FINAL §11.1: Notification event types include credential_deleted.
    This test WILL FAIL if notification endpoint is not implemented.
    """
    print("\n--- §11 Notification Endpoint (credential_deleted) ---")
    meta_resp = http("GET", f"{GATEWAY_BASE}/.well-known/openid-credential-issuer/org/{ORG_ID}")
    if meta_resp.status != 200:
        R.fail("notification_deleted.in_metadata", f"metadata status {meta_resp.status}")
        return
    notif_ep = meta_resp.json().get("notification_endpoint")
    if not notif_ep:
        R.fail("notification_deleted.in_metadata",
               "OID4VCI-1FINAL §11: notification_endpoint not implemented")
        return
    notif_ep = _localize_url(notif_ep)

    tx = _initiate_issuance()
    tok = _exchange_token(tx["pre_auth_code"])
    nonce = tok.get("nonce") or tok.get("c_nonce", "")
    proof = _build_proof_jwt(ISSUER_BASE_URL, nonce)
    issue_resp = _issue_credential(tok["access_token"], proof)
    if issue_resp.status != 200:
        R.fail("notification_deleted.prereq", f"{issue_resp.status}")
        return

    notif_id = issue_resp.json().get("notification_id", "fake-id")
    notif_resp = http(
        "POST",
        notif_ep,
        headers={"Authorization": f"Bearer {tok['access_token']}"},
        json_body={"notification_id": notif_id, "event": "credential_deleted"},
    )
    if 200 <= notif_resp.status < 300:
        R.ok("notification_endpoint.credential_deleted")
    else:
        R.fail("notification_endpoint.credential_deleted",
               f"OID4VCI-1FINAL §11.2: MUST return 2xx, got {notif_resp.status}: {notif_resp.text}")


# ---------------------------------------------------------------------------
# G. Credential Offer (§4, expanded)
# ---------------------------------------------------------------------------

def test_credential_offer_tx_code():
    """OID4VCI-1FINAL §4.1.1: Pre-auth offer with tx_code object for user PIN.

    When tx_code is specified, token request MUST include matching tx_code value.
    §3.5: tx_code object MUST have input_mode and MAY have length, description.
    This test WILL FAIL if tx_code is not supported in the offer/token flow.
    """
    print("\n--- §4.1.1 Credential Offer with tx_code ---")
    tx = _initiate_issuance()
    offer_uri = tx.get("credential_offer_uri", "")
    parsed = urllib.parse.urlparse(offer_uri)
    params = urllib.parse.parse_qs(parsed.query)
    offer_json_str = params.get("credential_offer", [None])[0]
    if not offer_json_str:
        offer_uri_ref = params.get("credential_offer_uri", [None])[0]
        if offer_uri_ref:
            ref_resp = http("GET", offer_uri_ref)
            if ref_resp.status == 200:
                offer = ref_resp.json()
            else:
                R.fail("credential_offer_tx_code.offer_available", f"status {ref_resp.status}")
                return
        else:
            R.fail("credential_offer_tx_code.offer_available", "no credential_offer param")
            return
    else:
        offer = json.loads(offer_json_str)

    grant = offer.get("grants", {}).get("urn:ietf:params:oauth:grant-type:pre-authorized_code", {})
    tx_code = grant.get("tx_code")
    if tx_code is None:
        R.fail("credential_offer_tx_code.tx_code_in_offer",
               "OID4VCI-1FINAL §4.1.1: tx_code not present in offer (feature not implemented). "
               "Offer should support tx_code for user PIN flows.")
        return
    R.ok("credential_offer_tx_code.tx_code_in_offer")

    if "input_mode" in tx_code:
        R.ok("credential_offer_tx_code.input_mode_present")
    else:
        R.fail("credential_offer_tx_code.input_mode_present",
               "OID4VCI-1FINAL §3.5: tx_code MUST have input_mode")


# ---------------------------------------------------------------------------
# H. Token Endpoint (§6, draft-to-final detection)
# ---------------------------------------------------------------------------

def test_token_endpoint_c_nonce_convention():
    """Detect whether token response uses Draft (c_nonce) or Final (nonce endpoint §7) convention.

    OID4VCI 1.0 Final §6 + §7: In the Final spec, nonce is NOT returned in the
    token response. Instead, the wallet calls the nonce_endpoint separately.
    """
    print("\n--- §6 Token Endpoint: Draft vs Final nonce convention ---")
    tx = _initiate_issuance()
    tok_resp = http(
        "POST",
        f"{GATEWAY_BASE}/v1/issuance/token",
        form_body={
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": tx["pre_auth_code"],
        },
    )
    if tok_resp.status != 200:
        R.fail("token_convention.available", f"status {tok_resp.status}")
        return
    tok = tok_resp.json()

    if "c_nonce" in tok or "nonce" in tok:
        R.fail("token_convention.uses_final_nonce_endpoint",
               "OID4VCI-1FINAL §6: token response MUST NOT include c_nonce in Final spec. "
               "Currently using Draft convention (c_nonce/nonce in token response). "
               "Final spec uses nonce_endpoint (§7) instead.")
    else:
        R.ok("token_convention.uses_final_nonce_endpoint")


def test_token_endpoint_pre_auth_code_with_tx_code():
    """§6.2: Token request with tx_code parameter when offer requires it.

    OID4VCI-1FINAL §6.2: If the offer includes a tx_code, the token request
    MUST include the matching tx_code value. Request without tx_code MUST fail.
    This test WILL FAIL if tx_code is not supported.
    """
    print("\n--- §6.2 Token Endpoint with tx_code ---")
    tx = _initiate_issuance()
    offer_uri = tx.get("credential_offer_uri", "")
    parsed = urllib.parse.urlparse(offer_uri)
    params = urllib.parse.parse_qs(parsed.query)
    offer_str = params.get("credential_offer", [None])[0]
    if offer_str:
        offer = json.loads(offer_str)
    else:
        R.fail("token_tx_code.offer_parseable", "no inline credential_offer")
        return

    grant = offer.get("grants", {}).get("urn:ietf:params:oauth:grant-type:pre-authorized_code", {})
    if "tx_code" not in grant:
        R.fail("token_tx_code.tx_code_in_offer",
               "OID4VCI-1FINAL §6.2: tx_code not in offer grant (feature not implemented)")
        return
    R.ok("token_tx_code.tx_code_in_offer")

    resp_no_code = http(
        "POST",
        f"{GATEWAY_BASE}/v1/issuance/token",
        form_body={
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": grant.get("pre-authorized_code", ""),
        },
    )
    if resp_no_code.status == 400:
        R.ok("token_tx_code.missing_tx_code_rejected")
    else:
        R.fail("token_tx_code.missing_tx_code_rejected",
               f"OID4VCI-1FINAL §6.2: token request without tx_code MUST return 400, "
               f"got {resp_no_code.status}")


# ---------------------------------------------------------------------------
# I. Proof Validation (Appendix F.4)
# ---------------------------------------------------------------------------

def test_proof_jwt_typ_header():
    """OID4VCI-1FINAL Appendix F.1: JWT proof MUST have typ=openid4vci-proof+jwt.

    OIDF: VCIIssuerHappyFlow (proof typ check)
    Server MUST accept the correct typ and SHOULD reject wrong typ.
    """
    print("\n--- Appendix F.1: Proof JWT typ header ---")
    tx = _initiate_issuance()
    tok = _exchange_token(tx["pre_auth_code"])
    nonce = tok.get("nonce") or tok.get("c_nonce", "")

    # Correct typ — MUST be accepted
    proof_correct = _build_proof_jwt(ISSUER_BASE_URL, nonce, typ="openid4vci-proof+jwt")
    resp_correct = _issue_credential(tok["access_token"], proof_correct)
    if resp_correct.status == 200:
        R.ok("proof_jwt_typ.correct_typ_accepted")
    else:
        R.fail("proof_jwt_typ.correct_typ_accepted",
               f"OID4VCI-1FINAL Appendix F.1: typ=openid4vci-proof+jwt MUST be accepted, "
               f"got {resp_correct.status}: {resp_correct.text}")

    # Wrong typ — SHOULD be rejected
    tx2 = _initiate_issuance()
    tok2 = _exchange_token(tx2["pre_auth_code"])
    nonce2 = tok2.get("nonce") or tok2.get("c_nonce", "")
    proof_wrong = _build_proof_jwt(ISSUER_BASE_URL, nonce2, typ="JWT")
    resp_wrong = _issue_credential(tok2["access_token"], proof_wrong)
    if resp_wrong.status == 400:
        R.ok("proof_jwt_typ.wrong_typ_rejected")
    else:
        R.fail("proof_jwt_typ.wrong_typ_rejected",
               f"OID4VCI-1FINAL Appendix F.1: wrong typ SHOULD be rejected with 400, "
               f"got {resp_wrong.status}")


def test_proof_jwt_aud_validation():
    """OID4VCI-1FINAL Appendix F.4 check 4: aud MUST equal credential_issuer identifier.

    Send proof with wrong aud — issuer MUST reject with 400.
    """
    print("\n--- Appendix F.4: Proof JWT aud validation ---")
    tx = _initiate_issuance()
    tok = _exchange_token(tx["pre_auth_code"])
    nonce = tok.get("nonce") or tok.get("c_nonce", "")
    proof = _build_proof_jwt(ISSUER_BASE_URL, nonce, bad_aud="https://wrong-issuer.example.com")
    resp = _issue_credential(tok["access_token"], proof)
    if resp.status == 400:
        R.ok("VCIIssuerFailOnInvalidAud")
    else:
        R.fail("VCIIssuerFailOnInvalidAud",
               f"OID4VCI-1FINAL Appendix F.4: wrong aud in proof MUST be rejected with 400, "
               f"got {resp.status}: {resp.text}")


def test_proof_jwt_iat_validation():
    """OID4VCI-1FINAL Appendix F.4 check 5: iat MUST be recent.

    Send proof with iat far in the past (-3600s) — issuer SHOULD reject.
    """
    print("\n--- Appendix F.4: Proof JWT iat validation ---")
    tx = _initiate_issuance()
    tok = _exchange_token(tx["pre_auth_code"])
    nonce = tok.get("nonce") or tok.get("c_nonce", "")
    proof = _build_proof_jwt(ISSUER_BASE_URL, nonce, iat_offset=-3600)
    resp = _issue_credential(tok["access_token"], proof)
    if resp.status == 400:
        R.ok("VCIIssuerFailOnExpiredIat")
    else:
        R.fail("VCIIssuerFailOnExpiredIat",
               f"OID4VCI-1FINAL Appendix F.4: stale iat (-3600s) SHOULD be rejected with 400, "
               f"got {resp.status}")


# ============================================================================
# Runner
# ============================================================================


def main():
    print("=" * 70)
    print("OID4VCI Issuer Conformance Test Suite")
    print(f"Target: {GATEWAY_BASE}")
    print(f"Org: {ORG_ID}")
    print("=" * 70)

    # Smoke check: gateway alive
    try:
        resp = http("GET", f"{GATEWAY_BASE}/health")
        if resp.status != 200:
            print(f"FATAL: gateway not healthy: {resp.status} {resp.text}")
            sys.exit(1)
    except Exception as e:
        print(f"FATAL: gateway unreachable at {GATEWAY_BASE}: {e}")
        sys.exit(1)
    print(f"Service healthy ✓\n")

    # Run all test sections
    test_issuer_metadata()
    test_issuer_metadata_per_org()
    test_oauth_as_metadata()
    test_token_endpoint_happy_path()
    test_token_endpoint_errors()
    test_credential_offer()
    test_credential_endpoint_happy_path()
    test_credential_endpoint_legacy_proof()
    test_credential_endpoint_errors()
    test_proof_extraction()
    test_full_e2e_flow()
    test_metadata_consistency()

    # OIDF-mirrored conformance tests (OID4VCI 1.0 Final)
    test_issuer_metadata_required_fields()
    test_issuer_metadata_credential_configurations_format()
    test_issuer_metadata_authorization_servers()
    test_nonce_endpoint_happy_path()
    test_nonce_endpoint_nonce_uniqueness()
    test_issuer_happy_flow()
    test_issuer_happy_flow_additional_requests()
    test_issuer_happy_flow_sd_jwt()
    test_issuer_happy_flow_mso_mdoc()
    test_issuer_fail_on_invalid_nonce()
    test_issuer_fail_on_replay_nonce()
    test_issuer_fail_on_invalid_jwt_proof_signature()
    test_issuer_fail_on_missing_proof()
    test_issuer_fail_on_unknown_credential_configuration_id()
    test_issuer_fail_on_unknown_credential_identifier()
    test_issuer_fail_on_access_token_in_query()
    test_deferred_credential_endpoint()
    test_notification_endpoint_credential_accepted()
    test_notification_endpoint_credential_deleted()
    test_credential_offer_tx_code()
    test_token_endpoint_c_nonce_convention()
    test_token_endpoint_pre_auth_code_with_tx_code()
    test_proof_jwt_typ_header()
    test_proof_jwt_aud_validation()
    test_proof_jwt_iat_validation()

    all_pass = R.summary()
    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
