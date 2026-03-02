#!/usr/bin/env python3
"""OID4VCI Issuer Conformance Test Suite.

Tests the marty-credentials issuance service (port 8005) against the
OpenID for Verifiable Credential Issuance (OID4VCI) specification:
  - OID4VCI v1 (Draft 14+)
  - RFC 8414 (OAuth 2.0 Authorization Server Metadata)
  - RFC 6749 (OAuth 2.0 error response format)

Each test class maps to a section of the conformance suite the OIDF
runs at https://www.certification.openid.net/.

Can be run directly:
    python3 tests/integration/test_oid4vci_issuer_conformance.py

Or via pytest:
    pytest tests/integration/test_oid4vci_issuer_conformance.py -v
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
# ---------------------------------------------------------------------------

ISSUANCE_BASE = os.environ.get("ISSUANCE_BASE", "http://localhost:8005")
ORG_ID = os.environ.get("ORG_ID", "22222222-2222-2222-2222-222222222222")
ISSUER_BASE_URL = os.environ.get("ISSUER_BASE_URL", "https://beta.elevenidllc.com")

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

def _initiate_issuance(
    org_id: str = ORG_ID,
    claims: dict | None = None,
    credential_template_id: str | None = None,
) -> dict:
    """Create a fresh issuance transaction and return the JSON response."""
    body: dict = {
        "organization_id": org_id,
        "claims": claims or {"given_name": "Conformance", "family_name": "Test"},
    }
    if credential_template_id:
        body["credential_template_id"] = credential_template_id
    resp = http("POST", f"{ISSUANCE_BASE}/v1/issuance/initiate", json_body=body)
    assert resp.status == 200, f"initiate failed: {resp.status} {resp.text}"
    return resp.json()


def _exchange_token(pre_auth_code: str) -> dict:
    """Exchange a pre-authorized code for an access token."""
    resp = http(
        "POST",
        f"{ISSUANCE_BASE}/v1/issuance/token",
        form_body={
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": pre_auth_code,
        },
    )
    assert resp.status == 200, f"token exchange failed: {resp.status} {resp.text}"
    return resp.json()


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
) -> HttpResult:
    """Call the credential endpoint with a proof."""
    body: dict = {"format": format}
    if use_v1_proofs:
        body["proofs"] = {"jwt": [proof_jwt]}
    else:
        body["proof"] = {"proof_type": "jwt", "jwt": proof_jwt}
    return http(
        "POST",
        f"{ISSUANCE_BASE}/v1/issuance/credential",
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
    resp = http("GET", f"{ISSUANCE_BASE}/.well-known/openid-credential-issuer")
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

    resp = http("GET", f"{ISSUANCE_BASE}/.well-known/openid-credential-issuer/org/{ORG_ID}")
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
    resp = http("GET", f"{ISSUANCE_BASE}/.well-known/oauth-authorization-server")
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
    resp2 = http("GET", f"{ISSUANCE_BASE}/.well-known/oauth-authorization-server/org/{ORG_ID}")
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
        f"{ISSUANCE_BASE}/v1/issuance/token",
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
        f"{ISSUANCE_BASE}/v1/issuance/token",
        form_body={"pre-authorized_code": "anything"},
    )
    if resp.status == 422 or resp.status == 400:
        R.ok("token_err_missing_grant_type")
    else:
        R.fail("token_err_missing_grant_type", f"expected 400/422, got {resp.status}")

    # 2. Unsupported grant_type → should be 400 with error=unsupported_grant_type (RFC 6749 §5.2)
    resp = http(
        "POST",
        f"{ISSUANCE_BASE}/v1/issuance/token",
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
        f"{ISSUANCE_BASE}/v1/issuance/token",
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
        f"{ISSUANCE_BASE}/v1/issuance/token",
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
        f"{ISSUANCE_BASE}/v1/issuance/credential",
        json_body={"format": "jwt_vc_json"},
    )
    if resp.status == 401:
        R.ok("credential_err_no_auth_401")
    else:
        R.fail("credential_err_no_auth_401", f"expected 401, got {resp.status}")

    # 2. Invalid Bearer token → 401
    resp = http(
        "POST",
        f"{ISSUANCE_BASE}/v1/issuance/credential",
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
        resp = http("GET", f"{ISSUANCE_BASE}/v1/issuance/offers/{tx_id}")
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

    # Holder DID should appear as 'sub' in the issued VC
    holder_kid = "did:key:z6MktestConformance123#z6MktestConformance123"
    expected_did = "did:key:z6MktestConformance123"

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
    meta_url = f"{ISSUANCE_BASE}/.well-known/openid-credential-issuer"
    if "/org/" in org_path:
        meta_url = f"{ISSUANCE_BASE}/.well-known/openid-credential-issuer{org_path}"
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

    issuer_resp = http("GET", f"{ISSUANCE_BASE}/.well-known/openid-credential-issuer")
    as_resp = http("GET", f"{ISSUANCE_BASE}/.well-known/oauth-authorization-server")

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
# Runner
# ============================================================================

def main():
    print("=" * 70)
    print("OID4VCI Issuer Conformance Test Suite")
    print(f"Target: {ISSUANCE_BASE}")
    print(f"Org: {ORG_ID}")
    print("=" * 70)

    # Smoke check: service alive
    try:
        resp = http("GET", f"{ISSUANCE_BASE}/health")
        if resp.status != 200:
            print(f"FATAL: issuance service not healthy: {resp.status} {resp.text}")
            sys.exit(1)
    except Exception as e:
        print(f"FATAL: issuance service unreachable at {ISSUANCE_BASE}: {e}")
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

    all_pass = R.summary()
    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
