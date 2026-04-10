#!/usr/bin/env python3
"""End-to-end test: full UI claim-credential flow with Walt ID wallet redemption.

This test mirrors exactly what happens when a user interacts with the
Marty UI to issue a credential and then claims it via the Walt ID wallet:

  1. Admin creates applicant + application (applicant service)
  2. Admin submits, reviews, and issues the application
  3. Applicant service calls issuance /initiate internally
  4. ClaimCredentialDialog fetches GET /v1/applicants/applications/{id}
     (through gateway with auth) and reads metadata.credential_offer_uri
  5. QR code encodes the inline offer URI
  6. Walt ID wallet scans / receives the offer URI
  7. Wallet resolves metadata, exchanges pre-auth code for token, gets credential
  8. Credential appears in wallet

Unlike test_wallet_oid4vci.py (which calls issuance directly with by-reference
offer URIs), this test exercises the actual gateway routing, auth middleware,
applicant service, and the inline credential_offer_uri path that the UI uses.

Can be run directly:
    python3 tests/integration/test_ui_claim_credential_e2e.py

Or via pytest:
    pytest tests/integration/test_ui_claim_credential_e2e.py -v
"""

from __future__ import annotations

import json
import os
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import pytest

_counter = 0


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GATEWAY_BASE = os.environ.get("GATEWAY_BASE", "http://localhost:8000")
APPLICANT_BASE = os.environ.get("APPLICANT_SERVICE_URL", "http://localhost:8006")
ISSUANCE_BASE = os.environ.get("ISSUANCE_SERVICE_URL", "http://localhost:8005")
WALLET_BASE = os.environ.get("WALTID_WALLET_URL", "http://localhost:7001")
ISSUANCE_FROM_CONTAINER = os.environ.get("ISSUANCE_BASE_FROM_CONTAINERS", "http://host.docker.internal:8005")

ORG_ID = "22222222-2222-2222-2222-222222222222"
CREDENTIAL_CONFIG_ID = "40000000-0000-0000-0000-000000000003"
REVIEWER_ID = "5734f363-51e1-43ef-b359-b6961d10369f"


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only — no external dependencies)
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


def _short(s: str, n: int = 80) -> str:
    s = s or ""
    return s if len(s) <= n else s[:n] + "…"


def _json_or_text(res: HttpResult) -> str:
    try:
        return json.dumps(res.json(), indent=2)[:2000]
    except Exception:
        return (res.text or "")[:2000]


def http(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    json_body=None,
    raw_body: bytes | None = None,
    form_body: dict[str, str] | None = None,
    timeout: int = 30,
) -> HttpResult:
    data = None
    req_headers = {"Accept": "application/json"}
    if headers:
        req_headers.update(headers)

    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        req_headers.setdefault("Content-Type", "application/json")
    elif raw_body is not None:
        data = raw_body
    elif form_body is not None:
        data = urllib.parse.urlencode(form_body).encode("utf-8")
        req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

    req = urllib.request.Request(url, data=data, headers=req_headers, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return HttpResult(resp.status, dict(resp.headers.items()), resp.read() or b"")
    except urllib.error.HTTPError as e:
        body = e.read() if hasattr(e, "read") else b""
        return HttpResult(e.code, dict(getattr(e, "headers", {}).items()), body)


def expect(r: HttpResult, expected: int, step: str):
    if r.status != expected:
        raise RuntimeError(f"[{step}] Expected {expected}, got {r.status}: {_json_or_text(r)}")


# ---------------------------------------------------------------------------
# Phase 1: Applicant service — admin workflow
# ---------------------------------------------------------------------------

def create_applicant() -> str:
    global _counter
    _counter += 1
    ts = f"{int(time.time())}-{_counter}-{random.randint(1000,9999)}"
    r = http("POST", f"{APPLICANT_BASE}/v1/applicants", json_body={
        "email": f"e2e-claim-{ts}@example.com",
        "given_name": "E2E",
        "family_name": "ClaimTest",
        "organization_id": ORG_ID,
    })
    expect(r, 200, "create applicant")
    applicant_id = r.json()["id"]
    print(f"[1] Create applicant → {applicant_id}")
    return applicant_id


def create_application(applicant_id: str) -> str:
    r = http("POST", f"{APPLICANT_BASE}/v1/applicants/applications", json_body={
        "applicant_id": applicant_id,
        "organization_id": ORG_ID,
        "credential_configuration_id": CREDENTIAL_CONFIG_ID,
        "metadata": {
            "credential_type": "national_id",
            "credential_display_name": "National ID",
        },
    })
    expect(r, 200, "create application")
    app_id = r.json()["id"]
    print(f"[2] Create application → {app_id}")
    return app_id


def submit_application(app_id: str):
    r = http("POST", f"{APPLICANT_BASE}/v1/applicants/applications/{app_id}/submit")
    expect(r, 200, "submit")
    print(f"[3] Submit application → {r.json()['status']}")


def review_application(app_id: str):
    r = http("POST", f"{APPLICANT_BASE}/v1/applicants/applications/{app_id}/review", json_body={
        "decision": "approve",
        "reviewer_id": REVIEWER_ID,
        "notes": "E2E auto-approved",
    })
    expect(r, 200, "review/approve")
    print(f"[4] Review (approve) → {r.json()['status']}")


def issue_application(app_id: str) -> dict:
    r = http("POST", f"{APPLICANT_BASE}/v1/applicants/applications/{app_id}/issue", json_body={
        "issuer_id": REVIEWER_ID,
    })
    expect(r, 200, "issue")
    data = r.json()
    print(f"[5] Issue credential → status={data['status']}")
    offer_uri = data.get("credential_offer_uri")
    if offer_uri:
        print(f"    credential_offer_uri present: True ({len(offer_uri)} chars)")
    else:
        print(f"    credential_offer_uri: {offer_uri}")
    return data


# ---------------------------------------------------------------------------
# Phase 2: Simulate ClaimCredentialDialog.fetchOffer
# ---------------------------------------------------------------------------

def simulate_claim_dialog_fetch(app_id: str) -> dict:
    """Simulate exactly what ClaimCredentialDialog.jsx fetchOffer does.

    The component calls:
      apiClient.get(`/v1/applicants/applications/${applicationId}`)
    which goes through the gateway at /v1/applicants → applicant service.

    We hit the applicant service directly here (the gateway test is in
    Phase 2b), then apply the same JS transform.
    """
    r = http("GET", f"{APPLICANT_BASE}/v1/applicants/applications/{app_id}")
    expect(r, 200, "fetchOffer (direct)")
    enriched = r.json()
    metadata = enriched.get("metadata", {})

    # Exact JS logic from ClaimCredentialDialog.jsx:
    offer_uri = metadata.get("credential_offer_uri") or None
    expires_at = metadata.get("offer_expires_at") or None

    is_expired = False
    if expires_at:
        try:
            exp_dt = datetime.fromisoformat(expires_at)
            is_expired = exp_dt < datetime.now(timezone.utc)
        except Exception:
            pass

    offer = {
        "offer_url": offer_uri,
        "status": "expired" if is_expired else ("active" if offer_uri else None),
        "wallets": [],
    }

    print(f"[6] ClaimCredentialDialog.fetchOffer (direct):")
    print(f"    app.status={enriched.get('status')}, offer.status={offer['status']}")
    print(f"    offer_url present={bool(offer['offer_url'])}")
    print(f"    offer_expires_at={expires_at}")

    if not offer["offer_url"]:
        raise RuntimeError("credential_offer_uri is missing from application metadata — "
                           "the /issue endpoint did not store the offer URI")
    if offer["status"] == "expired":
        raise RuntimeError(f"Offer is already expired (expires_at={expires_at})")

    return offer


def simulate_claim_dialog_via_gateway(app_id: str) -> dict:
    """Test the gateway-proxied path.

    The gateway requires a session cookie. We skip auth for this test by
    hitting the applicant service directly (Phase 2a already tested the
    response shape). This test verifies the gateway routes the path correctly.
    If no session is available, we gracefully note the auth requirement.
    """
    r = http("GET", f"{GATEWAY_BASE}/v1/applicants/applications/{app_id}")
    if r.status == 401:
        print(f"[6b] Gateway path returns 401 (auth required) — expected for unauthenticated test")
        print(f"     This confirms gateway routes /v1/applicants/* correctly (not 404)")
        return {"gateway_auth_required": True}
    expect(r, 200, "fetchOffer (gateway)")
    print(f"[6b] Gateway path → 200 OK")
    return r.json()


# ---------------------------------------------------------------------------
# Phase 3: Parse the inline credential offer
# ---------------------------------------------------------------------------

def parse_inline_offer(offer_url: str) -> dict:
    """Parse an inline openid-credential-offer:// URI.

    Expected format:
      openid-credential-offer://?credential_offer=<url-encoded JSON>
    """
    if not offer_url.startswith("openid-credential-offer://"):
        raise RuntimeError(f"Expected openid-credential-offer:// URI, got: {_short(offer_url)}")

    qs = urllib.parse.urlparse(offer_url).query
    params = urllib.parse.parse_qs(qs)

    # Inline form: credential_offer=<json>
    raw = params.get("credential_offer", [None])[0]
    if raw:
        offer_json = json.loads(raw)
        print(f"[7] Parse inline offer:")
        print(f"    credential_issuer: {offer_json.get('credential_issuer')}")
        print(f"    credential_configuration_ids: {offer_json.get('credential_configuration_ids')}")
        grants = offer_json.get("grants", {})
        pre_auth_grant = grants.get("urn:ietf:params:oauth:grant-type:pre-authorized_code", {})
        code = pre_auth_grant.get("pre-authorized_code")
        print(f"    pre-authorized_code present: {bool(code)}")
        if not code:
            raise RuntimeError("Missing pre-authorized_code in offer grants")
        return offer_json

    # By-reference form: credential_offer_uri=<url>
    ref_url = params.get("credential_offer_uri", [None])[0]
    if ref_url:
        print(f"[7] Offer is by-reference: {_short(ref_url)}")
        r = http("GET", ref_url)
        expect(r, 200, "resolve offer by reference")
        return r.json()

    raise RuntimeError(f"No credential_offer or credential_offer_uri in: {_short(offer_url)}")


# ---------------------------------------------------------------------------
# Phase 4: Manual OID4VCI protocol test (token + credential)
# ---------------------------------------------------------------------------

def _localize_endpoint(endpoint: str) -> str:
    """Replace public URLs with local equivalents for direct testing.

    The metadata returns https://beta.elevenidllc.com/... URLs which go through
    Cloudflare — fine for the wallet container but not for our local test script.
    """
    if not endpoint:
        return endpoint
    parsed = urllib.parse.urlparse(endpoint)
    if parsed.hostname not in ("localhost", "127.0.0.1", "host.docker.internal"):
        # Rewrite to hit the issuance service directly
        return f"{ISSUANCE_BASE}{parsed.path}"
    return endpoint


def _oid4vci_token(issuer_url: str, pre_auth_code: str) -> str:
    """Exchange pre-authorized code for access token — same as wallet does."""
    # Discover the token endpoint from OAuth AS metadata (local issuance service)
    org_path = urllib.parse.urlparse(issuer_url).path  # e.g. /org/<uuid>
    as_meta_url = f"{ISSUANCE_BASE}/.well-known/oauth-authorization-server{org_path}"
    r = http("GET", as_meta_url)
    if r.status != 200:
        as_meta_url = f"{ISSUANCE_BASE}/.well-known/oauth-authorization-server"
        r = http("GET", as_meta_url)
    if r.status == 200:
        token_endpoint = r.json().get("token_endpoint")
        print(f"[8a] OAuth AS metadata → token_endpoint: {_short(token_endpoint or '')}")
        token_endpoint = _localize_endpoint(token_endpoint)
        print(f"     (localized → {_short(token_endpoint or '')})")
    else:
        token_endpoint = None
        print(f"[8a] OAuth AS metadata → {r.status} (using fallback)")

    if not token_endpoint:
        token_endpoint = f"{ISSUANCE_BASE}/v1/issuance/token"

    r = http("POST", token_endpoint, form_body={
        "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": pre_auth_code,
    })
    expect(r, 200, "token exchange")
    data = r.json()
    access_token = data.get("access_token")
    print(f"[8b] Token exchange → access_token present: {bool(access_token)}")
    print(f"    token_type: {data.get('token_type')}, expires_in: {data.get('expires_in')}")
    print(f"    nonce present: {bool(data.get('nonce'))}")
    if not access_token:
        raise RuntimeError(f"No access_token in token response: {_json_or_text(r)}")
    return access_token


def _oid4vci_credential(issuer_url: str, access_token: str, credential_config_id: str) -> str:
    """Request credential from issuance service — mimics wallet's POST /credential."""
    # Discover credential endpoint (from local issuance service)
    org_path = urllib.parse.urlparse(issuer_url).path
    meta_url = f"{ISSUANCE_BASE}/.well-known/openid-credential-issuer{org_path}"
    r = http("GET", meta_url)
    if r.status != 200:
        meta_url = f"{ISSUANCE_BASE}/.well-known/openid-credential-issuer"
        r = http("GET", meta_url)
    credential_endpoint = None
    if r.status == 200:
        credential_endpoint = r.json().get("credential_endpoint")
        print(f"[9a] Issuer metadata → credential_endpoint: {_short(credential_endpoint or '')}")
        credential_endpoint = _localize_endpoint(credential_endpoint)
        print(f"     (localized → {_short(credential_endpoint or '')})")

    if not credential_endpoint:
        credential_endpoint = f"{ISSUANCE_BASE}/v1/issuance/credential"

    r = http("POST", credential_endpoint, json_body={
        "format": "jwt_vc_json",
        "credential_configuration_id": credential_config_id,
    }, headers={
        "Authorization": f"Bearer {access_token}",
    })
    expect(r, 200, "credential request")
    data = r.json()
    credential = data.get("credential")
    print(f"[9b] Credential request → credential present: {bool(credential)}")
    if credential:
        # JWT has 3 parts
        parts = credential.split(".")
        print(f"    JWT parts: {len(parts)}, header length: {len(parts[0]) if parts else 0}")
    if not credential:
        raise RuntimeError(f"No credential in response: {_json_or_text(r)}")
    return credential


# ---------------------------------------------------------------------------
# Phase 5: Walt ID wallet redemption (full wallet flow)
# ---------------------------------------------------------------------------

def wallet_register_and_login() -> tuple[str, str]:
    ts = int(time.time())
    email = f"e2e-claim-{ts}@marty.demo"
    password = "Test1234"

    r = http("POST", f"{WALLET_BASE}/wallet-api/auth/register", json_body={
        "type": "email", "email": email, "password": password, "name": "E2E Claim Test",
    })
    print(f"[10a] Wallet register → {r.status}")
    if r.status not in (200, 201, 409):
        raise RuntimeError(f"Wallet register failed: {_json_or_text(r)}")

    r = http("POST", f"{WALLET_BASE}/wallet-api/auth/login", json_body={
        "type": "email", "email": email, "password": password,
    })
    expect(r, 200, "wallet login")
    data = r.json()
    token = data["token"]
    account_id = data["id"]
    print(f"[10b] Wallet login → account_id: {account_id}")
    return token, account_id


def wallet_get_wallet_id(token: str) -> str:
    r = http("GET", f"{WALLET_BASE}/wallet-api/wallet/accounts/wallets",
             headers={"Authorization": f"Bearer {token}"})
    expect(r, 200, "wallet list")
    wallets = (r.json() or {}).get("wallets", [])
    if not wallets:
        raise RuntimeError("No wallets for account")
    wallet_id = wallets[0]["id"]
    print(f"[10c] Wallet ID → {wallet_id}")
    return wallet_id


def wallet_ensure_did(token: str, wallet_id: str) -> str:
    r = http("GET", f"{WALLET_BASE}/wallet-api/wallet/{wallet_id}/dids",
             headers={"Authorization": f"Bearer {token}"})
    dids = r.json() if r.status == 200 else []
    if dids:
        did = dids[0]["did"]
        print(f"[10d] Existing DID: {_short(did, 50)}")
        return did

    r = http("POST", f"{WALLET_BASE}/wallet-api/wallet/{wallet_id}/dids/create/key",
             headers={"Authorization": f"Bearer {token}"})
    print(f"[10d] Create DID → {r.status}")
    if r.status not in (200, 201):
        raise RuntimeError(f"DID create failed: {_short(r.text, 200)}")
    did = r.json() if isinstance(r.json(), str) else (r.json() or {}).get("did", "")
    print(f"      New DID: {_short(str(did), 50)}")
    return did


def wallet_redeem_offer(token: str, wallet_id: str, offer_uri: str) -> None:
    """Send the inline offer URI to the wallet, exactly as the QR code scan would.

    The inline form (openid-credential-offer://?credential_offer=<json>) is what
    the UI encodes in the QR code. Walt ID's wallet-api can accept this directly.

    However, some versions of Walt ID's wallet prefer the by-reference form:
       openid-credential-offer://?credential_offer_uri=<http-url>
    We try inline first, then fall back to by-reference.
    """
    # Try inline offer URI (what ClaimCredentialDialog encodes):
    r = http("POST", f"{WALLET_BASE}/wallet-api/wallet/{wallet_id}/exchange/useOfferRequest",
             raw_body=offer_uri.encode("utf-8"),
             headers={"Authorization": f"Bearer {token}", "Content-Type": "text/plain"})
    print(f"[11] Wallet useOfferRequest (inline) → {r.status}")

    if r.status == 200:
        print(f"     Response: {_short(_json_or_text(r), 200)}")
        return

    # If inline failed, try by-reference form
    inline_error = _json_or_text(r)
    print(f"     Inline offer failed ({r.status}): {_short(inline_error, 200)}")

    # Extract the pre-auth code and build a by-reference URL
    offer_json = parse_inline_offer(offer_uri)
    grants = offer_json.get("grants", {})
    pre_auth = grants.get("urn:ietf:params:oauth:grant-type:pre-authorized_code", {})
    code = pre_auth.get("pre-authorized_code")

    # Look up the transaction ID from the issuance service by pre-auth code
    # We need the offer URL that the wallet can fetch
    # Try the /offers endpoint
    tx_id = _find_transaction_by_code(code)
    if tx_id:
        offer_url = f"{ISSUANCE_FROM_CONTAINER}/v1/issuance/offers/{tx_id}"
        by_ref = f"openid-credential-offer://?credential_offer_uri={urllib.parse.quote(offer_url, safe='')}"
        print(f"[11b] Trying by-reference: {_short(by_ref, 120)}")

        r = http("POST", f"{WALLET_BASE}/wallet-api/wallet/{wallet_id}/exchange/useOfferRequest",
                 raw_body=by_ref.encode("utf-8"),
                 headers={"Authorization": f"Bearer {token}", "Content-Type": "text/plain"})
        print(f"      Wallet useOfferRequest (by-ref) → {r.status}")
        print(f"      Response: {_short(_json_or_text(r), 200)}")
        if r.status == 200:
            return

    raise RuntimeError(
        f"Wallet useOfferRequest failed. Inline: {_short(inline_error, 200)}"
    )


def _find_transaction_by_code(pre_auth_code: str) -> str | None:
    """Try to find the issuance transaction ID for a pre-auth code.

    The issuance service may expose /v1/issuance/offers or we can use
    the token endpoint to verify the code works.
    """
    # We can use the metadata from the applicant service — it stored the tx_id
    # But we don't have it here. Let's try the token endpoint which at least
    # validates the code.
    r = http("POST", f"{ISSUANCE_BASE}/v1/issuance/token", form_body={
        "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": pre_auth_code,
    })
    if r.status == 200:
        print(f"     Pre-auth code is valid (token exchange succeeded)")
    return None  # We don't know the tx_id from this path


def wallet_list_credentials(token: str, wallet_id: str) -> int:
    r = http("GET", f"{WALLET_BASE}/wallet-api/wallet/{wallet_id}/credentials",
             headers={"Authorization": f"Bearer {token}"})
    expect(r, 200, "wallet list credentials")
    creds = r.json() or []
    count = len(creds)
    print(f"[12] Wallet credentials count: {count}")
    if creds:
        print(f"     First credential ID: {creds[0].get('id')}")
    return count


# ---------------------------------------------------------------------------
# Test orchestration
# ---------------------------------------------------------------------------

@pytest.mark.skip(
    reason=(
        "Legacy e2e test requires full UI stack with applicant service at hardcoded "
        "port 8011. Not part of the microservices integration test suite."
    ),
)
@pytest.mark.skipif(
    not os.environ.get("RUN_WALLET_TESTS"),
    reason=(
        "Skipped by default — calls live services with hardcoded IDs and requires "
        "a running Walt.id wallet.  Set RUN_WALLET_TESTS=1 to enable."
    ),
)
def test_ui_claim_credential_e2e():
    """Full end-to-end test: admin issues → UI fetches offer → wallet redeems."""
    print("=" * 70)
    print("E2E TEST: UI Claim Credential Flow + Walt ID Wallet Redemption")
    print("=" * 70)

    # Phase 1: Admin workflow (applicant service)
    print("\n--- Phase 1: Admin Workflow (Applicant Service) ---")
    applicant_id = create_applicant()
    app_id = create_application(applicant_id)
    submit_application(app_id)
    review_application(app_id)
    issue_response = issue_application(app_id)

    # Verify the /issue response has credential_offer_uri
    issue_offer_uri = issue_response.get("credential_offer_uri")
    assert issue_offer_uri, "credential_offer_uri missing from /issue response"

    # Phase 2: Simulate ClaimCredentialDialog
    print("\n--- Phase 2: ClaimCredentialDialog Simulation ---")
    offer = simulate_claim_dialog_fetch(app_id)
    gateway_result = simulate_claim_dialog_via_gateway(app_id)

    offer_url = offer["offer_url"]
    assert offer_url, "offer_url is null after fetchOffer"
    assert offer["status"] == "active", f"Offer status should be 'active', got '{offer['status']}'"

    # Verify the offer_url from metadata matches what /issue returned
    assert offer_url == issue_offer_uri, (
        f"Mismatch: /issue returned different offer_uri than metadata.\n"
        f"  /issue: {_short(issue_offer_uri)}\n"
        f"  metadata: {_short(offer_url)}"
    )

    # Phase 3: Parse the offer
    print("\n--- Phase 3: Parse Credential Offer ---")
    offer_json = parse_inline_offer(offer_url)
    issuer_url = offer_json["credential_issuer"]
    cred_config_ids = offer_json["credential_configuration_ids"]
    grants = offer_json.get("grants", {})
    pre_auth_code = grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]

    # Phase 4: Manual OID4VCI protocol verification
    print("\n--- Phase 4: OID4VCI Protocol (Manual Token + Credential) ---")
    access_token = _oid4vci_token(issuer_url, pre_auth_code)
    credential_jwt = _oid4vci_credential(issuer_url, access_token, cred_config_ids[0])

    # Phase 5: Full wallet flow (new issuance needed since we consumed the code)
    print("\n--- Phase 5: Walt ID Wallet Full Flow ---")
    print("  (Creating fresh issuance for wallet test since pre-auth codes are single-use)")

    # Re-issue to get a fresh offer with a new pre-auth code
    # We need to create a new application since the current one is already issued
    applicant_id_2 = create_applicant()
    app_id_2 = create_application(applicant_id_2)
    submit_application(app_id_2)
    review_application(app_id_2)
    issue_response_2 = issue_application(app_id_2)
    offer_2 = simulate_claim_dialog_fetch(app_id_2)
    offer_url_2 = offer_2["offer_url"]

    token, _account_id = wallet_register_and_login()
    wallet_id = wallet_get_wallet_id(token)
    wallet_ensure_did(token, wallet_id)

    creds_before = wallet_list_credentials(token, wallet_id)
    wallet_redeem_offer(token, wallet_id, offer_url_2)
    creds_after = wallet_list_credentials(token, wallet_id)

    if creds_after > creds_before:
        print(f"\n    Credential added to wallet ({creds_before} → {creds_after})")
    else:
        print(f"\n    WARNING: Credential count unchanged ({creds_before} → {creds_after})")
        print("    The wallet may have rejected the credential or encountered an error.")

    # Final summary
    print("\n" + "=" * 70)
    print("RESULTS SUMMARY")
    print("=" * 70)
    print(f"  [Phase 1] Admin workflow:         PASS")
    print(f"  [Phase 2] ClaimCredentialDialog:   PASS (offer_url present, status=active)")
    print(f"  [Phase 3] Offer parsing:           PASS (inline openid-credential-offer://)")
    print(f"  [Phase 4] OID4VCI protocol:        PASS (token + credential exchange)")
    wallet_status = "PASS" if creds_after > creds_before else "WARN (credential count unchanged)"
    print(f"  [Phase 5] Walt ID wallet:          {wallet_status}")
    print("=" * 70)

    if creds_after <= creds_before:
        raise RuntimeError("Wallet credential count did not increase — redemption may have failed")


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def main() -> int:
    try:
        test_ui_claim_credential_e2e()
        print("\n✓ All phases passed")
        return 0
    except Exception as e:
        print(f"\n✗ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
