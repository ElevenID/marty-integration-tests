#!/usr/bin/env python3
"""OID4VCI end-to-end smoke tests [DEPRECATED: direct service bypass]

.. warning::
    This script calls the issuance service directly on port 8005, bypassing the
    gateway and all authentication.  It exists only as a quick sanity-check when
    the full stack is not available.

    For real integration tests that exercise the same path as a mobile wallet
    (Keycloak PKCE auth → authenticated gateway → OID4VCI → Walt.id wallet),
    use the new test::

        pytest tests/integration/gateway/test_wallet_oid4vci_gateway.py -v

Notes:
- The wallet API is exposed via nginx at http://localhost:7101/wallet-api/...
- The issuer referenced in the offer is typically https://beta.elevenidllc.com
  which means wallet redemption will only succeed if the external tunnel routes
  `/.well-known/*` correctly.

Can be run directly:
    python3 tests/integration/test_wallet_oid4vci.py

Or via pytest:
    pytest tests/integration/test_wallet_oid4vci.py -v
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest


WALLET_BASE = os.environ.get("WALTID_WALLET_URL", "http://localhost:7001")  # walt.id wallet
ISSUANCE_BASE = "http://localhost:8005"  # issuance service (host port)
# When the wallet API container fetches offer URLs, it must use a host-reachable
# name (localhost would be the container itself).
ISSUANCE_BASE_FROM_CONTAINERS = "http://host.docker.internal:8005"

ORG_ID = "22222222-2222-2222-2222-222222222222"
TEMPLATE_ID = "40000000-0000-0000-0000-000000000007"


def _short(s: str, n: int = 80) -> str:
    s = s or ""
    return s if len(s) <= n else s[:n] + "…"


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


def _json_or_text(res: HttpResult) -> str:
    try:
        return json.dumps(res.json(), indent=2)[:2000]
    except Exception:
        return (res.text or "")[:2000]


def http_request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
    json_body=None,
    raw_body: bytes | None = None,
    timeout: int = 30,
) -> HttpResult:
    if params:
        parsed = urllib.parse.urlsplit(url)
        q = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        q.extend(list(params.items()))
        url = urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(q), parsed.fragment)
        )

    data = None
    req_headers = {"Accept": "application/json"}
    if headers:
        req_headers.update(headers)

    if raw_body is not None and json_body is not None:
        raise ValueError("Provide either json_body or raw_body, not both")

    if raw_body is not None:
        data = raw_body

    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        req_headers.setdefault("Content-Type", "application/json")

    req = urllib.request.Request(url, data=data, headers=req_headers, method=method.upper())

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read() or b""
            return HttpResult(resp.status, dict(resp.headers.items()), body)
    except urllib.error.HTTPError as e:
        body = e.read() if hasattr(e, "read") else b""
        return HttpResult(e.code, dict(getattr(e, "headers", {}).items()), body)


def initiate_issuance() -> tuple[str, str]:
    """Initiate issuance and return (tx_id, offer_uri)."""
    r = http_request(
        "POST",
        f"{ISSUANCE_BASE}/v1/issuance/initiate",
        json_body={
            "organization_id": ORG_ID,
            "credential_template_id": TEMPLATE_ID,
            "applicant_id": "wallet-api-smoke-test",
            "claims": {"name": "Wallet API Smoke Test"},
        },
    )
    print(f"[offer] issuance initiate → {r.status}")
    if r.status != 200:
        raise RuntimeError(f"Failed to initiate issuance: {_json_or_text(r)}")

    data = r.json()
    tx_id = data.get("id")
    offer_uri = data.get("credential_offer_uri")
    if not tx_id or not offer_uri:
        raise RuntimeError(f"Missing id/credential_offer_uri in response: {_json_or_text(r)}")
    return tx_id, offer_uri


def wallet_register_and_login() -> tuple[str, str]:
    ts = int(time.time())
    email = f"oid4vci-test-{ts}@marty.demo"
    password = "Test1234"

    # Register (201) or already exists (409). We don't care which.
    r = http_request(
        "POST",
        f"{WALLET_BASE}/wallet-api/auth/register",
        json_body={"type": "email", "email": email, "password": password, "name": "OID4VCI Test"},
    )
    print(f"[wallet] register → {r.status}")
    if r.status not in (201, 409):
        raise RuntimeError(f"Wallet register failed: {_json_or_text(r)}")

    r = http_request(
        "POST",
        f"{WALLET_BASE}/wallet-api/auth/login",
        json_body={"type": "email", "email": email, "password": password},
    )
    print(f"[wallet] login → {r.status}")
    if r.status != 200:
        raise RuntimeError(f"Wallet login failed: {_json_or_text(r)}")

    data = r.json()
    token = data["token"]
    account_id = data["id"]
    print(f"         account_id: {account_id}")
    print(f"         token: {_short(token, 30)}")
    return token, account_id


def wallet_get_wallet_id(token: str) -> str:
    r = http_request(
        "GET",
        f"{WALLET_BASE}/wallet-api/wallet/accounts/wallets",
        headers={"Authorization": f"Bearer {token}"},
    )
    print(f"[wallet] list wallets → {r.status}")
    if r.status != 200:
        raise RuntimeError(f"List wallets failed: {_json_or_text(r)}")

    wallets = (r.json() or {}).get("wallets", [])
    if not wallets:
        raise RuntimeError(f"No wallets returned for account: {_json_or_text(r)}")
    wallet_id = wallets[0]["id"]
    print(f"         wallet_id: {wallet_id}")
    return wallet_id


def wallet_ensure_did(token: str, wallet_id: str) -> str:
    """Ensure the wallet has at least one DID:key and return it.

    Walt.ID's CredentialOfferProcessor NPEs at the proof-generation step if the
    wallet has no DID registered.  A fresh account has no DIDs, so we create one
    on demand.  Idempotent — if a DID already exists we return it unchanged.
    """
    r = http_request(
        "GET",
        f"{WALLET_BASE}/wallet-api/wallet/{wallet_id}/dids",
        headers={"Authorization": f"Bearer {token}"},
    )
    dids = r.json() if r.status == 200 else []
    if dids:
        did = dids[0]["did"]
        print(f"         existing DID: {_short(did, 60)}")
        return did

    # Create a did:key backed by Ed25519
    r = http_request(
        "POST",
        f"{WALLET_BASE}/wallet-api/wallet/{wallet_id}/dids/create/key",
        headers={"Authorization": f"Bearer {token}"},
    )
    print(f"[wallet] create DID → {r.status}")
    if r.status not in (200, 201):
        raise RuntimeError(f"DID create failed: {_short(r.text, 200)}")
    did = r.json() if isinstance(r.json(), str) else (r.json() or {}).get("did", "")
    print(f"         new DID: {_short(str(did), 60)}")
    return did


def wallet_resolve_issuer_metadata(token: str, wallet_id: str, issuer_url: str) -> None:
    r = http_request(
        "GET",
        f"{WALLET_BASE}/wallet-api/wallet/{wallet_id}/exchange/resolveIssuerOpenIDMetadata",
        params={"issuer": issuer_url},
        headers={"Authorization": f"Bearer {token}"},
    )
    print(f"[wallet] resolve issuer metadata → {r.status}")
    print("         ", _short(_json_or_text(r), 300))


def wallet_resolve_offer(token: str, wallet_id: str, offer_uri: str) -> None:
    # Despite the OpenAPI saying application/json string, this endpoint appears
    # to reject JSON-string bodies in this deployment. Send as plain text.
    r = http_request(
        "POST",
        f"{WALLET_BASE}/wallet-api/wallet/{wallet_id}/exchange/resolveCredentialOffer",
        raw_body=offer_uri.encode("utf-8"),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "text/plain"},
    )
    print(f"[wallet] resolve credential offer → {r.status}")
    print("         ", _short(_json_or_text(r), 500))


def wallet_redeem_offer(token: str, wallet_id: str, offer_uri: str) -> None:
    r = http_request(
        "POST",
        f"{WALLET_BASE}/wallet-api/wallet/{wallet_id}/exchange/useOfferRequest",
        raw_body=offer_uri.encode("utf-8"),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "text/plain"},
    )
    print(f"[wallet] redeem offer (useOfferRequest) → {r.status}")
    print("         ", _short(_json_or_text(r), 700))

    if r.status != 200:
        raise RuntimeError(
            "Redeem failed. If this is a 404/metadata error, it likely means the tunnel/gateway isn't routing "
            "`https://beta.elevenidllc.com/.well-known/openid-credential-issuer/org/{org_id}` to issuance."
        )


def wallet_list_credentials(token: str, wallet_id: str) -> None:
    r = http_request(
        "GET",
        f"{WALLET_BASE}/wallet-api/wallet/{wallet_id}/credentials",
        headers={"Authorization": f"Bearer {token}"},
    )
    print(f"[wallet] list credentials → {r.status}")
    if r.status != 200:
        raise RuntimeError(f"List credentials failed: {_json_or_text(r)}")

    creds = r.json() or []
    print(f"         credentials count: {len(creds)}")
    if creds:
        print("         first credential id:", creds[0].get("id"))


def parse_offer_issuer(offer_uri: str) -> str:
    # openid-credential-offer://?credential_offer=<urlencoded-json>
    qs = urllib.parse.urlparse(offer_uri).query
    params = urllib.parse.parse_qs(qs)
    raw = params.get("credential_offer", [None])[0]
    if not raw:
        raise ValueError("No credential_offer query param in offer URI")
    offer = json.loads(urllib.parse.unquote(raw))
    return offer["credential_issuer"]


def offer_url_for_wallet(tx_id: str) -> str:
    """Return an HTTP(S) URL the wallet API can fetch to obtain the offer JSON."""
    return f"{ISSUANCE_BASE_FROM_CONTAINERS}/v1/issuance/offers/{tx_id}"


def build_credential_offer_request_url(offer_url: str) -> str:
    """Build an OID4VCI credential offer request URL.

    Walt.ID's wallet API expects the incoming string to be a URL containing
    either:
        - credential_offer=... (inline offer object)
        - credential_offer_uri=... (by-reference offer object)

    We use the by-reference form to avoid custom-scheme parsing issues.
    """
    encoded = urllib.parse.quote(offer_url, safe="")
    return f"openid-credential-offer://?credential_offer_uri={encoded}"


# ---------------------------------------------------------------------------
# Pytest-compatible test
# ---------------------------------------------------------------------------

@pytest.mark.skip(
    reason=(
        "DEPRECATED: calls issuance service directly on port 8005 with hardcoded "
        "org/template IDs, bypassing the gateway.  Use the gateway-authenticated "
        "test instead: tests/integration/gateway/test_wallet_oid4vci_gateway.py"
    )
)
def test_wallet_oid4vci_flow() -> None:
    """Full OID4VCI credential redemption via the walt.id wallet API."""
    tx_id, offer_uri = initiate_issuance()
    issuer_url = parse_offer_issuer(offer_uri)
    offer_url = offer_url_for_wallet(tx_id)
    wallet_offer_request_url = build_credential_offer_request_url(offer_url)

    print(f"[offer] issuer_url: {issuer_url}")
    print(f"[offer] offer_url (for wallet): {offer_url}")
    print(f"[offer] wallet offer request url: {_short(wallet_offer_request_url, 140)}")
    print(f"[offer] offer_uri (inline): {_short(offer_uri, 120)}")

    token, _account_id = wallet_register_and_login()
    wallet_id = wallet_get_wallet_id(token)
    wallet_ensure_did(token, wallet_id)

    wallet_resolve_issuer_metadata(token, wallet_id, issuer_url)
    wallet_resolve_offer(token, wallet_id, wallet_offer_request_url)
    wallet_redeem_offer(token, wallet_id, wallet_offer_request_url)
    wallet_list_credentials(token, wallet_id)


# ---------------------------------------------------------------------------
# Direct-run entry point
# ---------------------------------------------------------------------------

def main() -> int:
    try:
        test_wallet_oid4vci_flow()
        print("\n✓ Wallet API flow completed")
        return 0
    except Exception as e:
        print("\n✗ ERROR:", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
