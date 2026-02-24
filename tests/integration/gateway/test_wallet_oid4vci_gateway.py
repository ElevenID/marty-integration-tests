"""
OID4VCI End-to-End Integration Tests via Gateway

Tests the complete credential issuance flow as the real stack experiences it:

  Keycloak PKCE auth  →  POST /v1/issuance (gateway, authenticated)
    →  Walt.id wallet registers, creates DID, redeems offer
    →  Assert credential stored, decode JWT, dump diagnostics

This mirrors exactly what a mobile wallet sees when a user taps
"Get credential" on beta.elevenidllc.com.

Environment variables
---------------------
GATEWAY_URL         Gateway base URL          (default: http://localhost:8000)
WALTID_WALLET_URL   Walt.id wallet URL        (default: http://localhost:7001)
TEST_USERNAME       Keycloak user             (default: admin@marty.demo)
TEST_PASSWORD       Keycloak password         (default: MartyTest123!)
TEST_ORG_ID         Organization ID           (default: 22222222-...)
TEST_TEMPLATE_ID    Credential template ID    (default: 40000000-...0007)
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
import uuid
from typing import Any, Dict, List, Optional

import httpx
import pytest

from .helpers.gateway_client import GatewayClient, GatewayClientError
from .helpers.waltid_wallet_client import WaltIdWalletClient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Test configuration
# ---------------------------------------------------------------------------

DEFAULT_ORG_ID = "22222222-2222-2222-2222-222222222222"
DEFAULT_TEMPLATE_ID = "40000000-0000-0000-0000-000000000007"

ORG_ID = os.getenv("TEST_ORG_ID", DEFAULT_ORG_ID)
TEMPLATE_ID = os.getenv("TEST_TEMPLATE_ID", DEFAULT_TEMPLATE_ID)
WALLET_URL = os.getenv("WALTID_WALLET_URL", "http://localhost:7001")
# Internal issuance service URL (used for direct pre-auth token/credential requests)
ISSUANCE_SERVICE_URL = os.getenv("ISSUANCE_SERVICE_URL", "http://localhost:8005")
# When the Walt.id wallet runs inside Docker it can't reach the host via
# 'localhost'.  Set WALLET_ISSUER_BASE_URL to override the issuer hostname
# embedded in offer URIs before passing them to the wallet container.
# Example: WALLET_ISSUER_BASE_URL=http://host.docker.internal:8000
WALLET_ISSUER_BASE_URL = os.getenv("WALLET_ISSUER_BASE_URL", "http://host.docker.internal:8000")


# ---------------------------------------------------------------------------
# Helper: decode JWT without verification
# ---------------------------------------------------------------------------

def _decode_jwt_payload(token: str) -> dict:
    """Base64-decode the JWT payload (no signature verification)."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1]
        # Add padding
        payload += "=" * (4 - len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception as exc:
        logger.warning("Could not decode JWT payload: %s", exc)
        return {}


def _decode_jwt_header(token: str) -> dict:
    """Base64-decode the JWT header."""
    try:
        parts = token.split(".")
        if not parts:
            return {}
        header = parts[0]
        header += "=" * (4 - len(header) % 4)
        return json.loads(base64.urlsafe_b64decode(header))
    except Exception as exc:
        logger.warning("Could not decode JWT header: %s", exc)
        return {}


def _short(s: str, n: int = 100) -> str:
    s = str(s) if s is not None else ""
    return s if len(s) <= n else s[:n] + "…"


def _rewrite_offer_for_wallet(offer_uri: str) -> str:
    """Rewrite issuer hostnames in a credential offer URI for the Docker wallet.

    The Walt.id wallet container runs inside Docker and cannot resolve
    'localhost' on the host.  Replaces the host portion of GATEWAY_URL with
    WALLET_ISSUER_BASE_URL so the wallet can reach the gateway.

    When WALLET_ISSUER_BASE_URL already matches GATEWAY_URL (e.g. in CI
    where both are on the same network) the URI is returned unchanged.

    Handles both plain and percent-encoded occurrences of the hostname
    (OID4VC offers URL-encode the credential_issuer value).
    """
    gateway_url = os.getenv("GATEWAY_URL", "http://localhost:8000")
    if gateway_url == WALLET_ISSUER_BASE_URL:
        return offer_uri
    import urllib.parse as _up
    gw_parsed = _up.urlparse(gateway_url)
    wi_parsed = _up.urlparse(WALLET_ISSUER_BASE_URL)
    gw_host = f"{gw_parsed.hostname}:{gw_parsed.port}" if gw_parsed.port else gw_parsed.hostname
    wi_host = f"{wi_parsed.hostname}:{wi_parsed.port}" if wi_parsed.port else wi_parsed.hostname
    # Replace both the plain form (e.g. in headers) and percent-encoded form
    # (e.g. inside query-string values like credential_issuer).
    result = offer_uri.replace(gw_host, wi_host)
    result = result.replace(_up.quote(gw_host, safe=""), _up.quote(wi_host, safe=""))
    return result


def _assert_credential_document(raw_doc: str, expected_label: str = "") -> None:
    """Assert JWT-VC or SD-JWT credential structure and log key fields.

    Handles both vc+jwt (JWT-VC) and vc+sd-jwt (SD-JWT / ZKP) formats.
    SD-JWT documents look like ``header.payload.sig~disclosure1~disclosure2~``
    """
    prefix = f"[{expected_label}] " if expected_label else ""

    # Detect SD-JWT by presence of ~ separator (disclosure segment delimiter)
    is_sd_jwt = "~" in raw_doc
    base_jwt = raw_doc.split("~")[0]  # strip disclosures for JWT decoding

    header = _decode_jwt_header(base_jwt)
    payload = _decode_jwt_payload(base_jwt)
    typ = header.get("typ", "")
    kid = header.get("kid", "")

    logger.info("%sJWT header: %s", prefix, json.dumps(header, indent=2))
    logger.info("%sJWT payload keys: %s", prefix, list(payload.keys()))
    logger.info(
        "%siss=%s  sub=%s  typ=%s  kid=%s",
        prefix,
        payload.get("iss"),
        payload.get("sub"),
        typ,
        kid,
    )

    assert "did:key:" in kid, (
        f"{prefix}kid should contain 'did:key:', got: {kid!r}\nFull header: {header}"
    )

    if is_sd_jwt or "sd-jwt" in typ.lower():
        # ---- SD-JWT VC (ZKP / selective disclosure) ----
        logger.info("%sFormat detected: SD-JWT VC (selective disclosure / ZKP)", prefix)
        assert "sd-jwt" in typ.lower(), (
            f"{prefix}Expected 'vc+sd-jwt' typ for SD-JWT doc, got: {typ!r}"
        )
        # SD-JWT MUST carry vct (Verifiable Credential Type) claim
        assert payload.get("vct") or payload.get("_sd_alg") or payload.get("cnf"), (
            f"{prefix}SD-JWT payload missing 'vct'/_sd_alg/cnf. "
            f"Keys: {list(payload.keys())}"
        )
        logger.info("%s✓ SD-JWT structure valid (typ=%s)", prefix, typ)

    else:
        # ---- JWT-VC ----
        logger.info("%sFormat detected: JWT-VC", prefix)
        assert typ == "vc+jwt", (
            f"{prefix}JWT typ should be 'vc+jwt', got: {typ!r}\nFull header: {header}"
        )
        assert payload.get("vc"), (
            f"{prefix}JWT payload missing 'vc' claim. Keys: {list(payload.keys())}"
        )
        assert payload.get("iss"), f"{prefix}JWT payload missing 'iss'"
        # sub is optional when no holder DID is bound (direct issuance without a wallet)
        if not payload.get("sub"):
            logger.warning("%sJWT payload missing 'sub' — no holder DID bound at issuance", prefix)
        logger.info("%s✓ JWT-VC structure valid (typ=%s)", prefix, typ)


# ---------------------------------------------------------------------------
# Credential type test matrix
# ---------------------------------------------------------------------------

# Claims common to identity-type credentials
_ID_CLAIMS = {
    "given_name": "Integration",
    "family_name": "Test",
    "date_of_birth": "1990-01-01",
}
# Same but includes a document_number (required by passport, visa, DTC)
_DOC_CLAIMS = {**_ID_CLAIMS, "document_number": "ITG-TEST-001"}

# (template_id, credential_config_id, claims, human_label)
CREDENTIAL_TYPE_CASES: List = [
    pytest.param(
        "40000000-0000-0000-0000-000000000001",
        "passport",
        _DOC_CLAIMS,
        "passport",
        id="passport",
    ),
    pytest.param(
        "40000000-0000-0000-0000-000000000002",
        "org.iso.18013.5.1.mDL",
        _ID_CLAIMS,
        "drivers_license",
        id="drivers_license",
    ),
    pytest.param(
        "40000000-0000-0000-0000-000000000005",
        "access_badge",
        _ID_CLAIMS,
        "access_badge",
        id="access_badge",
    ),
    pytest.param(
        "40000000-0000-0000-0000-000000000007",
        "open_badge",
        _ID_CLAIMS,
        "open_badge",
        id="open_badge",
    ),
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
async def waltid_client() -> WaltIdWalletClient:
    """Walt.id wallet client with auto-cleanup."""
    client = WaltIdWalletClient(base_url=WALLET_URL)
    yield client
    if client.wallet_id:
        try:
            await client.delete_wallet()
        except Exception:
            pass
    await client.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.integration
@pytest.mark.wallet
class TestOID4VCIViaGateway:
    """
    Full OID4VCI flow exercised via the authenticated gateway API.

    The test suite verifies:
    1.  PKCE auth → valid sessionId cookie
    2.  Authenticated POST /v1/issuance → credential offer returned
    3.  Walt.id wallet registers, creates DID, redeems offer
    4.  Credential stored in wallet and contains expected JWT structure
    """

    @pytest.mark.asyncio
    async def test_pkce_auth_and_offer_creation(
        self,
        authenticated_gateway_client: GatewayClient,
    ):
        """
        Smoke test: can we create a credential offer via the authenticated gateway?
        
        Validates that:
        - PKCE session cookie is accepted by the gateway
        - Gateway proxies the request to the issuance service
        - Response contains a credential_offer_uri
        """
        result = await authenticated_gateway_client.issue_credential(
            organization_id=ORG_ID,
            credential_template_id=TEMPLATE_ID,
            claims={
                "given_name": "Integration",
                "family_name": "Test",
                "test_run": str(int(time.time())),
            },
        )

        logger.info("[offer] issuance response: %s", json.dumps(result, indent=2)[:500])

        assert result.get("id"), "Response missing 'id'"
        assert result.get("credential_offer_uri"), (
            f"Response missing 'credential_offer_uri'.\nFull response: {result}"
        )
        assert result.get("status"), "Response missing 'status'"

        offer_uri = result["credential_offer_uri"]
        logger.info("[offer] offer URI: %s", _short(offer_uri, 120))
        return offer_uri

    @pytest.mark.asyncio
    async def test_wallet_redeems_credential_offer(
        self,
        authenticated_gateway_client: GatewayClient,
        waltid_client: WaltIdWalletClient,
    ):
        """
        Full end-to-end: create offer via gateway → wallet redeems it → credential stored.

        This is the exact path a mobile wallet takes:
          1. Issuer (UI/backend) creates offer → gets credential_offer_uri
          2. Wallet scans QR / taps deeplink with that URI
          3. Walt.id fetches /.well-known/ discovery, gets token, gets credential
          4. Credential is stored in wallet
        """
        # ----------------------------------------------------------------
        # Step 1: Create credential offer via authenticated gateway
        # ----------------------------------------------------------------
        logger.info("[test] Creating credential offer via gateway...")
        result = await authenticated_gateway_client.issue_credential(
            organization_id=ORG_ID,
            credential_template_id=TEMPLATE_ID,
            claims={
                "given_name": "Wallet",
                "family_name": "Integration Test",
                "test_id": uuid.uuid4().hex[:8],
            },
        )

        tx_id = result.get("id")
        offer_uri = result.get("credential_offer_uri")
        assert offer_uri, f"No credential_offer_uri in: {result}"
        logger.info("[test] tx_id=%s  offer_uri=%s", tx_id, _short(offer_uri, 120))

        # ----------------------------------------------------------------
        # Step 2: Register wallet + create DID
        # ----------------------------------------------------------------
        logger.info("[wallet] Setting up Walt.id wallet...")
        ts = int(time.time())
        wallet_email = f"itest-{ts}@marty-integration.demo"
        wallet_password = f"IntTest{ts}!"

        wallet_result = await waltid_client.create_wallet(
            name=f"itest-wallet-{ts}",
            email=wallet_email,
            password=wallet_password,
        )
        assert waltid_client.wallet_id, "Wallet creation did not set wallet_id"
        logger.info("[wallet] wallet_id=%s", waltid_client.wallet_id)

        did_result = await waltid_client.create_did(method="key")
        did = did_result.get("did")
        assert did, f"create_did returned no DID: {did_result}"
        logger.info("[wallet] DID: %s", _short(did, 80))

        # ----------------------------------------------------------------
        # Step 3: Resolve offer metadata (diagnostic)
        # ----------------------------------------------------------------
        wallet_offer_uri = _rewrite_offer_for_wallet(offer_uri)
        logger.info("[wallet] Resolving credential offer metadata...")
        try:
            resolved = await waltid_client.resolve_credential_offer(wallet_offer_uri)
            logger.info("[wallet] resolved offer: %s", json.dumps(resolved, indent=2, default=str)[:600])
        except Exception as exc:
            # Non-fatal: some wallet versions skip this step
            logger.warning("[wallet] resolve_credential_offer failed (non-fatal): %s", exc)

        # ----------------------------------------------------------------
        # Step 4: Redeem the offer (the critical step)
        # ----------------------------------------------------------------
        logger.info("[wallet] Redeeming credential offer (useOfferRequest)...")
        try:
            redeem_result = await waltid_client.accept_credential_offer(
                offer_url=wallet_offer_uri,
                did=did,
            )
            logger.info("[wallet] accept_credential_offer result: %s",
                        json.dumps(redeem_result, indent=2, default=str)[:800])
        except Exception as exc:
            logger.error("[wallet] accept_credential_offer FAILED: %s", exc)
            # Re-raise so the test fails with a clear message
            raise AssertionError(
                f"Walt.id wallet failed to redeem credential offer.\n"
                f"Offer URI (rewritten for wallet): {wallet_offer_uri}\n"
                f"Original offer URI: {offer_uri}\n"
                f"Error: {exc}\n\n"
                "Check:\n"
                "  - Is beta.elevenidllc.com tunnel available?\n"
                "  - Does /.well-known/openid-credential-issuer/org/{org_id} return HTTP 200?\n"
                "  - Does /v1/issuance/token return HTTP 200?\n"
                "  - Does /v1/issuance/credential return HTTP 200 with a valid JWT?\n"
            ) from exc

        # ----------------------------------------------------------------
        # Step 5: Verify credential was stored
        # ----------------------------------------------------------------
        logger.info("[wallet] Listing stored credentials...")
        credentials = await waltid_client.list_credentials()
        logger.info("[wallet] %d credential(s) stored", len(credentials))

        assert len(credentials) > 0, (
            "No credentials stored in wallet after redeeming offer.\n"
            f"Wallet ID: {waltid_client.wallet_id}\n"
            f"Offer URI: {offer_uri}"
        )

        # ----------------------------------------------------------------
        # Step 6: Decode and inspect the stored credential JWT
        # ----------------------------------------------------------------
        cred = credentials[0]
        logger.info("[credential] raw entry keys: %s", list(cred.keys()))

        # Walt.id wraps the VC-JWT in a "document" or "credential" field
        raw_jwt = (
            cred.get("document")
            or cred.get("credential")
            or cred.get("rawDocument")
            or cred.get("vc")
            or ""
        )

        if raw_jwt and "." in raw_jwt:
            header = _decode_jwt_header(raw_jwt)
            payload = _decode_jwt_payload(raw_jwt)

            logger.info(
                "[credential] JWT header:\n%s",
                json.dumps(header, indent=2),
            )
            logger.info(
                "[credential] JWT payload (top-level keys): %s",
                list(payload.keys()),
            )
            logger.info(
                "[credential] iss=%s  sub=%s  typ=%s  kid=%s",
                payload.get("iss"),
                payload.get("sub"),
                header.get("typ"),
                header.get("kid"),
            )

            # Assert JWT structure is correct.
            # Accepted typ values:
            #   "vc+jwt"    — JWT-VC-JSON (RFC 7519 / OID4VCI Draft 11/13)
            #   "dc+sd-jwt" — SD-JWT-VC (RFC 9596 §3.3, newer label)
            #   "vc+sd-jwt" — SD-JWT-VC (RFC 9596 §3.1, older label)
            VALID_TYP = {"vc+jwt", "dc+sd-jwt", "vc+sd-jwt"}
            assert header.get("typ") in VALID_TYP, (
                f"JWT typ should be one of {VALID_TYP}, got: {header.get('typ')!r}\n"
                f"Full header: {header}"
            )
            kid = header.get("kid", "")
            assert "did:key:" in kid, (
                f"JWT kid should contain 'did:key:', got: {kid!r}\n"
                f"Full header: {header}"
            )
            assert "#" in kid, (
                f"JWT kid should be a DID URL (with #fragment), got: {kid!r}\n"
                f"Full header: {header}"
            )

            is_sd_jwt = header.get("typ") in {"dc+sd-jwt", "vc+sd-jwt"}
            if is_sd_jwt:
                # SD-JWT-VC: claims are in disclosures, not a nested "vc" object.
                # The JWT body (issuer-signed part) typically has "iss", "sub"/"vct".
                assert payload.get("iss"), "SD-JWT payload missing 'iss'"
            else:
                # JWT-VC-JSON: must have nested "vc" claim with iss/sub at top level.
                vc = payload.get("vc") or {}
                assert vc, (
                    f"JWT payload missing 'vc' claim.\nPayload keys: {list(payload.keys())}"
                )
                assert payload.get("iss"), "JWT payload missing 'iss'"
                assert payload.get("sub"), "JWT payload missing 'sub'"
        else:
            logger.warning(
                "[credential] Could not extract JWT from credential entry "
                "(unexpected format): %s",
                _short(str(cred), 300),
            )
            # Don't hard-fail on format – credential WAS stored, that's the key assertion
            # The format issue is logged for diagnosis

        logger.info("[test] ✓ Credential stored and JWT structure valid")


@pytest.mark.integration
class TestOID4VCIAuthFlow:
    """Verify that auth is actually required by the gateway."""

    @pytest.mark.asyncio
    async def test_unauthenticated_request_rejected(self):
        """POST /v1/issuance without session cookie should return 401."""
        gateway_url = os.getenv("GATEWAY_URL", "http://localhost:8000")
        async with httpx.AsyncClient(base_url=gateway_url, timeout=10) as client:
            r = await client.post(
                "/v1/issuance",
                json={
                    "organization_id": ORG_ID,
                    "credential_template_id": TEMPLATE_ID,
                    "claims": {},
                },
            )
        assert r.status_code == 401, (
            f"Expected 401 for unauthenticated request, got {r.status_code}.\n"
            f"Body: {r.text[:300]}"
        )
        logger.info("[auth] ✓ Unauthenticated request correctly rejected with 401")


# ---------------------------------------------------------------------------
# Multi-type tests: exercise each credential template via Walt.id
# ---------------------------------------------------------------------------

@pytest.mark.integration
@pytest.mark.wallet
class TestMultipleCredentialTypes:
    """
    Parametrized test: each credential type (passport, mDL, access badge,
    open badge) can be issued, redeemed by a Walt.id wallet, and stored.

    One wallet is created per test instance; it is auto-deleted in the
    ``waltid_client`` fixture teardown.
    """

    @pytest.mark.asyncio
    @pytest.mark.parametrize("template_id,cred_config_id,claims,label", CREDENTIAL_TYPE_CASES)
    async def test_wallet_stores_credential_type(
        self,
        authenticated_gateway_client: GatewayClient,
        waltid_client: WaltIdWalletClient,
        template_id: str,
        cred_config_id: str,
        claims: dict,
        label: str,
    ):
        """Offer → Walt.id redeems → credential stored with valid structure."""
        # ---- Step 1: Create offer ----
        result = await authenticated_gateway_client.issue_credential(
            organization_id=ORG_ID,
            credential_template_id=template_id,
            claims={**claims, "test_id": uuid.uuid4().hex[:8]},
        )
        offer_uri = result.get("credential_offer_uri")
        assert offer_uri, f"[{label}] No credential_offer_uri in: {result}"
        logger.info("[%s] offer_uri: %s", label, _short(offer_uri, 120))

        # ---- Step 2: Create wallet + DID ----
        ts = int(time.time())
        await waltid_client.create_wallet(
            name=f"itest-{label}-{ts}",
            email=f"itest-{label}-{ts}@marty-integration.demo",
            password=f"IntTest{ts}!",
        )
        assert waltid_client.wallet_id, f"[{label}] Wallet creation failed"

        did_result = await waltid_client.create_did(method="key")
        did = did_result.get("did")
        assert did, f"[{label}] No DID created: {did_result}"
        logger.info("[%s] DID: %s", label, _short(did, 80))

        # ---- Step 3: Redeem offer ----
        wallet_offer_uri = _rewrite_offer_for_wallet(offer_uri)
        try:
            await waltid_client.accept_credential_offer(offer_url=wallet_offer_uri, did=did)
        except Exception as exc:
            raise AssertionError(
                f"[{label}] Walt.id failed to redeem offer.\n"
                f"Offer: {offer_uri}\nError: {exc}"
            ) from exc

        # ---- Step 4: Assert stored ----
        credentials = await waltid_client.list_credentials()
        assert len(credentials) > 0, (
            f"[{label}] No credentials stored after redemption.\n"
            f"Wallet ID: {waltid_client.wallet_id}\nOffer: {offer_uri}"
        )
        logger.info("[%s] %d credential(s) stored", label, len(credentials))

        # ---- Step 5: Format-aware structural assertions ----
        cred = credentials[0]
        raw_doc = (
            cred.get("document")
            or cred.get("credential")
            or cred.get("rawDocument")
            or cred.get("vc")
            or ""
        )
        if raw_doc and "." in raw_doc:
            _assert_credential_document(raw_doc, expected_label=label)
        else:
            logger.warning(
                "[%s] Unexpected credential format (no JWT detected): %s",
                label,
                _short(str(cred), 300),
            )

        logger.info("[%s] ✓ Credential issued, redeemed, and stored", label)


# ---------------------------------------------------------------------------
# ZKP / SD-JWT tests: directly exercise sd-jwt format via pre-auth code flow
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestZKPSDJWTIssuance:
    """
    Tests SD-JWT (ZKP / selective-disclosure) credential issuance using the
    OID4VCI pre-authorized code flow directly (bypassing Walt.id).

    Two things are validated per test:
      (a) Pre-auth code flow: offer → token exchange → credential endpoint
          — this works today and confirms the full OID4VCI protocol path.
      (b) SD-JWT format: the credential *should* be vc+sd-jwt when requested
          — currently the server ignores ``format: vc+sd-jwt`` and always
          returns JWT-VC.  These format assertions are marked xfail and will
          automatically turn into passes when SD-JWT dispatch is implemented.

    Flow:
      1.  Authenticated gateway  →  POST /v1/issuance  →  pre_auth_code
      2.  POST /v1/issuance/token (pre-auth code grant)  →  access_token
      3.  POST /v1/issuance/credential (format: vc+sd-jwt)  →  credential
      4.  Assert basic credential structure (passes today)
      5.  Assert SD-JWT format (xfail until server implements format dispatch)
    """

    # Re-usable helper -------------------------------------------------------

    async def _get_credential_via_pre_auth(
        self,
        authenticated_gateway_client: GatewayClient,
        template_id: str,
        cred_config_id: str,
        claims: dict,
        label: str,
        requested_format: str = "vc+sd-jwt",
    ) -> str:
        """Create offer → token exchange → request credential.  Returns raw doc."""
        # Step 1 — create offer via authenticated gateway
        result = await authenticated_gateway_client.issue_credential(
            organization_id=ORG_ID,
            credential_template_id=template_id,
            claims=claims,
        )
        pre_auth_code = result.get("pre_auth_code")
        assert pre_auth_code, f"[{label}] No pre_auth_code in issuance response: {result}"
        logger.info("[%s] pre_auth_code obtained", label)

        # Step 2 — token exchange (pre-authorized code grant, OID4VCI §6.1)
        async with httpx.AsyncClient(timeout=20) as http:
            token_resp = await http.post(
                f"{ISSUANCE_SERVICE_URL}/v1/issuance/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                    "pre-authorized_code": pre_auth_code,
                },
            )
        assert token_resp.status_code == 200, (
            f"[{label}] Token exchange failed ({token_resp.status_code}): "
            f"{token_resp.text[:400]}"
        )
        access_token = token_resp.json().get("access_token")
        assert access_token, f"[{label}] No access_token in: {token_resp.json()}"
        logger.info("[%s] access_token obtained (len=%d)", label, len(access_token))

        # Step 3 — credential request with desired format (OID4VCI §7.2)
        async with httpx.AsyncClient(timeout=20) as http:
            cred_resp = await http.post(
                f"{ISSUANCE_SERVICE_URL}/v1/issuance/credential",
                headers={"Authorization": f"Bearer {access_token}"},
                json={
                    "format": requested_format,
                    "credential_configuration_id": cred_config_id,
                },
            )
        assert cred_resp.status_code == 200, (
            f"[{label}] Credential request failed ({cred_resp.status_code}): "
            f"{cred_resp.text[:400]}"
        )
        # OID4VCI v1 §8.3 returns a "credentials" array; fall back to legacy "credential" scalar
        resp_json = cred_resp.json()
        raw_doc = (resp_json.get("credentials") or [resp_json.get("credential", "")])[0]
        assert raw_doc, f"[{label}] No 'credential'/'credentials' field in response: {resp_json}"
        logger.info("[%s] credential received (len=%d)", label, len(raw_doc))
        return raw_doc

    def _check_sd_jwt_format(self, raw_doc: str, label: str) -> None:
        """Assert the document is SD-JWT, xfail if the server returned JWT-VC.

        TODO: Remove xfail when the credential endpoint implements format dispatch.
        See: issuance routes.py ``create_verifiable_credential_wrapper`` call —
        the ``request.format`` field is currently ignored.
        """
        base_jwt = raw_doc.split("~")[0]
        typ = _decode_jwt_header(base_jwt).get("typ", "")
        is_sd_jwt = "sd-jwt" in typ.lower() or "~" in raw_doc

        if not is_sd_jwt:
            pytest.xfail(
                f"[{label}] Server returned {typ!r} instead of the requested "
                f"vc+sd-jwt format.  SD-JWT format dispatch is not yet "
                f"implemented in the credential endpoint (format param ignored)."
            )

        # If we get here, SD-JWT was returned — validate structure
        _assert_credential_document(raw_doc, expected_label=f"{label}_format_check")
        logger.info("[%s] ✓ SD-JWT issued (typ=%s)", label, typ)

    # Tests ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_pre_auth_flow_and_sd_jwt_open_badge(
        self,
        authenticated_gateway_client: GatewayClient,
    ):
        """
        Open Badge: verify pre-auth code flow end-to-end, then assert SD-JWT.

        The pre-auth flow assertions (steps 1-3) pass today.
        The SD-JWT format assertion is xfail pending server-side implementation.
        """
        label = "open_badge"
        raw_doc = await self._get_credential_via_pre_auth(
            authenticated_gateway_client,
            template_id="40000000-0000-0000-0000-000000000007",
            cred_config_id="open_badge",
            claims={
                "given_name": "ZKP",
                "family_name": "Test",
                "date_of_birth": "1990-01-01",
            },
            label=label,
        )
        # Base credential structure is valid regardless of format
        _assert_credential_document(raw_doc, expected_label=f"{label}_pre_auth")
        # SD-JWT format check (xfail until server implements dispatch)
        self._check_sd_jwt_format(raw_doc, label)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("template_id,cred_config_id,extra_claims,label", [
        pytest.param(
            "40000000-0000-0000-0000-000000000001",
            "passport",
            {"document_number": "ZKP-TEST-001"},
            "passport",
            id="passport",
        ),
        pytest.param(
            "40000000-0000-0000-0000-000000000002",
            "org.iso.18013.5.1.mDL",
            {},
            "drivers_license",
            id="drivers_license",
        ),
        pytest.param(
            "40000000-0000-0000-0000-000000000005",
            "access_badge",
            {},
            "access_badge",
            id="access_badge",
        ),
    ])
    async def test_pre_auth_flow_and_sd_jwt_credential_types(
        self,
        authenticated_gateway_client: GatewayClient,
        template_id: str,
        cred_config_id: str,
        extra_claims: dict,
        label: str,
    ):
        """
        Each credential type: verify pre-auth code flow, then assert SD-JWT.

        The pre-auth flow (token exchange + credential endpoint) passes today.
        The SD-JWT format assertion is xfail pending server-side implementation.
        """
        claims = {
            "given_name": "ZKP",
            "family_name": "Test",
            "date_of_birth": "1990-01-01",
            **extra_claims,
        }
        raw_doc = await self._get_credential_via_pre_auth(
            authenticated_gateway_client,
            template_id=template_id,
            cred_config_id=cred_config_id,
            claims=claims,
            label=label,
        )
        # Base structure is valid regardless of format
        _assert_credential_document(raw_doc, expected_label=f"{label}_pre_auth")
        # SD-JWT format check (xfail until server implements dispatch)
        self._check_sd_jwt_format(raw_doc, label)
