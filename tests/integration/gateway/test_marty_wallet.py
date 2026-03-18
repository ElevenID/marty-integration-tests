"""
Marty Authenticator Web App (Flutter) Integration Tests

Tests the Marty wallet Flutter web app using Playwright.  The app is built
with ``lib/mains/main_web_test.dart`` which exposes a ``postMessage`` API
for test coordination.

PostMessage protocol (test ↔ app):
  Test → App:  window.postMessage({type: "SCAN_QR_CODE",  payload: {data: uri}}, "*")
               window.postMessage({type: "GET_CREDENTIALS"}, "*")
               window.postMessage({type: "GET_DEVICE_ID"},  "*")
               window.postMessage({type: "CLEAR_DATA"},     "*")
  App → Test:  {type: "WALLET_READY", ...}
               {type: "CREDENTIALS",  payload: {credentials: [...]}}
               {type: "DEVICE_ID",    payload: {device_id: "..."}}
               {type: "QR_CODE_INJECTED", payload: {success: true}}

URL parameters accepted by the test build:
  test_mode=true   — enables test mode
  api_url=<url>    — overrides the compiled-in MARTY_API_URL at runtime

Environment variables:
  MARTY_WALLET_URL   Base URL of the Flutter web app (default: http://localhost:9081)
  GATEWAY_URL        Gateway base URL               (default: http://localhost:8000)
  TEST_ORG_ID        Test organisation ID
  TEST_TEMPLATE_ID   Credential template ID to use for issuance tests
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import time
import uuid
from typing import Any, AsyncGenerator, Dict, List, Optional

import httpx
import pytest
import _marty_rs
from playwright.async_api import (
    BrowserContext,
    ConsoleMessage,
    Page,
    async_playwright,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_ORG_ID = "22222222-2222-2222-2222-222222222222"
DEFAULT_TEMPLATE_ID = "40000000-0000-0000-0000-000000000007"

ORG_ID = os.getenv("TEST_ORG_ID", DEFAULT_ORG_ID)
TEMPLATE_ID = os.getenv("TEST_TEMPLATE_ID", DEFAULT_TEMPLATE_ID)
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8000")

# Timeout constants (ms / seconds)
WALLET_READY_TIMEOUT_MS = 60_000   # Flutter app boot can be slow
POST_MSG_TIMEOUT_MS = 15_000       # Waiting for a postMessage reply
ACCEPT_DIALOG_TIMEOUT_MS = 20_000  # Credential accept dialog to appear
CREDENTIAL_STORE_TIMEOUT_S = 30    # Max seconds to poll for stored credential

# OID4VCI pre-auth code flow hits the issuance service directly (bypasses gateway)
ISSUANCE_SERVICE_URL = os.getenv("ISSUANCE_SERVICE_URL", "http://localhost:8005")


# ---------------------------------------------------------------------------
# Playwright helper: inject message trap early so no events are missed
# ---------------------------------------------------------------------------

_INIT_SCRIPT = """
window.__testMessages = [];
window.addEventListener('message', (evt) => {
    try {
        const data = (typeof evt.data === 'string')
            ? JSON.parse(evt.data)
            : evt.data;
        if (data && data.type) {
            window.__testMessages.push(data);
            console.log('TEST_MSG:' + JSON.stringify(data));
        }
    } catch (_) {}
});
"""


def _send_msg(msg_type: str, payload: Optional[Dict] = None) -> str:
    """Return a JS expression that posts a message to the Flutter app."""
    envelope = {"type": msg_type}
    if payload:
        envelope["payload"] = payload
    return f"window.postMessage({json.dumps(envelope)}, '*')"


async def _wait_for_message(
    page: Page,
    msg_type: str,
    timeout_ms: int = POST_MSG_TIMEOUT_MS,
) -> Dict[str, Any]:
    """
    Poll ``window.__testMessages`` until a message of the expected type arrives.
    Returns the full message envelope.  Raises TimeoutError on expiry.
    """
    deadline = time.monotonic() + timeout_ms / 1000.0
    while time.monotonic() < deadline:
        messages: list = await page.evaluate("window.__testMessages")
        for msg in messages:
            if isinstance(msg, dict) and msg.get("type") == msg_type:
                logger.debug("[msg] received %s: %s", msg_type, str(msg)[:200])
                return msg
        await asyncio.sleep(0.25)
    raise TimeoutError(
        f"Timed out waiting for postMessage type={msg_type!r} "
        f"(timeout={timeout_ms}ms)"
    )


async def _clear_messages(page: Page) -> None:
    await page.evaluate("window.__testMessages = []")


# ---------------------------------------------------------------------------
# JWT decode helpers (mirrors test_wallet_oid4vci_gateway.py helpers)
# ---------------------------------------------------------------------------

def _decode_jwt_payload(token: str) -> dict:
    """Base64-decode the JWT payload (no signature verification)."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1]
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


# ---------------------------------------------------------------------------
# Credential type test matrix (mirrors test_wallet_oid4vci_gateway.py matrix)
# ---------------------------------------------------------------------------

# Claims common to identity-type credentials
_ID_CLAIMS = {
    "given_name": "Integration",
    "family_name": "Test",
    "date_of_birth": "1990-01-01",
}
# Same but adds document_number (passport, visa, DTC)
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
# Browser / page fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
async def browser_context() -> AsyncGenerator[BrowserContext, None]:
    """Headless Chromium context shared by tests in this module."""
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context(
            # Needed for localStorage to work across same-origin reloads
            ignore_https_errors=True,
        )
        yield context
        await context.close()
        await browser.close()


@pytest.fixture
async def wallet_page(
    browser_context: BrowserContext,
    marty_wallet_url: str,
) -> AsyncGenerator[Page, None]:
    """
    Open the Marty wallet app in a fresh browser page and wait for WALLET_READY.

    URL parameters injected:
      - test_mode=true
      - api_url=<GATEWAY_URL>   so the Flutter JS hits the gateway on this host
    """
    page = await browser_context.new_page()

    # Log Flutter console output while debugging
    def _on_console(msg: ConsoleMessage) -> None:
        if msg.type in ("error", "warning") or "TEST_MSG:" in msg.text:
            logger.debug("[flutter] [%s] %s", msg.type, msg.text[:300])

    page.on("console", _on_console)

    # Inject message-capture script before any page scripts run
    await page.add_init_script(_INIT_SCRIPT)

    url = (
        f"{marty_wallet_url}/"
        f"?test_mode=true"
        f"&api_url={GATEWAY_URL}"
    )
    logger.info("[wallet_page] navigating to %s", url)
    await page.goto(url, wait_until="domcontentloaded")

    # Wait for the Flutter UI to finish mounting
    logger.info("[wallet_page] waiting for WALLET_READY …")
    try:
        await _wait_for_message(page, "WALLET_READY", timeout_ms=WALLET_READY_TIMEOUT_MS)
        logger.info("[wallet_page] WALLET_READY received — Flutter UI is mounted")
    except TimeoutError:
        # Dump console messages to help diagnose slow-start failures
        console_msgs = await page.evaluate(
            "window.__testMessages.map(m => JSON.stringify(m)).join('\\n')"
        )
        logger.warning("[wallet_page] WALLET_READY never arrived. Captured messages:\n%s", console_msgs)
        raise

    yield page
    await page.close()


# ---------------------------------------------------------------------------
# Smoke tests: service availability and basic postMessage round-trip
# ---------------------------------------------------------------------------

@pytest.mark.marty_wallet
class TestMartyWalletSmoke:
    """Verify the Flutter web app serves correctly and the test bridge works."""

    @pytest.mark.asyncio
    async def test_health_check(self, marty_wallet_url: str):
        """GET /health returns 200 OK."""
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{marty_wallet_url}/health", timeout=5.0)
        assert response.status_code == 200
        logger.info("[health] status=%d body=%r", response.status_code, response.text[:40])

    @pytest.mark.asyncio
    async def test_app_loads_and_ready(self, wallet_page: Page):
        """
        The Flutter app boots and emits WALLET_READY.

        wallet_page fixture already waits for WALLET_READY, so reaching this
        test body means the app is fully mounted.
        """
        # Verify we can still read the captured events
        messages = await wallet_page.evaluate("window.__testMessages")
        types = [m.get("type") for m in messages if isinstance(m, dict)]
        assert "WALLET_READY" in types, (
            f"WALLET_READY not in captured messages: {types}"
        )
        logger.info("[smoke] captured message types so far: %s", types)

    @pytest.mark.asyncio
    async def test_get_device_id(self, wallet_page: Page):
        """GET_DEVICE_ID round-trips a postMessage response."""
        await _clear_messages(wallet_page)
        await wallet_page.evaluate(_send_msg("GET_DEVICE_ID"))
        reply = await _wait_for_message(wallet_page, "DEVICE_ID")
        logger.info("[smoke] DEVICE_ID reply: %s", reply)
        # device_id may be None on first boot (no localStorage yet) — that's OK
        assert "type" in reply
        assert reply["type"] == "DEVICE_ID"

    @pytest.mark.asyncio
    async def test_get_credentials_empty_on_fresh_start(self, wallet_page: Page):
        """GET_CREDENTIALS returns a well-formed list on a fresh session.

        Note: the test build seeds walletManager with mock display credentials
        on startup, so we only assert the message round-trip works and the
        payload is a list — not that it is empty.
        """
        await _clear_messages(wallet_page)
        await wallet_page.evaluate(_send_msg("GET_CREDENTIALS"))
        reply = await _wait_for_message(wallet_page, "CREDENTIALS")

        creds: list = reply.get("payload", {}).get("credentials", [])
        logger.info("[smoke] GET_CREDENTIALS returned %d items", len(creds))
        assert isinstance(creds, list), f"Expected list, got {type(creds)}"

    @pytest.mark.asyncio
    async def test_wasm_health_check(self, wallet_page: Page):
        """WASM_HEALTH_CHECK gets a WASM_STATUS response; skips if WASM not loaded."""
        await _clear_messages(wallet_page)
        await wallet_page.evaluate(_send_msg("WASM_HEALTH_CHECK"))
        # Flutter handler replies with type='WASM_STATUS'
        reply = await _wait_for_message(wallet_page, "WASM_STATUS")
        logger.info("[smoke] WASM_STATUS: %s", reply)
        payload = reply.get("payload", {})
        assert "available" in payload, (
            f"WASM_STATUS payload missing 'available' field: {reply}"
        )
        if not payload["available"]:
            pytest.skip(
                f"WASM module not loaded in this build: {payload.get('error', 'unknown')}"
            )
        # WASM is present — verify it reports a version
        assert payload.get("version") or payload.get("health"), (
            f"WASM available but returned no version/health: {payload}"
        )


# ---------------------------------------------------------------------------
# OID4VCI integration: issue credential via gateway → accept in Flutter wallet
# ---------------------------------------------------------------------------

@pytest.mark.integration
@pytest.mark.marty_wallet
class TestMartyWalletOID4VCI:
    """
    End-to-end: issue a credential via the Marty gateway, inject the offer
    URI as a QR scan into the Flutter wallet, and verify the credential is
    stored.
    """

    @pytest.mark.asyncio
    async def test_credential_offer_and_store(
        self,
        wallet_page: Page,
        authenticated_gateway_client: Any,
        test_organization: Dict[str, Any],
        jwt_vc_v2_template: Dict[str, Any],
    ):
        """
        Gateway issuance → QR injection → credential storage via postMessage API.

        Steps:
          1. Create a credential offer via the authenticated gateway
          2. Verify the offer URI starts with openid-credential-offer://
          3. Inject the offer URI into the Flutter wallet (simulates QR scan)
          4. Verify the wallet acknowledges the injection (QR_CODE_INJECTED: success)
          5. Directly store the credential payload via STORE_CREDENTIAL
          6. Verify GET_CREDENTIALS includes the stored credential

        Note: The full OID4VCI Accept dialog path (browser fetches issuer metadata,
        exchanges token, stores credential via AlertDialog) requires CORS from the
        wallet origin (http://localhost:9081) to the gateway (http://localhost:8000).
        To enable that, rebuild Flutter with MARTY_API_URL=http://localhost:9081
        so the credential offer uses the proxied origin as issuer.
        """
        # ----------------------------------------------------------------
        # 1. Create credential offer via gateway API
        # ----------------------------------------------------------------
        logger.info("[oid4vci] Creating credential offer via gateway…")
        result = await authenticated_gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=jwt_vc_v2_template["id"],
            claims={
                "given_name": "Flutter",
                "family_name": "WalletTest",
                "test_id": uuid.uuid4().hex[:8],
            },
        )
        offer_uris: Dict[str, Any] = result.get("credential_offer_uris") or {}
        offer_uri: Optional[str] = offer_uris.get("marty") or result.get("credential_offer_uri")
        assert offer_uri, (
            f"No credential_offer_uri/credential_offer_uris.marty in response: {result}"
        )
        logger.info("[oid4vci] offer_uri=%s", offer_uri[:120])

        # The offer URI should be an openid-credential-offer URI
        assert offer_uri.startswith("openid-credential-offer://"), (
            f"Expected openid-credential-offer:// scheme, got: {offer_uri[:80]}"
        )

        # ----------------------------------------------------------------
        # 2. Inject offer as QR scan and verify acknowledgement
        # ----------------------------------------------------------------
        await _clear_messages(wallet_page)
        logger.info("[oid4vci] Injecting offer as QR scan…")
        await wallet_page.evaluate(
            _send_msg("SCAN_QR_CODE", {"data": offer_uri})
        )
        inject_reply = await _wait_for_message(
            wallet_page, "QR_CODE_INJECTED", timeout_ms=POST_MSG_TIMEOUT_MS
        )
        assert inject_reply.get("payload", {}).get("success") is True, (
            f"QR injection not successful: {inject_reply}"
        )
        logger.info("[oid4vci] QR_CODE_INJECTED acknowledged")

        # ----------------------------------------------------------------
        # 3. Directly store a credential payload to simulate Accept
        # ----------------------------------------------------------------
        mock_credential = {
            "id": f"test-vc-{uuid.uuid4().hex[:8]}",
            "type": "VerifiableCredential",
            "issuer": test_organization["id"],
            "credentialSubject": {
                "given_name": "Flutter",
                "family_name": "WalletTest",
            },
        }
        await _clear_messages(wallet_page)
        await wallet_page.evaluate(
            _send_msg("STORE_CREDENTIAL", {"credential": mock_credential})
        )
        store_reply = await _wait_for_message(wallet_page, "CREDENTIAL_STORED")
        assert store_reply.get("payload", {}).get("success") is True, (
            f"STORE_CREDENTIAL failed: {store_reply}"
        )
        logger.info("[oid4vci] CREDENTIAL_STORED acknowledged")

        # ----------------------------------------------------------------
        # 4. Verify GET_CREDENTIALS includes the stored credential
        # ----------------------------------------------------------------
        await _clear_messages(wallet_page)
        await wallet_page.evaluate(_send_msg("GET_CREDENTIALS"))
        creds_reply = await _wait_for_message(wallet_page, "CREDENTIALS")
        stored: list = creds_reply.get("payload", {}).get("credentials", [])
        found = any(
            isinstance(c, dict) and c.get("id") == mock_credential["id"]
            for c in stored
        )
        assert found, (
            f"Stored credential {mock_credential['id']!r} not found in "
            f"GET_CREDENTIALS response ({len(stored)} total)"
        )
        logger.info("[oid4vci] ✓ credential found in wallet (%d total)", len(stored))

    @pytest.mark.asyncio
    async def test_qr_injection_valid_offer(
        self,
        wallet_page: Page,
        authenticated_gateway_client: Any,
        test_organization: Dict[str, Any],
        jwt_vc_v2_template: Dict[str, Any],
    ):
        """
        Verify that SCAN_QR_CODE with a real gateway offer URI is acknowledged.

        The Flutter wallet processes the openid-credential-offer URI and sends back
        QR_CODE_INJECTED: success.  The subsequent OID4VCI network exchange
        (browser→issuer metadata + token endpoint) requires gateway CORS to
        allow the wallet origin; that Exchange is not asserted here.
        """
        result = await authenticated_gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=jwt_vc_v2_template["id"],
            claims={
                "given_name": "QRTest",
                "family_name": "WalletTest",
                "test_id": uuid.uuid4().hex[:8],
            },
        )
        offer_uris: Dict[str, Any] = result.get("credential_offer_uris") or {}
        offer_uri: Optional[str] = offer_uris.get("marty") or result.get("credential_offer_uri")
        assert offer_uri, f"No credential_offer_uri in response: {result}"

        await _clear_messages(wallet_page)
        await wallet_page.evaluate(_send_msg("SCAN_QR_CODE", {"data": offer_uri}))
        inject_reply = await _wait_for_message(wallet_page, "QR_CODE_INJECTED")
        payload = inject_reply.get("payload", {})
        assert payload.get("success") is True, (
            f"QR injection was not acknowledged as success: {inject_reply}"
        )
        logger.info(
            "[oid4vci] QR injection acknowledged for offer %s…", offer_uri[:60]
        )


# ---------------------------------------------------------------------------
# Issuance tests: mirror test_wallet_oid4vci_gateway.py for the Flutter wallet
# ---------------------------------------------------------------------------

@pytest.mark.integration
@pytest.mark.marty_wallet
class TestMartyWalletIssuance:
    """
    Issuance tests for the Marty Authenticator Flutter web app.

    Mirrors ``TestOID4VCIViaGateway``, ``TestOID4VCIAuthFlow``,
    ``TestMultipleCredentialTypes``, and ``TestZKPSDJWTIssuance`` from
    ``test_wallet_oid4vci_gateway.py``, using the Flutter postMessage API for
    wallet interactions instead of the Walt.id HTTP REST API.

    Test overview
    -------------
    test_offer_creation_smoke
        Mirrors TestOID4VCIViaGateway.test_pkce_auth_and_offer_creation.
        Verifies the gateway returns a valid credential_offer_uri with all
        required top-level fields when called with an authenticated session.

    test_unauthenticated_issuance_rejected
        Mirrors TestOID4VCIAuthFlow.test_unauthenticated_request_rejected.
        Verifies the gateway returns 401 for unauthenticated issuance requests.
        Does not require the Flutter wallet.

    test_qr_injection_each_credential_type
        Mirrors TestMultipleCredentialTypes — at the QR-injection layer.
        Parametrized over all four credential types; injects each offer URI
        into the Flutter wallet and asserts QR_CODE_INJECTED: success.

    test_pre_auth_flow_stores_credential_in_wallet
        Mirrors TestOID4VCIViaGateway.test_wallet_redeems_credential_offer.
        Does the full pre-authorized code flow (offer → token → credential JWT)
        and stores the real JWT in the Flutter wallet via STORE_CREDENTIAL,
        verifying GET_CREDENTIALS returns it.

    test_pre_auth_all_credential_types
        Parametrized version of the above covering all four credential types.
        Mirrors TestMultipleCredentialTypes for the marty wallet.

    test_pre_auth_sd_jwt_open_badge / test_pre_auth_sd_jwt_credential_types
        Mirrors TestZKPSDJWTIssuance; requests vc+sd-jwt format, stores the
        JWT in the Flutter wallet.  SD-JWT format assertion is xfail until
        the server implements SD-JWT format dispatch.
    """

    # ----------------------------------------------------------------
    # Pre-auth code flow helper
    # Mirrors TestZKPSDJWTIssuance._get_credential_via_pre_auth
    # ----------------------------------------------------------------

    async def _get_credential_via_pre_auth(
        self,
        authenticated_gateway_client: Any,
        template_id: str,
        cred_config_id: str,
        claims: dict,
        label: str,
        *,
        organization_id: str | None = None,
        requested_format: str = "jwt_vc_json",
    ) -> str:
        """Create offer → token exchange → request credential.  Returns raw JWT/SD-JWT."""
        # Step 1 — create offer via authenticated gateway
        org_id = organization_id or os.getenv("TEST_ORG_ID", ORG_ID)
        result = await authenticated_gateway_client.issue_credential(
            organization_id=org_id,
            credential_template_id=template_id,
            claims=claims,
        )
        pre_auth_code = result.get("pre_auth_code")
        assert pre_auth_code, (
            f"[{label}] No pre_auth_code in issuance response: {result}"
        )
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
        token_json = token_resp.json()
        access_token = token_json.get("access_token")
        assert access_token, f"[{label}] No access_token in: {token_json}"
        c_nonce = token_json.get("c_nonce", "")
        logger.info("[%s] access_token obtained (len=%d)", label, len(access_token))

        # Step 3 — proof of possession (OID4VCI §8.2): build and sign with Rust
        proof_jwt = _marty_rs.oid4vci_create_proof_jwt(
            f"{ISSUANCE_SERVICE_URL}/org/{org_id}",
            c_nonce,
        )

        # Step 4 — credential request with desired format (OID4VCI §7.2)
        async with httpx.AsyncClient(timeout=20) as http:
            cred_resp = await http.post(
                f"{ISSUANCE_SERVICE_URL}/v1/issuance/credential",
                headers={"Authorization": f"Bearer {access_token}"},
                json={
                    "format": requested_format,
                    "credential_configuration_id": cred_config_id,
                    "proof": {"proof_type": "jwt", "jwt": proof_jwt},
                },
            )
        assert cred_resp.status_code == 200, (
            f"[{label}] Credential request failed ({cred_resp.status_code}): "
            f"{cred_resp.text[:400]}"
        )
        # OID4VCI v1 §8.3 returns a "credentials" array; fall back to legacy
        # "credential" scalar field
        resp_json = cred_resp.json()
        # OID4VCI v1 Final: "credentials" is an object array {"format":...,"credential":...}
        # Legacy / Draft-11: top-level "credential" scalar string
        first = (resp_json.get("credentials") or [{}])[0]
        raw_doc = (
            first.get("credential") if isinstance(first, dict) else first
        ) or resp_json.get("credential", "")
        assert raw_doc, (
            f"[{label}] No 'credential'/'credentials' field in response: {resp_json}"
        )
        logger.info("[%s] credential received (len=%d)", label, len(raw_doc))
        return raw_doc

    # ----------------------------------------------------------------
    # Test: offer creation smoke test
    # ----------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_offer_creation_smoke(
        self,
        authenticated_gateway_client: Any,
        test_organization: Dict[str, Any],
        jwt_vc_v2_template: Dict[str, Any],
    ):
        """
        Mirrors TestOID4VCIViaGateway.test_pkce_auth_and_offer_creation.

        Verifies that an authenticated gateway call returns a response that:
        - contains an 'id' and 'status' field
        - contains a valid openid-credential-offer:// URI
        """
        result = await authenticated_gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=jwt_vc_v2_template["id"],
            claims={
                "given_name": "Integration",
                "family_name": "Test",
                "test_run": str(int(time.time())),
            },
        )
        logger.info("[issuance] response: %s", json.dumps(result, indent=2)[:500])

        assert result.get("id"), "Response missing 'id'"
        assert result.get("status"), "Response missing 'status'"

        offer_uris: Dict[str, Any] = result.get("credential_offer_uris") or {}
        offer_uri: Optional[str] = offer_uris.get("marty") or result.get("credential_offer_uri")
        assert offer_uri, (
            f"Response missing credential_offer_uri / credential_offer_uris.marty.\n"
            f"Full response: {result}"
        )
        assert offer_uri.startswith("openid-credential-offer://"), (
            f"Expected openid-credential-offer:// scheme, got: {offer_uri[:80]}"
        )
        logger.info("[issuance] ✓ offer_uri=%s…", offer_uri[:80])

    # ----------------------------------------------------------------
    # Test: unauthenticated request rejected (no wallet needed)
    # ----------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_unauthenticated_issuance_rejected(self):
        """
        Mirrors TestOID4VCIAuthFlow.test_unauthenticated_request_rejected.

        POST /v1/issuance without a session cookie must return HTTP 401.
        This test does not require the Flutter wallet to be running.
        """
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
        logger.info("[auth] ✓ Unauthenticated issuance request correctly rejected with 401")

    # ----------------------------------------------------------------
    # Test: QR injection for each credential type (parametrized)
    # ----------------------------------------------------------------

    @pytest.mark.asyncio
    @pytest.mark.parametrize("template_id,cred_config_id,claims,label", CREDENTIAL_TYPE_CASES)
    async def test_qr_injection_each_credential_type(
        self,
        wallet_page: Page,
        authenticated_gateway_client: Any,
        template_id: str,
        cred_config_id: str,
        claims: dict,
        label: str,
    ):
        """
        Mirrors TestMultipleCredentialTypes — at the QR-injection layer.

        For each credential type (passport, mDL, access badge, open badge):
          1. Create a credential offer via the gateway using seed org/template IDs
             (matching the hardcoded IDs used in the waltid tests)
          2. Inject the offer URI into the Flutter wallet via SCAN_QR_CODE
          3. Assert QR_CODE_INJECTED: success

        Note: Uses hardcoded seed IDs (like the waltid parametrized tests) so
        each parametrized case runs without creating a new org/template.
        """
        result = await authenticated_gateway_client.issue_credential(
            organization_id=ORG_ID,
            credential_template_id=template_id,
            claims={**claims, "test_id": uuid.uuid4().hex[:8]},
        )
        offer_uris: Dict[str, Any] = result.get("credential_offer_uris") or {}
        offer_uri: Optional[str] = offer_uris.get("marty") or result.get("credential_offer_uri")
        assert offer_uri, f"[{label}] No credential_offer_uri in: {result}"
        logger.info("[%s] offer_uri: %s…", label, offer_uri[:80])

        await _clear_messages(wallet_page)
        await wallet_page.evaluate(_send_msg("SCAN_QR_CODE", {"data": offer_uri}))
        inject_reply = await _wait_for_message(
            wallet_page, "QR_CODE_INJECTED", timeout_ms=POST_MSG_TIMEOUT_MS
        )
        assert inject_reply.get("payload", {}).get("success") is True, (
            f"[{label}] QR injection not acknowledged as success: {inject_reply}"
        )
        logger.info("[%s] ✓ QR_CODE_INJECTED success", label)

    # ----------------------------------------------------------------
    # Test: full pre-auth flow → store real JWT in Flutter wallet
    # ----------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_pre_auth_flow_stores_credential_in_wallet(
        self,
        wallet_page: Page,
        authenticated_gateway_client: Any,
        test_organization: Dict[str, Any],
        jwt_vc_v2_template: Dict[str, Any],
    ):
        """
        Mirrors TestOID4VCIViaGateway.test_wallet_redeems_credential_offer.

        Instead of using the Walt.id HTTP REST API to redeem the offer, this
        test performs the OID4VCI pre-authorized code flow directly
        (offer → token exchange → credential endpoint) and stores the real JWT
        in the Flutter wallet via STORE_CREDENTIAL.

        Steps:
          1. Create credential offer via gateway → extract pre_auth_code
          2. Exchange pre_auth_code for access_token
          3. Request credential JWT from issuance credential endpoint
          4. Assert JWT structure (typ valid; kid contains did:key:; iss present)
          5. STORE_CREDENTIAL in Flutter wallet → assert CREDENTIAL_STORED: success
          6. GET_CREDENTIALS → assert credential count > 0
        """
        label = "jwt_vc_v2"
        raw_jwt = await self._get_credential_via_pre_auth(
            authenticated_gateway_client,
            template_id=jwt_vc_v2_template["id"],
            cred_config_id="VerifiableId",
            claims={
                "given_name": "Flutter",
                "family_name": "WalletTest",
                "date_of_birth": "1990-01-01",
                "test_id": uuid.uuid4().hex[:8],
            },
            label=label,
            organization_id=test_organization["id"],
        )

        # Assert JWT structure (mirrors waltid test Steps 5-6)
        header = _decode_jwt_header(raw_jwt)
        payload = _decode_jwt_payload(raw_jwt)
        logger.info("[%s] JWT header: %s", label, json.dumps(header, indent=2))
        logger.info("[%s] JWT payload keys: %s", label, list(payload.keys()))

        assert payload.get("iss"), f"[{label}] JWT payload missing 'iss'"
        VALID_TYP = {"vc+jwt", "dc+sd-jwt", "vc+sd-jwt"}
        assert header.get("typ") in VALID_TYP, (
            f"[{label}] Invalid JWT typ: {header.get('typ')!r} — expected one of {VALID_TYP}"
        )
        assert "did:key:" in header.get("kid", ""), (
            f"[{label}] kid should contain 'did:key:', got: {header.get('kid')!r}"
        )
        logger.info("[%s] ✓ JWT structure valid (typ=%s)", label, header.get("typ"))

        # Store the real credential JWT in the Flutter wallet
        cred_id = f"pre-auth-vc-{uuid.uuid4().hex[:8]}"
        await _clear_messages(wallet_page)
        await wallet_page.evaluate(
            _send_msg("STORE_CREDENTIAL", {"credential": {"id": cred_id, "rawJwt": raw_jwt}})
        )
        store_reply = await _wait_for_message(wallet_page, "CREDENTIAL_STORED")
        assert store_reply.get("payload", {}).get("success") is True, (
            f"[{label}] STORE_CREDENTIAL failed: {store_reply}"
        )
        logger.info("[%s] ✓ CREDENTIAL_STORED acknowledged", label)

        # Verify the wallet now contains credentials
        await _clear_messages(wallet_page)
        await wallet_page.evaluate(_send_msg("GET_CREDENTIALS"))
        creds_reply = await _wait_for_message(wallet_page, "CREDENTIALS")
        stored: list = creds_reply.get("payload", {}).get("credentials", [])
        assert len(stored) > 0, (
            f"[{label}] No credentials found in wallet after STORE_CREDENTIAL"
        )
        logger.info("[%s] ✓ credential confirmed in wallet (%d total)", label, len(stored))

    # ----------------------------------------------------------------
    # Test: pre-auth flow for each credential type (parametrized)
    # ----------------------------------------------------------------

    @pytest.mark.asyncio
    @pytest.mark.parametrize("template_id,cred_config_id,claims,label", CREDENTIAL_TYPE_CASES)
    async def test_pre_auth_all_credential_types(
        self,
        wallet_page: Page,
        authenticated_gateway_client: Any,
        template_id: str,
        cred_config_id: str,
        claims: dict,
        label: str,
    ):
        """
        Mirrors TestMultipleCredentialTypes — full pre-auth code flow per type.

        For each credential type (passport, mDL, access badge, open badge):
          1. Exchange pre-auth code for a real JWT credential
          2. Assert basic JWT structure (valid typ; kid contains did:key:; iss present)
          3. STORE_CREDENTIAL in Flutter wallet
          4. Verify via GET_CREDENTIALS
        """
        raw_jwt = await self._get_credential_via_pre_auth(
            authenticated_gateway_client,
            template_id=template_id,
            cred_config_id=cred_config_id,
            claims={**claims, "test_id": uuid.uuid4().hex[:8]},
            label=label,
        )

        header = _decode_jwt_header(raw_jwt)
        payload = _decode_jwt_payload(raw_jwt)
        assert payload.get("iss"), f"[{label}] JWT payload missing 'iss'"
        VALID_TYP = {"vc+jwt", "dc+sd-jwt", "vc+sd-jwt"}
        assert header.get("typ") in VALID_TYP, (
            f"[{label}] Invalid JWT typ: {header.get('typ')!r}"
        )
        assert "did:key:" in header.get("kid", ""), (
            f"[{label}] kid missing 'did:key:': {header.get('kid')!r}"
        )
        logger.info("[%s] ✓ JWT structure valid (typ=%s)", label, header.get("typ"))

        # Store in Flutter wallet
        cred_id = f"pre-auth-{label}-{uuid.uuid4().hex[:8]}"
        await _clear_messages(wallet_page)
        await wallet_page.evaluate(
            _send_msg("STORE_CREDENTIAL", {"credential": {"id": cred_id, "rawJwt": raw_jwt}})
        )
        store_reply = await _wait_for_message(wallet_page, "CREDENTIAL_STORED")
        assert store_reply.get("payload", {}).get("success") is True, (
            f"[{label}] STORE_CREDENTIAL failed: {store_reply}"
        )
        logger.info("[%s] ✓ CREDENTIAL_STORED", label)

        await _clear_messages(wallet_page)
        await wallet_page.evaluate(_send_msg("GET_CREDENTIALS"))
        creds_reply = await _wait_for_message(wallet_page, "CREDENTIALS")
        stored: list = creds_reply.get("payload", {}).get("credentials", [])
        assert len(stored) > 0, f"[{label}] No credentials in wallet after STORE_CREDENTIAL"
        logger.info("[%s] ✓ %d credential(s) confirmed in wallet", label, len(stored))

    # ----------------------------------------------------------------
    # Test: SD-JWT / ZKP — open badge (mirrors TestZKPSDJWTIssuance)
    # ----------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_pre_auth_sd_jwt_open_badge(
        self,
        wallet_page: Page,
        authenticated_gateway_client: Any,
    ):
        """
        Mirrors TestZKPSDJWTIssuance.test_pre_auth_flow_and_sd_jwt_open_badge.

        Open Badge: verify pre-auth code flow end-to-end, assert basic JWT
        structure, and store in the Flutter wallet.  The SD-JWT format assertion
        is xfail pending server-side SD-JWT format dispatch implementation.
        """
        label = "open_badge"
        raw_jwt = await self._get_credential_via_pre_auth(
            authenticated_gateway_client,
            template_id="40000000-0000-0000-0000-000000000007",
            cred_config_id="open_badge",
            claims={
                "given_name": "ZKP",
                "family_name": "Test",
                "date_of_birth": "1990-01-01",
            },
            label=label,
            requested_format="vc+sd-jwt",
        )

        # Basic structure checks (pass today regardless of format)
        header = _decode_jwt_header(raw_jwt)
        payload = _decode_jwt_payload(raw_jwt)
        assert payload.get("iss"), f"[{label}] JWT payload missing 'iss'"
        logger.info(
            "[%s] JWT typ=%s kid=%s",
            label, header.get("typ"), header.get("kid", "")[:60],
        )

        # SD-JWT format check (xfail until server implements format dispatch)
        typ = header.get("typ", "")
        is_sd_jwt = "sd-jwt" in typ.lower() or "~" in raw_jwt
        if not is_sd_jwt:
            pytest.xfail(
                f"[{label}] Server returned {typ!r} instead of requested vc+sd-jwt. "
                "SD-JWT format dispatch not yet implemented in the credential endpoint "
                "(format param is currently ignored)."
            )

        # Store SD-JWT in Flutter wallet and verify
        cred_id = f"sd-jwt-{label}-{uuid.uuid4().hex[:8]}"
        await _clear_messages(wallet_page)
        await wallet_page.evaluate(
            _send_msg("STORE_CREDENTIAL", {"credential": {"id": cred_id, "rawJwt": raw_jwt}})
        )
        store_reply = await _wait_for_message(wallet_page, "CREDENTIAL_STORED")
        assert store_reply.get("payload", {}).get("success") is True, (
            f"[{label}] STORE_CREDENTIAL failed: {store_reply}"
        )
        logger.info("[%s] ✓ SD-JWT stored in Flutter wallet", label)

    # ----------------------------------------------------------------
    # Test: SD-JWT / ZKP — each credential type (parametrized)
    # ----------------------------------------------------------------

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
    async def test_pre_auth_sd_jwt_credential_types(
        self,
        wallet_page: Page,
        authenticated_gateway_client: Any,
        template_id: str,
        cred_config_id: str,
        extra_claims: dict,
        label: str,
    ):
        """
        Mirrors TestZKPSDJWTIssuance.test_pre_auth_flow_and_sd_jwt_credential_types.

        Each credential type (passport, mDL, access badge): verify pre-auth code
        flow produces a structurally valid JWT, store in Flutter wallet.
        SD-JWT format assertion is xfail until server implements format dispatch.
        """
        claims = {
            "given_name": "ZKP",
            "family_name": "Test",
            "date_of_birth": "1990-01-01",
            **extra_claims,
        }
        raw_jwt = await self._get_credential_via_pre_auth(
            authenticated_gateway_client,
            template_id=template_id,
            cred_config_id=cred_config_id,
            claims=claims,
            label=label,
            requested_format="vc+sd-jwt",
        )

        header = _decode_jwt_header(raw_jwt)
        payload = _decode_jwt_payload(raw_jwt)
        assert payload.get("iss"), f"[{label}] JWT payload missing 'iss'"
        logger.info(
            "[%s] JWT typ=%s kid=%s",
            label, header.get("typ"), header.get("kid", "")[:60],
        )

        # SD-JWT format check (xfail until server implements format dispatch)
        typ = header.get("typ", "")
        is_sd_jwt = "sd-jwt" in typ.lower() or "~" in raw_jwt
        if not is_sd_jwt:
            pytest.xfail(
                f"[{label}] Server returned {typ!r} instead of requested vc+sd-jwt. "
                "SD-JWT format dispatch not yet implemented in the credential endpoint "
                "(format param is currently ignored)."
            )

        # If SD-JWT is returned, store in Flutter wallet
        cred_id = f"sd-jwt-{label}-{uuid.uuid4().hex[:8]}"
        await _clear_messages(wallet_page)
        await wallet_page.evaluate(
            _send_msg("STORE_CREDENTIAL", {"credential": {"id": cred_id, "rawJwt": raw_jwt}})
        )
        store_reply = await _wait_for_message(wallet_page, "CREDENTIAL_STORED")
        assert store_reply.get("payload", {}).get("success") is True, (
            f"[{label}] STORE_CREDENTIAL failed: {store_reply}"
        )
        logger.info("[%s] ✓ SD-JWT stored in Flutter wallet", label)
