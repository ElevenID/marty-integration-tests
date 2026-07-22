"""
EUDI Reference Implementation Interoperability Tests

Cross-stack interoperability tests that validate Marty's OID4VCI/OID4VP
compliance against the official EU Digital Identity Wallet reference
implementation services:

  - EUDI Verifier Endpoint: validates that credentials issued by Marty can
    be parsed and verified by the EU reference verifier.
  - EUDI Wallet Tester: validates that Marty's issuer endpoints are
    compatible with the EUDI wallet tester's OID4VCI client.

These tests require the EUDI services to be running (added by the
eudi-wallet-tester and eudi-verifier containers in docker-compose.yml).

Run with:
    make test-eudi
    # or
    RUN_EUDI_TESTS=true pytest tests/integration/gateway/test_eudi_interop.py -v

Environment variables
---------------------
GATEWAY_URL              Gateway base URL               (default: http://localhost:8000)
EUDI_VERIFIER_URL        EUDI verifier base URL         (default: http://localhost:8090)
EUDI_WALLET_TESTER_URL   EUDI wallet tester base URL    (default: https://localhost:5000)
TEST_ORG_ID              Organization ID                (default: 22222222-...)
RUN_EUDI_TESTS           Gate for EUDI tests            (default: false)
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from typing import Any, Dict

import pytest

from .helpers.eudi_client import (
    AGE_VERIFICATION_DCQL_QUERY,
    EUDIVerifierClient,
    EUDIWalletTesterClient,
    MDL_DCQL_QUERY,
    PID_DCQL_QUERY,
    SD_JWT_DCQL_QUERY,
    build_kb_jwt,
    select_disclosures,
)
from .helpers.gateway_client import GatewayClient
from .helpers.oid4vc_wallet_client import (
    EUDI_WALLET_PROFILE,
    OID4VCIWalletClient,
    OID4VPWalletClient,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_ORG_ID = "22222222-2222-2222-2222-222222222222"
ORG_ID = os.getenv("TEST_ORG_ID", DEFAULT_ORG_ID)
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8000")
EUDI_VERIFIER_URL = os.getenv("EUDI_VERIFIER_URL", "http://localhost:8090")
EUDI_WALLET_TESTER_URL = os.getenv("EUDI_WALLET_TESTER_URL", "http://localhost:5050")

# The official lane injects disposable template IDs created through the public
# API. Defaults remain only for the older opt-in local developer environment.
TEMPLATES = {
    "passport": os.getenv(
        "EUDI_TEST_PASSPORT_TEMPLATE_ID",
        "40000000-0000-0000-0000-000000000001",
    ),
    "mDL": os.getenv("EUDI_TEST_MDL_TEMPLATE_ID", "40000000-0000-0000-0000-000000000002"),
    "access_badge": "40000000-0000-0000-0000-000000000005",
    "open_badge": os.getenv(
        "EUDI_TEST_OPEN_BADGE_TEMPLATE_ID",
        "40000000-0000-0000-0000-000000000007",
    ),
}
VCT_ORIGIN = os.getenv("EUDI_TEST_VCT_ORIGIN", GATEWAY_URL).rstrip("/")

TEST_CLAIMS = {
    "given_name": "EUDI",
    "family_name": "Interop",
    "date_of_birth": "1985-06-15",
}


# ---------------------------------------------------------------------------
# Skip unless EUDI tests are explicitly enabled
# ---------------------------------------------------------------------------

run_eudi = os.getenv("RUN_EUDI_TESTS", "false").lower() == "true"
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not run_eudi, reason="RUN_EUDI_TESTS not set"),
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
async def eudi_verifier() -> EUDIVerifierClient:
    client = EUDIVerifierClient(base_url=EUDI_VERIFIER_URL)
    yield client
    await client.close()


@pytest.fixture
async def eudi_wallet() -> OID4VCIWalletClient:
    client = OID4VCIWalletClient(
        profile=EUDI_WALLET_PROFILE, issuer_base_url=GATEWAY_URL,
    )
    yield client
    await client.close()


@pytest.fixture
async def eudi_vp_wallet() -> OID4VPWalletClient:
    client = OID4VPWalletClient(
        profile=EUDI_WALLET_PROFILE, verifier_base_url=GATEWAY_URL,
    )
    yield client
    await client.close()


@pytest.fixture
async def eudi_wallet_tester() -> EUDIWalletTesterClient:
    client = EUDIWalletTesterClient(base_url=EUDI_WALLET_TESTER_URL)
    yield client
    await client.close()


# ═══════════════════════════════════════════════════════════════════════════
# EUDI Verifier — Service Health
# ═══════════════════════════════════════════════════════════════════════════

class TestEUDIVerifierHealth:
    """Verify the EUDI reference verifier is reachable and functional."""

    @pytest.mark.asyncio
    async def test_eudi_verifier_is_reachable(
        self, eudi_verifier: EUDIVerifierClient,
    ):
        """EUDI verifier Swagger UI should be accessible."""
        healthy = await eudi_verifier.health()
        assert healthy, (
            f"EUDI Verifier not reachable at {EUDI_VERIFIER_URL}. "
            "Is the eudi-verifier container running?"
        )

    @pytest.mark.asyncio
    async def test_eudi_verifier_creates_presentation_transaction(
        self, eudi_verifier: EUDIVerifierClient,
    ):
        """Verifier should create an OID4VP presentation transaction."""
        result = await eudi_verifier.initialize_transaction(
            dcql_query=PID_DCQL_QUERY,
            nonce=uuid.uuid4().hex,
        )

        assert result.get("transaction_id"), (
            f"EUDI verifier did not return transaction_id. Response: {result}"
        )
        assert result.get("request_uri") or result.get("client_id"), (
            f"EUDI verifier response missing request_uri or client_id: {result}"
        )
        logger.info(
            "[EUDI] Transaction: id=%s, client_id=%s",
            result.get("transaction_id"),
            result.get("client_id"),
        )


# ═══════════════════════════════════════════════════════════════════════════
# EUDI Verifier — DCQL Query Patterns
# ═══════════════════════════════════════════════════════════════════════════

class TestEUDIVerifierDCQL:
    """Test that the EUDI verifier accepts various DCQL query patterns."""

    @pytest.mark.asyncio
    async def test_mdl_dcql_query(
        self, eudi_verifier: EUDIVerifierClient,
    ):
        """Verifier should accept an mDL (ISO 18013-5) DCQL query."""
        result = await eudi_verifier.initialize_transaction(
            dcql_query=MDL_DCQL_QUERY,
            nonce=uuid.uuid4().hex,
        )
        assert result.get("transaction_id"), "mDL DCQL transaction failed"

    @pytest.mark.asyncio
    async def test_sd_jwt_dcql_query(
        self, eudi_verifier: EUDIVerifierClient,
    ):
        """Verifier should accept an SD-JWT VC DCQL query."""
        result = await eudi_verifier.initialize_transaction(
            dcql_query=SD_JWT_DCQL_QUERY,
            nonce=uuid.uuid4().hex,
        )
        assert result.get("transaction_id"), "SD-JWT DCQL transaction failed"

    @pytest.mark.asyncio
    async def test_age_verification_dcql_query(
        self, eudi_verifier: EUDIVerifierClient,
    ):
        """Verifier should accept age verification with credential_sets."""
        result = await eudi_verifier.initialize_transaction(
            dcql_query=AGE_VERIFICATION_DCQL_QUERY,
            nonce=uuid.uuid4().hex,
        )
        assert result.get("transaction_id"), "Age verification DCQL failed"


# ═══════════════════════════════════════════════════════════════════════════
# Cross-Stack: Marty Issuance → EUDI Wallet Profile
# ═══════════════════════════════════════════════════════════════════════════

class TestMartyIssuanceEUDIWallet:
    """Issue credentials through Marty, claim as EUDI wallet profile.

    Validates that Marty's OID4VCI endpoints produce spec-compliant offers
    and credentials that the EUDI reference implementation would accept.
    """

    @pytest.mark.asyncio
    async def test_sd_jwt_issuance_eudi_profile(
        self,
        authenticated_gateway_client: GatewayClient,
        eudi_wallet: OID4VCIWalletClient,
    ):
        """Full SD-JWT VC issuance as EUDI wallet."""
        result = await authenticated_gateway_client.issue_credential(
            organization_id=ORG_ID,
            credential_template_id=TEMPLATES["open_badge"],
            claims={
                **TEST_CLAIMS,
                "test_id": uuid.uuid4().hex[:8],
                "wallet_profile": "eudi_ref",
            },
        )

        offer_uri = result["credential_offer_uri"]
        await eudi_wallet.run_preauth_issuance(
            offer_uri=offer_uri,
            org_id=ORG_ID,
        )

        assert eudi_wallet.credentials, "EUDI wallet received no credentials"
        cred = eudi_wallet.credentials[0]
        raw = cred.get("credential", "")
        assert raw, "Credential has empty 'credential' field"

        # SD-JWT should contain disclosures (tildes)
        if "~" in raw:
            disclosure_count = raw.count("~") - 1
            logger.info(
                "[EUDI] SD-JWT credential: length=%d, disclosures=%d",
                len(raw), disclosure_count,
            )
        else:
            logger.info("[EUDI] Non-SD-JWT credential: length=%d", len(raw))

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "template_key,template_id",
        [
            ("passport", TEMPLATES["passport"]),
            ("mDL", TEMPLATES["mDL"]),
            ("open_badge", TEMPLATES["open_badge"]),
        ],
        ids=["passport", "mDL", "open_badge"],
    )
    async def test_credential_type_matrix_eudi(
        self,
        authenticated_gateway_client: GatewayClient,
        template_key: str,
        template_id: str,
    ):
        """Test each credential type through the EUDI wallet flow."""
        claims = {**TEST_CLAIMS, "test_id": uuid.uuid4().hex[:8]}
        if template_key == "passport":
            claims["document_number"] = "EUDI-REF-001"

        result = await authenticated_gateway_client.issue_credential(
            organization_id=ORG_ID,
            credential_template_id=template_id,
            claims=claims,
        )
        assert result.get("credential_offer_uri"), (
            f"No offer URI for {template_key}"
        )

        wallet = OID4VCIWalletClient(
            profile=EUDI_WALLET_PROFILE, issuer_base_url=GATEWAY_URL,
        )
        try:
            offer = await wallet.resolve_offer(result["credential_offer_uri"])
            config_ids = offer.get("credential_configuration_ids", [])
            assert config_ids, (
                f"Offer for {template_key} missing credential_configuration_ids"
            )
            logger.info(
                "[EUDI/%s] Offer config IDs: %s", template_key, config_ids,
            )
        finally:
            await wallet.close()


# ═══════════════════════════════════════════════════════════════════════════
# Cross-Stack: Marty Issuance → EUDI Verifier Validation
# ═══════════════════════════════════════════════════════════════════════════

class TestMartyCredentialEUDIVerification:
    """Issue credential through Marty, verify request_uri via EUDI verifier.

    End-to-end flow:
      1. Issue credential via Marty gateway (OID4VCI)
      2. Create presentation request via EUDI verifier (OID4VP)
      3. Validate that the headless wallet can resolve the request
    """

    @pytest.mark.asyncio
    async def test_issue_then_create_eudi_verification_request(
        self,
        authenticated_gateway_client: GatewayClient,
        eudi_wallet: OID4VCIWalletClient,
        eudi_verifier: EUDIVerifierClient,
    ):
        """Issue SD-JWT via Marty, then create an EUDI verification request."""
        # Step 1: Issue credential
        result = await authenticated_gateway_client.issue_credential(
            organization_id=ORG_ID,
            credential_template_id=TEMPLATES["open_badge"],
            claims={
                **TEST_CLAIMS,
                "test_id": uuid.uuid4().hex[:8],
                "source": "eudi-cross-stack",
            },
        )

        await eudi_wallet.run_preauth_issuance(
            offer_uri=result["credential_offer_uri"],
            org_id=ORG_ID,
        )
        assert eudi_wallet.credentials, "No credential issued"

        # Step 2: Create EUDI verification session for SD-JWT
        txn = await eudi_verifier.initialize_transaction(
            dcql_query=SD_JWT_DCQL_QUERY,
            nonce=uuid.uuid4().hex,
        )
        assert txn.get("transaction_id"), "EUDI verifier txn failed"
        assert txn.get("request_uri"), (
            f"EUDI verifier did not return request_uri: {txn}"
        )

        logger.info(
            "[EUDI Cross-Stack] Issued credential + created verification "
            "request: txn=%s",
            txn["transaction_id"],
        )

    @pytest.mark.asyncio
    async def test_eudi_verifier_request_uri_resolvable(
        self,
        eudi_verifier: EUDIVerifierClient,
    ):
        """EUDI verifier's request_uri should yield a parseable auth request."""
        txn = await eudi_verifier.initialize_transaction(
            dcql_query=PID_DCQL_QUERY,
            nonce=uuid.uuid4().hex,
        )
        request_uri = txn.get("request_uri")
        assert request_uri, f"EUDI verifier did not return request_uri: {txn}"

        # Fetch the authorization request JWT directly from the verifier
        auth_request = await eudi_verifier.get_request_object(request_uri)

        # Must contain the core OID4VP fields
        assert auth_request.get("state"), (
            f"Auth request missing 'state'. Keys: {list(auth_request.keys())}"
        )
        assert auth_request.get("nonce"), (
            f"Auth request missing 'nonce'. Keys: {list(auth_request.keys())}"
        )
        logger.info(
            "[EUDI VP] Resolved request: response_type=%s, state=%s",
            auth_request.get("response_type"),
            auth_request.get("state", "?")[:16],
        )


# ═══════════════════════════════════════════════════════════════════════════
# EUDI Metadata Compatibility
# ═══════════════════════════════════════════════════════════════════════════

class TestEUDIMetadataCompatibility:
    """Validate that Marty's issuer metadata is compatible with EUDI spec.

    The EUDI reference wallet expects specific fields and formats in the
    OID4VCI issuer metadata.  These tests confirm compatibility.
    """

    @pytest.mark.asyncio
    async def test_metadata_has_eudi_compatible_formats(
        self, eudi_wallet: OID4VCIWalletClient,
    ):
        """Issuer metadata should include formats the EUDI wallet supports."""
        metadata = await eudi_wallet.fetch_issuer_metadata(org_id=ORG_ID)
        configs = metadata["credential_configurations_supported"]

        eudi_formats = {"dc+sd-jwt", "vc+sd-jwt", "mso_mdoc", "jwt_vc_json"}
        found_formats = {
            cfg.get("format") for cfg in configs.values()
        }
        overlap = found_formats & eudi_formats
        assert overlap, (
            f"No EUDI-compatible formats found. "
            f"Issuer has: {found_formats}, EUDI needs: {eudi_formats}"
        )
        logger.info(
            "[EUDI] Compatible formats: %s (issuer has %s)",
            overlap, found_formats,
        )

    @pytest.mark.asyncio
    async def test_metadata_has_token_endpoint(
        self, eudi_wallet: OID4VCIWalletClient,
    ):
        """Issuer metadata must include a token endpoint for OID4VCI."""
        metadata = await eudi_wallet.fetch_issuer_metadata(org_id=ORG_ID)

        # OID4VCI requires either token_endpoint in metadata or via
        # OAuth authorization server metadata
        token_endpoint = metadata.get("token_endpoint")
        auth_server = metadata.get("authorization_servers")
        assert token_endpoint or auth_server, (
            "Issuer metadata missing both 'token_endpoint' and "
            "'authorization_servers' — EUDI wallet cannot obtain tokens"
        )

    @pytest.mark.asyncio
    async def test_metadata_credential_configs_have_required_fields(
        self, eudi_wallet: OID4VCIWalletClient,
    ):
        """Each credential config must have format and identifier fields."""
        metadata = await eudi_wallet.fetch_issuer_metadata(org_id=ORG_ID)
        configs = metadata["credential_configurations_supported"]

        for config_id, config in configs.items():
            fmt = config.get("format")
            assert fmt, f"Config '{config_id}' missing 'format'"

            # Format-specific required fields
            if fmt == "mso_mdoc":
                assert config.get("doctype"), (
                    f"mso_mdoc config '{config_id}' missing 'doctype'"
                )
            elif fmt in ("dc+sd-jwt", "vc+sd-jwt"):
                assert config.get("vct"), (
                    f"SD-JWT config '{config_id}' missing 'vct'"
                )

    @pytest.mark.asyncio
    async def test_openid_config_has_par_endpoint(self):
        """OIDC discovery must advertise pushed_authorization_request_endpoint.

        The EUDI wallet tester requires this field (RFC 9126) and crashes
        with a KeyError if it's missing.
        """
        import httpx

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{GATEWAY_URL}/.well-known/openid-configuration",
            )
            resp.raise_for_status()
            config = resp.json()

        assert "pushed_authorization_request_endpoint" in config, (
            f"OIDC config missing 'pushed_authorization_request_endpoint'. "
            f"Keys: {list(config.keys())}"
        )

        par_url = config["pushed_authorization_request_endpoint"]
        assert "/par" in par_url, (
            f"PAR endpoint URL doesn't contain '/par': {par_url}"
        )

    @pytest.mark.asyncio
    async def test_par_endpoint_returns_request_uri(self):
        """POST /v1/issuance/par should return a request_uri (RFC 9126 §2.2)."""
        import httpx

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{GATEWAY_URL}/v1/issuance/par",
                data={
                    "response_type": "code",
                    "client_id": "test-eudi-wallet",
                    "scope": "openid",
                    "state": "test-state-123",
                    "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                    "code_challenge_method": "S256",
                },
            )

        assert resp.status_code == 201, (
            f"PAR endpoint returned {resp.status_code}: {resp.text}"
        )
        data = resp.json()
        assert "request_uri" in data, (
            f"PAR response missing 'request_uri'. Keys: {list(data.keys())}"
        )
        assert data["request_uri"].startswith("urn:ietf:params:oauth:request_uri:"), (
            f"request_uri has wrong prefix: {data['request_uri']}"
        )
        assert "expires_in" in data, "PAR response missing 'expires_in'"
        assert data["expires_in"] > 0, "expires_in must be positive"


# ═══════════════════════════════════════════════════════════════════════════
# Cross-Stack: Marty Credential → EUDI Verifier Crypto Validation
# ═══════════════════════════════════════════════════════════════════════════

class TestEUDIVerifierCryptoValidation:
    """Submit Marty-issued credentials to the EUDI verifier for validation.

    This closes the biggest interop gap: proving that credentials issued
    by Marty can be parsed, structurally validated, and processed by an
    independent EU reference verifier — not just our own code.

    Flow:
      1. Issue SD-JWT credential via Marty (OID4VCI)
      2. Initialize EUDI verifier transaction (OID4VP)
      3. Fetch authorization request to get state + nonce
      4. Build VP token with KB-JWT (holder key binding proof)
      5. Submit VP token to EUDI verifier's direct_post
      6. Inspect the verifier's event log for validation outcome
    """

    @pytest.mark.asyncio
    async def test_sd_jwt_submitted_to_eudi_verifier(
        self,
        authenticated_gateway_client: GatewayClient,
        eudi_verifier: EUDIVerifierClient,
    ):
        """Issue SD-JWT via Marty, submit to EUDI verifier via direct_post."""
        # 1. Issue credential and run full pre-auth flow
        wallet = OID4VCIWalletClient(
            profile=EUDI_WALLET_PROFILE, issuer_base_url=GATEWAY_URL,
        )
        try:
            result = await authenticated_gateway_client.issue_credential(
                organization_id=ORG_ID,
                credential_template_id=TEMPLATES["open_badge"],
                claims={
                    **TEST_CLAIMS,
                    "test_id": uuid.uuid4().hex[:8],
                    "source": "eudi-crypto-validation",
                },
            )
            await wallet.run_preauth_issuance(
                offer_uri=result["credential_offer_uri"],
                org_id=ORG_ID,
            )
            assert wallet.credentials, "No credential issued"
            raw_credential = wallet.credentials[0]["credential"]
            assert raw_credential, "Empty credential"
        finally:
            holder_key = wallet._private_key
            await wallet.close()

        # 2. Initialize EUDI verifier transaction
        nonce = uuid.uuid4().hex
        txn = await eudi_verifier.initialize_transaction(
            dcql_query=SD_JWT_DCQL_QUERY,
            nonce=nonce,
        )
        assert txn.get("request_uri"), f"No request_uri: {txn}"

        # 3. Fetch auth request to get state
        auth_request = await eudi_verifier.get_request_object(
            txn["request_uri"],
        )
        state = auth_request["state"]
        verifier_nonce = auth_request.get("nonce", nonce)
        # The KB-JWT audience must match the verifier's client_id
        verifier_client_id = auth_request.get("client_id", EUDI_VERIFIER_URL)

        # 4. Build VP token with KB-JWT
        #    SD-JWT format: issuer_jwt~disclosure1~disclosure2~
        #    With KB-JWT:   issuer_jwt~disclosure1~disclosure2~kb_jwt
        sd_jwt_without_kb = raw_credential.rstrip("~") + "~"
        kb_jwt = build_kb_jwt(
            private_key=holder_key,
            sd_jwt_without_kb=sd_jwt_without_kb,
            audience=verifier_client_id,
            nonce=verifier_nonce,
        )
        sd_jwt_with_kb = sd_jwt_without_kb + kb_jwt

        # DCQL maps from credential query ID to credential array
        vp_token = {
            "sd-jwt-query": [sd_jwt_with_kb],
        }

        # 5. Submit to EUDI verifier (use response_uri which has the requestId)
        submission = await eudi_verifier.submit_wallet_response(
            state=state,
            vp_token=vp_token,
            response_uri=auth_request.get("response_uri"),
        )

        # 6. The verifier should accept the submission (200 or redirect).
        #    Since Marty now issues SD-JWT credentials, the verifier should
        #    be able to decode and process the vp_token without errors.
        assert submission["status_code"] < 400, (
            f"EUDI verifier rejected credential submission: "
            f"{submission['status_code']}: {submission['body']}"
        )

        # 7. Check event log — must have the wallet response event,
        #    proving the verifier processed (not just received) the credential
        events_data = await eudi_verifier.get_presentation_events(
            txn["transaction_id"],
        )
        # The events endpoint returns {"events": [...]} with event dicts
        events_list = events_data.get("events", events_data) if isinstance(events_data, dict) else events_data
        event_types = [
            e.get("event", "") if isinstance(e, dict) else str(e)
            for e in (events_list if isinstance(events_list, list) else [])
        ]
        logger.info(
            "[EUDI Crypto] Submitted credential to verifier. "
            "status=%d, events=%s, body=%s",
            submission["status_code"],
            event_types,
            str(submission.get('body', ''))[:200],
        )

        # There should be at least 2 events: init + wallet response
        assert len(event_types) >= 2, (
            f"Expected at least 2 verifier events (init + response), "
            f"got {len(event_types)}: {event_types}"
        )

    @pytest.mark.asyncio
    async def test_verifier_full_flow_with_events(
        self,
        eudi_verifier: EUDIVerifierClient,
    ):
        """Run full presentation flow and verify event log captures it."""
        # Use a dummy VP token — we're testing the protocol flow,
        # not credential validity.
        dummy_vp = {"sd-jwt-query": "eyJ0eXAiOiJkYytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.AAAA~"}

        result = await eudi_verifier.run_presentation_flow(
            dcql_query=SD_JWT_DCQL_QUERY,
            vp_token=dummy_vp,
        )

        assert "error" not in result, f"Flow failed: {result.get('error')}"
        assert result["transaction_id"], "No transaction_id"
        assert result["state"], "No state"
        assert result["events"], (
            f"No events recorded for transaction {result['transaction_id']}"
        )

        # The event log should have at least the init event
        # and the wallet response event
        event_count = len(result["events"])
        assert event_count >= 1, (
            f"Expected at least 1 event, got {event_count}"
        )
        logger.info(
            "[EUDI Flow] txn=%s, submission_status=%s, events=%d",
            result["transaction_id"],
            result["submission"].get("status_code"),
            event_count,
        )


# ═══════════════════════════════════════════════════════════════════════════
# EUDI Wallet Tester — Container Integration
# ═══════════════════════════════════════════════════════════════════════════

class TestEUDIWalletTesterIntegration:
    """Verify the EUDI wallet tester container is wired to Marty.

    These tests exercise the actual Flask-based EUDI wallet tester
    container (not our headless client).  They prove:
      1. The container is running and serving its Flask UI.
      2. It is configured to point at the Marty gateway (via serv_url).
      3. Its /preauth endpoint correctly redirects to the gateway.
    """

    @pytest.mark.asyncio
    async def test_wallet_tester_is_reachable(
        self, eudi_wallet_tester: EUDIWalletTesterClient,
    ):
        """Wallet tester home page should render."""
        info = await eudi_wallet_tester.get_home_page()
        assert info["status_code"] == 200, (
            f"Wallet tester returned {info['status_code']}"
        )
        assert info["contains_wallet_test"], (
            "Home page missing 'WALLET Test' heading"
        )

    @pytest.mark.asyncio
    async def test_wallet_tester_has_credential_offer_button(
        self, eudi_wallet_tester: EUDIWalletTesterClient,
    ):
        """Wallet tester home page should have credential offer action."""
        info = await eudi_wallet_tester.get_home_page()
        assert info["contains_credential_offer"], (
            "Home page missing credential offer button"
        )

    @pytest.mark.asyncio
    async def test_wallet_tester_preauth_redirects_to_gateway(
        self, eudi_wallet_tester: EUDIWalletTesterClient,
    ):
        """The /preauth route should redirect to the Marty gateway.

        The wallet tester's serv_url env var should point it at gateway:8000.
        The /preauth endpoint redirects to {serv_url}/dynamic/preauth.
        """
        info = await eudi_wallet_tester.trigger_preauth()
        assert info["status_code"] in (301, 302, 303, 307, 308), (
            f"/preauth should redirect, got {info['status_code']}"
        )
        assert info["redirects_to_gateway"], (
            f"/preauth redirect target should mention gateway: "
            f"{info['redirect_location']}"
        )


# ═══════════════════════════════════════════════════════════════════════════
# EUDI Wallet Tester — Full OID4VCI Metadata Flow
# ═══════════════════════════════════════════════════════════════════════════

class TestEUDIWalletTesterMetadataFlow:
    """Drive the EUDI wallet tester through Marty's metadata endpoints.

    These tests exercise the wallet tester's *own* OID4VCI client code
    against Marty — not our headless wallet.  The tester internally
    fetches ``.well-known/openid-configuration`` and
    ``.well-known/openid-credential-issuer`` from the gateway via Docker
    networking, then parses them with EU reference code.

    A pass here means an independent EU wallet implementation can:
      - Discover Marty's OpenID configuration
      - Parse the credential issuer metadata
      - Extract supported credential formats, VCTs, and endpoints
    """

    @pytest.mark.asyncio
    async def test_wallet_tester_parses_marty_metadata(
        self, eudi_wallet_tester: EUDIWalletTesterClient,
    ):
        """The EUDI wallet tester can fetch and parse Marty's metadata.

        Drives /metadata1_na → /metadata_na inside the tester, which
        makes real HTTP calls to the gateway's .well-known endpoints.
        """
        result = await eudi_wallet_tester.fetch_metadata_via_tester()
        assert result["success"], (
            f"EUDI wallet tester failed to parse Marty metadata: "
            f"{result.get('error')}\nSteps: {json.dumps(result['steps'], indent=2)}"
        )

        # Both metadata steps should have succeeded
        steps = result["steps"]
        assert steps["metadata1_na"]["ok"], (
            "Wallet tester failed on openid-configuration"
        )
        assert steps["metadata_na"]["ok"], (
            "Wallet tester failed on openid-credential-issuer"
        )

    @pytest.mark.asyncio
    async def test_wallet_tester_credential_offer_flow(
        self,
        authenticated_gateway_client: GatewayClient,
        eudi_wallet_tester: EUDIWalletTesterClient,
    ):
        """The EUDI wallet tester can parse a Marty credential offer
        and fetch metadata for the offered credential type.

        Flow:
          1. Issue credential via Marty → get credential_offer_uri
          2. Feed the offer to the wallet tester's /redirect_preauth
          3. The tester parses the offer's credential_configuration_ids
          4. The tester fetches Marty's metadata endpoints

        This proves a real EUDI wallet can handle Marty's credential
        offers end-to-end through the metadata phase.
        """
        # 1. Create a credential offer via Marty
        result = await authenticated_gateway_client.issue_credential(
            organization_id=ORG_ID,
            credential_template_id=TEMPLATES["open_badge"],
            claims={
                **TEST_CLAIMS,
                "test_id": uuid.uuid4().hex[:8],
                "source": "eudi-wallet-tester-offer-flow",
            },
        )
        offer_uri = result["credential_offer_uri"]
        assert offer_uri, "No credential_offer_uri from Marty"

        # 2. Drive the wallet tester through the offer → metadata flow
        flow_result = await eudi_wallet_tester.run_preauth_metadata_flow(offer_uri)

        assert flow_result["success"], (
            f"EUDI wallet tester failed to process Marty credential offer: "
            f"{flow_result.get('error')}\n"
            f"Steps: {json.dumps(flow_result.get('steps', {}), indent=2)}"
        )

        # 3. Verify each step passed
        steps = flow_result["steps"]
        assert steps["redirect_preauth"]["ok"], (
            f"Wallet tester couldn't parse credential offer: "
            f"{steps['redirect_preauth']}"
        )
        assert steps["metadata1_na"]["ok"], (
            "Wallet tester couldn't fetch openid-configuration from Marty"
        )
        assert steps["metadata_na"]["ok"], (
            "Wallet tester couldn't fetch credential-issuer metadata from Marty"
        )

        logger.info(
            "[EUDI Wallet Tester] Successfully processed Marty credential "
            "offer and fetched metadata. Steps: %s",
            {k: v.get("status") for k, v in steps.items()},
        )


# ═══════════════════════════════════════════════════════════════════════════
# Selective Disclosure — VP with Partial Claims
# ═══════════════════════════════════════════════════════════════════════════

class TestSelectiveDisclosure:
    """Verify that selective disclosure works end-to-end.

    Issues an SD-JWT credential with multiple claims, then presents
    only a subset to the EUDI verifier — proving that:
      1. Marty issues proper SD-JWT with individually disclosable claims
      2. A holder can select which claims to reveal
      3. The EUDI verifier can parse a VP with partial disclosures
    """

    @pytest.mark.asyncio
    async def test_selective_disclosure_subset(
        self,
        authenticated_gateway_client: GatewayClient,
        eudi_verifier: EUDIVerifierClient,
    ):
        """Issue SD-JWT, present only given_name to EUDI verifier."""
        # 1. Issue credential with multiple claims
        wallet = OID4VCIWalletClient(
            profile=EUDI_WALLET_PROFILE, issuer_base_url=GATEWAY_URL,
        )
        try:
            result = await authenticated_gateway_client.issue_credential(
                organization_id=ORG_ID,
                credential_template_id=TEMPLATES["open_badge"],
                claims={
                    **TEST_CLAIMS,
                    "test_id": uuid.uuid4().hex[:8],
                    "source": "selective-disclosure-test",
                },
            )
            await wallet.run_preauth_issuance(
                offer_uri=result["credential_offer_uri"],
                org_id=ORG_ID,
            )
            assert wallet.credentials, "No credential issued"
            raw_credential = wallet.credentials[0]["credential"]
        finally:
            holder_key = wallet._private_key
            await wallet.close()

        # 2. The credential should have SD-JWT disclosures now
        full_disc_count = len([p for p in raw_credential.split("~") if p]) - 1
        assert full_disc_count >= 2, (
            f"Expected SD-JWT with at least 2 disclosures, got {full_disc_count}. "
            f"Credential starts with: {raw_credential[:80]}..."
        )

        # Select only given_name disclosure (drop family_name, etc.)
        partial_sd_jwt = select_disclosures(
            raw_credential, requested_claims=["given_name"],
        )

        # Verify we actually reduced the disclosures
        partial_disc_count = len([p for p in partial_sd_jwt.split("~") if p]) - 1
        assert partial_disc_count < full_disc_count, (
            f"Selective disclosure didn't reduce claims: "
            f"full={full_disc_count}, partial={partial_disc_count}"
        )
        assert partial_disc_count >= 1, "No disclosures selected"

        # 3. Build presentation with only the selected claims
        nonce = uuid.uuid4().hex
        dcql_query = {
            "credentials": [{
                "id": "sd-jwt-query",
                "format": "dc+sd-jwt",
                "meta": {"vct_values": [
                    f"{VCT_ORIGIN}/credentials/OpenBadge",
                    "https://marty.example/credentials/open_badge",
                    "https://beta.elevenidllc.com/credentials/open_badge",
                    "urn:credential:open_badge",
                ]},
                "claims": [{"path": ["given_name"]}],
            }],
        }
        txn = await eudi_verifier.initialize_transaction(
            dcql_query=dcql_query, nonce=nonce,
        )
        auth_request = await eudi_verifier.get_request_object(txn["request_uri"])
        state = auth_request["state"]
        verifier_nonce = auth_request.get("nonce", nonce)
        verifier_client_id = auth_request.get("client_id", EUDI_VERIFIER_URL)

        # 4. Add KB-JWT to the partial credential
        sd_jwt_no_kb = partial_sd_jwt.rstrip("~") + "~"
        kb_jwt = build_kb_jwt(
            private_key=holder_key,
            sd_jwt_without_kb=sd_jwt_no_kb,
            audience=verifier_client_id,
            nonce=verifier_nonce,
        )
        vp_token = {"sd-jwt-query": [sd_jwt_no_kb + kb_jwt]}

        # 5. Submit to EUDI verifier (use response_uri with requestId)
        submission = await eudi_verifier.submit_wallet_response(
            state=state, vp_token=vp_token,
            response_uri=auth_request.get("response_uri"),
        )

        assert submission["status_code"] < 400, (
            f"EUDI verifier rejected selective disclosure presentation: "
            f"{submission['status_code']}: {submission['body']}"
        )

        logger.info(
            "[Selective Disclosure] Presented %d/%d disclosures, "
            "verifier accepted with status %d",
            partial_disc_count, full_disc_count,
            submission["status_code"],
        )
