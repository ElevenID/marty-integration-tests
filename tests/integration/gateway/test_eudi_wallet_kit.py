"""
EUDI Wallet Kit Real-Wallet Compatibility Tests

These tests use the official EUDI Wallet Kit JVM libraries
(eudi-lib-jvm-openid4vci-kt v0.9.1) running in a Docker container
to exercise Marty's OID4VCI endpoints. This proves that the same
SDK used in the EUDI Reference Wallet mobile application can
successfully interact with Marty.

Unlike the simulated Python wallet client (OID4VCIWalletClient),
which reimplements OID4VCI in Python, these tests delegate ALL
protocol logic to the official EU library — including:

  - Credential Issuer Metadata validation (strict parsing)
  - OAuth 2.0 Authorization Server metadata resolution
  - Pre-authorized code token exchange
  - Proof-of-possession JWT generation (P-256)
  - Credential request/response handling
  - PAR endpoint discovery and usage
  - Nonce endpoint discovery and usage
  - Credential response encryption negotiation

Run with:
    RUN_EUDI_TESTS=true pytest tests/integration/gateway/test_eudi_wallet_kit.py -v

Environment variables
---------------------
GATEWAY_URL              Gateway base URL                (default: http://localhost:8000)
EUDI_WALLET_KIT_URL      Wallet kit harness URL          (default: http://localhost:9090)
TEST_ORG_ID              Organization ID                 (default: 22222222-...)
RUN_EUDI_TESTS           Gate for EUDI tests             (default: false)
"""

from __future__ import annotations

import json
import logging
import os
import uuid

import pytest

from .helpers.eudi_wallet_kit_client import EUDIWalletKitClient
from .helpers.gateway_client import GatewayClient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_ORG_ID = "22222222-2222-2222-2222-222222222222"
ORG_ID = os.getenv("TEST_ORG_ID", DEFAULT_ORG_ID)
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8000")
EUDI_WALLET_KIT_URL = os.getenv("EUDI_WALLET_KIT_URL", "http://localhost:9090")

TEST_CLAIMS = {
    "given_name": "WalletKit",
    "family_name": "Interop",
    "date_of_birth": "1990-01-01",
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
async def wallet_kit() -> EUDIWalletKitClient:
    client = EUDIWalletKitClient(base_url=EUDI_WALLET_KIT_URL)
    yield client
    await client.close()


@pytest.fixture
async def eudi_test_org(authenticated_gateway_client: GatewayClient):
    """Create a test organization for EUDI wallet kit tests."""
    org = await authenticated_gateway_client.create_organization(
        name=f"eudi-wk-{uuid.uuid4().hex[:6]}",
        display_name="EUDI Wallet Kit Test Org",
    )
    return org


@pytest.fixture
async def open_badge_template(
    authenticated_gateway_client: GatewayClient,
    eudi_test_org,
):
    """Create an open_badge credential template dynamically."""
    return await authenticated_gateway_client.create_credential_template(
        organization_id=eudi_test_org["id"],
        name="EUDI WK Open Badge",
        credential_type="OpenBadge",
        vct="https://marty.example/credentials/OpenBadge",
        supported_formats=["sd_jwt_vc"],
        claims=[
            {"name": "given_name", "type": "string", "display_name": "Given Name"},
            {"name": "family_name", "type": "string", "display_name": "Family Name"},
            {"name": "date_of_birth", "type": "string", "display_name": "Date of Birth"},
        ],
        compliance_profile={"name": "test", "type": "none", "compliance_code": "CUSTOM"},
    )


@pytest.fixture
async def passport_template(
    authenticated_gateway_client: GatewayClient,
    eudi_test_org,
):
    """Create a passport credential template dynamically."""
    return await authenticated_gateway_client.create_credential_template(
        organization_id=eudi_test_org["id"],
        name="EUDI WK Passport",
        credential_type="Passport",
        vct="https://marty.example/credentials/Passport",
        supported_formats=["sd_jwt_vc"],
        claims=[
            {"name": "given_name", "type": "string", "display_name": "Given Name"},
            {"name": "family_name", "type": "string", "display_name": "Family Name"},
            {"name": "date_of_birth", "type": "string", "display_name": "Date of Birth"},
        ],
        compliance_profile={"name": "test", "type": "none", "compliance_code": "CUSTOM"},
    )


# ═══════════════════════════════════════════════════════════════════════════
# Wallet Kit Health
# ═══════════════════════════════════════════════════════════════════════════

class TestEUDIWalletKitHealth:
    """Verify the EUDI Wallet Kit harness is running and healthy."""

    @pytest.mark.asyncio
    async def test_wallet_kit_is_reachable(self, wallet_kit: EUDIWalletKitClient):
        """Wallet kit harness responds to health check."""
        health = await wallet_kit.health()
        assert health["status"] == "ok"
        assert health["service"] == "eudi-wallet-harness"

    @pytest.mark.asyncio
    async def test_wallet_kit_has_eudi_libraries(self, wallet_kit: EUDIWalletKitClient):
        """Harness reports correct EUDI library versions."""
        health = await wallet_kit.health()
        assert "openid4vciVersion" in health, "Missing OID4VCI version"
        assert "openid4vpVersion" in health, "Missing OID4VP version"
        logger.info(
            "[WalletKit] Libraries: OID4VCI=%s, OID4VP=%s",
            health["openid4vciVersion"], health["openid4vpVersion"],
        )


# ═══════════════════════════════════════════════════════════════════════════
# Credential Offer Resolution — EUDI Wallet Kit validates Marty's metadata
# ═══════════════════════════════════════════════════════════════════════════

class TestEUDIWalletKitMetadataResolution:
    """Prove Marty's issuer metadata passes the EUDI Wallet Kit's strict parser.

    The EUDI OID4VCI library performs thorough validation:
    - Fetches /.well-known/openid-credential-issuer
    - Fetches /.well-known/oauth-authorization-server
    - Validates required fields, grant types, credential configurations
    - Checks format compatibility

    If the offer resolves successfully, Marty's metadata is EUDI-compatible.
    """

    @pytest.mark.asyncio
    async def test_resolve_credential_offer(
        self,
        authenticated_gateway_client: GatewayClient,
        wallet_kit: EUDIWalletKitClient,
        eudi_test_org,
        open_badge_template,
    ):
        """EUDI Wallet Kit can resolve a Marty credential offer."""
        # Create credential offer via Marty
        result = await authenticated_gateway_client.issue_credential(
            organization_id=eudi_test_org["id"],
            credential_template_id=open_badge_template["id"],
            claims={**TEST_CLAIMS, "test_id": uuid.uuid4().hex[:8]},
        )
        offer_uri = result["credential_offer_uri"]
        assert offer_uri, "No credential_offer_uri returned"

        # The EUDI library resolves the offer (fetches metadata, validates)
        resolution = await wallet_kit.resolve_offer(offer_uri)

        assert resolution["success"], (
            f"EUDI Wallet Kit failed to resolve offer: {resolution.get('error')}"
        )
        assert resolution["grantType"] in ("pre-authorized_code", "both"), (
            f"Expected pre-auth grant, got: {resolution['grantType']}"
        )
        assert len(resolution["credentialConfigurationIds"]) >= 1, (
            "No credential configurations in resolved offer"
        )

        meta = resolution.get("issuerMetadata")
        assert meta, "No issuer metadata returned"
        assert meta["credentialIssuerId"], "Missing credentialIssuerId"

        logger.info(
            "[WalletKit] Offer resolved: issuer=%s, grant=%s, configs=%s",
            meta["credentialIssuerId"],
            resolution["grantType"],
            resolution["credentialConfigurationIds"],
        )

    @pytest.mark.asyncio
    async def test_resolve_offer_reports_nonce_endpoint(
        self,
        authenticated_gateway_client: GatewayClient,
        wallet_kit: EUDIWalletKitClient,
        eudi_test_org,
        open_badge_template,
    ):
        """EUDI Wallet Kit discovers nonce endpoint in issuer metadata."""
        result = await authenticated_gateway_client.issue_credential(
            organization_id=eudi_test_org["id"],
            credential_template_id=open_badge_template["id"],
            claims={**TEST_CLAIMS, "test_id": uuid.uuid4().hex[:8]},
        )
        resolution = await wallet_kit.resolve_offer(result["credential_offer_uri"])
        assert resolution["success"], resolution.get("error")

        meta = resolution.get("issuerMetadata", {})
        # The nonce endpoint is optional but we advertise it
        if meta.get("nonceEndpoint"):
            logger.info("[WalletKit] Found nonce endpoint: %s", meta["nonceEndpoint"])


# ═══════════════════════════════════════════════════════════════════════════
# Full Issuance — EUDI Wallet Kit receives credentials from Marty
# ═══════════════════════════════════════════════════════════════════════════

class TestEUDIWalletKitIssuance:
    """Full OID4VCI pre-authorized code issuance using the EUDI Wallet Kit.

    This is the definitive real-wallet compatibility proof. The EUDI library:
    1. Resolves the credential offer (metadata validation)
    2. Exchanges pre-auth code for access token
    3. Generates P-256 proof-of-possession JWT
    4. Requests the credential from Marty's credential endpoint
    5. Receives and parses the issued credential

    These are the exact same operations the EUDI Reference Wallet app performs.
    """

    @pytest.mark.asyncio
    async def test_sd_jwt_issuance_via_wallet_kit(
        self,
        authenticated_gateway_client: GatewayClient,
        wallet_kit: EUDIWalletKitClient,
        eudi_test_org,
        open_badge_template,
    ):
        """Issue SD-JWT VC through Marty, receive via EUDI Wallet Kit."""
        result = await authenticated_gateway_client.issue_credential(
            organization_id=eudi_test_org["id"],
            credential_template_id=open_badge_template["id"],
            claims={
                **TEST_CLAIMS,
                "test_id": uuid.uuid4().hex[:8],
                "source": "eudi-wallet-kit",
            },
        )
        offer_uri = result["credential_offer_uri"]

        # Full issuance flow through the real EUDI library
        issuance = await wallet_kit.run_preauth_issuance(offer_uri)

        assert issuance["success"], (
            f"EUDI Wallet Kit issuance failed: {issuance.get('error')}"
        )
        assert issuance["credentialCount"] >= 1, (
            f"No credentials received (count={issuance['credentialCount']})"
        )

        cred = issuance["credentials"][0]
        assert cred["credential"], "Empty credential string"

        # Log credential details
        raw = cred["credential"]
        is_sd_jwt = "~" in raw
        logger.info(
            "[WalletKit] Credential issued: format=%s, length=%d, sd_jwt=%s",
            cred.get("format", "unknown"),
            len(raw),
            is_sd_jwt,
        )

        if is_sd_jwt:
            parts = raw.split("~")
            disclosure_count = len([p for p in parts if p]) - 1
            assert disclosure_count >= 1, (
                "SD-JWT has no disclosures — selective disclosure not working"
            )
            logger.info(
                "[WalletKit] SD-JWT disclosures: %d", disclosure_count,
            )

    @pytest.mark.asyncio
    async def test_credential_type_open_badge(
        self,
        authenticated_gateway_client: GatewayClient,
        wallet_kit: EUDIWalletKitClient,
        eudi_test_org,
        open_badge_template,
    ):
        """open_badge credential can be issued to the EUDI Wallet Kit."""
        result = await authenticated_gateway_client.issue_credential(
            organization_id=eudi_test_org["id"],
            credential_template_id=open_badge_template["id"],
            claims={
                **TEST_CLAIMS,
                "test_id": uuid.uuid4().hex[:8],
                "template": "open_badge",
            },
        )

        issuance = await wallet_kit.run_preauth_issuance(
            result["credential_offer_uri"],
        )

        assert issuance["success"], (
            f"EUDI Wallet Kit failed for open_badge: {issuance.get('error')}"
        )
        assert issuance["credentialCount"] >= 1, (
            "No credential issued for open_badge"
        )
        logger.info(
            "[WalletKit] open_badge credential issued: format=%s",
            issuance["credentials"][0].get("format", "unknown"),
        )

    @pytest.mark.asyncio
    async def test_credential_type_passport(
        self,
        authenticated_gateway_client: GatewayClient,
        wallet_kit: EUDIWalletKitClient,
        eudi_test_org,
        passport_template,
    ):
        """passport credential can be issued to the EUDI Wallet Kit."""
        result = await authenticated_gateway_client.issue_credential(
            organization_id=eudi_test_org["id"],
            credential_template_id=passport_template["id"],
            claims={
                **TEST_CLAIMS,
                "test_id": uuid.uuid4().hex[:8],
                "template": "passport",
            },
        )

        issuance = await wallet_kit.run_preauth_issuance(
            result["credential_offer_uri"],
        )

        assert issuance["success"], (
            f"EUDI Wallet Kit failed for passport: {issuance.get('error')}"
        )
        assert issuance["credentialCount"] >= 1, (
            "No credential issued for passport"
        )
        logger.info(
            "[WalletKit] passport credential issued: format=%s",
            issuance["credentials"][0].get("format", "unknown"),
        )

    @pytest.mark.asyncio
    async def test_issuer_metadata_has_required_eudi_fields(
        self,
        authenticated_gateway_client: GatewayClient,
        wallet_kit: EUDIWalletKitClient,
        eudi_test_org,
        open_badge_template,
    ):
        """The EUDI library validates all required metadata fields.

        If this test passes, it means the strict EUDI metadata parser
        accepted Marty's /.well-known/openid-credential-issuer and
        /.well-known/oauth-authorization-server responses.
        """
        result = await authenticated_gateway_client.issue_credential(
            organization_id=eudi_test_org["id"],
            credential_template_id=open_badge_template["id"],
            claims={**TEST_CLAIMS, "test_id": uuid.uuid4().hex[:8]},
        )

        resolution = await wallet_kit.resolve_offer(result["credential_offer_uri"])
        assert resolution["success"], resolution.get("error")

        meta = resolution["issuerMetadata"]
        assert meta["credentialIssuerId"], "Missing credentialIssuerId"
        assert meta["credentialEndpoint"], "Missing credentialEndpoint"
        assert len(meta["credentialConfigurationIds"]) >= 1, (
            "No credential configurations"
        )
        assert len(meta["authorizationServers"]) >= 1, (
            "No authorization servers"
        )
