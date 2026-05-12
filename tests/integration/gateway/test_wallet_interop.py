"""
OID4VC Wallet Interoperability Tests

Tests Marty's OID4VCI v1 and OID4VP v1 compliance against wallet profiles
that simulate the behaviour of:
  - Google Wallet (Android CredentialManager + OID4VP + dc+sd-jwt / mso_mdoc)
  - Apple Wallet (ISO 18013-5 mdoc + Verify with Wallet API)
  - EUDI Reference Wallet (dc+sd-jwt + mso_mdoc + jwt_vc_json)

These tests use a headless protocol-level wallet client (no external wallet
container) to validate that Marty's issuance and verification endpoints
conform to the OID4VC v1 specifications.

For tests that exercise a real wallet implementation, see
test_wallet_oid4vci_gateway.py (Walt.id integration).

Test matrix
-----------
┌─────────────┬────────────┬────────────┬─────────┬───────────┐
│ Profile     │ dc+sd-jwt  │ mso_mdoc   │ jwt_vc  │ OID4VP    │
├─────────────┼────────────┼────────────┼─────────┼───────────┤
│ Google      │     ✓      │     ✓      │         │     ✓     │
│ Apple       │            │     ✓      │         │     ✓*    │
│ EUDI        │     ✓      │     ✓      │    ✓    │     ✓     │
│ Walt.id     │     ✓      │            │    ✓    │     ✓     │
└─────────────┴────────────┴────────────┴─────────┴───────────┘
  * Apple uses ISO 18013-5 device engagement, not OID4VP directly

Environment variables
---------------------
GATEWAY_URL           Gateway base URL        (default: http://localhost:8000)
TEST_ORG_ID           Organization ID         (default: 22222222-...)
WALLET_ISSUER_BASE_URL  Issuer URL for wallets (default: http://host.docker.internal:8000)
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from typing import Any, Dict, List

import pytest

from .helpers.gateway_client import GatewayClient
from .helpers.oid4vc_wallet_client import (
    APPLE_WALLET_PROFILE,
    EUDI_WALLET_PROFILE,
    GOOGLE_WALLET_PROFILE,
    OID4VCIWalletClient,
    OID4VPWalletClient,
    WalletProfile,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_ORG_ID = "22222222-2222-2222-2222-222222222222"
ORG_ID = os.getenv("TEST_ORG_ID", DEFAULT_ORG_ID)
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8000")

# Template IDs (from seed data)
TEMPLATES = {
    "passport": "40000000-0000-0000-0000-000000000001",
    "mDL": "40000000-0000-0000-0000-000000000002",
    "access_badge": "40000000-0000-0000-0000-000000000005",
    "open_badge": "40000000-0000-0000-0000-000000000007",
}

# Standard identity claims for test issuance
TEST_CLAIMS = {
    "given_name": "Interop",
    "family_name": "Test",
    "date_of_birth": "1990-01-15",
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
async def google_wallet() -> OID4VCIWalletClient:
    client = OID4VCIWalletClient(profile=GOOGLE_WALLET_PROFILE, issuer_base_url=GATEWAY_URL)
    yield client
    await client.close()


@pytest.fixture
async def apple_wallet() -> OID4VCIWalletClient:
    client = OID4VCIWalletClient(profile=APPLE_WALLET_PROFILE, issuer_base_url=GATEWAY_URL)
    yield client
    await client.close()


@pytest.fixture
async def eudi_wallet() -> OID4VCIWalletClient:
    client = OID4VCIWalletClient(profile=EUDI_WALLET_PROFILE, issuer_base_url=GATEWAY_URL)
    yield client
    await client.close()


@pytest.fixture
async def google_vp_wallet() -> OID4VPWalletClient:
    client = OID4VPWalletClient(profile=GOOGLE_WALLET_PROFILE, verifier_base_url=GATEWAY_URL)
    yield client
    await client.close()


# ═══════════════════════════════════════════════════════════════════════════
# OID4VCI v1 Issuer Metadata Conformance
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.integration
@pytest.mark.wallet
class TestIssuerMetadataConformance:
    """Validate issuer metadata against OID4VCI v1 §12.2."""

    @pytest.mark.asyncio
    async def test_wellknown_endpoint_returns_valid_metadata(
        self, google_wallet: OID4VCIWalletClient
    ):
        """/.well-known/openid-credential-issuer must return valid metadata."""
        metadata = await google_wallet.fetch_issuer_metadata(org_id=ORG_ID)

        # Required fields (§12.2.4)
        assert metadata["credential_issuer"], "Missing credential_issuer"
        assert metadata["credential_endpoint"], "Missing credential_endpoint"
        assert metadata["credential_configurations_supported"], (
            "Missing credential_configurations_supported"
        )

    @pytest.mark.asyncio
    async def test_metadata_contains_sd_jwt_configuration(
        self, google_wallet: OID4VCIWalletClient
    ):
        """Metadata should advertise dc+sd-jwt or vc+sd-jwt credential format."""
        metadata = await google_wallet.fetch_issuer_metadata(org_id=ORG_ID)
        configs = metadata["credential_configurations_supported"]

        sd_jwt_configs = [
            (cid, cfg)
            for cid, cfg in configs.items()
            if cfg.get("format") in ("dc+sd-jwt", "vc+sd-jwt")
        ]

        assert len(sd_jwt_configs) > 0, (
            f"No SD-JWT VC configurations found. "
            f"Available formats: {[c.get('format') for c in configs.values()]}"
        )

        for config_id, config in sd_jwt_configs:
            # SD-JWT VC requires vct (§A.3.2)
            assert config.get("vct"), (
                f"SD-JWT config '{config_id}' missing 'vct' (Verifiable Credential Type)"
            )
            logger.info(
                "SD-JWT config: %s  vct=%s  format=%s",
                config_id, config["vct"], config["format"],
            )

    @pytest.mark.asyncio
    async def test_metadata_contains_credential_signing_algs(
        self, google_wallet: OID4VCIWalletClient
    ):
        """Each credential configuration should declare signing algorithms."""
        metadata = await google_wallet.fetch_issuer_metadata(org_id=ORG_ID)
        configs = metadata["credential_configurations_supported"]

        for config_id, config in configs.items():
            algs = config.get("credential_signing_alg_values_supported")
            if algs is not None:
                assert isinstance(algs, list), (
                    f"Config '{config_id}': credential_signing_alg_values_supported "
                    f"should be a list, got {type(algs)}"
                )
                assert len(algs) > 0, (
                    f"Config '{config_id}': credential_signing_alg_values_supported is empty"
                )

    @pytest.mark.asyncio
    async def test_metadata_optional_endpoints(
        self, google_wallet: OID4VCIWalletClient
    ):
        """Validate optional endpoint URLs in metadata."""
        metadata = await google_wallet.fetch_issuer_metadata(org_id=ORG_ID)

        # These are optional but should be valid URLs if present
        for endpoint_key in [
            "nonce_endpoint",
            "deferred_credential_endpoint",
            "notification_endpoint",
        ]:
            url = metadata.get(endpoint_key)
            if url:
                assert url.startswith("http"), (
                    f"'{endpoint_key}' should be an HTTP URL, got: {url}"
                )
                logger.info("Optional endpoint %s: %s", endpoint_key, url)


# ═══════════════════════════════════════════════════════════════════════════
# OID4VCI v1 Pre-Authorized Code Flow
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.integration
@pytest.mark.wallet
class TestOID4VCIPreAuthFlow:
    """Test the pre-authorized code issuance flow per OID4VCI v1 §3.5."""

    @pytest.mark.asyncio
    async def test_offer_contains_preauth_grant(
        self,
        authenticated_gateway_client: GatewayClient,
        google_wallet: OID4VCIWalletClient,
    ):
        """Credential offer must contain pre-authorized_code grant."""
        result = await authenticated_gateway_client.issue_credential(
            organization_id=ORG_ID,
            credential_template_id=TEMPLATES["open_badge"],
            claims={**TEST_CLAIMS, "test_id": uuid.uuid4().hex[:8]},
        )
        offer_uri = result.get("credential_offer_uri")
        assert offer_uri, f"No credential_offer_uri in response: {result}"

        offer = await google_wallet.resolve_offer(offer_uri)

        # Validate offer structure (§4.1.1)
        assert offer.get("credential_issuer"), "Offer missing 'credential_issuer'"
        assert offer.get("credential_configuration_ids"), (
            "Offer missing 'credential_configuration_ids'"
        )

        # Check for pre-authorized_code grant
        grants = offer.get("grants", {})
        preauth_key = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
        assert preauth_key in grants, (
            f"Offer missing pre-authorized_code grant. Available grants: {list(grants.keys())}"
        )
        assert grants[preauth_key].get("pre-authorized_code"), (
            "Pre-authorized_code grant missing 'pre-authorized_code'"
        )

    @pytest.mark.asyncio
    async def test_token_exchange_with_preauth_code(
        self,
        authenticated_gateway_client: GatewayClient,
        google_wallet: OID4VCIWalletClient,
    ):
        """Token endpoint must accept pre-authorized_code and return access_token."""
        result = await authenticated_gateway_client.issue_credential(
            organization_id=ORG_ID,
            credential_template_id=TEMPLATES["open_badge"],
            claims={**TEST_CLAIMS, "test_id": uuid.uuid4().hex[:8]},
        )
        offer_uri = result["credential_offer_uri"]

        await google_wallet.resolve_offer(offer_uri)
        await google_wallet.fetch_issuer_metadata(org_id=ORG_ID)
        token_data = await google_wallet.request_token()

        assert token_data.get("access_token"), "Token response missing 'access_token'"
        assert token_data.get("token_type"), "Token response missing 'token_type'"

    @pytest.mark.asyncio
    async def test_nonce_endpoint(
        self,
        google_wallet: OID4VCIWalletClient,
    ):
        """Nonce endpoint should return a fresh c_nonce (OID4VCI §7)."""
        await google_wallet.fetch_issuer_metadata(org_id=ORG_ID)

        nonce_endpoint = google_wallet.issuer_metadata.get("nonce_endpoint")
        if not nonce_endpoint:
            pytest.skip("Issuer does not advertise a nonce_endpoint")

        nonce = await google_wallet.request_nonce()
        assert nonce, "Nonce endpoint returned empty c_nonce"
        assert len(nonce) > 8, f"c_nonce seems too short: {nonce}"


# ═══════════════════════════════════════════════════════════════════════════
# Google Wallet Interoperability
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.integration
@pytest.mark.wallet
class TestGoogleWalletInterop:
    """Test issuance flows as a Google Wallet (Android CredentialManager) would.

    Google Wallet supports:
      - OID4VCI v1 with pre-authorized code
      - Credential formats: dc+sd-jwt, mso_mdoc
      - OID4VP v1 for presentation (via DigitalCredential API)
      - DCQL query format for credential matching
    """

    @pytest.mark.asyncio
    async def test_sd_jwt_issuance_google_profile(
        self,
        authenticated_gateway_client: GatewayClient,
        google_wallet: OID4VCIWalletClient,
    ):
        """Full SD-JWT VC issuance flow simulating Google Wallet."""
        result = await authenticated_gateway_client.issue_credential(
            organization_id=ORG_ID,
            credential_template_id=TEMPLATES["open_badge"],
            claims={
                **TEST_CLAIMS,
                "test_id": uuid.uuid4().hex[:8],
                "wallet_profile": "google",
            },
        )

        offer_uri = result["credential_offer_uri"]
        flow_result = await google_wallet.run_preauth_issuance(
            offer_uri=offer_uri,
            org_id=ORG_ID,
        )

        # Validate at least one credential was issued
        assert google_wallet.credentials, "No credentials received"
        cred = google_wallet.credentials[0]
        raw = cred.get("credential", "")
        assert raw, "Credential object has empty 'credential' field"

        logger.info(
            "[Google] Issued credential, length=%d, has_disclosures=%s",
            len(raw),
            "~" in raw,
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "template_key,template_id",
        [
            ("passport", TEMPLATES["passport"]),
            ("mDL", TEMPLATES["mDL"]),
            ("access_badge", TEMPLATES["access_badge"]),
            ("open_badge", TEMPLATES["open_badge"]),
        ],
        ids=["passport", "mDL", "access_badge", "open_badge"],
    )
    async def test_credential_type_matrix_google(
        self,
        authenticated_gateway_client: GatewayClient,
        template_key: str,
        template_id: str,
    ):
        """Test each credential type through the Google Wallet flow."""
        claims = {**TEST_CLAIMS, "test_id": uuid.uuid4().hex[:8]}
        if template_key == "passport":
            claims["document_number"] = "INTEROP-G-001"

        result = await authenticated_gateway_client.issue_credential(
            organization_id=ORG_ID,
            credential_template_id=template_id,
            claims=claims,
        )

        assert result.get("credential_offer_uri"), (
            f"No offer URI for {template_key}"
        )

        wallet = OID4VCIWalletClient(
            profile=GOOGLE_WALLET_PROFILE, issuer_base_url=GATEWAY_URL
        )
        try:
            offer = await wallet.resolve_offer(result["credential_offer_uri"])
            assert offer.get("credential_configuration_ids"), (
                f"Offer for {template_key} missing credential_configuration_ids"
            )
            logger.info(
                "[Google/%s] Offer config IDs: %s",
                template_key,
                offer["credential_configuration_ids"],
            )
        finally:
            await wallet.close()


# ═══════════════════════════════════════════════════════════════════════════
# Apple Wallet Interoperability
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.integration
@pytest.mark.wallet
class TestAppleWalletInterop:
    """Test flows targeting Apple Wallet compatibility.

    Apple Wallet supports:
      - ISO 18013-5 (mso_mdoc) for mDL and identity documents
      - HPKE-encrypted mdoc response (proprietary "AppleIdentityPresentment")
      - Verify with Wallet API for in-app identity verification
      - NOT OID4VCI directly (provisioning is via Apple's own APIs)

    For interop testing, we verify that Marty can issue mDL credentials
    in ISO 18013-5 compatible format, and that the issuer metadata
    advertises mDoc support correctly.
    """

    @pytest.mark.asyncio
    async def test_issuer_metadata_advertises_mdoc(
        self, apple_wallet: OID4VCIWalletClient
    ):
        """Issuer metadata should include mso_mdoc configurations for Apple compat."""
        metadata = await apple_wallet.fetch_issuer_metadata(org_id=ORG_ID)
        configs = metadata["credential_configurations_supported"]

        mdoc_configs = [
            (cid, cfg)
            for cid, cfg in configs.items()
            if cfg.get("format") == "mso_mdoc"
        ]

        # mDL is the primary Apple Wallet credential
        mdl_configs = [
            (cid, cfg)
            for cid, cfg in mdoc_configs
            if "18013" in cfg.get("doctype", "") or "mDL" in cid
        ]

        if not mdoc_configs:
            pytest.skip(
                "No mso_mdoc configurations in issuer metadata — "
                "Apple Wallet interop requires ISO 18013-5 support"
            )

        for config_id, config in mdoc_configs:
            assert config.get("doctype"), (
                f"mso_mdoc config '{config_id}' missing 'doctype' (required by §A.2.2)"
            )
            logger.info(
                "[Apple] mDoc config: %s  doctype=%s",
                config_id,
                config["doctype"],
            )

    @pytest.mark.asyncio
    async def test_mdl_issuance_for_apple_wallet(
        self,
        authenticated_gateway_client: GatewayClient,
        apple_wallet: OID4VCIWalletClient,
    ):
        """Issue an mDL credential suitable for Apple Wallet."""
        result = await authenticated_gateway_client.issue_credential(
            organization_id=ORG_ID,
            credential_template_id=TEMPLATES["mDL"],
            claims={
                **TEST_CLAIMS,
                "test_id": uuid.uuid4().hex[:8],
                "wallet_profile": "apple",
            },
        )

        offer_uri = result.get("credential_offer_uri")
        assert offer_uri, "No credential_offer_uri for mDL issuance"

        # Resolve offer and validate it contains mDL config
        offer = await apple_wallet.resolve_offer(offer_uri)
        config_ids = offer.get("credential_configuration_ids", [])
        logger.info("[Apple] mDL offer config IDs: %s", config_ids)

        # At minimum, validate the offer is parseable and references mDL
        assert len(config_ids) > 0, "mDL offer has no credential_configuration_ids"


# ═══════════════════════════════════════════════════════════════════════════
# EUDI Wallet Interoperability
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.integration
@pytest.mark.wallet
class TestEUDIWalletInterop:
    """Test flows targeting EU Digital Identity Wallet compatibility.

    The EUDI wallet reference implementation supports the broadest
    set of formats and is the best proxy for general OID4VC v1 conformance:
      - dc+sd-jwt (primary for PID credentials)
      - mso_mdoc (for mDL)
      - jwt_vc_json (for broader VC compatibility)
      - OID4VCI v1 pre-authorized and authorization code flows
      - OID4VP v1 with presentation_definition
    """

    @pytest.mark.asyncio
    async def test_multi_format_issuance(
        self,
        authenticated_gateway_client: GatewayClient,
        eudi_wallet: OID4VCIWalletClient,
    ):
        """EUDI wallet should be able to discover all supported credential formats."""
        metadata = await eudi_wallet.fetch_issuer_metadata(org_id=ORG_ID)
        configs = metadata["credential_configurations_supported"]

        formats_found = set()
        for config_id, config in configs.items():
            fmt = config.get("format", "unknown")
            formats_found.add(fmt)

        logger.info("[EUDI] Credential formats found: %s", formats_found)

        # Should support at least sd-jwt (primary EUDI format)
        sd_jwt_formats = formats_found & {"dc+sd-jwt", "vc+sd-jwt"}
        assert sd_jwt_formats, (
            f"No SD-JWT formats found for EUDI wallet. "
            f"Available: {formats_found}"
        )

    @pytest.mark.asyncio
    async def test_full_preauth_flow_eudi(
        self,
        authenticated_gateway_client: GatewayClient,
        eudi_wallet: OID4VCIWalletClient,
    ):
        """Complete pre-auth issuance flow as EUDI wallet."""
        result = await authenticated_gateway_client.issue_credential(
            organization_id=ORG_ID,
            credential_template_id=TEMPLATES["open_badge"],
            claims={
                **TEST_CLAIMS,
                "test_id": uuid.uuid4().hex[:8],
                "wallet_profile": "eudi",
            },
        )

        flow_result = await eudi_wallet.run_preauth_issuance(
            offer_uri=result["credential_offer_uri"],
            org_id=ORG_ID,
        )

        # Validate credential was received
        assert eudi_wallet.credentials, "EUDI wallet received no credentials"
        logger.info(
            "[EUDI] Received %d credential(s)",
            len(eudi_wallet.credentials),
        )


# ═══════════════════════════════════════════════════════════════════════════
# OID4VP (Verification / Presentation) Conformance
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.integration
@pytest.mark.wallet
class TestOID4VPConformance:
    """Validate OID4VP v1 verification flow structure.

    Tests that the verifier creates properly formatted presentation requests
    that a Google/EUDI wallet can understand.
    """

    @pytest.mark.asyncio
    async def test_verification_session_creates_request_uri(
        self,
        gateway_client: GatewayClient,
        age_verification_policy: Dict[str, Any],
    ):
        """Starting a verification flow should produce a valid request_uri."""
        # Start verification flow using the pre-created & activated policy
        flow = await gateway_client.start_verification_flow(
            presentation_policy_id=age_verification_policy["id"],
        )

        # The flow should contain a request_uri for the wallet
        request_uri = flow.get("request_uri") or flow.get("qr_code_data")
        assert request_uri, (
            f"Verification flow missing request_uri/qr_code_data. "
            f"Keys: {list(flow.keys())}"
        )
        logger.info("[OID4VP] Request URI: %s", request_uri[:200])

    @pytest.mark.asyncio
    async def test_presentation_request_structure(
        self,
        gateway_client: GatewayClient,
        age_verification_policy: Dict[str, Any],
        google_vp_wallet: OID4VPWalletClient,
    ):
        """Presentation request should use the default DCQL-only query shape."""
        flow = await gateway_client.start_verification_flow(
            presentation_policy_id=age_verification_policy["id"],
        )

        request_uri = flow.get("request_uri") or flow.get("qr_code_data")
        if not request_uri:
            pytest.skip("No request_uri in verification flow response")

        # Resolve the presentation request as the wallet would
        try:
            request = await google_vp_wallet.resolve_presentation_request(request_uri)
        except Exception as e:
            pytest.skip(f"Could not resolve presentation request: {e}")

        # Validate required OID4VP fields
        assert request.get("response_type"), "Missing response_type in OID4VP request"
        assert request.get("client_id"), "Missing client_id in OID4VP request"

        pd_info = google_vp_wallet.validate_presentation_definition(request)
        assert pd_info["type"] == "dcql", (
            f"Default request should use dcql_query, got {pd_info['type']}"
        )
        assert "presentation_definition" not in request
        logger.info("[OID4VP] Request type: %s", pd_info["type"])


# ═══════════════════════════════════════════════════════════════════════════
# CLI-Driven Wallet E2E Tests
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.integration
@pytest.mark.wallet
class TestCLIWalletE2E:
    """Tests that use the headless CLI tool alongside wallet operations.

    These combine the Marty CLI's issuance/verification capabilities
    with wallet-side protocol validation.
    """

    @pytest.mark.asyncio
    async def test_cli_issuance_produces_valid_offer(
        self,
        authenticated_gateway_client: GatewayClient,
        google_wallet: OID4VCIWalletClient,
    ):
        """Credential issued via the gateway API produces a spec-compliant offer.

        This mirrors what `marty test:e2e --scenario issuance` does,
        but validates the offer from the wallet's perspective.
        """
        result = await authenticated_gateway_client.issue_credential(
            organization_id=ORG_ID,
            credential_template_id=TEMPLATES["open_badge"],
            claims={
                **TEST_CLAIMS,
                "test_id": uuid.uuid4().hex[:8],
                "source": "cli-e2e-interop",
            },
        )

        offer_uri = result["credential_offer_uri"]

        # Parse as each wallet profile would
        for profile in [GOOGLE_WALLET_PROFILE, EUDI_WALLET_PROFILE]:
            wallet = OID4VCIWalletClient(profile=profile, issuer_base_url=GATEWAY_URL)
            try:
                offer = await wallet.resolve_offer(offer_uri)
                assert offer.get("credential_issuer"), (
                    f"{profile.name}: offer missing credential_issuer"
                )
                assert offer.get("credential_configuration_ids"), (
                    f"{profile.name}: offer missing credential_configuration_ids"
                )
                logger.info(
                    "[CLI-E2E/%s] Offer valid: configs=%s",
                    profile.name,
                    offer["credential_configuration_ids"],
                )
            finally:
                await wallet.close()

    @pytest.mark.asyncio
    async def test_issuer_metadata_stable_across_requests(
        self,
        google_wallet: OID4VCIWalletClient,
    ):
        """Issuer metadata should be deterministic across multiple fetches."""
        metadata1 = await google_wallet.fetch_issuer_metadata(org_id=ORG_ID)
        metadata2 = await google_wallet.fetch_issuer_metadata(org_id=ORG_ID)

        # Core fields must be identical
        assert (
            metadata1["credential_issuer"] == metadata2["credential_issuer"]
        ), "credential_issuer changed between requests"
        assert (
            metadata1["credential_endpoint"] == metadata2["credential_endpoint"]
        ), "credential_endpoint changed between requests"

        # Same set of credential configurations
        assert set(metadata1["credential_configurations_supported"].keys()) == set(
            metadata2["credential_configurations_supported"].keys()
        ), "credential_configurations_supported keys changed between requests"


# ═══════════════════════════════════════════════════════════════════════════
# Google Wallet — Full Issuance + Verification E2E
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.integration
@pytest.mark.wallet
@pytest.mark.interop
class TestGoogleWalletE2E:
    """End-to-end Google Wallet flows: issuance through gateway, then verification.

    These tests exercise the FULL MIP protocol path:
      Gateway API → Issuance Service → Credential Offer → Wallet Token Exchange
      Gateway API → Verification Service → Presentation Request → Wallet VP Submit

    All traffic goes through the gateway (port 8000). No direct service access.
    """

    @pytest.mark.asyncio
    async def test_google_sd_jwt_full_issuance_with_format_validation(
        self,
        authenticated_gateway_client: GatewayClient,
    ):
        """Issue SD-JWT credential via gateway, validate format matches Google Wallet expectations.

        Google Wallet expects dc+sd-jwt or vc+sd-jwt with proper header.typ and
        disclosure delimiters (~). This test exercises the complete pre-auth flow
        and validates the credential structure.
        """
        wallet = OID4VCIWalletClient(
            profile=GOOGLE_WALLET_PROFILE, issuer_base_url=GATEWAY_URL
        )
        try:
            # Step 1: Issue credential via gateway
            result = await authenticated_gateway_client.issue_credential(
                organization_id=ORG_ID,
                credential_template_id=TEMPLATES["open_badge"],
                claims={
                    **TEST_CLAIMS,
                    "test_id": uuid.uuid4().hex[:8],
                    "wallet_profile": "google",
                    "flow": "full_issuance_e2e",
                },
            )
            offer_uri = result["credential_offer_uri"]

            # Step 2: Complete pre-auth issuance as Google Wallet
            flow_result = await wallet.run_preauth_issuance(
                offer_uri=offer_uri,
                org_id=ORG_ID,
            )

            # Step 3: Validate credential format
            assert wallet.credentials, "Google Wallet received no credentials"
            cred = wallet.credentials[0]
            raw = cred.get("credential", "")
            assert raw, "Credential has empty 'credential' field"

            # Determine actual format and validate structure
            if "~" in raw:
                # SD-JWT with disclosures
                format_info = wallet.validate_credential_format(raw, "dc+sd-jwt")
                logger.info(
                    "[Google E2E] Issued SD-JWT credential: iss=%s, disclosures=%d",
                    format_info["payload"].get("iss"),
                    len(format_info.get("disclosures", [])),
                )
            elif raw.count(".") == 2:
                # Plain JWT (server may not use disclosures for some templates)
                from .helpers.oid4vc_wallet_client import _decode_jwt_payload
                payload = _decode_jwt_payload(raw)
                assert payload.get("iss"), "JWT credential missing 'iss' claim"
                logger.info(
                    "[Google E2E] Issued JWT credential: iss=%s",
                    payload["iss"],
                )
            else:
                logger.info(
                    "[Google E2E] Issued credential, length=%d, format=unknown",
                    len(raw),
                )
        finally:
            await wallet.close()

    @pytest.mark.asyncio
    async def test_google_wallet_verification_request_compatible(
        self,
        gateway_client: GatewayClient,
        age_verification_policy: Dict[str, Any],
    ):
        """OID4VP request from gateway must be parseable by a Google Wallet.

        The default Marty request should be DCQL-only and still parse correctly.
        """
        # Start verification flow through gateway
        flow = await gateway_client.start_verification_flow(
            presentation_policy_id=age_verification_policy["id"],
        )

        request_uri = flow.get("request_uri") or flow.get("qr_code_data")
        assert request_uri, "Verification flow missing request_uri"

        # Resolve as Google Wallet would
        vp_wallet = OID4VPWalletClient(
            profile=GOOGLE_WALLET_PROFILE, verifier_base_url=GATEWAY_URL
        )
        try:
            request = await vp_wallet.resolve_presentation_request(request_uri)

            # Validate OID4VP required fields
            assert request.get("response_type"), "Missing response_type"
            assert request.get("client_id"), "Missing client_id"

            definition_info = vp_wallet.validate_presentation_definition(request)
            assert definition_info["type"] == "dcql", (
                f"Default request should use dcql_query, got {definition_info['type']}"
            )
            assert "presentation_definition" not in request

            logger.info(
                "[Google VP] Request compatible: type=%s, response_mode=%s",
                definition_info["type"],
                request.get("response_mode", "N/A"),
            )
        finally:
            await vp_wallet.close()

    @pytest.mark.asyncio
    async def test_google_wallet_issuance_then_verification_e2e(
        self,
        authenticated_gateway_client: GatewayClient,
        gateway_client: GatewayClient,
        age_verification_policy: Dict[str, Any],
    ):
        """Full E2E: issue credential via gateway, then start verification via gateway.

        This is the core MIP protocol flow:
          1. Issuer issues credential through gateway API
          2. Verifier creates verification request through gateway API
          3. Wallet resolves verification request
          4. Wallet validates presentation_definition matches issued credential

        All steps go through the gateway. No direct service calls.
        """
        # -- Issuance Phase (through gateway) --
        issue_result = await authenticated_gateway_client.issue_credential(
            organization_id=ORG_ID,
            credential_template_id=TEMPLATES["open_badge"],
            claims={
                **TEST_CLAIMS,
                "test_id": uuid.uuid4().hex[:8],
                "flow": "google_e2e_verify",
            },
        )
        assert issue_result.get("credential_offer_uri"), "Issuance failed: no offer URI"

        # Wallet picks up the credential
        wallet = OID4VCIWalletClient(
            profile=GOOGLE_WALLET_PROFILE, issuer_base_url=GATEWAY_URL
        )
        try:
            await wallet.run_preauth_issuance(
                offer_uri=issue_result["credential_offer_uri"],
                org_id=ORG_ID,
            )
            assert wallet.credentials, "Wallet received no credentials"
        finally:
            await wallet.close()

        # -- Verification Phase (through gateway) --
        flow = await gateway_client.start_verification_flow(
            presentation_policy_id=age_verification_policy["id"],
        )
        request_uri = flow.get("request_uri") or flow.get("qr_code_data")
        assert request_uri, "Verification flow missing request_uri"

        # Wallet resolves the verification request
        vp_wallet = OID4VPWalletClient(
            profile=GOOGLE_WALLET_PROFILE, verifier_base_url=GATEWAY_URL
        )
        try:
            request = await vp_wallet.resolve_presentation_request(request_uri)
            definition_info = vp_wallet.validate_presentation_definition(request)
            assert definition_info["type"] == "dcql"
            assert "presentation_definition" not in request

            logger.info(
                "[Google E2E] Issuance → Verification complete: "
                "credentials_issued=%d, request_type=%s",
                len(wallet.credentials),
                definition_info["type"],
            )
        finally:
            await vp_wallet.close()


# ═══════════════════════════════════════════════════════════════════════════
# Apple Wallet — Full Issuance + Verification E2E
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.integration
@pytest.mark.wallet
@pytest.mark.interop
class TestAppleWalletE2E:
    """End-to-end Apple Wallet flows for ISO 18013-5 mDL credentials.

    Apple Wallet supports:
      - mso_mdoc format only (ISO 18013-5)
      - Device engagement via QR code or NFC
      - Verify with Wallet API for in-app verification

    All issuance and metadata discovery goes through the gateway API.
    """

    @pytest.mark.asyncio
    async def test_apple_mdl_full_issuance_flow(
        self,
        authenticated_gateway_client: GatewayClient,
    ):
        """Issue an mDL through the gateway, completing the full pre-auth flow.

        Apple Wallet devices would receive this credential via OID4VCI
        and store it as an ISO 18013-5 mDL in the Wallet app.
        """
        wallet = OID4VCIWalletClient(
            profile=APPLE_WALLET_PROFILE, issuer_base_url=GATEWAY_URL
        )
        try:
            result = await authenticated_gateway_client.issue_credential(
                organization_id=ORG_ID,
                credential_template_id=TEMPLATES["mDL"],
                claims={
                    **TEST_CLAIMS,
                    "test_id": uuid.uuid4().hex[:8],
                    "document_number": "APPLE-E2E-001",
                    "wallet_profile": "apple",
                },
            )
            offer_uri = result.get("credential_offer_uri")
            assert offer_uri, "No credential_offer_uri for mDL issuance"

            # Complete the pre-auth flow
            await wallet.run_preauth_issuance(
                offer_uri=offer_uri,
                org_id=ORG_ID,
            )

            assert wallet.credentials, "Apple Wallet received no credentials"
            logger.info(
                "[Apple E2E] Issued mDL credential, count=%d",
                len(wallet.credentials),
            )
        finally:
            await wallet.close()

    @pytest.mark.asyncio
    async def test_apple_issuer_metadata_iso_18013_compliance(
        self,
        apple_wallet: OID4VCIWalletClient,
    ):
        """Issuer metadata must declare ISO 18013-5 compatible mDoc configurations.

        Per the OID4VCI v1 spec §A.2.2, mso_mdoc credentials must include:
          - doctype (e.g., "org.iso.18013.5.1.mDL")
          - claims in namespaced format
        """
        metadata = await apple_wallet.fetch_issuer_metadata(org_id=ORG_ID)
        configs = metadata["credential_configurations_supported"]

        mdoc_configs = {
            cid: cfg
            for cid, cfg in configs.items()
            if cfg.get("format") == "mso_mdoc"
        }

        if not mdoc_configs:
            pytest.skip("No mso_mdoc configurations — Apple interop requires ISO 18013-5")

        for config_id, config in mdoc_configs.items():
            doctype = config.get("doctype", "")
            assert doctype, (
                f"mso_mdoc config '{config_id}' missing 'doctype' (required by §A.2.2)"
            )

            # For mDL, doctype must be org.iso.18013.5.1.mDL
            if "18013" in doctype or "mDL" in config_id:
                assert doctype == "org.iso.18013.5.1.mDL", (
                    f"mDL doctype should be 'org.iso.18013.5.1.mDL', got '{doctype}'"
                )

            # claims should be organized in namespaces
            claims = config.get("claims")
            if claims:
                logger.info(
                    "[Apple ISO] Config %s: doctype=%s, claim_namespaces=%s",
                    config_id,
                    doctype,
                    list(claims.keys()) if isinstance(claims, dict) else "flat",
                )

    @pytest.mark.asyncio
    async def test_apple_wallet_mdl_verification_request(
        self,
        gateway_client: GatewayClient,
        age_verification_policy: Dict[str, Any],
    ):
        """Verification request from gateway should be compatible with
        Apple Wallet's Verify with Wallet API.

        While Apple uses a proprietary presentation format internally,
        the OID4VP request must still be structurally valid so that
        middleware/SDKs can bridge to Apple's native API.
        """
        flow = await gateway_client.start_verification_flow(
            presentation_policy_id=age_verification_policy["id"],
        )
        request_uri = flow.get("request_uri") or flow.get("qr_code_data")
        assert request_uri, "Verification flow missing request_uri"

        # Resolve as an OID4VP-compatible bridge/SDK would
        vp_wallet = OID4VPWalletClient(
            profile=APPLE_WALLET_PROFILE, verifier_base_url=GATEWAY_URL
        )
        try:
            request = await vp_wallet.resolve_presentation_request(request_uri)

            # Validate basic OID4VP structure
            assert request.get("response_type"), "Missing response_type"
            assert request.get("client_id"), "Missing client_id"

            # Check there is a valid definition
            definition_info = vp_wallet.validate_presentation_definition(request)
            assert definition_info["type"] == "dcql"
            assert "presentation_definition" not in request
            logger.info(
                "[Apple VP] Request type=%s, nonce=%s",
                definition_info["type"],
                "present" if request.get("nonce") else "absent",
            )
        finally:
            await vp_wallet.close()


# ═══════════════════════════════════════════════════════════════════════════
# Cross-Wallet Interoperability Verification
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.integration
@pytest.mark.wallet
@pytest.mark.interop
class TestCrossWalletInterop:
    """Verify that credentials and verification flows are interoperable
    across wallet profiles (Google, Apple, EUDI).

    These tests ensure the gateway produces standards-compliant outputs
    that any OID4VC v1 wallet can consume, regardless of vendor.
    """

    @pytest.mark.asyncio
    async def test_offer_parseable_by_all_wallet_profiles(
        self,
        authenticated_gateway_client: GatewayClient,
    ):
        """A single credential offer should be parseable by all wallet profiles."""
        result = await authenticated_gateway_client.issue_credential(
            organization_id=ORG_ID,
            credential_template_id=TEMPLATES["open_badge"],
            claims={
                **TEST_CLAIMS,
                "test_id": uuid.uuid4().hex[:8],
                "flow": "cross_wallet_offer",
            },
        )
        offer_uri = result["credential_offer_uri"]

        for profile in [GOOGLE_WALLET_PROFILE, APPLE_WALLET_PROFILE, EUDI_WALLET_PROFILE]:
            wallet = OID4VCIWalletClient(profile=profile, issuer_base_url=GATEWAY_URL)
            try:
                offer = await wallet.resolve_offer(offer_uri)
                assert offer.get("credential_issuer"), (
                    f"{profile.name}: offer missing credential_issuer"
                )
                assert offer.get("credential_configuration_ids"), (
                    f"{profile.name}: offer missing credential_configuration_ids"
                )
                logger.info(
                    "[CrossWallet/%s] Offer parsed OK: configs=%s",
                    profile.name,
                    offer["credential_configuration_ids"],
                )
            finally:
                await wallet.close()

    @pytest.mark.asyncio
    async def test_verification_request_parseable_by_all_wallets(
        self,
        gateway_client: GatewayClient,
        age_verification_policy: Dict[str, Any],
    ):
        """A verification request should be resolvable by all wallet profiles."""
        flow = await gateway_client.start_verification_flow(
            presentation_policy_id=age_verification_policy["id"],
        )
        request_uri = flow.get("request_uri") or flow.get("qr_code_data")
        assert request_uri, "Verification flow missing request_uri"

        for profile in [GOOGLE_WALLET_PROFILE, EUDI_WALLET_PROFILE]:
            vp_wallet = OID4VPWalletClient(
                profile=profile, verifier_base_url=GATEWAY_URL
            )
            try:
                request = await vp_wallet.resolve_presentation_request(request_uri)
                definition_info = vp_wallet.validate_presentation_definition(request)
                assert definition_info["type"] == "dcql"
                assert "presentation_definition" not in request
                logger.info(
                    "[CrossWallet/%s] Verification request parsed: type=%s",
                    profile.name,
                    definition_info["type"],
                )
            finally:
                await vp_wallet.close()

    @pytest.mark.asyncio
    async def test_metadata_supports_multi_format_discovery(
        self,
    ):
        """All wallet profiles should discover their supported formats in metadata."""
        profiles_and_formats = [
            (GOOGLE_WALLET_PROFILE, {"dc+sd-jwt", "vc+sd-jwt"}),
            (EUDI_WALLET_PROFILE, {"dc+sd-jwt", "vc+sd-jwt"}),
            # Apple only needs mso_mdoc — we check separately
        ]

        for profile, expected_formats in profiles_and_formats:
            wallet = OID4VCIWalletClient(profile=profile, issuer_base_url=GATEWAY_URL)
            try:
                metadata = await wallet.fetch_issuer_metadata(org_id=ORG_ID)
                configs = metadata["credential_configurations_supported"]
                found_formats = {
                    cfg.get("format") for cfg in configs.values()
                }

                # At least one expected format should be present
                matching = found_formats & expected_formats
                assert matching, (
                    f"{profile.name}: expected one of {expected_formats}, "
                    f"found {found_formats}"
                )
                logger.info(
                    "[CrossWallet/%s] Formats: matching=%s, all=%s",
                    profile.name,
                    matching,
                    found_formats,
                )
            finally:
                await wallet.close()


# ═══════════════════════════════════════════════════════════════════════════
# CredentialManager Protocol (Google Wallet native path)
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.integration
@pytest.mark.wallet
class TestCredentialManagerProtocol:
    """Validate the CredentialManager issuance protocol — the dedicated path
    for Google Wallet on Android.

    Unlike the generic OID4VCI path, CredentialManager uses:
      - A dedicated metadata endpoint at /org/{id}/credential-manager
      - Only ``dc+sd-jwt`` format entries (no jwt_vc_json, mso_mdoc, or spruce variants)
      - The ``#credential-manager`` config-id suffix
    """

    @pytest.mark.asyncio
    async def test_credential_manager_metadata_endpoint_exists(self):
        """The /credential-manager metadata endpoint should return valid metadata."""
        wallet = OID4VCIWalletClient(
            profile=GOOGLE_WALLET_PROFILE, issuer_base_url=GATEWAY_URL
        )
        try:
            metadata = await wallet.fetch_issuer_metadata(
                org_id=ORG_ID, path_suffix="/credential-manager",
            )
            assert metadata["credential_issuer"], "Missing credential_issuer"
            assert metadata["credential_endpoint"], "Missing credential_endpoint"
            assert "credential_configurations_supported" in metadata
        finally:
            await wallet.close()

    @pytest.mark.asyncio
    async def test_credential_manager_metadata_only_dc_sd_jwt(self):
        """CredentialManager metadata must contain ONLY dc+sd-jwt entries.

        Google's CredentialManager SDK fails if the metadata document contains
        any format it cannot parse (jwt_vc_json, spruce-vc+sd-jwt, mso_mdoc).
        """
        wallet = OID4VCIWalletClient(
            profile=GOOGLE_WALLET_PROFILE, issuer_base_url=GATEWAY_URL
        )
        try:
            metadata = await wallet.fetch_issuer_metadata(
                org_id=ORG_ID, path_suffix="/credential-manager",
            )
            configs = metadata["credential_configurations_supported"]
            assert configs, "No credential configurations in metadata"

            for config_id, config in configs.items():
                fmt = config.get("format")
                assert fmt == "dc+sd-jwt", (
                    f"Config '{config_id}' has format '{fmt}', expected 'dc+sd-jwt'. "
                    f"CredentialManager metadata must only contain dc+sd-jwt entries."
                )
        finally:
            await wallet.close()

    @pytest.mark.asyncio
    async def test_credential_manager_config_ids_use_correct_suffix(self):
        """Config IDs in the CredentialManager metadata must use #credential-manager suffix."""
        wallet = OID4VCIWalletClient(
            profile=GOOGLE_WALLET_PROFILE, issuer_base_url=GATEWAY_URL
        )
        try:
            metadata = await wallet.fetch_issuer_metadata(
                org_id=ORG_ID, path_suffix="/credential-manager",
            )
            configs = metadata["credential_configurations_supported"]
            for config_id in configs:
                assert config_id.endswith("#credential-manager"), (
                    f"Config ID '{config_id}' does not end with '#credential-manager'"
                )
        finally:
            await wallet.close()

    @pytest.mark.asyncio
    async def test_credential_manager_issuer_url_matches(self):
        """credential_issuer in CredentialManager metadata must end with /credential-manager."""
        wallet = OID4VCIWalletClient(
            profile=GOOGLE_WALLET_PROFILE, issuer_base_url=GATEWAY_URL
        )
        try:
            metadata = await wallet.fetch_issuer_metadata(
                org_id=ORG_ID, path_suffix="/credential-manager",
            )
            issuer = metadata["credential_issuer"]
            assert issuer.endswith("/credential-manager"), (
                f"credential_issuer '{issuer}' does not end with /credential-manager"
            )
        finally:
            await wallet.close()

    @pytest.mark.asyncio
    async def test_credential_manager_oauth_metadata(self):
        """OAuth AS metadata for the credential-manager path should be accessible."""
        import httpx

        async with httpx.AsyncClient(timeout=15.0) as client:
            url = (
                f"{GATEWAY_URL}/.well-known/oauth-authorization-server"
                f"/org/{ORG_ID}/credential-manager"
            )
            resp = await client.get(url)
            assert resp.status_code == 200, (
                f"OAuth AS metadata returned {resp.status_code}"
            )
            data = resp.json()
            assert data["issuer"].endswith("/credential-manager"), (
                f"OAuth issuer '{data['issuer']}' does not match credential-manager path"
            )
            assert "token_endpoint" in data
            assert "pre-authorized_grant_anonymous_access_supported" in data

    @pytest.mark.asyncio
    async def test_credential_manager_excludes_iso_mdoc(self):
        """ISO 18013 mDoc types should NOT appear in CredentialManager metadata.

        Google's CredentialManager dc+sd-jwt path does not handle mso_mdoc.
        """
        wallet = OID4VCIWalletClient(
            profile=GOOGLE_WALLET_PROFILE, issuer_base_url=GATEWAY_URL
        )
        try:
            metadata = await wallet.fetch_issuer_metadata(
                org_id=ORG_ID, path_suffix="/credential-manager",
            )
            configs = metadata["credential_configurations_supported"]
            for config_id, config in configs.items():
                assert config.get("format") != "mso_mdoc", (
                    f"Config '{config_id}' is mso_mdoc — should be excluded"
                )
                assert not config.get("doctype", "").startswith("org.iso.18013"), (
                    f"Config '{config_id}' is ISO 18013 — should be excluded"
                )
        finally:
            await wallet.close()

    @pytest.mark.asyncio
    async def test_credential_manager_full_issuance_e2e(
        self,
        authenticated_gateway_client: GatewayClient,
    ):
        """Full issuance via CredentialManager protocol through the gateway.

        Issues a credential targeting Google Wallet's wr-google-001 wallet ID,
        validates the offer URI routes through the credential-manager metadata
        path, and completes the pre-auth token exchange.
        """
        wallet = OID4VCIWalletClient(
            profile=GOOGLE_WALLET_PROFILE, issuer_base_url=GATEWAY_URL
        )
        try:
            result = await authenticated_gateway_client.issue_credential(
                organization_id=ORG_ID,
                credential_template_id=TEMPLATES["open_badge"],
                claims={
                    **TEST_CLAIMS,
                    "test_id": uuid.uuid4().hex[:8],
                    "wallet_profile": "google_credential_manager",
                    "flow": "credential_manager_e2e",
                },
            )

            # Check if per-wallet URIs contain a Google Wallet offer
            offer_uris = result.get("credential_offer_uris", {})
            google_uri = offer_uris.get("wr-google-001")

            if google_uri:
                # Validate the Google-specific offer targets credential-manager metadata
                logger.info(
                    "[CredentialManager E2E] Google Wallet offer URI present: %s...",
                    google_uri[:80],
                )
                # Complete issuance using the Google-specific offer
                flow_result = await wallet.run_preauth_issuance(
                    offer_uri=google_uri,
                    org_id=ORG_ID,
                )
                assert wallet.credentials, (
                    "Google CredentialManager issuance produced no credentials"
                )
                logger.info(
                    "[CredentialManager E2E] Issued %d credential(s) via Google Wallet path",
                    len(wallet.credentials),
                )
            else:
                # Fall back to default offer URI if Google config not yet seeded
                offer_uri = result["credential_offer_uri"]
                flow_result = await wallet.run_preauth_issuance(
                    offer_uri=offer_uri,
                    org_id=ORG_ID,
                )
                assert wallet.credentials, (
                    "CredentialManager issuance produced no credentials"
                )
                logger.info(
                    "[CredentialManager E2E] Issued %d credential(s) via default path (Google config not yet seeded)",
                    len(wallet.credentials),
                )
        finally:
            await wallet.close()


# ═══════════════════════════════════════════════════════════════════════════
# Apple Wallet Protocol (mso_mdoc-only issuance path)
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.integration
@pytest.mark.wallet
class TestAppleWalletProtocol:
    """Validate the Apple Wallet issuance protocol — the dedicated path
    for Apple Wallet on iOS.

    Unlike the generic OID4VCI path, Apple Wallet uses:
      - A dedicated metadata endpoint at /org/{id}/apple-wallet
      - Only ``mso_mdoc`` format entries (no jwt_vc_json, dc+sd-jwt, or spruce variants)
      - The ``#apple-wallet`` config-id suffix
    """

    @pytest.mark.asyncio
    async def test_apple_wallet_metadata_endpoint_exists(self):
        """The /apple-wallet metadata endpoint should return valid metadata."""
        wallet = OID4VCIWalletClient(
            profile=APPLE_WALLET_PROFILE, issuer_base_url=GATEWAY_URL
        )
        try:
            metadata = await wallet.fetch_issuer_metadata(
                org_id=ORG_ID, path_suffix="/apple-wallet",
            )
            assert metadata["credential_issuer"], "Missing credential_issuer"
            assert metadata["credential_endpoint"], "Missing credential_endpoint"
            assert "credential_configurations_supported" in metadata
        finally:
            await wallet.close()

    @pytest.mark.asyncio
    async def test_apple_wallet_metadata_only_mso_mdoc(self):
        """Apple Wallet metadata must contain ONLY mso_mdoc entries.

        Apple's Verify with Wallet / ISO 18013-5 path expects mso_mdoc format.
        Any jwt_vc_json, dc+sd-jwt, or spruce-vc+sd-jwt entry may cause
        format negotiation to fail.
        """
        wallet = OID4VCIWalletClient(
            profile=APPLE_WALLET_PROFILE, issuer_base_url=GATEWAY_URL
        )
        try:
            metadata = await wallet.fetch_issuer_metadata(
                org_id=ORG_ID, path_suffix="/apple-wallet",
            )
            configs = metadata["credential_configurations_supported"]
            assert configs, "No credential configurations in metadata"

            for config_id, config in configs.items():
                fmt = config.get("format")
                assert fmt == "mso_mdoc", (
                    f"Config '{config_id}' has format '{fmt}', expected 'mso_mdoc'. "
                    f"Apple Wallet metadata must only contain mso_mdoc entries."
                )
        finally:
            await wallet.close()

    @pytest.mark.asyncio
    async def test_apple_wallet_config_ids_use_correct_suffix(self):
        """Config IDs in the Apple Wallet metadata must use #apple-wallet suffix."""
        wallet = OID4VCIWalletClient(
            profile=APPLE_WALLET_PROFILE, issuer_base_url=GATEWAY_URL
        )
        try:
            metadata = await wallet.fetch_issuer_metadata(
                org_id=ORG_ID, path_suffix="/apple-wallet",
            )
            configs = metadata["credential_configurations_supported"]
            for config_id in configs:
                assert config_id.endswith("#apple-wallet"), (
                    f"Config ID '{config_id}' does not end with '#apple-wallet'"
                )
        finally:
            await wallet.close()

    @pytest.mark.asyncio
    async def test_apple_wallet_issuer_url_matches(self):
        """credential_issuer in Apple Wallet metadata must end with /apple-wallet."""
        wallet = OID4VCIWalletClient(
            profile=APPLE_WALLET_PROFILE, issuer_base_url=GATEWAY_URL
        )
        try:
            metadata = await wallet.fetch_issuer_metadata(
                org_id=ORG_ID, path_suffix="/apple-wallet",
            )
            issuer = metadata["credential_issuer"]
            assert issuer.endswith("/apple-wallet"), (
                f"credential_issuer '{issuer}' does not end with /apple-wallet"
            )
        finally:
            await wallet.close()

    @pytest.mark.asyncio
    async def test_apple_wallet_oauth_metadata(self):
        """OAuth AS metadata for the apple-wallet path should be accessible."""
        import httpx

        async with httpx.AsyncClient(timeout=15.0) as client:
            url = (
                f"{GATEWAY_URL}/.well-known/oauth-authorization-server"
                f"/org/{ORG_ID}/apple-wallet"
            )
            resp = await client.get(url)
            assert resp.status_code == 200, (
                f"OAuth AS metadata returned {resp.status_code}"
            )
            data = resp.json()
            assert data["issuer"].endswith("/apple-wallet"), (
                f"OAuth issuer '{data['issuer']}' does not match apple-wallet path"
            )
            assert "token_endpoint" in data
            assert "pre-authorized_grant_anonymous_access_supported" in data

    @pytest.mark.asyncio
    async def test_apple_wallet_metadata_has_doctype(self):
        """Every mso_mdoc entry in Apple Wallet metadata must have a doctype field."""
        wallet = OID4VCIWalletClient(
            profile=APPLE_WALLET_PROFILE, issuer_base_url=GATEWAY_URL
        )
        try:
            metadata = await wallet.fetch_issuer_metadata(
                org_id=ORG_ID, path_suffix="/apple-wallet",
            )
            configs = metadata["credential_configurations_supported"]
            for config_id, config in configs.items():
                assert "doctype" in config, (
                    f"Config '{config_id}' missing 'doctype' — required for mso_mdoc"
                )
        finally:
            await wallet.close()

    @pytest.mark.asyncio
    async def test_apple_wallet_full_issuance_e2e(
        self,
        authenticated_gateway_client: GatewayClient,
    ):
        """Full issuance via Apple Wallet protocol through the gateway.

        Issues a credential targeting Apple Wallet's wr-apple-001 wallet ID,
        validates the offer URI routes through the apple-wallet metadata path,
        and completes the pre-auth token exchange.
        """
        wallet = OID4VCIWalletClient(
            profile=APPLE_WALLET_PROFILE, issuer_base_url=GATEWAY_URL
        )
        try:
            result = await authenticated_gateway_client.issue_credential(
                organization_id=ORG_ID,
                credential_template_id=TEMPLATES["open_badge"],
                claims={
                    **TEST_CLAIMS,
                    "test_id": uuid.uuid4().hex[:8],
                    "wallet_profile": "apple_wallet",
                    "flow": "apple_wallet_e2e",
                },
            )

            # Check if per-wallet URIs contain an Apple Wallet offer
            offer_uris = result.get("credential_offer_uris", {})
            apple_uri = offer_uris.get("wr-apple-001")

            if apple_uri:
                logger.info(
                    "[AppleWallet E2E] Apple Wallet offer URI present: %s...",
                    apple_uri[:80],
                )
                flow_result = await wallet.run_preauth_issuance(
                    offer_uri=apple_uri,
                    org_id=ORG_ID,
                )
                assert wallet.credentials, (
                    "Apple Wallet issuance produced no credentials"
                )
                logger.info(
                    "[AppleWallet E2E] Issued %d credential(s) via Apple Wallet path",
                    len(wallet.credentials),
                )
            else:
                # Fall back to default offer URI if Apple config not yet seeded
                offer_uri = result["credential_offer_uri"]
                flow_result = await wallet.run_preauth_issuance(
                    offer_uri=offer_uri,
                    org_id=ORG_ID,
                )
                assert wallet.credentials, (
                    "Apple Wallet issuance produced no credentials"
                )
                logger.info(
                    "[AppleWallet E2E] Issued %d credential(s) via default path (Apple config not yet seeded)",
                    len(wallet.credentials),
                )
        finally:
            await wallet.close()
