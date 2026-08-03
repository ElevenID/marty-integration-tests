"""
EUDI Reference Implementation Interoperability Tests

Cross-stack interoperability tests that validate Marty's OID4VCI/OID4VP
compliance against the official EU Digital Identity Wallet reference
implementation services:

  - EUDI Verifier Endpoint: validates that credentials issued by Marty can
    be parsed and verified by the EU reference verifier.
These tests require the EUDI verifier service to be running.

Run with:
    make test-eudi
    # or
    RUN_EUDI_TESTS=true pytest tests/integration/gateway/test_eudi_interop.py -v

Environment variables
---------------------
GATEWAY_URL              Gateway base URL               (default: http://localhost:8000)
EUDI_VERIFIER_URL        EUDI verifier base URL         (default: http://localhost:8090)
TEST_ORG_ID              Organization ID                (default: 22222222-...)
RUN_EUDI_TESTS           Gate for EUDI tests            (default: false)
"""

from __future__ import annotations

import logging
import os
import uuid

import pytest

from .helpers.eudi_client import (
    AGE_VERIFICATION_DCQL_QUERY,
    MDL_DCQL_QUERY,
    PID_DCQL_QUERY,
    SD_JWT_DCQL_QUERY,
    EUDIVerifierClient,
)
from .helpers.gateway_client import GatewayClient
from .helpers.oid4vc_wallet_client import (
    EUDI_WALLET_PROFILE,
    OID4VCIWalletClient,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_ORG_ID = "22222222-2222-2222-2222-222222222222"
ORG_ID = os.getenv("TEST_ORG_ID", DEFAULT_ORG_ID)
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8000")
EUDI_VERIFIER_URL = os.getenv("EUDI_VERIFIER_URL", "http://localhost:8090")

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
# Cross-Stack: Marty Offers → EUDI Wallet Dispatch
# ═══════════════════════════════════════════════════════════════════════════

class TestMartyEUDICredentialOffers:
    """Validate organization-scoped offers before official wallet dispatch."""

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
        """Each current credential type publishes a selectable offer."""
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

class TestEUDIVerifierRequests:
    """Validate current EUDI verifier request creation and resolution."""

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

        eudi_formats = {"dc+sd-jwt", "mso_mdoc", "jwt_vc_json"}
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
            elif fmt == "dc+sd-jwt":
                assert config.get("vct"), (
                    f"SD-JWT config '{config_id}' missing 'vct'"
                )
            jwt_proof = config.get("proof_types_supported", {}).get("jwt")
            if jwt_proof is not None:
                assert "key_attestations_required" in jwt_proof, (
                    f"JWT proof config '{config_id}' uses the obsolete pre-Final "
                    "metadata shape"
                )

    @pytest.mark.asyncio
    async def test_openid_config_has_par_endpoint(self):
        """OIDC discovery must advertise pushed_authorization_request_endpoint.

        The current EUDI wallet library uses this RFC 9126 endpoint when the
        authorization server advertises PAR support.
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
