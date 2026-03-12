"""
Pytest configuration and shared fixtures for Gateway integration tests.

Provides fixtures for gateway client, test organizations, and common test data.
"""

import os
from typing import AsyncGenerator, Dict, Any, Optional

import httpx
import pytest

from .helpers.auth_helper import AuthHelper
from .helpers.gateway_client import GatewayClient, GatewayClientError
from .helpers.test_data import TestDataBuilder
from .helpers.waltid_wallet_client import WaltIdWalletClient


# =============================================================================
# Pytest Configuration
# =============================================================================

def pytest_configure(config):
    """Register custom markers"""
    config.addinivalue_line(
        "markers",
        "integration: mark test as integration test requiring live gateway",
    )
    config.addinivalue_line(
        "markers",
        "wallet: mark test as requiring functional Walt.id wallet with network access",
    )


def pytest_collection_modifyitems(config, items):
    """Auto-skip integration tests if gateway is not available"""
    gateway_url = os.getenv("GATEWAY_URL", "http://localhost:8000")
    
    # Check if gateway is reachable
    gateway_available = False
    try:
        response = httpx.get(f"{gateway_url}/health", timeout=2.0)
        gateway_available = response.status_code == 200
    except Exception:
        pass
    
    # Check if wallet tests should run
    run_wallet_tests = os.getenv("RUN_WALLET_TESTS", "true").lower() == "true"
    
    if not gateway_available:
        skip_marker = pytest.mark.skip(
            reason=f"Gateway not available at {gateway_url}. "
            "Start gateway or set GATEWAY_URL environment variable."
        )
        for item in items:
            if "integration" in item.keywords:
                item.add_marker(skip_marker)
    
    if not run_wallet_tests:
        skip_marker = pytest.mark.skip(
            reason="Wallet tests require RUN_WALLET_TESTS=true and proper network configuration. "
            "See tests/integration/gateway/README.md for details."
        )
        for item in items:
            if "wallet" in item.keywords:
                item.add_marker(skip_marker)


# =============================================================================
# Gateway Client Fixtures
# =============================================================================

@pytest.fixture
async def gateway_client(test_session_id: str) -> AsyncGenerator[GatewayClient, None]:
    """
    Provide an authenticated gateway client (Keycloak session via PKCE).

    The session is established once per test session by the ``test_session_id``
    fixture and reused here so that all downstream fixtures and tests that
    depend on ``gateway_client`` receive a properly-authenticated client.

    Usage:
        async def test_something(gateway_client):
            org = await gateway_client.create_organization("test-org")
    """
    client = GatewayClient()
    client.set_session(test_session_id)
    try:
        await client.health_check()
        yield client
    finally:
        await client.close()


# Module-level session ID cache.
# Using a plain dict (not an async fixture) ensures the PKCE flow runs
# exactly ONCE per process even if pytest-asyncio 1.x re-enters the
# session-scoped fixture in different event loop contexts.
_SESSION_CACHE: Dict[str, Optional[str]] = {"session_id": None}


@pytest.fixture(scope="session")
async def test_session_id() -> str:
    """
    Perform the Keycloak PKCE flow once per test session.

    Returns the ``sessionId`` cookie value for the configured test user
    (``TEST_USERNAME`` / ``TEST_PASSWORD`` env vars, defaulting to
    ``admin@marty.demo`` / ``MartyTest123!``).

    The result is stored in the module-level ``_SESSION_CACHE`` dict so
    that it is shared across all event loop contexts (pytest-asyncio
    may re-enter session-scoped async fixtures in separate event loops).
    """
    if _SESSION_CACHE["session_id"] is None:
        helper = AuthHelper()
        _SESSION_CACHE["session_id"] = await helper.get_session_id()
    return _SESSION_CACHE["session_id"]  # type: ignore[return-value]


@pytest.fixture
async def authenticated_gateway_client(
    test_session_id: str,
) -> AsyncGenerator[GatewayClient, None]:
    """
    Provide a gateway client pre-authenticated via Keycloak PKCE.

    Sends the ``sessionId`` cookie with every request, mirroring how
    the browser-based UI communicates with the gateway.

    Usage::

        async def test_something(authenticated_gateway_client):
            offer = await authenticated_gateway_client.issue_credential(...)
    """
    client = GatewayClient()
    client.set_session(test_session_id)
    try:
        await client.health_check()
        yield client
    finally:
        await client.close()


# =============================================================================
# Organization Fixtures
# =============================================================================

@pytest.fixture
async def test_organization(gateway_client: GatewayClient) -> Dict[str, Any]:
    """
    Create a unique test organization for each test.
    
    Returns:
        Organization object with id, name, created_at, etc.
        
    Usage:
        async def test_something(test_organization):
            org_id = test_organization["id"]
    """
    org_data = TestDataBuilder.organization()
    org = await gateway_client.create_organization(
        name=org_data["name"],
        display_name=org_data["display_name"],
    )
    return org


# =============================================================================
# Trust Profile Fixtures
# =============================================================================

@pytest.fixture
async def test_trust_profile(
    gateway_client: GatewayClient,
    test_organization: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Create a trust profile for the test organization.
    
    Returns:
        Trust profile object
    """
    trust_profile_data = TestDataBuilder.trust_profile(
        organization_id=test_organization["id"]
    )
    trust_profile = await gateway_client.create_trust_profile(**trust_profile_data)
    return trust_profile


# =============================================================================
# Compliance Profile Fixtures
# =============================================================================

# Compliance profiles are now embedded in credential templates
# No separate compliance-profile fixtures needed


# =============================================================================
# Credential Template Fixtures
# =============================================================================

@pytest.fixture
async def mdl_template(
    gateway_client: GatewayClient,
    test_organization: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Create an mDL credential template.
    
    Returns:
        Credential template object for mobile driver's license
    """
    template_data = TestDataBuilder.mdl_template(
        organization_id=test_organization["id"],
    )
    template = await gateway_client.create_credential_template(**template_data)
    return template


@pytest.fixture
async def employee_badge_template(
    gateway_client: GatewayClient,
    test_organization: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Create an employee badge credential template.
    
    Returns:
        Credential template object for employee badge
    """
    template_data = TestDataBuilder.employee_badge_template(
        organization_id=test_organization["id"],
    )
    template = await gateway_client.create_credential_template(**template_data)
    return template


@pytest.fixture
async def jwt_vc_template(
    gateway_client: GatewayClient,
    test_organization: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Create a W3C JWT VC (jwt_vc) credential template.

    Returns:
        Credential template object for VerifiableId (jwt_vc format)
    """
    template_data = TestDataBuilder.jwt_vc_template(
        organization_id=test_organization["id"],
    )
    template = await gateway_client.create_credential_template(**template_data)
    return template


@pytest.fixture
async def jwt_vc_v2_template(
    gateway_client: GatewayClient,
    test_organization: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Create a W3C JWT VC credential template using the VCDM v2 payload format.

    Sets ``credential_payload_format = "w3c_vcdm_v2_jwt_vc"`` and includes a
    ``wallet_configs`` entry for the *marty* wallet, so issuance responses
    will include a ``credential_offer_uris`` dict.

    Returns:
        Credential template object for VerifiableId (jwt_vc / VCDM v2 format)
    """
    template_data = TestDataBuilder.jwt_vc_v2_template(
        organization_id=test_organization["id"],
    )
    template = await gateway_client.create_credential_template(**template_data)
    return template


@pytest.fixture
async def zk_mdoc_template(
    gateway_client: GatewayClient,
    test_organization: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Create a ZK mDoc credential template with ZK predicate claims.

    Returns:
        Credential template object for ZK mDL (zk_mdoc format)
    """
    template_data = TestDataBuilder.zk_mdoc_template(
        organization_id=test_organization["id"],
    )
    template = await gateway_client.create_credential_template(**template_data)
    return template


# =============================================================================
# Presentation Policy Fixtures
# =============================================================================

@pytest.fixture
async def age_verification_policy(
    gateway_client: GatewayClient,
    test_organization: Dict[str, Any],
    mdl_template: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Create a presentation policy for age verification (21+).
    
    Returns:
        Presentation policy object
    """
    policy_data = TestDataBuilder.presentation_policy_age_verification(
        organization_id=test_organization["id"],
        credential_template_id=mdl_template["id"],
        min_age=21,
    )
    policy = await gateway_client.create_presentation_policy(**policy_data)
    # Activate the policy so it can be used
    policy = await gateway_client.activate_presentation_policy(policy["id"])
    return policy


@pytest.fixture
async def identity_verification_policy(
    gateway_client: GatewayClient,
    test_organization: Dict[str, Any],
    mdl_template: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Create a presentation policy for full identity verification.
    
    Returns:
        Presentation policy object
    """
    policy_data = TestDataBuilder.presentation_policy_identity_verification(
        organization_id=test_organization["id"],
        credential_template_id=mdl_template["id"],
    )
    policy = await gateway_client.create_presentation_policy(**policy_data)
    # Activate the policy so it can be used
    policy = await gateway_client.activate_presentation_policy(policy["id"])
    return policy


# =============================================================================
# Application Template Fixtures
# =============================================================================

@pytest.fixture
async def mdl_application_template(
    gateway_client: GatewayClient,
    test_organization: Dict[str, Any],
    mdl_template: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Create an application template for mDL applications.
    
    Returns:
        Application template object
    """
    app_template = await gateway_client.create_application_template(
        organization_id=test_organization["id"],
        name="mDL Application Process",
        credential_template_id=mdl_template["id"],  # Link to credential template
        form_fields=[
            {
                "field_id": "given_name",
                "field_type": "text",
                "label": "Given Name",
                "required": True
            },
            {
                "field_id": "family_name",
                "field_type": "text",
                "label": "Family Name",
                "required": True
            }
        ],
    )
    return app_template


# =============================================================================
# Deployment Profile Fixtures
# =============================================================================

@pytest.fixture
async def test_deployment_profile(
    gateway_client: GatewayClient,
    test_organization: Dict[str, Any],
    age_verification_policy: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Create a deployment profile for testing.
    
    Returns:
        Deployment profile object
    """
    profile_data = TestDataBuilder.deployment_profile(
        organization_id=test_organization["id"],
        default_presentation_policy_id=age_verification_policy["id"],
    )
    profile = await gateway_client.create_deployment_profile(**profile_data)
    return profile


@pytest.fixture
async def test_lane(
    gateway_client: GatewayClient,
    test_deployment_profile: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Create a lane within a deployment profile.
    
    Returns:
        Lane object
    """
    lane_data = TestDataBuilder.lane(
        deployment_profile_id=test_deployment_profile["id"],
    )
    lane = await gateway_client.create_lane(
        profile_id=test_deployment_profile["id"],
        **lane_data,
    )
    return lane


@pytest.fixture
async def zk_age_verification_policy(
    gateway_client: GatewayClient,
    test_organization: Dict[str, Any],
    zk_mdoc_template: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Create a ZK presentation policy for age verification.
    
    Returns:
        Presentation policy with ZK predicate configuration
    """
    policy_data = TestDataBuilder.presentation_policy_zk_age_verification(
        organization_id=test_organization["id"],
        credential_template_id=zk_mdoc_template["id"],
        min_age=21,
    )
    policy = await gateway_client.create_presentation_policy(**policy_data)
    # Activate the policy so it can be used
    policy = await gateway_client.activate_presentation_policy(policy["id"])
    return policy


# =============================================================================
# Helper Fixtures
# =============================================================================

@pytest.fixture
def test_data_builder() -> TestDataBuilder:
    """
    Provide TestDataBuilder instance.
    
    Usage:
        def test_something(test_data_builder):
            claims = test_data_builder.mdl_claims()
    """
    return TestDataBuilder()


# =============================================================================
# Walt.id Wallet Fixtures
# =============================================================================

@pytest.fixture
async def waltid_wallet_client() -> AsyncGenerator[WaltIdWalletClient, None]:
    """
    Provide configured Walt.id wallet client.
    
    The wallet client connects to Walt.id Wallet Kit running in Docker.
    Each test gets a fresh client instance.
    
    Usage:
        async def test_something(waltid_wallet_client):
            await waltid_wallet_client.create_wallet("test-wallet")
            did = await waltid_wallet_client.create_did()
    """
    wallet_url = os.getenv("WALTID_WALLET_URL", "http://localhost:7001")
    client = WaltIdWalletClient(base_url=wallet_url)
    
    try:
        # Simple connectivity test - wallet doesn't have a standard health endpoint
        # Just verify we can connect to the base URL
        async with httpx.AsyncClient(timeout=5.0) as test_client:
            response = await test_client.get(f"{wallet_url}/wallet-api")
            # We expect 404 for base path, which means the server is responding
            if response.status_code not in [200, 404]:
                pytest.skip(f"Walt.id wallet not available at {wallet_url}")
        
        yield client
    finally:
        # Cleanup: delete wallet if one was created
        if client.wallet_id:
            try:
                await client.delete_wallet()
            except Exception:
                pass  # Ignore cleanup errors
        await client.close()


@pytest.fixture
async def test_wallet(
    waltid_wallet_client: WaltIdWalletClient,
) -> Dict[str, Any]:
    """
    Create a unique test wallet with a DID for each test.
    
    Returns:
        Dictionary with:
            - wallet_id: Wallet identifier
            - did: Primary DID for the wallet
            - client: WaltIdWalletClient instance
    
    Usage:
        async def test_something(test_wallet):
            wallet_id = test_wallet["wallet_id"]
            did = test_wallet["did"]
            await test_wallet["client"].list_credentials()
    """
    import uuid
    
    # Create unique wallet for this test
    wallet_name = f"test-wallet-{uuid.uuid4().hex[:8]}"
    wallet_result = await waltid_wallet_client.create_wallet(wallet_name)
    
    # Create a DID for the wallet
    did_result = await waltid_wallet_client.create_did(method="key")
    
    return {
        "wallet_id": waltid_wallet_client.wallet_id,
        "did": did_result.get("did"),
        "client": waltid_wallet_client,
    }


# =============================================================================
# Marty Authenticator Web App Fixtures
# =============================================================================

@pytest.fixture
async def marty_wallet_url() -> AsyncGenerator[str, None]:
    """
    Provide the base URL of the Marty Authenticator Flutter web app.

    The app is built from ``marty-authenticator/docker/Dockerfile.flutter.web.test``
    and served by nginx on port 9081.  It exposes a ``/health`` endpoint that
    returns 200 ``OK`` when ready.

    The app accepts an optional ``api_url`` query parameter which overrides the
    compiled-in ``MARTY_API_URL`` dart-define at runtime, e.g.::

        url = f"{marty_wallet_url}/?api_url=http://gateway:8000"

    Tests interact with the app via Playwright (browser automation) or by
    navigating to credential-offer deep-links.

    Example::

        @pytest.mark.marty_wallet
        async def test_credential_offer(marty_wallet_url, page):
            await page.goto(f"{marty_wallet_url}/")
            ...

    Skip behaviour: if the ``/health`` endpoint is unreachable or returns a
    non-200 status the test is automatically skipped with an informative
    message.
    """
    wallet_url = os.getenv("MARTY_WALLET_URL", "http://localhost:9081")

    try:
        async with httpx.AsyncClient(timeout=5.0) as probe:
            response = await probe.get(f"{wallet_url}/health")
            if response.status_code != 200:
                pytest.skip(
                    f"Marty wallet not available at {wallet_url} "
                    f"(HTTP {response.status_code})"
                )
    except Exception as exc:
        pytest.skip(f"Marty wallet not available at {wallet_url}: {exc}")

    yield wallet_url
