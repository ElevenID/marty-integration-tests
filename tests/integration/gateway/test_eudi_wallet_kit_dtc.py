"""
EUDI Wallet Kit — DTC (Digital Travel Credential) Interop Tests

Proves that Marty's ICAO DTC credential issuance and verification flows
are compatible with the EUDI Wallet Kit libraries.  DTC credentials use
mDoc format (ISO 18013-5) with the ``com.icao.dtc`` namespace per
ICAO Doc 9303 Part 13.

The test flow:
1. Create a DTC credential template (com.icao.dtc, mDoc format)
2. Issue a DTC credential via Marty (OID4VCI pre-authorized) → EUDI wallet receives mDoc
3. Create and activate a DTC verification policy
4. Start an OID4VP verification flow → parse authorization request
5. Build mDoc VP token via the EUDI wallet harness
6. Direct-post VP token to Marty's submit endpoint
7. Verify the result — Marty accepts and evaluates the DTC presentation

Run with:
    RUN_EUDI_TESTS=true pytest tests/integration/gateway/test_eudi_wallet_kit_dtc.py -v

Environment variables
---------------------
GATEWAY_URL              Gateway base URL                (default: http://localhost:8000)
EUDI_WALLET_KIT_URL      Wallet kit harness URL          (default: http://localhost:9090)
RUN_EUDI_TESTS           Gate for EUDI tests             (default: false)
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from typing import Any, Dict

import pytest

from .helpers.eudi_wallet_kit_client import EUDIWalletKitClient
from .helpers.gateway_client import GatewayClient
from .helpers.test_data import TestDataBuilder

logger = logging.getLogger(__name__)


def _presentation_submission_for_request(
    auth_req: Dict[str, Any],
    credential_format: str,
) -> str | None:
    """Build Presentation Exchange metadata only when the request actually uses PE."""
    pd = auth_req.get("presentation_definition")
    if not pd:
        return None

    descriptor_id = pd.get("input_descriptors", [{}])[0].get("id", "0")
    return json.dumps({
        "id": str(uuid.uuid4()),
        "definition_id": pd.get("id", str(uuid.uuid4())),
        "descriptor_map": [
            {"id": descriptor_id, "format": credential_format, "path": "$"},
        ],
    })

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8000")
EUDI_WALLET_KIT_URL = os.getenv("EUDI_WALLET_KIT_URL", "http://localhost:9090")

# ---------------------------------------------------------------------------
# Skip unless EUDI tests are explicitly enabled
# ---------------------------------------------------------------------------

run_eudi = os.getenv("RUN_EUDI_TESTS", "false").lower() == "true"
pytestmark = [
    pytest.mark.integration,
    pytest.mark.eudi,
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
async def dtc_test_org(authenticated_gateway_client: GatewayClient):
    """Create a test organization for DTC wallet tests."""
    org = await authenticated_gateway_client.create_organization(
        name=f"eudi-dtc-{uuid.uuid4().hex[:6]}",
        display_name="EUDI DTC Wallet Test Org",
    )
    return org


@pytest.fixture
async def dtc_mdoc_resources(authenticated_gateway_client: GatewayClient, dtc_test_org):
    """Create the separately managed mDoc resources required by the public API."""
    compliance = await authenticated_gateway_client.create_compliance_profile(
        organization_id=dtc_test_org["id"],
        name="EUDI DTC mDoc",
        compliance_code="ICAO_DTC",
        credential_format="mso_mdoc",
        frameworks=["icao_doc_9303"],
    )
    service = None
    resolution_error: Exception | None = None
    for organization_id in (dtc_test_org["id"], None):
        try:
            resolved = await authenticated_gateway_client.resolve_signing_service(
                organization_id=organization_id,
                credential_format="mso_mdoc",
                key_purpose="mdoc_dsc",
                algorithm="ES256",
            )
            candidate = resolved.get("service")
            if isinstance(candidate, dict) and candidate.get("id"):
                service = candidate
                break
        except Exception as exc:  # Capability absence is surfaced by the public API.
            resolution_error = exc
    if not isinstance(service, dict) or not service.get("id"):
        raise RuntimeError(f"No mDoc document signer is available: {resolution_error}")
    domain = os.getenv("PUBLIC_DOMAIN", "marty-oidf2.local")
    domain = domain.removeprefix("https://").removeprefix("http://").strip("/")
    issuer = await authenticated_gateway_client.create_issuer_profile(
        organization_id=dtc_test_org["id"],
        name="EUDI DTC document signer",
        issuer_did=f"did:web:{domain.replace('/', ':')}:orgs:{dtc_test_org['id']}",
        signing_service_id=str(service["id"]),
        signing_key_reference=str(service.get("key_reference") or "") or None,
        key_purpose="mdoc_dsc",
        status="active",
    )
    revocation = await authenticated_gateway_client.create_revocation_profile(
        organization_id=dtc_test_org["id"],
        name="EUDI DTC status list",
        revocation_mechanism=["STATUS_LIST_2021"],
    )
    revocation = await authenticated_gateway_client.activate_revocation_profile(revocation["id"])
    return {
        "compliance_profile_id": compliance["id"],
        "issuer_profile_id": issuer["id"],
        "revocation_profile_id": revocation["id"],
    }


@pytest.fixture
async def dtc_mdoc_template(
    authenticated_gateway_client: GatewayClient,
    dtc_test_org,
    dtc_mdoc_resources,
):
    """Create an ICAO DTC credential template (mDoc format, com.icao.dtc namespace)."""
    template_data = TestDataBuilder.dtc_template(
        organization_id=dtc_test_org["id"],
        name=f"DTC Wallet Test ({uuid.uuid4().hex[:6]})",
        compliance_profile_id=dtc_mdoc_resources["compliance_profile_id"],
    )
    template_data.update({
        "issuer_profile_id": dtc_mdoc_resources["issuer_profile_id"],
        "revocation_profile_id": dtc_mdoc_resources["revocation_profile_id"],
    })
    return await authenticated_gateway_client.create_credential_template(**template_data)


@pytest.fixture
async def issued_dtc_credential(
    authenticated_gateway_client: GatewayClient,
    wallet_kit: EUDIWalletKitClient,
    dtc_test_org,
    dtc_mdoc_template,
) -> Dict[str, Any]:
    """Issue a DTC credential via Marty OID4VCI and receive it through the EUDI wallet harness.

    Returns a dict with keys: credential, format, issuance_result, claims.
    """
    claims = TestDataBuilder.dtc_claims(
        given_name="ERIKA",
        family_name="MUSTERMANN",
        birth_date="1964-08-12",
        document_number="PMB09A5929",
    )

    result = await authenticated_gateway_client.issue_credential(
        organization_id=dtc_test_org["id"],
        credential_template_id=dtc_mdoc_template["id"],
        claims=claims,
    )
    offer_uri = result["credential_offer_uri"]
    logger.info("[DTC] Credential offer created: %s", offer_uri[:100])

    # Wallet picks up the offer via OID4VCI pre-authorized flow
    issuance = await wallet_kit.run_preauth_issuance(offer_uri)
    assert issuance["success"], f"DTC issuance failed: {issuance.get('error')}"
    assert issuance["credentialCount"] >= 1

    cred = issuance["credentials"][0]
    logger.info(
        "[DTC] Credential received by wallet: format=%s, length=%d",
        cred.get("format", "unknown"),
        len(cred["credential"]),
    )

    return {
        "credential": cred["credential"],
        "format": cred.get("format", "mso_mdoc"),
        "issuance_result": issuance,
        "claims": claims,
    }


@pytest.fixture
async def dtc_vp_policy(
    authenticated_gateway_client: GatewayClient,
    dtc_test_org,
    dtc_mdoc_template,
):
    """Create and activate a DTC verification policy for wallet VP tests."""
    policy_data = TestDataBuilder.presentation_policy_dtc_verification(
        organization_id=dtc_test_org["id"],
        credential_template_id=dtc_mdoc_template["id"],
    )
    policy = await authenticated_gateway_client.create_presentation_policy(**policy_data)
    policy = await authenticated_gateway_client.activate_presentation_policy(
        policy["id"]
    )
    return policy


@pytest.fixture
async def dtc_identity_vp_policy(
    authenticated_gateway_client: GatewayClient,
    dtc_test_org,
    dtc_mdoc_template,
):
    """Create and activate a DTC identity-only verification policy (no biometrics)."""
    policy_data = TestDataBuilder.presentation_policy_dtc_identity_only(
        organization_id=dtc_test_org["id"],
        credential_template_id=dtc_mdoc_template["id"],
    )
    policy = await authenticated_gateway_client.create_presentation_policy(**policy_data)
    policy = await authenticated_gateway_client.activate_presentation_policy(
        policy["id"]
    )
    return policy


# ═══════════════════════════════════════════════════════════════════════════
# DTC Issuance via EUDI Wallet Kit
# ═══════════════════════════════════════════════════════════════════════════

class TestDtcWalletIssuance:
    """Verify DTC credential issuance via OID4VCI with EUDI Wallet Kit.

    Proves that the Marty issuer can produce a DTC credential in mDoc
    format that the EUDI wallet libraries can successfully receive.
    """

    @pytest.mark.asyncio
    async def test_dtc_issuance_via_wallet_kit(
        self,
        issued_dtc_credential,
    ):
        """DTC mDoc credential can be issued and received by EUDI wallet kit."""
        assert issued_dtc_credential["credential"], "Empty DTC credential"
        assert issued_dtc_credential["issuance_result"]["credentialCount"] >= 1
        logger.info(
            "[DTC] Issuance verified: format=%s, size=%d",
            issued_dtc_credential["format"],
            len(issued_dtc_credential["credential"]),
        )

    @pytest.mark.asyncio
    async def test_dtc_credential_is_mdoc_format(
        self,
        issued_dtc_credential,
    ):
        """Issued DTC credential is in mDoc format (CBOR-encoded)."""
        cred = issued_dtc_credential["credential"]
        # mDoc credentials are CBOR-encoded — should be substantial binary
        assert len(cred) > 100, f"DTC mDoc credential too short: {len(cred)}"
        logger.info("[DTC] mDoc format confirmed: length=%d", len(cred))

    @pytest.mark.asyncio
    async def test_dtc_issuance_with_different_holder(
        self,
        authenticated_gateway_client: GatewayClient,
        wallet_kit: EUDIWalletKitClient,
        dtc_test_org,
        dtc_mdoc_resources,
        dtc_mdoc_template,
    ):
        """Issue a DTC with different holder data and verify wallet receives it."""
        claims = TestDataBuilder.dtc_claims(
            given_name="ANNA",
            family_name="SCHMIDT",
            birth_date="1985-03-20",
        )

        result = await authenticated_gateway_client.issue_credential(
            organization_id=dtc_test_org["id"],
            credential_template_id=dtc_mdoc_template["id"],
            claims=claims,
        )

        issuance = await wallet_kit.run_preauth_issuance(result["credential_offer_uri"])
        assert issuance["success"], f"DTC issuance failed: {issuance.get('error')}"
        assert issuance["credentialCount"] >= 1
        logger.info("[DTC] Second holder issuance succeeded")


# ═══════════════════════════════════════════════════════════════════════════
# DTC OID4VP Authorization Request
# ═══════════════════════════════════════════════════════════════════════════

class TestDtcWalletAuthorizationRequest:
    """Verify OID4VP authorization request structure for DTC verification."""

    @pytest.mark.asyncio
    async def test_dtc_verification_produces_request_uri(
        self,
        authenticated_gateway_client: GatewayClient,
        dtc_vp_policy,
    ):
        """Starting a DTC verification flow produces an openid4vp:// URI."""
        flow = await authenticated_gateway_client.start_verification_flow(
            presentation_policy_id=dtc_vp_policy["id"],
        )

        assert "instance_id" in flow
        assert "request_uri" in flow
        assert flow["request_uri"].startswith("openid4vp://")
        logger.info("[DTC VP] Flow started: %s", flow["instance_id"])

    @pytest.mark.asyncio
    async def test_dtc_auth_request_has_credential_query(
        self,
        authenticated_gateway_client: GatewayClient,
        dtc_vp_policy,
    ):
        """DTC authorization request includes a DCQL query by default."""
        flow = await authenticated_gateway_client.start_verification_flow(
            presentation_policy_id=dtc_vp_policy["id"],
        )
        auth_req = await authenticated_gateway_client.get_verification_request(
            flow["instance_id"]
        )

        pd = auth_req.get("presentation_definition")
        dcql = auth_req.get("dcql_query")
        assert dcql, "Missing dcql_query"
        assert pd is None, "Default request should omit presentation_definition"
        assert "credentials" in dcql
        assert len(dcql["credentials"]) >= 1
        logger.info(
            "[DTC VP] DCQL query: credentials=%d",
            len(dcql["credentials"]),
        )


# ═══════════════════════════════════════════════════════════════════════════
# DTC Presentation via EUDI Wallet Kit
# ═══════════════════════════════════════════════════════════════════════════

class TestDtcWalletPresentation:
    """Full OID4VP flow for DTC: issue mDoc → present to verifier.

    Proves that a DTC credential issued by Marty can be presented back
    via the OID4VP direct_post flow using the EUDI Wallet Kit.
    """

    @pytest.mark.asyncio
    async def test_dtc_mdoc_vp_direct_post(
        self,
        authenticated_gateway_client: GatewayClient,
        wallet_kit: EUDIWalletKitClient,
        issued_dtc_credential,
        dtc_vp_policy,
    ):
        """Issue DTC mDoc, present to verifier via OID4VP direct-post."""
        credential = issued_dtc_credential["credential"]

        # Start verification flow
        flow = await authenticated_gateway_client.start_verification_flow(
            presentation_policy_id=dtc_vp_policy["id"],
        )
        instance_id = flow["instance_id"]

        # Parse authorization request
        auth_req = await authenticated_gateway_client.get_verification_request(
            instance_id
        )
        nonce = auth_req["nonce"]
        client_id = auth_req["client_id"]
        response_uri = auth_req["response_uri"]
        state = auth_req.get("state", instance_id)

        logger.info(
            "[DTC VP] Auth request: client_id=%s, nonce=%s",
            client_id, nonce,
        )

        # Build mDoc VP token via wallet harness
        vp_token = await wallet_kit.build_vp_token(
            credential=credential,
            audience=client_id,
            nonce=nonce,
            format="mso_mdoc",
        )
        assert vp_token, "VP token is empty"
        logger.info("[DTC VP] VP token built: length=%d", len(vp_token))

        presentation_submission = _presentation_submission_for_request(
            auth_req,
            "mso_mdoc",
        )

        # Direct-post to Marty's verifier endpoint
        result = await wallet_kit.direct_post_presentation(
            response_uri=response_uri,
            vp_token=vp_token,
            presentation_submission=presentation_submission,
            state=state,
        )

        logger.info(
            "[DTC VP] Direct-post result: success=%s, status=%s",
            result.get("success"),
            result.get("responseStatus"),
        )

        assert result["success"], (
            f"DTC VP direct-post failed: status={result.get('responseStatus')}, "
            f"body={(result.get('responseBody') or '')[:500]}"
        )

    @pytest.mark.asyncio
    async def test_dtc_identity_only_presentation(
        self,
        authenticated_gateway_client: GatewayClient,
        wallet_kit: EUDIWalletKitClient,
        issued_dtc_credential,
        dtc_identity_vp_policy,
    ):
        """Present DTC with identity-only policy (no biometrics)."""
        credential = issued_dtc_credential["credential"]

        flow = await authenticated_gateway_client.start_verification_flow(
            presentation_policy_id=dtc_identity_vp_policy["id"],
        )
        instance_id = flow["instance_id"]

        auth_req = await authenticated_gateway_client.get_verification_request(
            instance_id
        )

        vp_token = await wallet_kit.build_vp_token(
            credential=credential,
            audience=auth_req["client_id"],
            nonce=auth_req["nonce"],
            format="mso_mdoc",
        )

        presentation_submission = _presentation_submission_for_request(
            auth_req,
            "mso_mdoc",
        )

        result = await wallet_kit.direct_post_presentation(
            response_uri=auth_req["response_uri"],
            vp_token=vp_token,
            presentation_submission=presentation_submission,
            state=auth_req.get("state", instance_id),
        )

        assert result["success"], (
            f"DTC identity-only VP failed: status={result.get('responseStatus')}, "
            f"body={(result.get('responseBody') or '')[:500]}"
        )
        logger.info("[DTC VP] Identity-only presentation accepted")


# ═══════════════════════════════════════════════════════════════════════════
# End-to-End: DTC Issue + Present + Verify
# ═══════════════════════════════════════════════════════════════════════════

class TestDtcWalletEndToEnd:
    """Full DTC lifecycle: issuance → wallet presentation → verification.

    Exercises the complete ICAO Digital Travel Credential lifecycle
    using the EUDI Wallet Kit libraries — the same libraries that
    power the EUDI Reference Wallet mobile application.
    """

    @pytest.mark.asyncio
    async def test_dtc_full_lifecycle(
        self,
        authenticated_gateway_client: GatewayClient,
        wallet_kit: EUDIWalletKitClient,
        dtc_test_org,
        dtc_mdoc_resources,
    ):
        """Full DTC lifecycle: create template → issue → wallet receive → present → verify."""
        # 1. Create DTC template
        template_data = TestDataBuilder.dtc_template(
            organization_id=dtc_test_org["id"],
            name=f"DTC E2E ({uuid.uuid4().hex[:6]})",
            compliance_profile_id=dtc_mdoc_resources["compliance_profile_id"],
        )
        template_data.update({
            "issuer_profile_id": dtc_mdoc_resources["issuer_profile_id"],
            "revocation_profile_id": dtc_mdoc_resources["revocation_profile_id"],
        })
        template = await authenticated_gateway_client.create_credential_template(
            **template_data
        )
        logger.info("[DTC E2E] Template created: %s", template["id"])

        # 2. Issue DTC credential
        claims = TestDataBuilder.dtc_claims(
            given_name="HANS",
            family_name="GRUBER",
            birth_date="1970-11-25",
            document_number="PMC12B6677",
        )
        issuance = await authenticated_gateway_client.issue_credential(
            organization_id=dtc_test_org["id"],
            credential_template_id=template["id"],
            claims=claims,
        )
        offer_uri = issuance["credential_offer_uri"]
        logger.info("[DTC E2E] Credential offer created")

        # 3. Wallet receives DTC via OID4VCI
        wallet_result = await wallet_kit.run_preauth_issuance(offer_uri)
        assert wallet_result["success"], f"DTC issuance failed: {wallet_result.get('error')}"
        credential = wallet_result["credentials"][0]["credential"]
        logger.info("[DTC E2E] Credential received by wallet: length=%d", len(credential))

        # 4. Create and activate DTC verification policy
        policy_data = TestDataBuilder.presentation_policy_dtc_verification(
            organization_id=dtc_test_org["id"],
            credential_template_id=template["id"],
        )
        policy = await authenticated_gateway_client.create_presentation_policy(
            **policy_data
        )
        policy = await authenticated_gateway_client.activate_presentation_policy(
            policy["id"]
        )
        logger.info("[DTC E2E] Verification policy activated: %s", policy["id"])

        # 5. Start OID4VP verification flow
        flow = await authenticated_gateway_client.start_verification_flow(
            presentation_policy_id=policy["id"],
        )
        instance_id = flow["instance_id"]
        logger.info("[DTC E2E] Verification flow started: %s", instance_id)

        # 6. Parse authorization request
        auth_req = await authenticated_gateway_client.get_verification_request(
            instance_id
        )
        assert auth_req.get("response_type") == "vp_token"
        assert auth_req.get("nonce")

        # 7. Build mDoc VP token via wallet harness
        vp_token = await wallet_kit.build_vp_token(
            credential=credential,
            audience=auth_req["client_id"],
            nonce=auth_req["nonce"],
            format="mso_mdoc",
        )
        logger.info("[DTC E2E] VP token built: length=%d", len(vp_token))

        # 8. Direct-post to verifier
        presentation_submission = _presentation_submission_for_request(
            auth_req,
            "mso_mdoc",
        )

        post_result = await wallet_kit.direct_post_presentation(
            response_uri=auth_req["response_uri"],
            vp_token=vp_token,
            presentation_submission=presentation_submission,
            state=auth_req.get("state", instance_id),
        )
        assert post_result["success"], (
            f"DTC VP direct-post failed: {(post_result.get('responseBody') or '')[:500]}"
        )
        logger.info("[DTC E2E] VP token accepted by verifier")

        # 9. Check verification result
        result = await authenticated_gateway_client.get_verification_result(
            instance_id
        )
        logger.info("[DTC E2E] Verification result: status=%s", result.get("status"))

        status = result.get("status", "").upper()
        assert status in (
            "COMPLETED", "VERIFIED", "SUCCESS", "APPROVED",
        ), f"Unexpected final status: {status} — result: {json.dumps(result)[:500]}"

        logger.info(
            "[DTC E2E] ✓ Full DTC passport lifecycle passed: "
            "issue → wallet receive → present → verify"
        )
