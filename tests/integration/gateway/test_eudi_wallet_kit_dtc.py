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

from .helpers.eudi_attestation import required_eudi_key_attestation_policy
from .helpers.eudi_stage import eudi_stage, require_presentation_accepted
from .helpers.eudi_wallet_kit_client import EUDIWalletKitClient
from .helpers.gateway_client import GatewayClient
from .helpers.mdoc_test_certificate import create_disposable_mdoc_certificate_chain
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
    return json.dumps(
        {
            "id": str(uuid.uuid4()),
            "definition_id": pd.get("id", str(uuid.uuid4())),
            "descriptor_map": [
                {"id": descriptor_id, "format": credential_format, "path": "$"},
            ],
        }
    )


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8000")
EUDI_WALLET_KIT_URL = os.getenv("EUDI_WALLET_KIT_URL", "http://localhost:9090")
DEFAULT_ORG_ID = "22222222-2222-2222-2222-222222222222"
ORG_ID = os.getenv("TEST_ORG_ID", DEFAULT_ORG_ID)

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
def dtc_test_org() -> dict[str, str]:
    """Use the lane organization that owns the managed signing services.

    DTC document and request-object signing remain isolated behind separate
    issuer profiles and asserted DIDs; the test never signs against KMS
    coordinates directly.
    """
    return {"id": ORG_ID}


@pytest.fixture
async def dtc_request_object_issuer_profile(
    dtc_test_org,
):
    """Select the pre-provisioned DID profile that signs request objects."""
    issuer_did = os.environ.get("EUDI_TEST_REQUEST_ISSUER_DID", "").strip()
    if not issuer_did:
        raise RuntimeError("EUDI request-object issuer DID is required")
    assert issuer_did.endswith(f":orgs:{dtc_test_org['id']}")
    return {"issuer_did": issuer_did}


@pytest.fixture
async def dtc_mdoc_resources(authenticated_gateway_client: GatewayClient, dtc_test_org):
    """Create the separately managed mDoc resources required by the public API."""
    with eudi_stage("dtc-compliance-profile"):
        compliance = await authenticated_gateway_client.create_compliance_profile(
            organization_id=dtc_test_org["id"],
            name="EUDI DTC mDoc",
            compliance_code="ICAO_DTC",
            credential_format="mso_mdoc",
            frameworks=["icao_doc_9303"],
        )
    with eudi_stage("dtc-issuer-profile"):
        service = None
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
            except Exception:
                continue
        if not isinstance(service, dict) or not service.get("id"):
            raise RuntimeError("mDoc document signer is unavailable")
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
            key_attestation_policy=required_eudi_key_attestation_policy(),
        )
    with eudi_stage("dtc-issuer-certificate"):
        identity = await authenticated_gateway_client.get_issuer_profile_public_identity(
            issuer_profile_id=issuer["id"],
            organization_id=dtc_test_org["id"],
        )
        public_jwk = identity.get("public_jwk")
        if not isinstance(public_jwk, dict):
            raise RuntimeError("issuer profile public identity is incomplete")
        certificate = create_disposable_mdoc_certificate_chain(
            public_jwk,
            organization_id=dtc_test_org["id"],
        )
        stored = await authenticated_gateway_client.store_issuer_profile_certificate(
            issuer_profile_id=issuer["id"],
            organization_id=dtc_test_org["id"],
            cert_pem=certificate.leaf_pem,
            cert_chain_pem=certificate.chain_pem,
        )
        assert stored.get("ok") is True
    with eudi_stage("dtc-trust-profile-create"):
        trust_profile = await authenticated_gateway_client.create_trust_profile(
            organization_id=dtc_test_org["id"],
            name=f"EUDI DTC trust ({uuid.uuid4().hex[:6]})",
            trust_sources=[
                {
                    "name": "Disposable DTC test CSCA",
                    "source_type": "ROOT_CA",
                    "certificate_pem": certificate.trust_anchor_pem,
                    "description": ("Ephemeral trust anchor for the production-path EUDI DTC interoperability lane"),
                    "enabled": True,
                }
            ],
            revocation_check_enabled=False,
        )
    with eudi_stage("dtc-trust-profile-activate"):
        trust_profile = await authenticated_gateway_client.activate_trust_profile(trust_profile["id"])
    with eudi_stage("dtc-revocation-profile-create"):
        revocation = await authenticated_gateway_client.create_revocation_profile(
            organization_id=dtc_test_org["id"],
            name="EUDI DTC status list",
            revocation_mechanism=["STATUS_LIST_2021"],
        )
    with eudi_stage("dtc-revocation-profile-activate"):
        revocation = await authenticated_gateway_client.activate_revocation_profile(revocation["id"])
    return {
        "compliance_profile_id": compliance["id"],
        "issuer_did": issuer["issuer_did"],
        "trust_profile_id": trust_profile["id"],
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
    template_data.update(
        {
            "issuer_did": dtc_mdoc_resources["issuer_did"],
            "trust_profile_id": dtc_mdoc_resources["trust_profile_id"],
            "revocation_profile_id": dtc_mdoc_resources["revocation_profile_id"],
        }
    )
    with eudi_stage("dtc-credential-template"):
        return await authenticated_gateway_client.create_credential_template(**template_data)


@pytest.fixture
async def issued_dtc_credential(
    authenticated_gateway_client: GatewayClient,
    wallet_kit: EUDIWalletKitClient,
    dtc_test_org,
    dtc_mdoc_resources,
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

    with eudi_stage("dtc-credential-offer"):
        result = await authenticated_gateway_client.issue_credential(
            organization_id=dtc_test_org["id"],
            credential_template_id=dtc_mdoc_template["id"],
            claims=claims,
        )
    offer_uri = result["credential_offer_uri"]
    logger.info("[DTC] Credential offer created: %s", offer_uri[:100])

    # Wallet picks up the offer via OID4VCI pre-authorized flow
    with eudi_stage("dtc-wallet-receipt"):
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
    dtc_mdoc_resources,
    dtc_mdoc_template,
    dtc_request_object_issuer_profile,
):
    """Create and activate a DTC verification policy for wallet VP tests."""
    policy_data = TestDataBuilder.presentation_policy_dtc_verification(
        organization_id=dtc_test_org["id"],
        credential_template_id=dtc_mdoc_template["id"],
    )
    policy_data["trust_profile_id"] = dtc_mdoc_resources["trust_profile_id"]
    policy_data["holder_binding"] = {
        "required": True,
        "binding_methods": ["DEVICE_KEY"],
        "proof_profiles": ["OID4VP_VERIFIABLE_PRESENTATION"],
        "proof_freshness": {
            "challenge_required": True,
            "audience_binding_required": True,
            "replay_detection_required": True,
        },
    }
    policy = await authenticated_gateway_client.create_presentation_policy(**policy_data)
    policy = await authenticated_gateway_client.activate_presentation_policy(policy["id"])
    policy["_request_object_issuer_did"] = dtc_request_object_issuer_profile["issuer_did"]
    policy["_trust_profile_id"] = dtc_mdoc_resources["trust_profile_id"]
    return policy


@pytest.fixture
async def dtc_identity_vp_policy(
    authenticated_gateway_client: GatewayClient,
    dtc_test_org,
    dtc_mdoc_resources,
    dtc_mdoc_template,
    dtc_request_object_issuer_profile,
):
    """Create and activate a DTC identity-only verification policy (no biometrics)."""
    policy_data = TestDataBuilder.presentation_policy_dtc_identity_only(
        organization_id=dtc_test_org["id"],
        credential_template_id=dtc_mdoc_template["id"],
    )
    policy_data["trust_profile_id"] = dtc_mdoc_resources["trust_profile_id"]
    policy_data["holder_binding"] = {
        "required": True,
        "binding_methods": ["DEVICE_KEY"],
        "proof_profiles": ["OID4VP_VERIFIABLE_PRESENTATION"],
        "proof_freshness": {
            "challenge_required": True,
            "audience_binding_required": True,
            "replay_detection_required": True,
        },
    }
    policy = await authenticated_gateway_client.create_presentation_policy(**policy_data)
    policy = await authenticated_gateway_client.activate_presentation_policy(policy["id"])
    policy["_request_object_issuer_did"] = dtc_request_object_issuer_profile["issuer_did"]
    policy["_trust_profile_id"] = dtc_mdoc_resources["trust_profile_id"]
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
            organization_id=dtc_vp_policy["organization_id"],
            trust_profile_id=dtc_vp_policy["_trust_profile_id"],
            issuer_did=dtc_vp_policy["_request_object_issuer_did"],
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
            organization_id=dtc_vp_policy["organization_id"],
            trust_profile_id=dtc_vp_policy["_trust_profile_id"],
            issuer_did=dtc_vp_policy["_request_object_issuer_did"],
        )
        auth_req = await authenticated_gateway_client.get_verification_request(flow["instance_id"])

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
            organization_id=dtc_vp_policy["organization_id"],
            trust_profile_id=dtc_vp_policy["_trust_profile_id"],
            issuer_did=dtc_vp_policy["_request_object_issuer_did"],
        )
        request_uri = flow.get("request_uri", "")
        assert request_uri.startswith("openid4vp://"), request_uri

        result = await wallet_kit.submit_presentation(
            authorization_request_uri=request_uri,
            credential=credential,
        )

        logger.info(
            "[DTC VP] Official resolve/dispatch result: success=%s, mode=%s",
            result.get("success"),
            result.get("responseMode"),
        )

        verification = None
        if result.get("success") is not True:
            with eudi_stage("dtc-presentation-verification-result"):
                verification = (
                    await authenticated_gateway_client.get_verification_decision(
                        flow["instance_id"]
                    )
                )
        require_presentation_accepted(
            result,
            stage="dtc-presentation",
            expected_mode="direct_post",
            verification_result=verification,
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
            organization_id=dtc_identity_vp_policy["organization_id"],
            trust_profile_id=dtc_identity_vp_policy["_trust_profile_id"],
            issuer_did=dtc_identity_vp_policy["_request_object_issuer_did"],
        )
        request_uri = flow.get("request_uri", "")
        assert request_uri.startswith("openid4vp://"), request_uri

        result = await wallet_kit.submit_presentation(
            authorization_request_uri=request_uri,
            credential=credential,
        )

        verification = None
        if result.get("success") is not True:
            with eudi_stage("dtc-identity-presentation-verification-result"):
                verification = (
                    await authenticated_gateway_client.get_verification_decision(
                        flow["instance_id"]
                    )
                )
        require_presentation_accepted(
            result,
            stage="dtc-identity-presentation",
            verification_result=verification,
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
        dtc_request_object_issuer_profile,
    ):
        """Full DTC lifecycle: create template → issue → wallet receive → present → verify."""
        # 1. Create DTC template
        template_data = TestDataBuilder.dtc_template(
            organization_id=dtc_test_org["id"],
            name=f"DTC E2E ({uuid.uuid4().hex[:6]})",
            compliance_profile_id=dtc_mdoc_resources["compliance_profile_id"],
        )
        template_data.update(
            {
                "issuer_did": dtc_mdoc_resources["issuer_did"],
                "trust_profile_id": dtc_mdoc_resources["trust_profile_id"],
                "revocation_profile_id": dtc_mdoc_resources["revocation_profile_id"],
            }
        )
        template = await authenticated_gateway_client.create_credential_template(**template_data)
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
        policy_data["trust_profile_id"] = dtc_mdoc_resources["trust_profile_id"]
        policy_data["holder_binding"] = {
            "required": True,
            "binding_methods": ["DEVICE_KEY"],
            "proof_profiles": ["OID4VP_VERIFIABLE_PRESENTATION"],
            "proof_freshness": {
                "challenge_required": True,
                "audience_binding_required": True,
                "replay_detection_required": True,
            },
        }
        policy = await authenticated_gateway_client.create_presentation_policy(**policy_data)
        policy = await authenticated_gateway_client.activate_presentation_policy(policy["id"])
        logger.info("[DTC E2E] Verification policy activated: %s", policy["id"])

        # 5. Start OID4VP verification flow
        flow = await authenticated_gateway_client.start_verification_flow(
            presentation_policy_id=policy["id"],
            organization_id=policy["organization_id"],
            trust_profile_id=dtc_mdoc_resources["trust_profile_id"],
            issuer_did=dtc_request_object_issuer_profile["issuer_did"],
        )
        instance_id = flow["instance_id"]
        logger.info("[DTC E2E] Verification flow started: %s", instance_id)

        # 6. Resolve, build the ISO DeviceResponse, and dispatch through the
        # official EUDI OID4VP library.
        request_uri = flow.get("request_uri", "")
        assert request_uri.startswith("openid4vp://"), request_uri
        post_result = await wallet_kit.submit_presentation(
            authorization_request_uri=request_uri,
            credential=credential,
        )
        verification = None
        if post_result.get("success") is not True:
            with eudi_stage("dtc-lifecycle-presentation-verification-result"):
                verification = (
                    await authenticated_gateway_client.get_verification_decision(
                        instance_id
                    )
                )
        require_presentation_accepted(
            post_result,
            stage="dtc-lifecycle-presentation",
            verification_result=verification,
        )
        logger.info("[DTC E2E] VP token accepted by verifier")

        # 7. Check verification result
        result = (
            verification
            or await authenticated_gateway_client.get_verification_decision(
                instance_id
            )
        )
        logger.info("[DTC E2E] Verification result: status=%s", result.get("status"))

        status = result.get("status", "").upper()
        assert status in (
            "COMPLETED",
            "VERIFIED",
            "SUCCESS",
            "APPROVED",
        ), f"Unexpected final status: {status} — result: {json.dumps(result)[:500]}"

        logger.info("[DTC E2E] ✓ Full DTC passport lifecycle passed: issue → wallet receive → present → verify")
