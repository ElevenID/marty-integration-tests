"""
EUDI Wallet Kit OID4VP (Verifiable Presentations) Tests

Proves that Marty's OID4VP verification flow is compatible with the EUDI
Wallet Kit libraries.  Uses the same eudi-lib-jvm-openid4vp-kt library
that powers the EUDI Reference Wallet mobile application.

The test flow:
1. Issue an SD-JWT VC credential via Marty (OID4VCI) → received by EUDI wallet harness
2. Create and activate a presentation policy
3. Start a verification flow → Marty generates an OID4VP authorization request
4. Parse the authorization request JWT to extract nonce, state, response_uri
5. Build a VP token (SD-JWT + KB-JWT) via the EUDI wallet harness
6. Direct-post the VP token to Marty's submit endpoint
7. Verify the result — Marty accepts and evaluates the presentation

Run with:
    RUN_EUDI_TESTS=true pytest tests/integration/gateway/test_eudi_wallet_kit_vp.py -v

Environment variables
---------------------
GATEWAY_URL              Gateway base URL                (default: http://localhost:8000)
EUDI_WALLET_KIT_URL      Wallet kit harness URL          (default: http://localhost:9090)
RUN_EUDI_TESTS           Gate for EUDI tests             (default: false)
"""

from __future__ import annotations

import base64
import json
import logging
import os
import uuid
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from .helpers.eudi_wallet_kit_client import EUDIWalletKitClient
from .helpers.gateway_client import GatewayClient
from .helpers.mdoc_evidence import validate_issuer_signed_mdoc
from .helpers.mdoc_test_certificate import create_disposable_mdoc_certificate_chain

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8000")
EUDI_WALLET_KIT_URL = os.getenv("EUDI_WALLET_KIT_URL", "http://localhost:9090")
DEFAULT_ORG_ID = "22222222-2222-2222-2222-222222222222"
ORG_ID = os.getenv("TEST_ORG_ID", DEFAULT_ORG_ID)

MDL_CLAIMS = {
    "given_name": "Erika",
    "family_name": "Mustermann",
    "birth_date": "1986-03-15",
    "age_over_18": True,
    "age_over_21": True,
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
# Helpers
# ---------------------------------------------------------------------------


def _decode_jwt_payload(jwt_str: str) -> Dict[str, Any]:
    """Decode a JWT's payload (no verification) for test inspection."""
    parts = jwt_str.strip().split(".")
    if len(parts) != 3:
        raise ValueError(f"Expected 3-part JWT, got {len(parts)} parts")
    payload_b64 = parts[1]
    # Add padding
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
        payload_b64 += "=" * padding
    return json.loads(base64.urlsafe_b64decode(payload_b64))


def _extract_request_uri(openid4vp_uri: str) -> str:
    """Extract the inner HTTP request_uri from an openid4vp:// URI."""
    parsed = urlparse(openid4vp_uri)
    qs = parse_qs(parsed.query)
    request_uris = qs.get("request_uri", [])
    if not request_uris:
        raise ValueError(f"No request_uri in: {openid4vp_uri}")
    return request_uris[0]


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
                {
                    "id": descriptor_id,
                    "format": credential_format,
                    "path": "$",
                },
            ],
        }
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def wallet_kit() -> EUDIWalletKitClient:
    client = EUDIWalletKitClient(base_url=EUDI_WALLET_KIT_URL)
    yield client
    await client.close()


@pytest.fixture
def vp_test_org() -> dict[str, str]:
    """Use the lane organization that owns the managed signing services.

    The tests still create purpose-specific issuer profiles and assert their
    DIDs.  Only profile administration sees the KMS service binding; every
    request-object and credential signing operation goes through the profile.
    """
    return {"id": ORG_ID}


async def _resolve_signing_service(
    client: GatewayClient,
    organization_id: str,
    *,
    credential_format: str | None,
    key_purpose: str,
    algorithm: str,
) -> Dict[str, Any]:
    """Resolve the production signing service, allowing the configured fallback scope."""
    service = None
    resolution_error: Exception | None = None
    for candidate_organization_id in (organization_id, None):
        try:
            resolved = await client.resolve_signing_service(
                organization_id=candidate_organization_id,
                credential_format=credential_format,
                key_purpose=key_purpose,
                algorithm=algorithm,
            )
            candidate = resolved.get("service")
            if isinstance(candidate, dict) and candidate.get("id"):
                service = candidate
                break
        except Exception as exc:  # API reports an unavailable capability as 4xx.
            resolution_error = exc
    if not isinstance(service, dict) or not service.get("id"):
        raise RuntimeError(f"No signing service for {credential_format}/{key_purpose}: {resolution_error}")
    return service


async def _issuer_profile(
    client: GatewayClient,
    organization_id: str,
    *,
    credential_format: str | None,
    key_purpose: str,
    algorithm: str,
    name: str,
    service: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Create an issuer profile backed by Marty's configured signing service."""
    if service is None:
        service = await _resolve_signing_service(
            client,
            organization_id,
            credential_format=credential_format,
            key_purpose=key_purpose,
            algorithm=algorithm,
        )
    domain = os.getenv("PUBLIC_DOMAIN", "marty-oidf2.local")
    domain = domain.removeprefix("https://").removeprefix("http://").strip("/")
    return await client.create_issuer_profile(
        organization_id=organization_id,
        name=name,
        issuer_did=f"did:web:{domain.replace('/', ':')}:orgs:{organization_id}",
        signing_service_id=str(service["id"]),
        signing_key_reference=str(service.get("key_reference") or "") or None,
        key_purpose=key_purpose,
        status="active",
    )


@pytest.fixture
async def vp_request_object_issuer_profile(
    authenticated_gateway_client: GatewayClient,
    vp_test_org,
):
    """Create the tenant-local DID identity that signs OID4VP Request Objects."""
    return await _issuer_profile(
        authenticated_gateway_client,
        vp_test_org["id"],
        credential_format=None,
        key_purpose="oid4vp_request_signing",
        algorithm="ES256",
        name="EUDI VP Request Object issuer",
    )


@pytest.fixture
async def vp_sd_jwt_resources(authenticated_gateway_client: GatewayClient, vp_test_org):
    """Provision the current API resources for an SD-JWT test template."""
    compliance = await authenticated_gateway_client.create_compliance_profile(
        organization_id=vp_test_org["id"],
        name="EUDI VP SD-JWT",
        compliance_code="EUDI_PID",
        credential_format="sd_jwt_vc",
        frameworks=["eudi"],
    )
    issuer = await _issuer_profile(
        authenticated_gateway_client,
        vp_test_org["id"],
        credential_format="dc+sd-jwt",
        key_purpose="vc_jwt_issuer",
        algorithm="ES256",
        name="EUDI VP SD-JWT issuer",
    )
    revocation = await authenticated_gateway_client.create_revocation_profile(
        organization_id=vp_test_org["id"],
        name="EUDI VP status list",
        revocation_mechanism=["STATUS_LIST_2021"],
    )
    return {
        "compliance_profile_id": compliance["id"],
        "issuer_profile_id": issuer["id"],
        "revocation_profile_id": (await authenticated_gateway_client.activate_revocation_profile(revocation["id"]))[
            "id"
        ],
    }


@pytest.fixture
async def vp_mdoc_resources(authenticated_gateway_client: GatewayClient, vp_test_org):
    """Provision the mDoc-specific profile and document signer used in production."""
    compliance = await authenticated_gateway_client.create_compliance_profile(
        organization_id=vp_test_org["id"],
        name="EUDI VP mDoc",
        compliance_code="AAMVA_MDL",
        credential_format="mso_mdoc",
        frameworks=["aamva", "iso_18013_5"],
    )
    service = await _resolve_signing_service(
        authenticated_gateway_client,
        vp_test_org["id"],
        credential_format="mso_mdoc",
        key_purpose="mdoc_dsc",
        algorithm="ES256",
    )
    service_id = str(service["id"])
    key_reference = str(service.get("key_reference") or "") or None
    publication = await authenticated_gateway_client.publish_signing_service_jwks(
        service_id=service_id,
        organization_id=vp_test_org["id"],
        key_reference=key_reference,
    )
    public_jwk = publication.get("jwk")
    if not isinstance(public_jwk, dict):
        raise RuntimeError("Gateway did not return the mDoc signing service public JWK")
    certificate = create_disposable_mdoc_certificate_chain(
        public_jwk,
        organization_id=vp_test_org["id"],
    )
    stored = await authenticated_gateway_client.store_signing_service_certificate(
        service_id=service_id,
        organization_id=vp_test_org["id"],
        cert_pem=certificate.leaf_pem,
        cert_chain_pem=certificate.chain_pem,
    )
    assert stored.get("ok") is True
    # Republish after certificate attachment so the same public JWKS path that
    # relying parties use exposes the corresponding x5c chain.
    publication = await authenticated_gateway_client.publish_signing_service_jwks(
        service_id=service_id,
        organization_id=vp_test_org["id"],
        key_reference=key_reference,
    )
    published_jwk = publication.get("jwk")
    assert isinstance(published_jwk, dict)
    assert len(published_jwk.get("x5c") or []) == 2
    logger.info(
        "[mDoc] Attached disposable DSC %s with test trust anchor %s to service %s",
        certificate.leaf_sha256,
        certificate.trust_anchor_sha256,
        service_id,
    )
    issuer = await _issuer_profile(
        authenticated_gateway_client,
        vp_test_org["id"],
        credential_format="mso_mdoc",
        key_purpose="mdoc_dsc",
        algorithm="ES256",
        name="EUDI VP mDoc document signer",
        service=service,
    )
    revocation = await authenticated_gateway_client.create_revocation_profile(
        organization_id=vp_test_org["id"],
        name="EUDI VP mDoc status list",
        revocation_mechanism=["STATUS_LIST_2021"],
    )
    return {
        "compliance_profile_id": compliance["id"],
        "issuer_profile_id": issuer["id"],
        "revocation_profile_id": (await authenticated_gateway_client.activate_revocation_profile(revocation["id"]))[
            "id"
        ],
    }


@pytest.fixture
async def sd_jwt_dl_template(
    authenticated_gateway_client: GatewayClient,
    vp_test_org,
    vp_sd_jwt_resources,
):
    """SD-JWT driver's license template for VP testing."""
    return await authenticated_gateway_client.create_credential_template(
        organization_id=vp_test_org["id"],
        name="VP Test DL (SD-JWT)",
        credential_type="DriversLicense",
        vct="https://credentials.marty.dev/DriversLicense",
        supported_formats=["sd_jwt_vc"],
        claims=[
            {"name": "given_name", "type": "string", "display_name": "Given Name"},
            {"name": "family_name", "type": "string", "display_name": "Family Name"},
            {"name": "birth_date", "type": "string", "display_name": "Birth Date"},
            {"name": "age_over_18", "type": "boolean", "display_name": "Age Over 18"},
            {"name": "age_over_21", "type": "boolean", "display_name": "Age Over 21"},
        ],
        **vp_sd_jwt_resources,
    )


@pytest.fixture
async def mdl_mdoc_template(
    authenticated_gateway_client: GatewayClient,
    vp_test_org,
    vp_mdoc_resources,
):
    """mDL mDoc template for mDoc/mDL VP testing."""
    return await authenticated_gateway_client.create_credential_template(
        organization_id=vp_test_org["id"],
        name="VP Test mDL (mDoc)",
        credential_type="org.iso.18013.5.1.mDL",
        vct="org.iso.18013.5.1.mDL",
        supported_formats=["mdoc"],
        schema={
            "namespaces": {
                "org.iso.18013.5.1": {
                    "family_name": {"type": "string", "required": True},
                    "given_name": {"type": "string", "required": True},
                    "birth_date": {"type": "string", "format": "full-date", "required": True},
                    "issue_date": {"type": "string", "format": "full-date", "required": True},
                    "expiry_date": {"type": "string", "format": "full-date", "required": True},
                    "issuing_country": {"type": "string", "required": True},
                    "issuing_authority": {"type": "string", "required": True},
                    "document_number": {"type": "string", "required": True},
                    "driving_privileges": {"type": "array", "required": True},
                    "un_distinguishing_sign": {"type": "string", "required": True},
                    "age_over_18": {"type": "boolean", "required": False},
                    "age_over_21": {"type": "boolean", "required": False},
                }
            }
        },
        claims=[
            {"name": "given_name", "display_name": "Given Name", "required": True},
            {"name": "family_name", "display_name": "Family Name", "required": True},
            {"name": "birth_date", "display_name": "Birth Date", "required": True},
        ],
        **vp_mdoc_resources,
    )


@pytest.fixture
async def issued_sd_jwt_credential(
    authenticated_gateway_client: GatewayClient,
    wallet_kit: EUDIWalletKitClient,
    vp_test_org,
    sd_jwt_dl_template,
) -> Dict[str, Any]:
    """Issue an SD-JWT VC via Marty and receive it through the EUDI wallet harness.

    Returns a dict with keys: credential, format, issuance_result.
    """
    # Issue credential through Marty
    result = await authenticated_gateway_client.issue_credential(
        organization_id=vp_test_org["id"],
        credential_template_id=sd_jwt_dl_template["id"],
        claims={**MDL_CLAIMS, "test_id": uuid.uuid4().hex[:8]},
    )
    offer_uri = result["credential_offer_uri"]

    # Receive credential through the EUDI wallet kit
    issuance = await wallet_kit.run_preauth_issuance(offer_uri)
    assert issuance["success"], f"Issuance failed: {issuance.get('error')}"
    assert issuance["credentialCount"] >= 1

    cred = issuance["credentials"][0]
    logger.info(
        "[VP] Issued SD-JWT credential: format=%s, length=%d",
        cred.get("format", "unknown"),
        len(cred["credential"]),
    )

    return {
        "credential": cred["credential"],
        "format": cred.get("format", "dc+sd-jwt"),
        "issuance_result": issuance,
    }


@pytest.fixture
async def issued_mdoc_credential(
    authenticated_gateway_client: GatewayClient,
    wallet_kit: EUDIWalletKitClient,
    vp_test_org,
    mdl_mdoc_template,
) -> Dict[str, Any]:
    """Issue an mDoc mDL via Marty and receive it through the EUDI wallet harness."""
    mdoc_claims = {
        "given_name": "Erika",
        "family_name": "Mustermann",
        "birth_date": "1986-03-15",
        "issue_date": "2024-01-01",
        "expiry_date": "2029-01-01",
        "issuing_country": "US",
        "issuing_authority": "State DMV",
        "document_number": "DL-2024-001",
        "driving_privileges": [{"vehicle_category_code": "B", "issue_date": "2020-01-01"}],
        "un_distinguishing_sign": "USA",
        "age_over_18": True,
        "age_over_21": True,
    }

    result = await authenticated_gateway_client.issue_credential(
        organization_id=vp_test_org["id"],
        credential_template_id=mdl_mdoc_template["id"],
        claims=mdoc_claims,
    )
    offer_uri = result["credential_offer_uri"]

    issuance = await wallet_kit.run_preauth_issuance(offer_uri)
    assert issuance["success"], f"mDoc issuance failed: {issuance.get('error')}"
    assert issuance["credentialCount"] >= 1

    cred = issuance["credentials"][0]
    logger.info(
        "[VP] Issued mDoc credential: format=%s, length=%d",
        cred.get("format", "unknown"),
        len(cred["credential"]),
    )

    return {
        "credential": cred["credential"],
        "format": cred.get("format", "mso_mdoc"),
        "claims": mdoc_claims,
        "issuance_result": issuance,
    }


@pytest.fixture
async def vp_age_policy(
    authenticated_gateway_client: GatewayClient,
    vp_test_org,
    sd_jwt_dl_template,
    vp_request_object_issuer_profile,
):
    """Create and activate an age verification policy for VP tests."""
    policy = await authenticated_gateway_client.create_presentation_policy(
        organization_id=vp_test_org["id"],
        name=f"VP Age 21+ ({uuid.uuid4().hex[:6]})",
        purpose="Verify holder is at least 21 years old",
        credential_requirements=[
            {
                "credential_template_id": sd_jwt_dl_template["id"],
                "display_name": "Driver's License",
                "requested_claims": [
                    {
                        "claim_name": "age_over_21",
                        "display_name": "Age Over 21",
                        "required": True,
                    },
                ],
            },
        ],
    )
    policy = await authenticated_gateway_client.activate_presentation_policy(policy["id"])
    policy["_request_object_issuer_profile_id"] = vp_request_object_issuer_profile["id"]
    policy["_request_object_issuer_did"] = vp_request_object_issuer_profile["issuer_did"]
    return policy


@pytest.fixture
async def vp_identity_policy(
    authenticated_gateway_client: GatewayClient,
    vp_test_org,
    sd_jwt_dl_template,
    vp_request_object_issuer_profile,
):
    """Create and activate an identity verification policy for VP tests."""
    policy = await authenticated_gateway_client.create_presentation_policy(
        organization_id=vp_test_org["id"],
        name=f"VP Identity ({uuid.uuid4().hex[:6]})",
        purpose="Verify holder identity",
        credential_requirements=[
            {
                "credential_template_id": sd_jwt_dl_template["id"],
                "display_name": "Driver's License",
                "requested_claims": [
                    {"claim_name": "given_name", "display_name": "Given Name", "required": True},
                    {"claim_name": "family_name", "display_name": "Family Name", "required": True},
                    {"claim_name": "birth_date", "display_name": "Birth Date", "required": True},
                ],
            },
        ],
    )
    policy = await authenticated_gateway_client.activate_presentation_policy(policy["id"])
    policy["_request_object_issuer_profile_id"] = vp_request_object_issuer_profile["id"]
    policy["_request_object_issuer_did"] = vp_request_object_issuer_profile["issuer_did"]
    return policy


@pytest.fixture
async def vp_mdoc_policy(
    authenticated_gateway_client: GatewayClient,
    vp_test_org,
    mdl_mdoc_template,
    vp_request_object_issuer_profile,
):
    """Create and activate an mDoc mDL verification policy."""
    policy = await authenticated_gateway_client.create_presentation_policy(
        organization_id=vp_test_org["id"],
        name=f"VP mDL mDoc ({uuid.uuid4().hex[:6]})",
        purpose="Verify mDL via mDoc",
        credential_requirements=[
            {
                "credential_template_id": mdl_mdoc_template["id"],
                "display_name": "Mobile Driver's License",
                "requested_claims": [
                    {"claim_name": "given_name", "display_name": "Given Name", "required": True},
                    {"claim_name": "family_name", "display_name": "Family Name", "required": True},
                    {"claim_name": "birth_date", "display_name": "Birth Date", "required": True},
                ],
            },
        ],
    )
    policy = await authenticated_gateway_client.activate_presentation_policy(policy["id"])
    policy["_request_object_issuer_profile_id"] = vp_request_object_issuer_profile["id"]
    policy["_request_object_issuer_did"] = vp_request_object_issuer_profile["issuer_did"]
    return policy


# ═══════════════════════════════════════════════════════════════════════════
# Authorization Request Structure
# ═══════════════════════════════════════════════════════════════════════════


class TestOID4VPAuthorizationRequest:
    """Verify Marty's OID4VP authorization request is well-formed.

    The EUDI Wallet Kit validates the authorization request JWT structure.
    These tests ensure the request_uri, JWT payload, and presentation
    definition conform to OID4VP 1.0 Final.
    """

    @pytest.mark.asyncio
    async def test_verification_flow_returns_request_uri(
        self,
        authenticated_gateway_client: GatewayClient,
        vp_age_policy,
    ):
        """Starting a verification flow produces an openid4vp:// request URI."""
        flow = await authenticated_gateway_client.start_verification_flow(
            presentation_policy_id=vp_age_policy["id"],
            organization_id=vp_age_policy["organization_id"],
            issuer_profile_id=vp_age_policy["_request_object_issuer_profile_id"],
            issuer_did=vp_age_policy["_request_object_issuer_did"],
        )

        assert "instance_id" in flow, f"Missing instance_id: {flow}"
        assert "request_uri" in flow, f"Missing request_uri: {flow}"

        request_uri = flow["request_uri"]
        assert request_uri.startswith("openid4vp://"), f"Expected openid4vp:// scheme, got: {request_uri}"
        logger.info("[VP] Flow started: instance=%s", flow["instance_id"])

    @pytest.mark.asyncio
    async def test_authorization_request_jwt_structure(
        self,
        authenticated_gateway_client: GatewayClient,
        vp_age_policy,
    ):
        """Authorization request JWT has required OID4VP fields."""
        flow = await authenticated_gateway_client.start_verification_flow(
            presentation_policy_id=vp_age_policy["id"],
            organization_id=vp_age_policy["organization_id"],
            issuer_profile_id=vp_age_policy["_request_object_issuer_profile_id"],
            issuer_did=vp_age_policy["_request_object_issuer_did"],
        )
        instance_id = flow["instance_id"]

        # Fetch the authorization request (decoded JWT payload)
        auth_req = await authenticated_gateway_client.get_verification_request(instance_id)

        # OID4VP 1.0 Final §5: required fields
        assert auth_req.get("response_type") == "vp_token"
        assert auth_req.get("response_mode") == "direct_post"
        assert auth_req.get("client_id"), "Missing client_id"
        assert auth_req.get("nonce"), "Missing nonce"
        assert auth_req.get("response_uri"), "Missing response_uri"

        # OID4VP 1.0 Final uses a client identifier prefix. The old separate
        # client_id_scheme parameter is intentionally absent.
        assert "client_id_scheme" not in auth_req
        assert auth_req["client_id"].startswith("x509_hash:"), (
            f"EUDI runs must use the HAIP x509_hash client identifier: {auth_req['client_id']}"
        )

        logger.info(
            "[VP] Auth request: client_id=%s, nonce=%s, response_mode=%s",
            auth_req["client_id"],
            auth_req["nonce"],
            auth_req["response_mode"],
        )

    @pytest.mark.asyncio
    async def test_authorization_request_has_credential_query(
        self,
        authenticated_gateway_client: GatewayClient,
        vp_age_policy,
    ):
        """Authorization request includes a DCQL query by default."""
        flow = await authenticated_gateway_client.start_verification_flow(
            presentation_policy_id=vp_age_policy["id"],
            organization_id=vp_age_policy["organization_id"],
            issuer_profile_id=vp_age_policy["_request_object_issuer_profile_id"],
            issuer_did=vp_age_policy["_request_object_issuer_did"],
        )
        auth_req = await authenticated_gateway_client.get_verification_request(flow["instance_id"])

        pd = auth_req.get("presentation_definition")
        dcql = auth_req.get("dcql_query")
        assert dcql, "Missing dcql_query"
        assert pd is None, "Default request should omit presentation_definition"
        assert "credentials" in dcql, "dcql_query missing credentials"
        assert len(dcql["credentials"]) >= 1, "dcql_query credentials empty"
        logger.info(
            "[VP] DCQL query: credentials=%d",
            len(dcql["credentials"]),
        )


# ═══════════════════════════════════════════════════════════════════════════
# SD-JWT VP Token Presentation
# ═══════════════════════════════════════════════════════════════════════════


class TestOID4VPSdJwtPresentation:
    """Full OID4VP flow: issue SD-JWT → present to verifier.

    These tests prove the complete verifiable presentation cycle:
    SD-JWT VC issuance via EUDI wallet kit → VP token construction
    with KB-JWT → form-encoded direct_post to Marty → verification.
    """

    @pytest.mark.asyncio
    async def test_official_library_resolves_and_dispatches_sd_jwt(
        self,
        authenticated_gateway_client: GatewayClient,
        wallet_kit: EUDIWalletKitClient,
        issued_sd_jwt_credential,
        vp_age_policy,
        record_property,
    ):
        """The pinned EUDI OID4VP library resolves and dispatches the real request."""
        record_property("evidence_id", "eudi.oid4vp.haip.resolve-dispatch.v1")
        flow = await authenticated_gateway_client.start_verification_flow(
            presentation_policy_id=vp_age_policy["id"],
            organization_id=vp_age_policy["organization_id"],
            issuer_profile_id=vp_age_policy["_request_object_issuer_profile_id"],
            issuer_did=vp_age_policy["_request_object_issuer_did"],
            oid4vp_profile="haip",
            request_uri_method="get",
        )
        request_uri = flow.get("request_uri", "")
        assert request_uri.startswith("openid4vp://"), request_uri
        outer = parse_qs(urlparse(request_uri).query, keep_blank_values=True)
        assert len(outer.get("client_id", [])) == 1, outer
        assert outer["client_id"][0].startswith("x509_hash:"), outer
        assert len(outer.get("request_uri", [])) == 1, outer
        # OID4VP's default GET retrieval is represented by omission; only POST
        # places request_uri_method in the outer authorization request.
        assert "request_uri_method" not in outer, outer

        signed_request = await authenticated_gateway_client.get_verification_request(flow["instance_id"])
        assert signed_request["client_id"] == outer["client_id"][0]
        assert signed_request["response_mode"] == "direct_post.jwt"
        assert signed_request["response_type"] == "vp_token"

        result = await wallet_kit.submit_presentation(
            authorization_request_uri=request_uri,
            credential=issued_sd_jwt_credential["credential"],
        )
        assert result["success"], result.get("error")
        assert result["responseMode"] == "direct_post.jwt"
        assert result["verifierAccepted"] is True

    @pytest.mark.asyncio
    async def test_unbound_credential_is_rejected_before_presentation(
        self,
        wallet_kit: EUDIWalletKitClient,
        record_property,
    ):
        """A credential without its issuance proof key cannot get a fake KB-JWT."""
        record_property(
            "evidence_id",
            "eudi.sd-jwt.missing-holder-binding-key.v1",
        )
        with pytest.raises(httpx.HTTPStatusError) as failure:
            await wallet_kit.build_vp_token(
                credential="unbound.header.signature~",
                audience="did:web:verifier.example",
                nonce="negative-holder-binding-test",
            )
        assert failure.value.response.status_code == 422
        assert failure.value.response.json()["error"] == "missing_holder_binding_key"

    @pytest.mark.asyncio
    async def test_sd_jwt_vp_direct_post(
        self,
        authenticated_gateway_client: GatewayClient,
        wallet_kit: EUDIWalletKitClient,
        issued_sd_jwt_credential,
        vp_age_policy,
    ):
        """Issue SD-JWT VC, build VP token with KB-JWT, direct-post to verifier."""
        credential = issued_sd_jwt_credential["credential"]

        # Start verification flow
        flow = await authenticated_gateway_client.start_verification_flow(
            presentation_policy_id=vp_age_policy["id"],
            organization_id=vp_age_policy["organization_id"],
            issuer_profile_id=vp_age_policy["_request_object_issuer_profile_id"],
            issuer_did=vp_age_policy["_request_object_issuer_did"],
        )
        instance_id = flow["instance_id"]

        # Parse authorization request to get nonce, client_id, response_uri, state
        auth_req = await authenticated_gateway_client.get_verification_request(instance_id)
        nonce = auth_req["nonce"]
        client_id = auth_req["client_id"]
        response_uri = auth_req["response_uri"]
        state = auth_req.get("state", instance_id)

        logger.info(
            "[VP] Auth request parsed: client_id=%s, nonce=%s",
            client_id,
            nonce,
        )

        # Build VP token using the wallet harness (adds KB-JWT with nonce binding)
        vp_token = await wallet_kit.build_vp_token(
            credential=credential,
            audience=client_id,
            nonce=nonce,
            format="dc+sd-jwt",
        )
        assert vp_token, "VP token is empty"
        assert "~" in vp_token, "VP token should contain SD-JWT disclosures"

        logger.info("[VP] VP token built: length=%d", len(vp_token))

        presentation_submission = _presentation_submission_for_request(
            auth_req,
            "dc+sd-jwt",
        )

        # Direct-post VP token to Marty's submit endpoint (form-encoded)
        result = await wallet_kit.direct_post_presentation(
            response_uri=response_uri,
            vp_token=vp_token,
            presentation_submission=presentation_submission,
            state=state,
        )

        logger.info(
            "[VP] Direct-post result: success=%s, status=%s, body=%s",
            result.get("success"),
            result.get("responseStatus"),
            str(result.get("responseBody", ""))[:200],
        )

        assert result["success"], (
            f"Direct-post failed: {result.get('error')} "
            f"(status={result.get('responseStatus')}, "
            f"body={(result.get('responseBody') or '')[:500]})"
        )

    @pytest.mark.asyncio
    async def test_sd_jwt_vp_identity_claims(
        self,
        authenticated_gateway_client: GatewayClient,
        wallet_kit: EUDIWalletKitClient,
        issued_sd_jwt_credential,
        vp_identity_policy,
    ):
        """Present SD-JWT VC with identity claims (name + DOB) to verifier."""
        credential = issued_sd_jwt_credential["credential"]

        flow = await authenticated_gateway_client.start_verification_flow(
            presentation_policy_id=vp_identity_policy["id"],
            organization_id=vp_identity_policy["organization_id"],
            issuer_profile_id=vp_identity_policy["_request_object_issuer_profile_id"],
            issuer_did=vp_identity_policy["_request_object_issuer_did"],
        )
        instance_id = flow["instance_id"]

        auth_req = await authenticated_gateway_client.get_verification_request(instance_id)

        vp_token = await wallet_kit.build_vp_token(
            credential=credential,
            audience=auth_req["client_id"],
            nonce=auth_req["nonce"],
            format="dc+sd-jwt",
        )

        presentation_submission = _presentation_submission_for_request(
            auth_req,
            "dc+sd-jwt",
        )

        result = await wallet_kit.direct_post_presentation(
            response_uri=auth_req["response_uri"],
            vp_token=vp_token,
            presentation_submission=presentation_submission,
            state=auth_req.get("state", instance_id),
        )

        assert result["success"], (
            f"Identity VP failed: status={result.get('responseStatus')}, "
            f"body={(result.get('responseBody') or '')[:500]}"
        )

        logger.info("[VP] Identity presentation accepted")

    @pytest.mark.asyncio
    async def test_sd_jwt_vp_verification_result(
        self,
        authenticated_gateway_client: GatewayClient,
        wallet_kit: EUDIWalletKitClient,
        issued_sd_jwt_credential,
        vp_age_policy,
    ):
        """After VP submission, the verification result is retrievable."""
        credential = issued_sd_jwt_credential["credential"]

        flow = await authenticated_gateway_client.start_verification_flow(
            presentation_policy_id=vp_age_policy["id"],
            organization_id=vp_age_policy["organization_id"],
            issuer_profile_id=vp_age_policy["_request_object_issuer_profile_id"],
            issuer_did=vp_age_policy["_request_object_issuer_did"],
        )
        instance_id = flow["instance_id"]

        auth_req = await authenticated_gateway_client.get_verification_request(instance_id)

        vp_token = await wallet_kit.build_vp_token(
            credential=credential,
            audience=auth_req["client_id"],
            nonce=auth_req["nonce"],
        )

        presentation_submission = _presentation_submission_for_request(
            auth_req,
            "dc+sd-jwt",
        )

        await wallet_kit.direct_post_presentation(
            response_uri=auth_req["response_uri"],
            vp_token=vp_token,
            presentation_submission=presentation_submission,
            state=auth_req.get("state", instance_id),
        )

        # Poll for the verification result
        result = await authenticated_gateway_client.get_verification_result(instance_id)
        logger.info("[VP] Verification result: %s", json.dumps(result, indent=2)[:500])

        status = result.get("status", "").upper()
        assert status in (
            "COMPLETED",
            "VERIFIED",
            "SUCCESS",
            "APPROVED",
        ), f"Unexpected verification status: {status}"


# ═══════════════════════════════════════════════════════════════════════════
# mDoc/mDL Credential Issuance
# ═══════════════════════════════════════════════════════════════════════════


class TestMDocIssuance:
    """Verify mDoc/mDL credential issuance via the EUDI Wallet Kit.

    mDoc (ISO 18013-5) is the standard format for mobile driver's licenses.
    These tests verify that Marty can issue mDL credentials in mso_mdoc
    format and the EUDI wallet kit can receive them.

    """

    @pytest.mark.asyncio
    async def test_mdoc_credential_issuance(
        self,
        issued_mdoc_credential,
        record_property,
    ):
        """The EUDI OID4VCI client receives a signed, digest-bound ISO mDL."""
        record_property("evidence_id", "eudi.oid4vci.mdoc-issuance.v1")
        evidence = validate_issuer_signed_mdoc(
            issued_mdoc_credential["credential"],
            expected_doc_type="org.iso.18013.5.1.mDL",
            expected_namespace="org.iso.18013.5.1",
            expected_claims=issued_mdoc_credential["claims"],
        )
        logger.info(
            "[mDoc] Verified credential: docType=%s, cert=%s, length=%d",
            evidence["doc_type"],
            evidence["certificate_sha256"],
            len(issued_mdoc_credential["credential"]),
        )

    @pytest.mark.asyncio
    async def test_mdoc_credential_format(
        self,
        issued_mdoc_credential,
    ):
        """The independent parser rejects format labels as proof and inspects bytes."""
        evidence = validate_issuer_signed_mdoc(
            issued_mdoc_credential["credential"],
            expected_doc_type="org.iso.18013.5.1.mDL",
            expected_namespace="org.iso.18013.5.1",
            expected_claims=issued_mdoc_credential["claims"],
        )
        assert evidence["cose_algorithm"] == -7


# ═══════════════════════════════════════════════════════════════════════════
# mDoc/mDL VP Presentation
# ═══════════════════════════════════════════════════════════════════════════


class TestMDocPresentation:
    """mDoc/mDL presentation flow.

    Tests issuing an mDoc credential and presenting it back to Marty
    via the OID4VP direct_post flow.
    """

    @pytest.mark.asyncio
    async def test_mdoc_vp_direct_post(
        self,
        authenticated_gateway_client: GatewayClient,
        wallet_kit: EUDIWalletKitClient,
        issued_mdoc_credential,
        vp_mdoc_policy,
    ):
        """Issue mDoc mDL, present to verifier via OID4VP direct-post."""
        credential = issued_mdoc_credential["credential"]

        flow = await authenticated_gateway_client.start_verification_flow(
            presentation_policy_id=vp_mdoc_policy["id"],
            organization_id=vp_mdoc_policy["organization_id"],
            issuer_profile_id=vp_mdoc_policy["_request_object_issuer_profile_id"],
            issuer_did=vp_mdoc_policy["_request_object_issuer_did"],
        )
        instance_id = flow["instance_id"]

        auth_req = await authenticated_gateway_client.get_verification_request(instance_id)

        # For mDoc, the VP token is the raw credential (no KB-JWT wrapping)
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

        logger.info(
            "[mDoc VP] Direct-post result: success=%s, status=%s",
            result.get("success"),
            result.get("responseStatus"),
        )

        assert result["success"], (
            f"mDoc VP direct-post failed: status={result.get('responseStatus')}, "
            f"body={(result.get('responseBody') or '')[:500]}"
        )


# ═══════════════════════════════════════════════════════════════════════════
# End-to-End: Issue + Present + Verify
# ═══════════════════════════════════════════════════════════════════════════


class TestEndToEndIssuanceAndPresentation:
    """Full lifecycle: credential issuance → wallet presentation → verification.

    These tests exercise the complete identity credential lifecycle
    using the same EUDI Wallet Kit libraries as the Reference Wallet.
    """

    @pytest.mark.asyncio
    async def test_sd_jwt_full_lifecycle(
        self,
        authenticated_gateway_client: GatewayClient,
        wallet_kit: EUDIWalletKitClient,
        vp_test_org,
        vp_sd_jwt_resources,
        vp_request_object_issuer_profile,
    ):
        """Full SD-JWT lifecycle: create template → issue → present → verify."""
        # 1. Create credential template
        template = await authenticated_gateway_client.create_credential_template(
            organization_id=vp_test_org["id"],
            name=f"Lifecycle Test ({uuid.uuid4().hex[:6]})",
            credential_type="IdentityCredential",
            vct="https://credentials.marty.dev/IdentityCredential",
            supported_formats=["sd_jwt_vc"],
            claims=[
                {"name": "given_name", "type": "string", "display_name": "Given Name"},
                {"name": "family_name", "type": "string", "display_name": "Family Name"},
                {"name": "birth_date", "type": "string", "display_name": "Birth Date"},
            ],
            **vp_sd_jwt_resources,
        )
        logger.info("[E2E] Template created: %s", template["id"])

        # 2. Issue credential
        issuance = await authenticated_gateway_client.issue_credential(
            organization_id=vp_test_org["id"],
            credential_template_id=template["id"],
            claims={
                "given_name": "Alice",
                "family_name": "Wonderland",
                "birth_date": "1995-06-15",
            },
        )
        offer_uri = issuance["credential_offer_uri"]
        logger.info("[E2E] Credential offer created")

        # 3. Receive credential via EUDI wallet kit
        wallet_result = await wallet_kit.run_preauth_issuance(offer_uri)
        assert wallet_result["success"], f"Issuance failed: {wallet_result.get('error')}"
        credential = wallet_result["credentials"][0]["credential"]
        logger.info("[E2E] Credential received via EUDI wallet kit")

        # 4. Create and activate presentation policy
        policy = await authenticated_gateway_client.create_presentation_policy(
            organization_id=vp_test_org["id"],
            name=f"E2E Policy ({uuid.uuid4().hex[:6]})",
            purpose="End-to-end test",
            credential_requirements=[
                {
                    "credential_template_id": template["id"],
                    "display_name": "Identity Credential",
                    "requested_claims": [
                        {"claim_name": "given_name", "display_name": "Given Name", "required": True},
                        {"claim_name": "family_name", "display_name": "Family Name", "required": True},
                    ],
                },
            ],
        )
        policy = await authenticated_gateway_client.activate_presentation_policy(policy["id"])
        logger.info("[E2E] Policy created and activated: %s", policy["id"])

        # 5. Start verification flow
        flow = await authenticated_gateway_client.start_verification_flow(
            presentation_policy_id=policy["id"],
            organization_id=policy["organization_id"],
            issuer_profile_id=vp_request_object_issuer_profile["id"],
            issuer_did=vp_request_object_issuer_profile["issuer_did"],
        )
        instance_id = flow["instance_id"]
        logger.info("[E2E] Verification flow started: %s", instance_id)

        # 6. Parse authorization request
        auth_req = await authenticated_gateway_client.get_verification_request(instance_id)
        assert auth_req.get("response_type") == "vp_token"
        assert auth_req.get("nonce")

        # 7. Build VP token with KB-JWT via wallet harness
        vp_token = await wallet_kit.build_vp_token(
            credential=credential,
            audience=auth_req["client_id"],
            nonce=auth_req["nonce"],
        )
        logger.info("[E2E] VP token built: length=%d", len(vp_token))

        # 8. Direct-post to verifier
        presentation_submission = _presentation_submission_for_request(
            auth_req,
            "dc+sd-jwt",
        )

        post_result = await wallet_kit.direct_post_presentation(
            response_uri=auth_req["response_uri"],
            vp_token=vp_token,
            presentation_submission=presentation_submission,
            state=auth_req.get("state", instance_id),
        )
        assert post_result["success"], f"VP direct-post failed: {(post_result.get('responseBody') or '')[:500]}"
        logger.info("[E2E] VP token accepted by verifier")

        # 9. Check verification result
        result = await authenticated_gateway_client.get_verification_result(instance_id)
        logger.info(
            "[E2E] Verification result: status=%s",
            result.get("status"),
        )

        status = result.get("status", "").upper()
        assert status in (
            "COMPLETED",
            "VERIFIED",
            "SUCCESS",
            "APPROVED",
        ), f"Unexpected final status: {status} — full result: {json.dumps(result)[:500]}"

        logger.info("[E2E] ✓ Full SD-JWT lifecycle passed: issue → present → verify")
