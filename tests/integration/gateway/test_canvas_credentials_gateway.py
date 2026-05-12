"""Gateway integration tests for signed Canvas credential events."""

from __future__ import annotations

import base64
import json
import os
import uuid
from typing import Any

import pytest

from .helpers.canvas_simulator import CanvasSimulator
from .helpers.gateway_client import GatewayClient, GatewayClientError
from .helpers.oid4vc_wallet_client import GOOGLE_WALLET_PROFILE, OID4VCIWalletClient


GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8000")
CANVAS_SHARED_SECRET = os.getenv("CANVAS_CREDENTIALS_SHARED_SECRET", "")
pytestmark = [pytest.mark.integration]


def _b64url_decode(value: str) -> bytes:
    padding = 4 - len(value) % 4
    if padding != 4:
        value += "=" * padding
    return base64.urlsafe_b64decode(value)


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _load_marty_rs():
    try:
        from marty_rs import _marty_rs

        return _marty_rs
    except ImportError:
        import _marty_rs

        return _marty_rs


def _build_lti_launch_material(
    *,
    issuer: str,
    client_id: str,
    deployment_id: str,
    nonce: str,
) -> tuple[str, dict[str, Any]]:
    marty_rs = _load_marty_rs()
    secret_key, public_key = marty_rs.generate_ed25519_key()
    kid = f"canvas-lti-{uuid.uuid4().hex[:8]}"
    header = {"alg": "EdDSA", "typ": "JWT", "kid": kid}
    claims = {
        "iss": issuer,
        "sub": "canvas-user-123",
        "aud": [client_id],
        "exp": 4102444800,
        "iat": 1700000000,
        "nonce": nonce,
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": deployment_id,
        "https://purl.imsglobal.org/spec/lti/claim/context": {
            "id": "course-101",
            "label": "PORTABLE101",
            "title": "Portable Trust 101",
        },
        "https://purl.imsglobal.org/spec/lti/claim/roles": ["Learner"],
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiResourceLinkRequest",
        "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
        "https://purl.imsglobal.org/spec/lti/claim/target_link_uri": "https://tool.example.edu/launch",
    }
    encoded_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    encoded_claims = _b64url_encode(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{encoded_header}.{encoded_claims}".encode("ascii")
    signature = bytes(marty_rs.sign_ed25519(bytes(secret_key), signing_input))
    id_token = f"{encoded_header}.{encoded_claims}.{_b64url_encode(signature)}"
    jwks = {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": kid,
                "alg": "EdDSA",
                "use": "sig",
                "x": _b64url_encode(bytes(public_key)),
            }
        ]
    }
    return id_token, jwks


def _decode_sd_jwt_disclosures(raw_credential: str) -> dict[str, object]:
    disclosures = [part for part in raw_credential.split("~")[1:-1] if part]
    decoded: dict[str, object] = {}
    for disclosure in disclosures:
        _, claim_name, claim_value = json.loads(_b64url_decode(disclosure))
        decoded[str(claim_name)] = claim_value
    return decoded


def _extract_raw_credential(wallet: OID4VCIWalletClient) -> str:
    assert wallet.credentials, "Wallet client recorded no credentials"
    first = wallet.credentials[0]
    raw = first.get("credential", "") if isinstance(first, dict) else ""
    assert raw, f"Credential entry missing raw credential: {first}"
    return raw


@pytest.fixture
async def canvas_simulator():
    simulator = CanvasSimulator(base_url=GATEWAY_URL, shared_secret=CANVAS_SHARED_SECRET)
    try:
        yield simulator
    finally:
        await simulator.close()


@pytest.fixture
async def canvas_open_badge_template(
    authenticated_gateway_client: GatewayClient,
    test_organization,
):
    """Create an Open Badge-style template compatible with Canvas event claims."""

    return await authenticated_gateway_client.create_credential_template(
        organization_id=test_organization["id"],
        name=f"Canvas Open Badge {uuid.uuid4().hex[:6]}",
        credential_type="OpenBadge",
        vct="https://marty.example/credentials/OpenBadge",
        supported_formats=["sd_jwt_vc"],
        credential_payload_format="w3c_vcdm_v2_sd_jwt",
        wallet_configs=[
            {
                "wallet_id": "wr-default",
                "display_name": "Default Wallet",
                "deep_link_scheme": "openid-credential-offer://",
                "format_variant": "sd_jwt_vc",
            },
            {
                "wallet_id": "wr-google",
                "display_name": "Google Wallet",
                "deep_link_scheme": "openid-credential-offer://",
                "format_variant": "credential-manager",
            }
        ],
        claims=[
            {"name": "email", "display_name": "Email", "required": True},
            {"name": "given_name", "display_name": "Given Name", "required": True},
            {"name": "family_name", "display_name": "Family Name", "required": True},
            {"name": "achievement_name", "display_name": "Achievement Name", "required": True},
            {"name": "achievement_description", "display_name": "Achievement Description"},
            {"name": "issued_at", "display_name": "Issued At", "required": True},
            {"name": "canvas_account_id", "display_name": "Canvas Account ID", "required": True},
            {"name": "canvas_course_id", "display_name": "Canvas Course ID", "required": True},
            {"name": "canvas_course_name", "display_name": "Canvas Course Name", "required": True},
            {"name": "canvas_enrollment_id", "display_name": "Canvas Enrollment ID", "required": True},
            {"name": "canvas_user_id", "display_name": "Canvas User ID", "required": True},
            {"name": "completion_at", "display_name": "Completion At", "required": True},
            {"name": "source_event_id", "display_name": "Source Event ID", "required": True},
        ],
        compliance_profile={
            "name": "Canvas Badge Compliance",
            "compliance_code": "CUSTOM",
            "credential_format": "sd_jwt_vc",
            "frameworks": ["canvas", "openbadges"],
        },
    )


@pytest.fixture
async def canvas_connector(
    authenticated_gateway_client: GatewayClient,
    test_organization,
    canvas_open_badge_template,
):
    """Create a Canvas connector mapping for the test organization."""

    return await authenticated_gateway_client.create_canvas_connector(
        organization_id=test_organization["id"],
        canvas_account_id=f"canvas-account-{uuid.uuid4().hex[:8]}",
        credential_template_id=canvas_open_badge_template["id"],
        display_name="Canvas Production",
        canvas_base_url="https://canvas.example.edu",
    )


@pytest.fixture
async def canvas_sd_jwt_issuer_profile(
    authenticated_gateway_client: GatewayClient,
    test_organization,
):
    """Provision an active issuer profile so Canvas SD-JWT offers can be redeemed."""

    service = None
    resolve_error: Exception | None = None
    for organization_id in (test_organization["id"], None):
        try:
            resolved = await authenticated_gateway_client.resolve_signing_service(
                organization_id=organization_id,
                credential_format="dc+sd-jwt",
                key_purpose="vc_jwt_issuer",
                algorithm="ES256",
            )
            candidate = resolved.get("service")
            if isinstance(candidate, dict) and candidate.get("id"):
                service = candidate
                break
        except GatewayClientError as exc:
            resolve_error = exc

    if not service:
        pytest.skip(
            "No signing service was resolvable for dc+sd-jwt issuance in this environment. "
            f"Last resolver error: {resolve_error}"
        )

    public_domain = os.getenv("PUBLIC_DOMAIN", "beta.elevenidllc.com")
    domain = public_domain.replace("https://", "").replace("http://", "").strip("/")
    issuer_did = f"did:web:{domain.replace('/', ':')}:orgs:{test_organization['id']}"

    return await authenticated_gateway_client.create_issuer_profile(
        organization_id=test_organization["id"],
        name="Canvas Test Issuer",
        issuer_did=issuer_did,
        signing_service_id=str(service["id"]),
        signing_key_reference=str(service.get("key_reference") or "") or None,
        key_purpose="vc_jwt_issuer",
        status="active",
    )


def _canvas_event_payload(
    *,
    organization_id: str,
    credential_template_id: str,
    event_id: str,
    canvas_account_id: str,
) -> dict[str, str]:
    return {
        "canvas_event_id": event_id,
        "organization_id": organization_id,
        "credential_template_id": credential_template_id,
        "canvas_account_id": canvas_account_id,
        "canvas_course_id": "course-101",
        "canvas_course_name": "Foundations of Portable Credentials",
        "canvas_enrollment_id": "enrollment-202",
        "canvas_user_id": "user-303",
        "learner_email": "student@example.edu",
        "learner_given_name": "Student",
        "learner_family_name": "Example",
        "achievement_name": "Canvas Course Completion",
        "achievement_description": "Completed the portable trust module.",
        "completion_at": "2026-05-07T14:00:00Z",
    }


@pytest.mark.asyncio
async def test_canvas_event_via_gateway_returns_offer_and_replays_duplicate(
    authenticated_gateway_client: GatewayClient,
    test_organization,
    canvas_open_badge_template,
    canvas_connector,
    canvas_simulator: CanvasSimulator,
):
    """A signed Canvas event should issue once through the public gateway route and replay duplicates safely."""

    if not CANVAS_SHARED_SECRET:
        pytest.skip(
            "CANVAS_CREDENTIALS_SHARED_SECRET is not set in the test environment. "
            "Set it to the same value used by the issuance service to run Canvas gateway integration tests."
        )

    event_id = f"evt-{uuid.uuid4().hex[:10]}"
    payload = _canvas_event_payload(
        organization_id="",
        credential_template_id="",
        event_id=event_id,
        canvas_account_id=canvas_connector["canvas_account_id"],
    )
    del payload["organization_id"]
    del payload["credential_template_id"]
    first = await canvas_simulator.post_credential_event(payload)
    second = await canvas_simulator.post_credential_event(payload)

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text

    first_json = first.json()
    second_json = second.json()

    assert first_json["source_event_id"] == event_id
    assert first_json["replayed"] is False
    assert first_json["credential_template_id"] == canvas_open_badge_template["id"]
    assert first_json.get("credential_offer_uri"), first_json
    assert first_json.get("pre_auth_code"), first_json

    assert second_json["id"] == first_json["id"]
    assert second_json["source_event_id"] == event_id
    assert second_json["replayed"] is True
    assert second_json.get("credential_offer_uri") == first_json.get("credential_offer_uri")

    issuance = await authenticated_gateway_client.get_issuance(first_json["id"])
    assert issuance["id"] == first_json["id"]


@pytest.mark.asyncio
async def test_canvas_event_via_gateway_rejects_invalid_signature(
    test_organization,
    canvas_open_badge_template,
    canvas_connector,
    canvas_simulator: CanvasSimulator,
):
    """The public Canvas route must reject tampered signatures instead of relying on browser auth."""

    if not CANVAS_SHARED_SECRET:
        pytest.skip(
            "CANVAS_CREDENTIALS_SHARED_SECRET is not set in the test environment. "
            "Set it to the same value used by the issuance service to run Canvas gateway integration tests."
        )

    payload = _canvas_event_payload(
        organization_id="",
        credential_template_id="",
        event_id=f"evt-{uuid.uuid4().hex[:10]}",
        canvas_account_id=canvas_connector["canvas_account_id"],
    )
    del payload["organization_id"]
    del payload["credential_template_id"]
    response = await canvas_simulator.post_credential_event(
        payload,
        signature_override="sha256=deadbeef",
    )

    assert response.status_code == 403, response.text


@pytest.mark.asyncio
async def test_canvas_event_offer_redeems_to_wallet_with_canvas_claims(
    authenticated_gateway_client: GatewayClient,
    test_organization,
    canvas_open_badge_template,
    canvas_connector,
    canvas_simulator: CanvasSimulator,
    canvas_sd_jwt_issuer_profile,
):
    """A signed Canvas completion event should produce a redeemable SD-JWT carrying the mapped Canvas claims."""

    if not CANVAS_SHARED_SECRET:
        pytest.skip(
            "CANVAS_CREDENTIALS_SHARED_SECRET is not set in the test environment. "
            "Set it to the same value used by the issuance service to run Canvas gateway integration tests."
        )

    event_id = f"evt-{uuid.uuid4().hex[:10]}"
    payload = _canvas_event_payload(
        organization_id="",
        credential_template_id="",
        event_id=event_id,
        canvas_account_id=canvas_connector["canvas_account_id"],
    )
    del payload["organization_id"]
    del payload["credential_template_id"]

    response = await canvas_simulator.post_credential_event(payload)
    assert response.status_code == 200, response.text
    response_json = response.json()

    wallet = OID4VCIWalletClient(
        profile=GOOGLE_WALLET_PROFILE,
        issuer_base_url=GATEWAY_URL,
    )
    offer_uri = (
        response_json.get("credential_offer_uris", {}).get("wr-google")
        or response_json["credential_offer_uri"]
    )
    try:
        await wallet.run_preauth_issuance(
            offer_uri=offer_uri,
            org_id=test_organization["id"],
        )
        raw_credential = _extract_raw_credential(wallet)
        format_info = wallet.validate_credential_format(raw_credential, "dc+sd-jwt")
        disclosed_claims = _decode_sd_jwt_disclosures(raw_credential)
    finally:
        await wallet.close()

    assert format_info["payload"].get("iss"), format_info
    assert len([part for part in format_info.get("disclosures", []) if part]) >= 1
    assert disclosed_claims["email"] == "student@example.edu"
    assert disclosed_claims["given_name"] == "Student"
    assert disclosed_claims["family_name"] == "Example"
    assert disclosed_claims["achievement_name"] == "Canvas Course Completion"
    assert disclosed_claims["achievement_description"] == "Completed the portable trust module."
    assert disclosed_claims["canvas_account_id"] == canvas_connector["canvas_account_id"]
    assert disclosed_claims["canvas_course_id"] == "course-101"
    assert disclosed_claims["canvas_course_name"] == "Foundations of Portable Credentials"
    assert disclosed_claims["canvas_enrollment_id"] == "enrollment-202"
    assert disclosed_claims["canvas_user_id"] == "user-303"
    assert disclosed_claims["completion_at"] == "2026-05-07T14:00:00Z"
    assert disclosed_claims["source_event_id"] == event_id
    assert response_json["credential_template_id"] == canvas_open_badge_template["id"]


@pytest.mark.asyncio
async def test_canvas_connector_crud_via_gateway(
    authenticated_gateway_client: GatewayClient,
    test_organization,
    canvas_open_badge_template,
):
    """Canvas connector config should support basic CRUD through the authenticated gateway path."""

    created = await authenticated_gateway_client.create_canvas_connector(
        organization_id=test_organization["id"],
        canvas_account_id=f"canvas-account-{uuid.uuid4().hex[:8]}",
        credential_template_id=canvas_open_badge_template["id"],
        display_name="Canvas Staging",
        canvas_base_url="https://canvas.staging.example.edu/",
    )

    fetched = await authenticated_gateway_client.get_canvas_connector(created["id"])
    listed = await authenticated_gateway_client.list_canvas_connectors(test_organization["id"])
    updated = await authenticated_gateway_client.update_canvas_connector(
        created["id"],
        organization_id=test_organization["id"],
        canvas_account_id=created["canvas_account_id"],
        credential_template_id=canvas_open_badge_template["id"],
        display_name="Canvas Staging Updated",
        canvas_base_url="https://canvas.staging.example.edu",
        enabled=False,
    )

    assert created["organization_id"] == test_organization["id"]
    assert created["canvas_base_url"] == "https://canvas.staging.example.edu"
    assert created["mip_primitives"]["provider"] == "canvas"
    assert "integration_connector" in created["mip_primitives"]["resources"]
    assert "oid4vci_pre_authorized_issuance" in created["mip_primitives"]["primitives"]
    assert fetched["id"] == created["id"]
    assert any(item["id"] == created["id"] for item in listed)
    assert updated["display_name"] == "Canvas Staging Updated"
    assert updated["enabled"] is False

    await authenticated_gateway_client.delete_canvas_connector(created["id"])

    with pytest.raises(GatewayClientError):
        await authenticated_gateway_client.get_canvas_connector(created["id"])


@pytest.mark.asyncio
async def test_canvas_lti_launch_via_gateway_verifies_identity_without_auth(
    authenticated_gateway_client: GatewayClient,
    test_organization,
    canvas_open_badge_template,
):
    """A public Canvas LTI launch should verify through the gateway using connector-scoped trust metadata."""

    connector_issuer = "https://canvas.example.edu"
    connector_client_id = f"canvas-client-{uuid.uuid4().hex[:8]}"
    connector_deployment_id = f"deployment-{uuid.uuid4().hex[:8]}"
    _, jwks = _build_lti_launch_material(
        issuer=connector_issuer,
        client_id=connector_client_id,
        deployment_id=connector_deployment_id,
        nonce="probe-nonce",
    )

    connector = await authenticated_gateway_client.create_canvas_connector(
        organization_id=test_organization["id"],
        canvas_account_id=f"canvas-account-{uuid.uuid4().hex[:8]}",
        credential_template_id=canvas_open_badge_template["id"],
        display_name="Canvas LTI Sandbox",
        canvas_base_url="https://canvas.example.edu",
        lti_client_id=connector_client_id,
        lti_deployment_id=connector_deployment_id,
        lti_issuer=connector_issuer,
        lti_jwks_url="https://canvas.example.edu/jwks",
        lti_jwks_json=jwks,
        lti_openid_configuration={
            "authorization_endpoint": "https://canvas.example.edu/oauth2/auth",
        },
    )

    public_client = GatewayClient(GATEWAY_URL)
    try:
        login = await public_client.initiate_canvas_lti_login(
            connector["id"],
            issuer=connector_issuer,
            login_hint="canvas-login-hint",
            target_link_uri=f"{GATEWAY_URL}/v1/integrations/canvas/lti/launch/{connector['id']}",
            lti_message_hint="canvas-message-hint",
            client_id=connector_client_id,
        )
        id_token, launch_jwks = _build_lti_launch_material(
            issuer=connector_issuer,
            client_id=connector_client_id,
            deployment_id=connector_deployment_id,
            nonce=login["nonce"],
        )
        await authenticated_gateway_client.update_canvas_connector(
            connector["id"],
            organization_id=test_organization["id"],
            canvas_account_id=connector["canvas_account_id"],
            credential_template_id=canvas_open_badge_template["id"],
            display_name="Canvas LTI Sandbox",
            canvas_base_url="https://canvas.example.edu",
            lti_client_id=connector_client_id,
            lti_deployment_id=connector_deployment_id,
            lti_issuer=connector_issuer,
            lti_jwks_url="https://canvas.example.edu/jwks",
            lti_jwks_json=launch_jwks,
            lti_openid_configuration={
                "authorization_endpoint": "https://canvas.example.edu/oauth2/auth",
            },
        )
        response = await public_client.launch_canvas_lti(
            connector["id"],
            id_token=id_token,
            state=login["state"],
        )
        with pytest.raises(GatewayClientError):
            await public_client.launch_canvas_lti(
                connector["id"],
                id_token=id_token,
                state=login["state"],
            )
    finally:
        await public_client.close()

    assert response["verified"] is True
    assert response["connector_id"] == connector["id"]
    assert response["organization_id"] == test_organization["id"]
    assert response["canvas_account_id"] == connector["canvas_account_id"]
    assert response["issuer"] == connector_issuer
    assert response["subject"] == "canvas-user-123"
    assert response["deployment_id"] == connector_deployment_id
    assert response["nonce"] == login["nonce"]
    assert response["state"] == login["state"]
    assert response["message_type"] == "LtiResourceLinkRequest"
    assert response["lti_version"] == "1.3.0"
    assert response["roles"] == ["Learner"]
    assert response["context"]["id"] == "course-101"
    assert response["learner_identity"]["subject"] == "canvas-user-123"
