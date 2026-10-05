"""Redeem a disposable application offer against the released OSS stack."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from tests.integration.gateway.helpers.oid4vc_wallet_client import OID4VCIWalletClient
from tests.oss_stack.application_event_probe import post_json, sign_application_event
from tests.oss_stack.test_application_offer_recovery import (
    _CREDENTIAL_TEMPLATE_ID,
    _ORGANIZATION_ID,
    _deactivate_disposable_application_flows,
    _install_disposable_application_flow,
)
from tests.oss_stack.test_public_stack import GATEWAY_URL

pytestmark = [pytest.mark.integration, pytest.mark.oss_stack]


def assert_member_badge_credential(
    wallet: OID4VCIWalletClient,
    credential: str,
    *,
    member_id: str,
    achievement_name: str,
    achievement_description: str,
) -> None:
    """Check JWT-VC shape and event correlation, not its signature."""
    assert credential
    assert all(credential.split("."))
    decoded = wallet.validate_credential_format(credential, "jwt_vc_json")
    payload = decoded["payload"]
    assert isinstance(payload, dict)
    assert isinstance(payload.get("iss"), str)
    assert payload["iss"]
    vc = payload["vc"]
    assert isinstance(vc, dict)
    assert vc.get("type") == ["VerifiableCredential", "OpenBadgeCredential"]
    subject = vc.get("credentialSubject")
    assert isinstance(subject, dict)
    assert subject.get("member_id") == member_id
    achievement = subject.get("achievement")
    assert isinstance(achievement, dict)
    assert achievement.get("name") == achievement_name
    assert achievement.get("description") == achievement_description


@pytest.mark.asyncio
@pytest.mark.nightly_public_smoke
async def test_application_offer_redeems_to_issued_credential() -> None:
    """Exercise Flow -> Issuance -> public gateway -> wallet without login mocks."""
    flow_id = str(uuid.uuid4())
    extension_uri = f"urn:elevenid:test:released-stack-positive-issuance:{flow_id}"
    application_id = f"artifact-issuance-{uuid.uuid4()}"
    issued_at = datetime.now(UTC).isoformat()
    achievement_name = "Disposable member badge"
    achievement_description = "Disposable released-stack issuance check"
    event = {
        "event_type": "application.approved",
        "aggregate_id": application_id,
        "aggregate_type": "application",
        "organization_id": _ORGANIZATION_ID,
        "data": {
            "applicant_id": f"applicant-{application_id}",
            "credential_template_id": _CREDENTIAL_TEMPLATE_ID,
            "claims": {
                "member_id": application_id,
                "email": "nightly-issuance@example.invalid",
                "organization_id": _ORGANIZATION_ID,
                "role": "applicant",
                "achievement_name": achievement_name,
                "achievement_description": achievement_description,
                "issued_at": issued_at,
            },
        },
        "timestamp": datetime.now(UTC).isoformat(),
    }
    try:
        _install_disposable_application_flow(flow_id, extension_uri=extension_uri)
        response = post_json(
            "http://flow-service:8011/v1/flows/webhooks/application-approved",
            event,
            sign_application_event(event),
        )
        assert response["status"] == 200
        body = response["body"]
        assert isinstance(body, dict)
        assert body["flows_triggered"] >= 1
        offers = body["offers"]
        assert isinstance(offers, list)
        assert len(offers) == body["flows_triggered"]
        own_offers = [offer for offer in offers if offer.get("flow_definition_id") == flow_id]
        assert len(own_offers) == 1
        offer = own_offers[0]
        assert isinstance(offer, dict)
        assert offer["flow_definition_id"] == flow_id
        assert offer["credential_offer_transaction_id"]
        offer_uri = offer["credential_offer_uri"]
        assert isinstance(offer_uri, str)
        assert offer_uri.startswith("openid-credential-offer://")

        wallet = OID4VCIWalletClient(issuer_base_url=GATEWAY_URL)
        try:
            result = await wallet.run_preauth_issuance(offer_uri, org_id=_ORGANIZATION_ID)
        finally:
            await wallet.close()
        assert result["offer"]["credential_issuer"]
        assert result["token"]["access_token"]
        credential_responses = result["credentials"]
        assert isinstance(credential_responses, list)
        assert len(credential_responses) == 1
        issued = credential_responses[0].get("credentials")
        assert isinstance(issued, list)
        assert len(issued) == 1
        credential = issued[0].get("credential")
        assert isinstance(credential, str)
        assert_member_badge_credential(
            wallet,
            credential,
            member_id=application_id,
            achievement_name=achievement_name,
            achievement_description=achievement_description,
        )
    finally:
        _deactivate_disposable_application_flows(extension_uri=extension_uri)
