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

pytestmark = [pytest.mark.integration, pytest.mark.oss_stack]


@pytest.mark.asyncio
@pytest.mark.nightly_public_smoke
async def test_application_offer_redeems_to_issued_credential() -> None:
    """Exercise Flow -> Issuance -> public gateway -> wallet without login mocks."""
    flow_id = str(uuid.uuid4())
    application_id = f"artifact-issuance-{uuid.uuid4()}"
    event = {
        "event_type": "application.approved",
        "aggregate_id": application_id,
        "aggregate_type": "application",
        "organization_id": _ORGANIZATION_ID,
        "data": {
            "applicant_id": f"applicant-{application_id}",
            "credential_template_id": _CREDENTIAL_TEMPLATE_ID,
            "claims": {"email": "nightly-issuance@example.invalid"},
        },
        "timestamp": datetime.now(UTC).isoformat(),
    }
    _deactivate_disposable_application_flows()
    _install_disposable_application_flow(flow_id)
    try:
        response = post_json(
            "http://flow-service:8011/v1/flows/webhooks/application-approved",
            event,
            sign_application_event(event),
        )
        assert response["status"] == 200
        body = response["body"]
        assert isinstance(body, dict)
        assert body["flows_triggered"] == 1
        offers = body["offers"]
        assert isinstance(offers, list)
        assert len(offers) == 1
        offer = offers[0]
        assert isinstance(offer, dict)
        assert offer["flow_definition_id"] == flow_id
        assert offer["credential_offer_transaction_id"]
        offer_uri = offer["credential_offer_uri"]
        assert isinstance(offer_uri, str)
        assert offer_uri.startswith("openid-credential-offer://")

        wallet = OID4VCIWalletClient(issuer_base_url="http://127.0.0.1:28000")
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
        assert credential
    finally:
        _deactivate_disposable_application_flows()
