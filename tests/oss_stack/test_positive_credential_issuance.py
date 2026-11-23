"""Redeem a disposable application offer against the released OSS stack."""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from tests.integration.gateway.helpers.oid4vc_wallet_client import OID4VCIWalletClient
from tests.oss_stack.application_event_probe import post_json
from tests.oss_stack.test_application_offer_recovery import (
    _CREDENTIAL_TEMPLATE_ID,
    _ORGANIZATION_ID,
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
    achievement_criteria_narrative: str,
) -> None:
    """Check JWT-VC shape and application correlation, not its signature."""
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
    criteria = achievement.get("criteria")
    assert isinstance(criteria, dict)
    assert criteria.get("narrative") == achievement_criteria_narrative


def _post_issuance(path: str, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    response = post_json(f"http://issuance-native:8005{path}", payload, headers)
    assert response["status"] == 200, f"Issuance {path} returned HTTP {response['status']}"
    body = response["body"]
    assert isinstance(body, dict)
    return body


@pytest.mark.asyncio
@pytest.mark.nightly_public_smoke
async def test_application_offer_redeems_to_issued_credential() -> None:
    """Approve an issuance-owned application and redeem its bound offer through the gateway."""
    member_id = f"artifact-issuance-{uuid.uuid4()}"
    achievement_name = "Disposable member badge"
    achievement_description = "Disposable released-stack issuance check"
    achievement_criteria_narrative = "Complete the disposable application approval journey"
    claims = {
        "member_id": member_id,
        "email": "nightly-issuance@example.invalid",
        "organization_id": _ORGANIZATION_ID,
        "role": "applicant",
        "achievement_name": achievement_name,
        "achievement_description": achievement_description,
        "achievement_criteria": {"narrative": achievement_criteria_narrative},
        "issued_at": datetime.now(UTC).isoformat(),
    }
    # The Compose fixture accepts this override for the same private Issuance listener.
    headers = {
        "x-api-key": os.environ.get("ISSUANCE_API_KEY") or "oss-ci-issuance-internal-key-32-bytes",
        "x-organization-id": _ORGANIZATION_ID,
    }
    template = _post_issuance(
        "/v1/application-templates",
        {
            "organization_id": _ORGANIZATION_ID,
            "name": member_id,
            "credential_template_id": _CREDENTIAL_TEMPLATE_ID,
            "form_fields": [
                {"field_id": "member_id", "label": "Member ID", "field_type": "TEXT", "required": True}
            ],
        },
        {**headers, "idempotency-key": member_id},
    )
    template_id = template["id"]
    assert isinstance(template_id, str) and template_id
    template_path = f"/v1/application-templates/{template_id}"
    try:
        activated = _post_issuance(f"{template_path}/activate", {}, headers)
        assert activated["status"].lower() == "active"
        application = _post_issuance(
            "/internal/applications",
            {"application_template_id": template_id, "applicant_data": claims},
            headers,
        )
        assert application["organization_id"] == _ORGANIZATION_ID
        application_id = application["id"]
        assert isinstance(application_id, str) and application_id
        application_path = f"/internal/applications/{application_id}"
        approved = _post_issuance(f"{application_path}/approve", {}, headers)
        assert approved["id"] == application_id
        assert approved["status"] == "approved"
        transaction_id = approved["issuance_transaction_id"]
        assert isinstance(transaction_id, str) and transaction_id
        offer = _post_issuance(f"{application_path}/issuance-offer", {}, headers)
        assert offer["status"] == "active"
        assert offer["transaction_id"] == transaction_id
        offer_uri = offer["offer_url"]
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
            member_id=member_id,
            achievement_name=achievement_name,
            achievement_description=achievement_description,
            achievement_criteria_narrative=achievement_criteria_narrative,
        )
    finally:
        _post_issuance(f"{template_path}/deprecate", {}, headers)
