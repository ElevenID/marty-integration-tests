from __future__ import annotations

from typing import Any

import pytest

from tests.integration.gateway import test_eudi_wallet_kit_vp as fixtures


class PolicyClient:
    def __init__(self) -> None:
        self.created: dict[str, Any] = {}

    async def create_presentation_policy(self, **payload: Any) -> dict[str, Any]:
        self.created = payload
        return {"id": "policy-1", **payload}

    async def activate_presentation_policy(self, policy_id: str) -> dict[str, Any]:
        assert policy_id == "policy-1"
        return {"id": policy_id, "status": "ACTIVE", **self.created}


@pytest.mark.parametrize("fixture_name", ["vp_age_policy", "vp_identity_policy"])
@pytest.mark.asyncio
async def test_sd_jwt_fixture_requires_exact_signed_claims(fixture_name: str) -> None:
    client = PolicyClient()
    policy = await getattr(fixtures, fixture_name).__wrapped__(
        client,
        {"id": "org-1"},
        {"id": "template-1"},
        {"id": "trust-1"},
        {"issuer_did": "did:example:verifier"},
    )
    assert policy["status"] == "ACTIVE"
    assert policy["trust_profile_id"] == "trust-1"
    claims = client.created["credential_requirements"][0]["requested_claims"]
    assert claims
    assert all(claim["required"] and claim["accept_derived"] is False for claim in claims)
