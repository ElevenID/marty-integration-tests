"""Regression tests for selected-organization gateway requests."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from tests.integration.gateway.helpers.gateway_client import GatewayClient


@pytest.mark.asyncio
async def test_start_verification_flow_sends_selected_organization_header() -> None:
    client = GatewayClient("https://gateway.example")
    request = AsyncMock(return_value={"instance_id": "flow-1"})
    client._request = request

    try:
        result = await client.start_verification_flow(
            presentation_policy_id="policy-1",
            trust_profile_id="trust-1",
            expiry_minutes=10,
            organization_id="org-1",
        )
    finally:
        await client.close()

    assert result == {"instance_id": "flow-1"}
    request.assert_awaited_once_with(
        "POST",
        "/v1/flows/verify",
        json={
            "presentation_policy_id": "policy-1",
            "trust_profile_id": "trust-1",
            "expiry_minutes": 10,
            "organization_id": "org-1",
        },
        headers={"X-Organization-ID": "org-1"},
    )
