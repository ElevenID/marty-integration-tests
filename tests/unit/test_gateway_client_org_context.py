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
            issuer_profile_id="request-object-profile-1",
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
            "issuer_profile_id": "request-object-profile-1",
        },
        headers={"X-Organization-ID": "org-1"},
    )


@pytest.mark.asyncio
async def test_start_verification_flow_can_select_the_production_haip_transport() -> None:
    client = GatewayClient("https://gateway.example")
    request = AsyncMock(return_value={"instance_id": "flow-haip"})
    client._request = request

    try:
        await client.start_verification_flow(
            presentation_policy_id="policy-1",
            organization_id="org-1",
            oid4vp_profile="haip",
            request_uri_method="get",
        )
    finally:
        await client.close()

    request.assert_awaited_once_with(
        "POST",
        "/v1/flows/verify",
        json={
            "presentation_policy_id": "policy-1",
            "trust_profile_id": None,
            "expiry_minutes": 15,
            "organization_id": "org-1",
            "oid4vp_profile": "haip",
            "request_uri_method": "get",
        },
        headers={"X-Organization-ID": "org-1"},
    )
