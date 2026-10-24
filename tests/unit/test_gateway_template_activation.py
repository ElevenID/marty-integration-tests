"""Keep explicit fixture activation on the public template lifecycle."""
from unittest.mock import AsyncMock, call

import pytest

from tests.integration.gateway.helpers.gateway_client import GatewayClient


@pytest.mark.asyncio
async def test_default_template_creation_stays_draft() -> None:
    client = GatewayClient("https://gateway.example")
    client._request = AsyncMock(return_value={"id": "template-1", "status": "draft"})
    try:
        result = await client.create_credential_template(
            "org-1", "Template", "OpenBadge", issuer_did="did:web:issuer.example",
        )
        assert result["status"] == "draft"
        assert client._request.await_count == 1
        assert "activate" not in client._request.call_args.kwargs["json"]
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_active_template_requires_public_transition() -> None:
    client = GatewayClient("https://gateway.example")
    active = {"id": "template-1", "status": "active", "name": "Template"}
    client._request = AsyncMock(side_effect=[{"id": "template-1", "status": "draft"}, active])
    try:
        result = await client.create_credential_template(
            "org-1", "Template", "OpenBadge", issuer_did="did:web:issuer.example", activate=True,
        )
        assert result == active
        assert client._request.call_args_list[1] == call("POST", "/v1/credential-templates/template-1/activate")
        assert "activate" not in client._request.call_args_list[0].kwargs["json"]
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("created", [{}, {"id": ""}, {"id": None}])
async def test_activation_rejects_missing_created_identity(created: dict[str, str | None]) -> None:
    client = GatewayClient("https://gateway.example")
    client._request = AsyncMock(return_value=created)
    try:
        with pytest.raises(ValueError, match="no public id"):
            await client.create_credential_template(
                "org-1", "Template", "OpenBadge", issuer_did="did:web:issuer.example", activate=True,
            )
        assert client._request.await_count == 1
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("activated", [
    {"id": "other", "status": "active"},
    {"id": "template-1", "status": "draft"},
    {"id": "template-1"},
])
async def test_activation_requires_same_active_identity(activated: dict[str, str]) -> None:
    client = GatewayClient("https://gateway.example")
    client._request = AsyncMock(side_effect=[{"id": "template-1"}, activated])
    try:
        with pytest.raises(ValueError, match="same active template"):
            await client.create_credential_template(
                "org-1", "Template", "OpenBadge", issuer_did="did:web:issuer.example", activate=True,
            )
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_activation_failure_is_not_reported_as_success() -> None:
    client = GatewayClient("https://gateway.example")
    client._request = AsyncMock(side_effect=[{"id": "template-1"}, RuntimeError("activation rejected")])
    try:
        with pytest.raises(RuntimeError, match="activation rejected"):
            await client.create_credential_template(
                "org-1", "Template", "OpenBadge", issuer_did="did:web:issuer.example", activate=True,
            )
    finally:
        await client.close()
