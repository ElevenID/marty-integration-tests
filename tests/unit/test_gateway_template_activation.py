"""Keep explicit fixture activation on the public template lifecycle."""
from unittest.mock import AsyncMock, call

import pytest

from tests.integration.gateway.helpers.gateway_client import GatewayClient


@pytest.mark.asyncio
async def test_default_template_creation_stays_draft() -> None:
    client = GatewayClient("https://gateway.example")
    client._request = AsyncMock(return_value={"id": "template-1", "status": "DRAFT"})
    try:
        result = await client.create_credential_template(
            "org-1", "Template", "OpenBadge", issuer_did="did:web:issuer.example",
        )
        assert result["status"] == "DRAFT"
        assert client._request.await_count == 1
        assert "activate" not in client._request.call_args.kwargs["json"]
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_active_template_requires_public_transition() -> None:
    client = GatewayClient("https://gateway.example")
    active = {"id": "template-1", "status": "ACTIVE", "name": "Template"}
    client._request = AsyncMock(side_effect=[{"id": "template-1", "status": "DRAFT"}, active])
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
    {"id": "other", "status": "ACTIVE"},
    {"id": "template-1", "status": "DRAFT"},
    {"id": "template-1", "status": "active"},
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


@pytest.mark.asyncio
async def test_default_compliance_profile_creation_stays_draft() -> None:
    client = GatewayClient("https://gateway.example")
    client._request = AsyncMock(return_value={"id": "cp-1", "status": "DRAFT"})
    try:
        result = await client.create_compliance_profile("org-1", "Profile")
        assert result["status"] == "DRAFT"
        assert client._request.await_count == 1
        assert "activate" not in client._request.call_args.kwargs["json"]
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_active_compliance_profile_requires_public_transition() -> None:
    client = GatewayClient("https://gateway.example")
    active = {"id": "cp-1", "status": "ACTIVE"}
    client._request = AsyncMock(side_effect=[{"id": "cp-1", "status": "DRAFT"}, active])
    try:
        assert await client.create_compliance_profile("org-1", "Profile", activate=True) == active
        assert client._request.call_args_list[1] == call("POST", "/v1/compliance-profiles/cp-1/activate")
        assert "activate" not in client._request.call_args_list[0].kwargs["json"]
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("activated", [
    {"id": "other", "status": "ACTIVE"}, {"id": "cp-1", "status": "DRAFT"},
    {"id": "cp-1", "status": "active"}, {"id": "cp-1"},
])
async def test_compliance_activation_requires_same_active_identity(activated: dict[str, str]) -> None:
    client = GatewayClient("https://gateway.example")
    client._request = AsyncMock(side_effect=[{"id": "cp-1"}, activated])
    try:
        with pytest.raises(ValueError, match="same active compliance profile"):
            await client.create_compliance_profile("org-1", "Profile", activate=True)
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("schema", [{}, {"namespaces": {"com.icao.dtc": {}}}])
async def test_legacy_schema_is_rejected_before_public_request(schema: dict) -> None:
    client = GatewayClient("https://gateway.example")
    client._request = AsyncMock()
    try:
        with pytest.raises(ValueError, match="declare credential claims"):
            await client.create_credential_template(
                "org-1", "Template", "com.icao.dtc", issuer_did="did:web:issuer.example", schema=schema,
            )
        client._request.assert_not_awaited()
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_dtc_compatibility_fixture_sends_namespaced_claims_without_schema_uri() -> None:
    from tests.integration.gateway.helpers.test_data import TestDataBuilder

    client = GatewayClient("https://gateway.example")
    client._request = AsyncMock(return_value={"id": "template-1", "status": "DRAFT"})
    try:
        template = TestDataBuilder.dtc_template("org-1", compliance_profile_id="compliance-1")
        assert "schema" not in template
        await client.create_credential_template(**template, issuer_did="did:web:issuer.example")
        sent = client._request.call_args.kwargs["json"]
        assert "schema_uri" not in sent
        assert sent["doctype"] == "com.icao.dtc"
        assert [claim["name"] for claim in sent["claims"]] == [
            "data_group_1", "data_group_2", "sod", "document_number", "issuing_authority", "expiry_date",
        ]
        assert all(claim["required"] and claim["mdoc_namespace"] == "com.icao.dtc"
                   and claim["mdoc_element_identifier"] == claim["name"] for claim in sent["claims"])
        assert sent["compliance_profile_id"] == "compliance-1"
    finally:
        await client.close()
