"""Regression tests for selected-organization gateway requests."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from tests.integration.gateway.helpers.gateway_client import GatewayClient


@pytest.mark.asyncio
async def test_credential_template_with_did_never_exposes_custody_selectors() -> None:
    client = GatewayClient("https://gateway.example")
    request = AsyncMock(return_value={"id": "template-1"})
    client._request = request

    try:
        await client.create_credential_template(
            organization_id="org-1",
            name="DID-first template",
            credential_type="EmployeeBadge",
            compliance_profile_id="compliance-1",
            issuer_did="did:web:issuer.example",
        )
    finally:
        await client.close()

    payload = request.await_args.kwargs["json"]
    assert payload["issuer_did"] == "did:web:issuer.example"
    assert "issuer_profile_id" not in payload
    assert "issuer_key_id" not in payload
    assert "issuer_key_algorithm" not in payload
    assert "issuer_certificate_chain_pem" not in payload

    with pytest.raises(TypeError, match="issuer_profile_id"):
        await client.create_credential_template(
            organization_id="org-1",
            name="Legacy selector",
            credential_type="EmployeeBadge",
            issuer_did="did:web:issuer.example",
            issuer_profile_id="legacy-profile",  # type: ignore[call-arg]
        )


@pytest.mark.asyncio
async def test_credential_template_requires_a_public_issuer_did() -> None:
    client = GatewayClient("https://gateway.example")
    try:
        with pytest.raises(ValueError, match="issuer_did is required"):
            await client.create_credential_template(
                organization_id="org-1",
                name="Legacy template",
                credential_type="EmployeeBadge",
            )
    finally:
        await client.close()


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
            issuer_did="did:web:verifier.example",
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
            "issuer_did": "did:web:verifier.example",
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
            issuer_did="did:web:verifier.example",
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
            "issuer_did": "did:web:verifier.example",
            "oid4vp_profile": "haip",
            "request_uri_method": "get",
        },
        headers={"X-Organization-ID": "org-1"},
    )


@pytest.mark.asyncio
async def test_get_verification_decision_uses_result_endpoint() -> None:
    client = GatewayClient("https://gateway.example")
    request = AsyncMock(
        return_value={
            "status": "completed",
            "result": {"decision": "deny"},
        }
    )
    client._request = request

    try:
        result = await client.get_verification_decision("flow-1")
    finally:
        await client.close()

    assert result["result"]["decision"] == "deny"
    request.assert_awaited_once_with(
        "GET",
        "/v1/flows/instances/flow-1/result",
    )


@pytest.mark.asyncio
async def test_create_standard_flow_uses_current_public_contract() -> None:
    client = GatewayClient("https://gateway.example")
    request = AsyncMock(return_value={"id": "flow-1"})
    client._request = request

    try:
        await client.create_flow_definition(
            organization_id="org-1",
            name="Verification flow",
            flow_type="verification",
            presentation_policy_id="policy-1",
        )
    finally:
        await client.close()

    request.assert_awaited_once_with(
        "POST",
        "/v1/flows/definitions",
        json={
            "organization_id": "org-1",
            "name": "Verification flow",
            "flow_type": "oid4vp_presentation",
            "approval_strategy": "AUTO",
            "hooks": {},
            "deployment_profile_ids": [],
            "presentation_policy_id": "policy-1",
        },
    )
    payload = request.await_args.kwargs["json"]
    assert "steps" not in payload
    assert "type" not in payload
    assert "trust_profile_id" not in payload


@pytest.mark.asyncio
async def test_activate_credential_template_uses_public_gateway() -> None:
    client = GatewayClient("https://gateway.example")
    request = AsyncMock(return_value={"id": "template-1", "status": "active"})
    client._request = request

    try:
        result = await client.activate_credential_template("template-1")
    finally:
        await client.close()

    assert result["status"] == "active"
    request.assert_awaited_once_with(
        "POST",
        "/v1/credential-templates/template-1/activate",
    )


@pytest.mark.asyncio
async def test_application_template_helper_uses_only_current_mip_contract() -> None:
    client = GatewayClient("https://gateway.example")
    request = AsyncMock(return_value={"id": "application-template-1"})
    client._request = request

    try:
        await client.create_application_template(
            organization_id="org-1",
            name="Current application",
            evidence_requirements=[
                {
                    "evidence_id": "identity_document",
                    "evidence_type": "DOCUMENT_SCAN",
                    "description": "Government-issued identity document",
                    "required": True,
                }
            ],
            form_fields=[
                {
                    "field_id": "email",
                    "field_type": "EMAIL",
                    "label": "Email",
                    "required": True,
                }
            ],
            claim_collection_rules=[
                {
                    "claim_name": "email",
                    "source": "FORM_FIELD",
                    "source_config": {"field_id": "email"},
                }
            ],
            approval_strategy="MANUAL",
        )

        with pytest.raises(ValueError, match="legacy string IDs"):
            await client.create_application_template(
                organization_id="org-1",
                name="Legacy application",
                evidence_requirements=["identity_document"],  # type: ignore[list-item]
            )
        with pytest.raises(ValueError, match="uppercase MIP value"):
            await client.create_application_template(
                organization_id="org-1",
                name="Legacy strategy",
                approval_strategy="manual",
            )
    finally:
        await client.close()

    request.assert_awaited_once()
    payload = request.await_args.kwargs["json"]
    assert payload["approval_strategy"] == "MANUAL"
    assert payload["evidence_requirements"][0]["evidence_type"] == "DOCUMENT_SCAN"
    assert payload["form_fields"][0]["field_type"] == "EMAIL"
    assert payload["claim_collection_rules"][0]["source"] == "FORM_FIELD"
    assert "notifications" not in payload


@pytest.mark.asyncio
async def test_activate_application_template_uses_public_lifecycle_route() -> None:
    client = GatewayClient("https://gateway.example")
    request = AsyncMock(
        return_value={"id": "application-template-1", "status": "ACTIVE"}
    )
    client._request = request

    try:
        result = await client.activate_application_template(
            "application-template-1"
        )
    finally:
        await client.close()

    assert result["status"] == "ACTIVE"
    request.assert_awaited_once_with(
        "POST",
        "/v1/application-templates/application-template-1/activate",
    )
