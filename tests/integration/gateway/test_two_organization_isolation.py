"""Adversarial organization-isolation checks through Marty's public gateway.

These tests intentionally use one authenticated operator session to prove that
resource identifiers remain tenant-scoped even when the caller is allowed to
administer both disposable organizations.  They exercise the same API surface
used by the UI and conformance fixtures; no internal service, test adapter, or
KMS endpoint is involved.
"""

from __future__ import annotations

import os
import uuid
from typing import Any
from urllib.parse import urlsplit

import pytest

from .helpers.gateway_client import GatewayClient, GatewayClientError
from .helpers.test_data import TestDataBuilder


def _assert_cross_tenant_denied(error: GatewayClientError) -> None:
    """Require authorization or boundary validation, never a successful substitution."""
    assert error.status_code in {403, 404, 422}, str(error)


def _assert_did_resolution_denied(error: GatewayClientError) -> None:
    """Require a fail-closed public error that does not expose custody internals."""
    assert error.status_code in {403, 404, 409, 422}, str(error)
    public_error = str(error).lower()
    for private_selector in (
        "issuer_profile_id",
        "signing_service_id",
        "signing_key_reference",
        "key_reference",
        "kms",
    ):
        assert private_selector not in public_error, (
            f"Cross-tenant DID failure exposed private selector {private_selector!r}: {error}"
        )


async def _resolve_signing_service(
    client: GatewayClient,
    organization_id: str,
    *,
    key_purpose: str,
) -> dict[str, Any]:
    """Resolve managed custody for test setup without exposing it to public calls."""
    last_error: Exception | None = None
    for scope in (organization_id, None):
        try:
            resolved = await client.resolve_signing_service(
                organization_id=scope,
                credential_format="dc+sd-jwt",
                key_purpose=key_purpose,
                algorithm="ES256",
            )
        except GatewayClientError as error:
            last_error = error
            continue
        service = resolved.get("service")
        if isinstance(service, dict) and service.get("id"):
            return service
    raise AssertionError(f"No managed signing service is available for {key_purpose}: {last_error}")


def _issuer_did(organization: dict[str, Any]) -> str:
    """Build the deployment's canonical public did:web for an organization."""
    domain = os.getenv("PUBLIC_DOMAIN", "").strip()
    if not domain:
        domain = urlsplit(os.getenv("GATEWAY_URL", "https://marty.test")).hostname or ""
    # Organization responses currently expose the canonical URL-safe name,
    # while the DID publication API records that name as the public org slug.
    slug = str(organization.get("slug") or organization.get("name") or "").strip().lower()
    assert domain, "PUBLIC_DOMAIN or a hostname-bearing GATEWAY_URL is required"
    assert slug, f"Organization response has no canonical slug: {organization}"
    return f"did:web:{domain}:orgs:{slug}"


async def _provision_issuer(
    client: GatewayClient,
    organization: dict[str, Any],
) -> str:
    """Create an active issuer profile through the normal administration API."""
    service = await _resolve_signing_service(
        client,
        str(organization["id"]),
        key_purpose="vc_jwt_issuer",
    )
    issuer_did = _issuer_did(organization)
    profile = await client.create_issuer_profile(
        organization_id=str(organization["id"]),
        name=f"{organization.get('name', organization['id'])} tenant-isolation issuer",
        issuer_did=issuer_did,
        signing_service_id=str(service["id"]),
        signing_key_reference=(str(service.get("key_reference")) if service.get("key_reference") else None),
        key_purpose="vc_jwt_issuer",
        status="active",
    )
    assert profile["issuer_did"] == issuer_did
    return issuer_did


async def _employee_badge_template_data(
    client: GatewayClient,
    *,
    organization_id: str,
    name: str,
    issuer_did: str | None = None,
) -> dict[str, Any]:
    """Build the current public template contract with a managed profile ID."""
    compliance_profile = await client.create_compliance_profile(
        organization_id=organization_id,
        name=f"{name} compliance",
        compliance_code="ENTERPRISE_VC",
        credential_format="sd_jwt_vc",
        frameworks=["enterprise"],
    )
    revocation_profile = await client.create_revocation_profile(
        organization_id=organization_id,
        name=f"{name} status list",
        revocation_mechanism=["STATUS_LIST_2021"],
    )
    revocation_profile = await client.activate_revocation_profile(revocation_profile["id"])
    template = TestDataBuilder.employee_badge_template(
        organization_id=organization_id,
        name=name,
    )
    # The generic builder retains legacy variants for tests of older endpoints.
    # This isolation suite must exercise the current strict public contract.
    template.pop("compliance_profile", None)
    template.pop("wallet_configs", None)
    template["compliance_profile_id"] = compliance_profile["id"]
    template["revocation_profile_id"] = revocation_profile["id"]
    if issuer_did is not None:
        template["issuer_did"] = issuer_did
    return template


@pytest.mark.asyncio
@pytest.mark.integration
async def test_two_organizations_cannot_substitute_templates_or_policies(
    authenticated_gateway_client: GatewayClient,
) -> None:
    """Resources from one organization cannot be listed, issued, or referenced by another."""
    client = authenticated_gateway_client
    organization_a = await client.create_organization(**TestDataBuilder.organization())
    organization_b = await client.create_organization(**TestDataBuilder.organization())
    issuer_did_a = await _provision_issuer(client, organization_a)
    issuer_did_b = await _provision_issuer(client, organization_b)

    template_a_data = await _employee_badge_template_data(
        client,
        organization_id=organization_a["id"],
        name="Organization A employee badge",
        issuer_did=issuer_did_a,
    )
    template_b_data = await _employee_badge_template_data(
        client,
        organization_id=organization_b["id"],
        name="Organization B employee badge",
        issuer_did=issuer_did_b,
    )
    template_a = await client.create_credential_template(**template_a_data)
    template_b = await client.create_credential_template(**template_b_data)

    templates_a = await client.list_credential_templates(organization_a["id"])
    templates_b = await client.list_credential_templates(organization_b["id"])
    assert template_a["id"] in {template["id"] for template in templates_a}
    assert template_b["id"] in {template["id"] for template in templates_b}
    assert template_a["id"] not in {template["id"] for template in templates_b}
    assert template_b["id"] not in {template["id"] for template in templates_a}

    # The gateway must reject a resource-ID substitution before attempting
    # issuance or resolving an issuer DID.  The claims are intentionally valid
    # for the template so a success could only mean that tenant isolation failed.
    with pytest.raises(GatewayClientError) as issuance_error:
        await client.issue_credential(
            organization_id=organization_b["id"],
            credential_template_id=template_a["id"],
            claims=TestDataBuilder.employee_badge_claims(),
            subject_did="did:key:z6MkTwoOrganizationSubject",
        )
    _assert_cross_tenant_denied(issuance_error.value)

    # A policy is an organization-owned authorization decision.  It cannot
    # point at a template from another organization, even for an operator who
    # can see both organizations in this isolated integration environment.
    policy_b_for_template_a = TestDataBuilder.presentation_policy_age_verification(
        organization_id=organization_b["id"],
        credential_template_id=template_a["id"],
        name="Cross-tenant policy substitution attempt",
    )
    with pytest.raises(GatewayClientError) as policy_error:
        await client.create_presentation_policy(**policy_b_for_template_a)
    _assert_cross_tenant_denied(policy_error.value)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_issuer_did_resolution_is_scoped_to_the_selected_organization(
    authenticated_gateway_client: GatewayClient,
) -> None:
    """A valid issuer DID in organization B cannot select B's custody from A."""
    client = authenticated_gateway_client
    organization_a = await client.create_organization(**TestDataBuilder.organization())
    organization_b = await client.create_organization(**TestDataBuilder.organization())

    await _provision_issuer(client, organization_a)
    issuer_did_b = await _provision_issuer(client, organization_b)
    # Prove this is a real, active DID mapping rather than an unknown-DID test.
    template_b_data = await _employee_badge_template_data(
        client,
        organization_id=organization_b["id"],
        name="Organization B DID control",
        issuer_did=issuer_did_b,
    )
    template_b = await client.create_credential_template(**template_b_data)
    issued_b = await client.issue_credential(
        organization_id=organization_b["id"],
        credential_template_id=template_b["id"],
        claims=TestDataBuilder.employee_badge_claims(),
        subject_did=f"did:key:z6Mk{uuid.uuid4().hex}",
    )
    assert issued_b

    # Template authoring may validate the DID eagerly or defer resolution until
    # issuance. Both are safe contracts, provided the foreign organization can
    # never use B's profile or managed signing key.
    template_a_data = await _employee_badge_template_data(
        client,
        organization_id=organization_a["id"],
        name="Organization A cross-tenant DID attempt",
        issuer_did=issuer_did_b,
    )
    try:
        template_a = await client.create_credential_template(**template_a_data)
    except GatewayClientError as error:
        _assert_did_resolution_denied(error)
        return

    with pytest.raises(GatewayClientError) as issuance_error:
        await client.issue_credential(
            organization_id=organization_a["id"],
            credential_template_id=template_a["id"],
            claims=TestDataBuilder.employee_badge_claims(),
            subject_did=f"did:key:z6Mk{uuid.uuid4().hex}",
        )
    _assert_did_resolution_denied(issuance_error.value)

    issuances_a = await client.list_issuances(organization_a["id"])
    issued_ids_a = {str(item.get("id")) for item in issuances_a if isinstance(item, dict) and item.get("id")}
    assert str(issued_b.get("id")) not in issued_ids_a
