"""Adversarial organization-isolation checks through Marty's public gateway.

These tests intentionally use one authenticated operator session to prove that
resource identifiers remain tenant-scoped even when the caller is allowed to
administer both disposable organizations.  They exercise the same API surface
used by the UI and conformance fixtures; no internal service, test adapter, or
KMS endpoint is involved.
"""

from __future__ import annotations

import pytest

from .helpers.gateway_client import GatewayClient, GatewayClientError
from .helpers.test_data import TestDataBuilder


def _assert_cross_tenant_denied(error: GatewayClientError) -> None:
    """Require an authorization-style failure, never a successful substitution."""
    assert error.status_code in {403, 404}, str(error)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_two_organizations_cannot_substitute_templates_or_policies(
    authenticated_gateway_client: GatewayClient,
) -> None:
    """Resources from one organization cannot be listed, issued, or referenced by another."""
    client = authenticated_gateway_client
    organization_a = await client.create_organization(**TestDataBuilder.organization())
    organization_b = await client.create_organization(**TestDataBuilder.organization())

    template_a_data = TestDataBuilder.employee_badge_template(
        organization_id=organization_a["id"],
        name="Organization A employee badge",
    )
    template_b_data = TestDataBuilder.employee_badge_template(
        organization_id=organization_b["id"],
        name="Organization B employee badge",
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
