"""Adversarial organization-isolation checks through Marty's public gateway.

These tests use public browser-equivalent sessions and scoped API keys to prove
that resource identifiers remain tenant-scoped. They exercise the same API
surface used by the UI and conformance fixtures; no internal service, test
adapter, or KMS endpoint is involved.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from typing import Any
from urllib.parse import urlsplit

import pytest

from .helpers.auth_helper import AuthHelper
from .helpers.gateway_client import GatewayClient, GatewayClientError
from .helpers.test_data import TestDataBuilder

MARTY_DEFAULT_ORGANIZATION_ID = "00000000-0000-0000-0000-000000000001"


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


def _assert_public_denial(response: Any, *, foreign_values: tuple[str, ...] = ()) -> None:
    """Require a non-enumerating public denial without foreign tenant data."""
    assert response.status_code in {403, 404}, response.text
    normalized = response.text.lower()
    for index, value in enumerate(foreign_values, start=1):
        if value:
            assert value.lower() not in normalized, (
                f"Cross-tenant denial exposed protected foreign value #{index}"
            )


async def _reviewer_session() -> str:
    public_session = os.getenv("MARTY_REVIEWER_TEST_SESSION_ID", "").strip()
    if public_session:
        return public_session
    email = os.getenv(
        "MARTY_CONFORMANCE_REVIEWER_EMAIL",
        "conformance.reviewer@elevenid.dev",
    ).strip()
    password = os.getenv("MARTY_CONFORMANCE_REVIEWER_PASSWORD", "").strip()
    if not password:
        pytest.skip(
            "MARTY_CONFORMANCE_REVIEWER_PASSWORD is required for the "
            "two-principal public-boundary matrix"
        )
    return await AuthHelper().get_session_id(email, password)


async def _grant_reviewer_boundary_roles(
    admin: GatewayClient,
    *,
    organization_id: str,
    reviewer_email: str,
) -> None:
    """Assign access-admin + viewer through the same public API used by the UI."""
    roles_response = await admin.client.get(
        f"/v1/organizations/{organization_id}/roles"
    )
    assert roles_response.status_code == 200, roles_response.text
    role_ids = {
        role["name"]: role["id"]
        for role in roles_response.json()
        if isinstance(role, dict) and role.get("name") and role.get("id")
    }
    assert {"access_admin", "viewer"} <= role_ids.keys(), role_ids

    members_response = await admin.client.get(
        f"/v1/organizations/{organization_id}/members"
    )
    assert members_response.status_code == 200, members_response.text
    reviewer = next(
        (
            member
            for member in members_response.json()
            if str(member.get("email") or "").lower() == reviewer_email.lower()
        ),
        None,
    )
    assert reviewer is not None, (
        f"Disposable reviewer membership {reviewer_email!r} was not bootstrapped"
    )
    update_response = await admin.client.put(
        f"/v1/organizations/{organization_id}/members/{reviewer['id']}/roles",
        json={"role_ids": [role_ids["access_admin"], role_ids["viewer"]]},
    )
    assert update_response.status_code == 200, update_response.text


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
    """Build the current public template contract with required policy profiles."""
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


@pytest.mark.asyncio
@pytest.mark.integration
async def test_two_principals_cannot_cross_rbac_api_key_scim_flow_or_webhook_boundaries(
    authenticated_gateway_client: GatewayClient,
) -> None:
    """Exercise actual foreign resources with distinct public identities.

    This is an ElevenID-owned product-security test. It is intentionally kept
    outside every imported official suite and must never be reported as an
    upstream compliance assertion.
    """
    admin = authenticated_gateway_client
    organization_a_id = os.getenv(
        "MARTY_CONFORMANCE_ORGANIZATION_ID",
        MARTY_DEFAULT_ORGANIZATION_ID,
    ).strip()
    reviewer_email = os.getenv(
        "MARTY_CONFORMANCE_REVIEWER_EMAIL",
        "conformance.reviewer@elevenid.dev",
    ).strip()

    # First login links the deterministic Keycloak subject to the seeded
    # reviewer membership. Role assignment and every later check use only the
    # public gateway.
    reviewer_session = await _reviewer_session()
    await _grant_reviewer_boundary_roles(
        admin,
        organization_id=organization_a_id,
        reviewer_email=reviewer_email,
    )
    reviewer = GatewayClient()
    reviewer.set_session(reviewer_session)

    api_key_client = GatewayClient()
    try:
        organization_a_response = await reviewer.client.get(
            f"/v1/organizations/{organization_a_id}"
        )
        assert organization_a_response.status_code == 200, organization_a_response.text
        permissions_response = await reviewer.client.get(
            f"/v1/organizations/{organization_a_id}/members/me/permissions"
        )
        assert permissions_response.status_code == 200, permissions_response.text
        assigned_roles = {
            role["name"]
            for role in permissions_response.json().get("roles", [])
            if isinstance(role, dict) and role.get("name")
        }
        assert {"access_admin", "viewer"} <= assigned_roles

        organization_b = await admin.create_organization(
            **TestDataBuilder.organization()
        )
        organization_b_id = str(organization_b["id"])
        organization_b_name = str(
            organization_b.get("display_name") or organization_b.get("name") or ""
        )
        issuer_did_b = await _provision_issuer(admin, organization_b)

        # A real foreign SCIM resource must not be addressable by substituting
        # its member ID into the reviewer's organization-A URL.
        scim_email = f"foreign-{uuid.uuid4().hex}@example.test"
        scim_create = await admin.client.post(
            f"/v1/organizations/{organization_b_id}/scim/v2/Users",
            json={
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": scim_email,
                "externalId": f"foreign-user-{uuid.uuid4().hex}",
                "active": True,
            },
            headers={"Content-Type": "application/scim+json"},
        )
        assert scim_create.status_code == 201, scim_create.text
        foreign_member_id = str(scim_create.json()["id"])

        scim_direct = await reviewer.client.get(
            f"/v1/organizations/{organization_b_id}/scim/v2/Users/{foreign_member_id}"
        )
        _assert_public_denial(
            scim_direct,
            foreign_values=(organization_b_name, scim_email),
        )
        scim_substitution = await reviewer.client.get(
            f"/v1/organizations/{organization_a_id}/scim/v2/Users/{foreign_member_id}"
        )
        assert scim_substitution.status_code == 404, scim_substitution.text
        _assert_public_denial(
            scim_substitution,
            foreign_values=(organization_b_name, scim_email),
        )

        # Create a real foreign webhook. The organization query is mandatory
        # for ID routes and the service independently verifies ownership, so a
        # caller authorized in A cannot fetch B's URL or signing-secret metadata.
        webhook_name = f"Organization B callback {uuid.uuid4().hex}"
        webhook_create = await admin.client.post(
            "/v1/webhooks",
            json={
                "organization_id": organization_b_id,
                "name": webhook_name,
                "url": "https://example.com/elevenid-tenant-boundary",
                "event_types": ["credential.issued"],
            },
        )
        assert webhook_create.status_code == 200, webhook_create.text
        foreign_webhook = webhook_create.json()
        foreign_webhook_id = str(foreign_webhook["id"])
        foreign_webhook_secret = str(
            foreign_webhook.get("signing_secret") or ""
        )

        webhook_substitution = await reviewer.client.get(
            f"/v1/webhooks/{foreign_webhook_id}",
            params={"organization_id": organization_a_id},
        )
        assert webhook_substitution.status_code == 404, webhook_substitution.text
        _assert_public_denial(
            webhook_substitution,
            foreign_values=(
                organization_b_name,
                webhook_name,
                foreign_webhook_secret,
            ),
        )
        webhook_direct = await reviewer.client.get(
            "/v1/webhooks",
            params={"organization_id": organization_b_id},
        )
        _assert_public_denial(
            webhook_direct,
            foreign_values=(organization_b_name, webhook_name),
        )

        # A real B-scoped API key can read B, but the same key cannot select A.
        api_key_create = await admin.client.post(
            "/v1/api-keys",
            params={"organization_id": organization_b_id},
            json={
                "name": f"Tenant B boundary key {uuid.uuid4().hex}",
                "scopes": ["admin:full"],
                "is_test": True,
            },
        )
        assert api_key_create.status_code == 200, api_key_create.text
        foreign_api_key = str(api_key_create.json()["key"])
        api_headers = {"X-API-Key": foreign_api_key}

        key_b_response = await api_key_client.client.get(
            "/v1/credential-templates",
            params={"organization_id": organization_b_id},
            headers=api_headers,
        )
        assert key_b_response.status_code == 200, key_b_response.text
        key_a_response = await api_key_client.client.get(
            "/v1/credential-templates",
            params={"organization_id": organization_a_id},
            headers=api_headers,
        )
        _assert_public_denial(
            key_a_response,
            foreign_values=(organization_b_name, foreign_api_key),
        )

        # Create real policy, flow, instance, and result resources in B.
        template_b_data = await _employee_badge_template_data(
            admin,
            organization_id=organization_b_id,
            name=f"Organization B flow template {uuid.uuid4().hex}",
            issuer_did=issuer_did_b,
        )
        template_b = await admin.create_credential_template(**template_b_data)
        policy_b_data = TestDataBuilder.presentation_policy_age_verification(
            organization_id=organization_b_id,
            credential_template_id=template_b["id"],
            name=f"Organization B flow policy {uuid.uuid4().hex}",
        )
        policy_b = await admin.create_presentation_policy(**policy_b_data)
        policy_b = await admin.activate_presentation_policy(policy_b["id"])
        flow_b = await admin.create_flow_definition(
            organization_id=organization_b_id,
            name=f"Organization B verification flow {uuid.uuid4().hex}",
            flow_type="oid4vp_presentation",
            presentation_policy_id=policy_b["id"],
        )
        flow_b = await admin.activate_flow_definition(flow_b["id"])
        instance_b = await admin.start_flow_instance(flow_b["id"])

        for path in (
            f"/v1/flows/definitions/{flow_b['id']}",
            f"/v1/flows/instances/{instance_b['id']}",
            f"/v1/flows/instances/{instance_b['id']}/result",
        ):
            response = await reviewer.client.get(path)
            _assert_public_denial(
                response,
                foreign_values=(organization_b_name, flow_b["name"]),
            )

        flows_a = await reviewer.client.get(
            "/v1/flows/definitions",
            params={"organization_id": organization_a_id},
        )
        assert flows_a.status_code == 200, flows_a.text
        assert flow_b["id"] not in {
            flow.get("id")
            for flow in flows_a.json()
            if isinstance(flow, dict)
        }

        # API-key creation emits a real audit record. Its identifier must not
        # become an oracle when substituted into A's public audit route.
        foreign_events: list[dict[str, Any]] = []
        for _ in range(20):
            audit_b = await admin.client.get(
                f"/v1/organizations/{organization_b_id}/audit-events",
                params={"limit": 100},
            )
            assert audit_b.status_code == 200, audit_b.text
            foreign_events = [
                event
                for event in audit_b.json().get("events", [])
                if isinstance(event, dict) and event.get("id")
            ]
            if foreign_events:
                break
            await asyncio.sleep(0.25)
        assert foreign_events, "Organization B emitted no auditable events"
        audit_substitution = await reviewer.client.get(
            f"/v1/organizations/{organization_a_id}/audit-events/{foreign_events[0]['id']}"
        )
        assert audit_substitution.status_code == 404, audit_substitution.text
        _assert_public_denial(
            audit_substitution,
            foreign_values=(organization_b_name, scim_email, webhook_name),
        )

        audit_direct = await reviewer.client.get(
            f"/v1/organizations/{organization_b_id}/audit-events"
        )
        _assert_public_denial(
            audit_direct,
            foreign_values=(organization_b_name, scim_email, webhook_name),
        )
    finally:
        await reviewer.close()
        await api_key_client.close()
