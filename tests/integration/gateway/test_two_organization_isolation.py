"""Adversarial organization-isolation checks through Marty's public gateway.

These tests use public browser-equivalent sessions and scoped API keys to prove
that resource identifiers remain tenant-scoped. They exercise the same API
surface used by the UI and conformance fixtures; no internal service, test
adapter, or KMS endpoint is involved.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import os
import uuid
from typing import Any
from urllib.parse import urlsplit

import pytest

from .helpers.auth_helper import AuthHelper
from .helpers.gateway_client import GatewayClient, GatewayClientError
from .helpers.marty_wallet_client import MartyHeadlessWalletClient
from .helpers.test_data import TestDataBuilder

MARTY_DEFAULT_ORGANIZATION_ID = "00000000-0000-0000-0000-000000000001"
FORBIDDEN_PUBLIC_SIGNING_SELECTORS = (
    "issuer_profile_id",
    "signing_service_id",
    "signing_key_reference",
    "key_reference",
    "kms_provider",
)


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


def _assert_no_private_signing_selectors(value: Any, *, path: str = "$") -> None:
    """Prove that successful public responses do not disclose custody routing."""
    if isinstance(value, dict):
        for key, child in value.items():
            assert key not in FORBIDDEN_PUBLIC_SIGNING_SELECTORS, (
                f"Public response exposed private signing selector {path}.{key}"
            )
            _assert_no_private_signing_selectors(child, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _assert_no_private_signing_selectors(child, path=f"{path}[{index}]")


async def _next_sse_frame(lines: Any, *, timeout: float = 10.0) -> tuple[str, Any]:
    """Read one complete SSE frame from an already-open public stream."""

    async def read() -> tuple[str, Any]:
        event_type = "message"
        data_lines: list[str] = []
        while True:
            line = await anext(lines)
            if not line:
                if data_lines:
                    return event_type, json.loads("\n".join(data_lines))
                continue
            if line.startswith("event:"):
                event_type = line.removeprefix("event:").strip()
            elif line.startswith("data:"):
                data_lines.append(line.removeprefix("data:").lstrip())

    return await asyncio.wait_for(read(), timeout=timeout)


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
    profile = await _provision_issuer_profile(client, organization)
    return str(profile["issuer_did"])


async def _provision_issuer_profile(
    client: GatewayClient,
    organization: dict[str, Any],
    *,
    key_purpose: str = "vc_jwt_issuer",
    status: str = "active",
) -> dict[str, Any]:
    """Create a managed profile for setup while returning only test-owned metadata."""
    service = await _resolve_signing_service(
        client,
        str(organization["id"]),
        key_purpose=key_purpose,
    )
    issuer_did = _issuer_did(organization)
    profile = await client.create_issuer_profile(
        organization_id=str(organization["id"]),
        name=(
            f"{organization.get('name', organization['id'])} "
            f"{key_purpose} tenant-isolation issuer"
        ),
        issuer_did=issuer_did,
        signing_service_id=str(service["id"]),
        signing_key_reference=(str(service.get("key_reference")) if service.get("key_reference") else None),
        key_purpose=key_purpose,
        status=status,
    )
    assert profile["issuer_did"] == issuer_did
    assert profile["key_purpose"] == key_purpose
    assert profile["status"] == status
    return profile


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
async def test_public_signing_is_did_first_and_fails_closed(
    authenticated_gateway_client: GatewayClient,
) -> None:
    """Exercise DID-first public signing without changing an imported suite.

    Profile and service coordinates are used only to provision disposable
    managed identities through the administration API. Browser-equivalent
    issuance and verification requests receive only the organization and DID.
    """
    client = authenticated_gateway_client
    organization = await client.create_organization(**TestDataBuilder.organization())
    organization_id = str(organization["id"])
    issuance_profile = await _provision_issuer_profile(client, organization)
    issuer_did = str(issuance_profile["issuer_did"])
    request_profile = await _provision_issuer_profile(
        client,
        organization,
        key_purpose="oid4vp_request_signing",
    )
    assert request_profile["issuer_did"] == issuer_did

    # Repeating setup for the same DID/service/purpose tuple must be
    # idempotent. It may not create an ambiguous second active mapping.
    duplicate = await _provision_issuer_profile(client, organization)
    assert duplicate["id"] == issuance_profile["id"]

    template_data = await _employee_badge_template_data(
        client,
        organization_id=organization_id,
        name="DID-first public boundary template",
        issuer_did=issuer_did,
    )
    public_template_payload = {
        "organization_id": template_data["organization_id"],
        "name": template_data["name"],
        "credential_type": template_data["credential_type"],
        "vct": template_data["vct"],
        "supported_formats": template_data["supported_formats"],
        "claims": template_data["claims"],
        "credential_payload_format": template_data["credential_payload_format"],
        "compliance_profile_id": template_data["compliance_profile_id"],
        "revocation_profile_id": template_data["revocation_profile_id"],
        "issuer_did": template_data["issuer_did"],
        "schema_uri": template_data["schema"],
    }

    # Public authoring, issuance, and verification models must reject every
    # private custody selector. Values are synthetic and never real KMS data.
    for selector in FORBIDDEN_PUBLIC_SIGNING_SELECTORS:
        synthetic_value = f"untrusted-{selector}"

        rejected_template = await client.client.post(
            "/v1/credential-templates",
            json={**public_template_payload, selector: synthetic_value},
        )
        assert rejected_template.status_code == 422, rejected_template.text

        rejected_issuance = await client.client.post(
            "/v1/issuance",
            json={
                "organization_id": organization_id,
                "issuer_did": issuer_did,
                "claims": {"credential_format": "dc+sd-jwt"},
                selector: synthetic_value,
            },
        )
        assert rejected_issuance.status_code == 422, rejected_issuance.text

    # Claims cannot smuggle custody routing through the otherwise extensible
    # credential subject.
    for selector in FORBIDDEN_PUBLIC_SIGNING_SELECTORS:
        rejected_claim = await client.client.post(
            "/v1/issuance",
            json={
                "organization_id": organization_id,
                "issuer_did": issuer_did,
                "claims": {
                    "credential_format": "dc+sd-jwt",
                    selector: f"untrusted-claim-{selector}",
                },
            },
        )
        assert rejected_claim.status_code == 422, rejected_claim.text

    template = await client.create_credential_template(**template_data)
    template = await client.activate_credential_template(template["id"])
    _assert_no_private_signing_selectors(template)

    issued = await client.issue_credential(
        organization_id=organization_id,
        credential_template_id=template["id"],
        claims=TestDataBuilder.employee_badge_claims(),
        subject_did=f"did:key:z6Mk{uuid.uuid4().hex}",
    )
    _assert_no_private_signing_selectors(issued)

    policy_data = TestDataBuilder.presentation_policy_age_verification(
        organization_id=organization_id,
        credential_template_id=template["id"],
        name="DID-first public boundary policy",
    )
    policy = await client.create_presentation_policy(**policy_data)
    policy = await client.activate_presentation_policy(policy["id"])

    for selector in FORBIDDEN_PUBLIC_SIGNING_SELECTORS:
        rejected_verification = await client.client.post(
            "/v1/flows/verify",
            headers={"X-Organization-ID": organization_id},
            json={
                "organization_id": organization_id,
                "issuer_did": issuer_did,
                "presentation_policy_id": policy["id"],
                selector: f"untrusted-{selector}",
            },
        )
        assert rejected_verification.status_code == 422, rejected_verification.text

    verification = await client.start_verification_flow(
        presentation_policy_id=policy["id"],
        organization_id=organization_id,
        issuer_did=issuer_did,
    )
    _assert_no_private_signing_selectors(verification)

    # Unknown DIDs and DIDs with no compatible issuance-purpose profile must
    # fail before a signing service is invoked.
    unknown_did = f"did:example:unknown-{uuid.uuid4().hex}"
    unknown_response = await client.client.post(
        "/v1/issuance",
        json={
            "organization_id": organization_id,
            "issuer_did": unknown_did,
            "claims": {"credential_format": "dc+sd-jwt"},
        },
    )
    assert unknown_response.status_code in {403, 404, 409, 422}, unknown_response.text
    _assert_no_private_signing_selectors(unknown_response.json())

    request_only_organization = await client.create_organization(
        **TestDataBuilder.organization()
    )
    request_only_profile = await _provision_issuer_profile(
        client,
        request_only_organization,
        key_purpose="oid4vp_request_signing",
    )
    incompatible_response = await client.client.post(
        "/v1/issuance",
        json={
            "organization_id": str(request_only_organization["id"]),
            "issuer_did": str(request_only_profile["issuer_did"]),
            "claims": {"credential_format": "dc+sd-jwt"},
        },
    )
    assert incompatible_response.status_code in {
        403,
        404,
        409,
        422,
    }, incompatible_response.text
    _assert_no_private_signing_selectors(incompatible_response.json())

    # A draft profile is non-active in the profile lifecycle. Once issuance is
    # returned to draft, the DID must not fall back to the still-active
    # request-object profile with the same public DID.
    inactive_update = await client.client.patch(
        f"/v1/signing-keys/issuer-profiles/{issuance_profile['id']}",
        params={"organization_id": organization_id},
        json={"status": "draft"},
    )
    assert inactive_update.status_code == 200, inactive_update.text
    inactive_response = await client.client.post(
        "/v1/issuance",
        json={
            "organization_id": organization_id,
            "issuer_did": issuer_did,
            "claims": {"credential_format": "dc+sd-jwt"},
        },
    )
    assert inactive_response.status_code in {403, 404, 409, 422}, inactive_response.text
    _assert_no_private_signing_selectors(inactive_response.json())


@pytest.mark.asyncio
@pytest.mark.integration
async def test_two_principals_cannot_cross_tenant_product_boundaries(
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
    wallet = MartyHeadlessWalletClient(gateway_url=admin.base_url)
    try:
        organization_a_response = await reviewer.client.get(
            f"/v1/organizations/{organization_a_id}"
        )
        assert organization_a_response.status_code == 200, organization_a_response.text
        issuer_identities_a = await admin.list_issuer_identities(
            organization_id=organization_a_id,
            key_purpose="vc_jwt_issuer",
        )
        active_issuer_identities_a = issuer_identities_a.get("identities")
        assert isinstance(active_issuer_identities_a, list)
        assert len(active_issuer_identities_a) == 1, (
            "The default organization must expose exactly one active VC issuer "
            f"identity, got {active_issuer_identities_a}"
        )
        issuer_identity_a = active_issuer_identities_a[0]
        assert isinstance(issuer_identity_a, dict)
        _assert_no_private_signing_selectors(issuer_identity_a)
        assert str(issuer_identity_a.get("issuer_did") or "").startswith("did:")
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

        # Wallet catalogue entries may be global or organization-owned. Create
        # a real B override through the public administration API, prove B's
        # organization-bound machine principal can use it, and then attempt
        # enumeration, dereference, open-link, mutation, and deletion from A.
        wallet_name_b = f"Organization B wallet override {uuid.uuid4().hex}"
        wallet_create = await admin.client.post(
            "/v1/wallet-registry",
            json={
                "organization_id": organization_b_id,
                "name": wallet_name_b,
                "wallet_apps": [wallet_name_b],
                "deep_link_pattern": (
                    "tenant-b-wallet://open?inner={inner_uri_encoded}"
                ),
                "supported_platforms": ["web"],
                "supports_deeplink": True,
            },
        )
        assert wallet_create.status_code == 201, wallet_create.text
        wallet_b = wallet_create.json()
        wallet_b_id = str(wallet_b["id"])

        wallets_b = await api_key_client.client.get(
            "/v1/wallet-registry",
            params={"organization_id": organization_b_id},
            headers=api_headers,
        )
        assert wallets_b.status_code == 200, wallets_b.text
        assert wallet_b_id in {
            str(wallet.get("id"))
            for wallet in wallets_b.json()
            if isinstance(wallet, dict)
        }
        wallet_b_owner = await api_key_client.client.get(
            f"/v1/wallet-registry/{wallet_b_id}",
            headers=api_headers,
        )
        assert wallet_b_owner.status_code == 200, wallet_b_owner.text

        global_wallets_a = await reviewer.client.get("/v1/wallet-registry")
        assert global_wallets_a.status_code == 200, global_wallets_a.text
        assert wallet_b_id not in {
            str(wallet.get("id"))
            for wallet in global_wallets_a.json()
            if isinstance(wallet, dict)
        }
        wallets_a = await reviewer.client.get(
            "/v1/wallet-registry",
            params={"organization_id": organization_a_id},
        )
        assert wallets_a.status_code == 200, wallets_a.text
        assert wallet_b_id not in {
            str(wallet.get("id"))
            for wallet in wallets_a.json()
            if isinstance(wallet, dict)
        }

        foreign_wallet_list = await reviewer.client.get(
            "/v1/wallet-registry",
            params={"organization_id": organization_b_id},
        )
        _assert_public_denial(
            foreign_wallet_list,
            foreign_values=(wallet_b_id, wallet_name_b, organization_b_name),
        )
        foreign_wallet_requests = (
            (
                "GET",
                f"/v1/wallet-registry/{wallet_b_id}",
                None,
                None,
            ),
            (
                "GET",
                f"/v1/wallet-registry/{wallet_b_id}/open-link",
                None,
                {
                    "inner_uri": (
                        "openid-credential-offer://?credential_offer_uri="
                        "https%3A%2F%2Fissuer.example%2Foffers%2Fboundary"
                    )
                },
            ),
            (
                "PATCH",
                f"/v1/wallet-registry/{wallet_b_id}",
                {"name": "foreign wallet mutation"},
                None,
            ),
            (
                "DELETE",
                f"/v1/wallet-registry/{wallet_b_id}",
                None,
                None,
            ),
        )
        for method, path, body, params in foreign_wallet_requests:
            response = await reviewer.client.request(
                method,
                path,
                json=body,
                params=params,
            )
            _assert_public_denial(
                response,
                foreign_values=(wallet_b_id, wallet_name_b, organization_b_name),
            )

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
        template_b = await admin.activate_credential_template(template_b["id"])

        # Produce a real organization-B issuance transaction and its separate
        # issued-credential lifecycle record.  The owner control proves both
        # records exist before the organization-A reviewer attempts ID
        # substitution through the same public routes used by the UI.
        await wallet.create_wallet("Organization B boundary wallet")
        holder = await wallet.create_did()
        issuance_b = await admin.issue_credential(
            organization_id=organization_b_id,
            credential_template_id=template_b["id"],
            claims=TestDataBuilder.employee_badge_claims(),
            subject_did=str(holder["did"]),
        )
        issuance_b_id = str(issuance_b["id"])
        offer_uri = str(issuance_b.get("credential_offer_uri") or "")
        assert offer_uri, "Organization-B issuance produced no credential offer"
        try:
            accepted = await wallet.accept_credential_offer(
                offer_url=offer_uri,
                did=str(holder["did"]),
            )
        except RuntimeError as exc:
            transaction_diagnostic = await admin.client.get(
                f"/v1/issuance/{issuance_b_id}",
            )
            transaction_status = "unavailable"
            if transaction_diagnostic.status_code == 200:
                candidate_status = transaction_diagnostic.json().get("status")
                if candidate_status in {
                    "pending",
                    "approved",
                    "offered",
                    "signing",
                    "issued",
                    "failed",
                    "revoked",
                    "expired",
                }:
                    transaction_status = candidate_status
            raise AssertionError(
                "Real OID4VCI redemption failed before lifecycle isolation: "
                f"transaction_status={transaction_status}; {exc}"
            ) from None
        assert accepted["status"] == "accepted"
        owner_transaction = await admin.client.get(
            f"/v1/issuance/{issuance_b_id}",
        )
        assert owner_transaction.status_code == 200, owner_transaction.text

        owner_credentials = await admin.client.get(
            "/v1/issued-credentials",
            params={"organization_id": organization_b_id},
        )
        assert owner_credentials.status_code == 200, owner_credentials.text
        issued_credential_b = next(
            (
                credential
                for credential in owner_credentials.json()
                if isinstance(credential, dict)
                and str(credential.get("flow_execution_id") or "")
                == issuance_b_id
            ),
            None,
        )
        assert issued_credential_b is not None, (
            "Organization-B issuance produced no public lifecycle record"
        )
        issued_credential_b_id = str(issued_credential_b["id"])

        transaction_list_a = await reviewer.client.get(
            "/v1/issuance",
            params={"organization_id": organization_a_id},
        )
        assert transaction_list_a.status_code == 200, transaction_list_a.text
        assert issuance_b_id not in {
            str(transaction.get("id"))
            for transaction in transaction_list_a.json()
            if isinstance(transaction, dict)
        }
        credential_list_a = await reviewer.client.get(
            "/v1/issued-credentials",
            params={"organization_id": organization_a_id},
        )
        assert credential_list_a.status_code == 200, credential_list_a.text
        assert issued_credential_b_id not in {
            str(credential.get("id"))
            for credential in credential_list_a.json()
            if isinstance(credential, dict)
        }

        for method, path, body in (
            ("GET", f"/v1/issuance/{issuance_b_id}", None),
            ("GET", f"/v1/issuance/{issuance_b_id}/revocation-status", None),
            (
                "POST",
                f"/v1/issuance/{issuance_b_id}/revoke",
                {"reason": "foreign transaction substitution"},
            ),
            ("GET", f"/v1/issued-credentials/{issued_credential_b_id}", None),
            (
                "POST",
                f"/v1/issued-credentials/{issued_credential_b_id}/suspend",
                {"reason": "foreign lifecycle substitution"},
            ),
            (
                "POST",
                f"/v1/issued-credentials/{issued_credential_b_id}/revoke",
                {"reason": "foreign lifecycle substitution"},
            ),
            (
                "POST",
                f"/v1/issued-credentials/{issued_credential_b_id}/renew",
                None,
            ),
        ):
            response = await reviewer.client.request(
                method,
                path,
                json=body,
            )
            _assert_public_denial(
                response,
                foreign_values=(
                    organization_b_name,
                    issuance_b_id,
                    issued_credential_b_id,
                ),
            )

        # Trust configuration uses the same public resource sequence as the
        # UI: create an organization-scoped IssuerEntity, then link its UUID
        # to a TrustProfile.  It must not fall back to a denormalized pinned-DID
        # object or expose any signing/custody selector.
        trust_profile_b = await admin.create_trust_profile(
            organization_id=organization_b_id,
            name=f"Organization B trust policy {uuid.uuid4().hex}",
        )
        trust_profile_b_id = str(trust_profile_b["id"])
        trust_profile_b_name = str(trust_profile_b["name"])
        trust_profile_a = await admin.create_trust_profile(
            organization_id=organization_a_id,
            name=f"Organization A substitution target {uuid.uuid4().hex}",
        )
        trust_profile_a_id = str(trust_profile_a["id"])

        issuer_entity_b_did = f"did:web:trust-{uuid.uuid4().hex}.example"
        issuer_entity_b_name = f"Organization B trust issuer {uuid.uuid4().hex}"
        issuer_entity_payload = {
            "organization_id": organization_b_id,
            "issuer_id": issuer_entity_b_did,
            "issuer_type": "ORGANIZATION",
            "display_name": issuer_entity_b_name,
            "description": "Foreign tenant issuer-registry evidence",
            "metadata": {"jurisdiction": "US"},
        }
        issuer_entity_create = await admin.client.post(
            "/v1/issuer-entities",
            json=issuer_entity_payload,
        )
        assert issuer_entity_create.status_code in {200, 201}, issuer_entity_create.text
        issuer_entity_b = issuer_entity_create.json()
        issuer_entity_b_id = str(issuer_entity_b["id"])
        assert issuer_entity_b["organization_id"] == organization_b_id
        assert issuer_entity_b["issuer_id"] == issuer_entity_b_did
        _assert_no_private_signing_selectors(issuer_entity_b)

        relationship_create = await admin.client.post(
            f"/v1/trust-profiles/{trust_profile_b_id}/issuers",
            json={
                "issuer_id": issuer_entity_b_id,
                "trust_level": 100,
                "relationship_status": "TRUSTED",
                "cascade_revocation_policy": "NOTIFY_ONLY",
                "metadata": {"credential_template_ids": []},
            },
        )
        assert relationship_create.status_code in {200, 201}, relationship_create.text
        relationship_b = relationship_create.json()
        relationship_b_id = str(relationship_b["id"])
        assert relationship_b["trust_profile_id"] == trust_profile_b_id
        assert relationship_b["issuer_id"] == issuer_entity_b_id
        assert "issuer_did" not in relationship_b
        assert "name" not in relationship_b
        _assert_no_private_signing_selectors(relationship_b)

        # Extensible metadata is not a custody escape hatch.  Both selector
        # fields and private JWK parameters must fail before persistence.
        for selector in FORBIDDEN_PUBLIC_SIGNING_SELECTORS:
            rejected_entity = await admin.client.post(
                "/v1/issuer-entities",
                json={
                    **issuer_entity_payload,
                    "issuer_id": f"did:example:rejected-{selector}-{uuid.uuid4().hex}",
                    "metadata": {"nested": {selector: "untrusted-custody-route"}},
                },
            )
            assert rejected_entity.status_code == 422, rejected_entity.text

            rejected_relationship = await admin.client.post(
                f"/v1/trust-profiles/{trust_profile_b_id}/issuers",
                json={
                    "issuer_id": issuer_entity_b_id,
                    "metadata": {"nested": {selector: "untrusted-custody-route"}},
                },
            )
            assert rejected_relationship.status_code == 422, rejected_relationship.text

        rejected_private_jwk = await admin.client.post(
            "/v1/issuer-entities",
            json={
                **issuer_entity_payload,
                "issuer_id": f"did:example:private-jwk-{uuid.uuid4().hex}",
                "metadata": {
                    "verification_keys": [
                        {
                            "kty": "EC",
                            "crv": "P-256",
                            "x": "public-x",
                            "y": "public-y",
                            "d": "must-remain-in-managed-custody",
                        }
                    ]
                },
            },
        )
        assert rejected_private_jwk.status_code == 422, rejected_private_jwk.text

        owner_entity_list = await admin.client.get(
            "/v1/issuer-entities",
            params={"organization_id": organization_b_id},
        )
        assert owner_entity_list.status_code == 200, owner_entity_list.text
        assert issuer_entity_b_id in {
            str(entity.get("id"))
            for entity in owner_entity_list.json()
            if isinstance(entity, dict)
        }
        owner_entity = await admin.client.get(
            f"/v1/issuer-entities/{issuer_entity_b_id}"
        )
        assert owner_entity.status_code == 200, owner_entity.text
        owner_entity_update = await admin.client.patch(
            f"/v1/issuer-entities/{issuer_entity_b_id}",
            json={
                "organization_id": organization_b_id,
                "display_name": f"{issuer_entity_b_name} updated",
            },
        )
        assert owner_entity_update.status_code == 200, owner_entity_update.text

        owner_relationships = await admin.client.get(
            f"/v1/trust-profiles/{trust_profile_b_id}/issuers"
        )
        assert owner_relationships.status_code == 200, owner_relationships.text
        assert relationship_b_id in {
            str(relationship.get("id"))
            for relationship in owner_relationships.json()
            if isinstance(relationship, dict)
        }
        owner_relationship = await admin.client.get(
            f"/v1/trust-profiles/{trust_profile_b_id}/issuers/{relationship_b_id}"
        )
        assert owner_relationship.status_code == 200, owner_relationship.text
        owner_relationship_update = await admin.client.patch(
            f"/v1/trust-profiles/{trust_profile_b_id}/issuers/{relationship_b_id}",
            json={
                "trust_level": 85,
                "relationship_status": "UNDER_REVIEW",
                "cascade_revocation_policy": "MANUAL",
                "metadata": {"credential_template_ids": []},
            },
        )
        assert owner_relationship_update.status_code == 200, owner_relationship_update.text
        assert owner_relationship_update.json()["trust_level"] == 85

        # A trust profile and its issuer registry/relationship resources are
        # tenant-owned security policy. Prove the B owner path first, then
        # ensure an A-only principal cannot enumerate or substitute their IDs.
        owner_trust_profile = await admin.client.get(
            f"/v1/trust-profiles/{trust_profile_b_id}",
        )
        assert owner_trust_profile.status_code == 200, owner_trust_profile.text

        trust_profiles_a = await reviewer.client.get(
            "/v1/trust-profiles",
            params={"organization_id": organization_a_id},
        )
        assert trust_profiles_a.status_code == 200, trust_profiles_a.text
        assert trust_profile_b_id not in {
            str(profile.get("id"))
            for profile in trust_profiles_a.json()
            if isinstance(profile, dict)
        }

        issuer_entities_a = await reviewer.client.get(
            "/v1/issuer-entities",
            params={"organization_id": organization_a_id},
        )
        assert issuer_entities_a.status_code == 200, issuer_entities_a.text
        assert issuer_entity_b_id not in {
            str(entity.get("id"))
            for entity in issuer_entities_a.json()
            if isinstance(entity, dict)
        }
        assert issuer_entity_b_did not in {
            str(entity.get("issuer_id"))
            for entity in issuer_entities_a.json()
            if isinstance(entity, dict)
        }

        for method, path, body in (
            ("GET", f"/v1/issuer-entities/{issuer_entity_b_id}", None),
            (
                "PATCH",
                f"/v1/issuer-entities/{issuer_entity_b_id}",
                {
                    "organization_id": organization_a_id,
                    "display_name": "foreign issuer-entity substitution",
                },
            ),
            ("DELETE", f"/v1/issuer-entities/{issuer_entity_b_id}", None),
            (
                "GET",
                f"/v1/trust-profiles/{trust_profile_b_id}/issuers/{relationship_b_id}",
                None,
            ),
            (
                "PATCH",
                f"/v1/trust-profiles/{trust_profile_b_id}/issuers/{relationship_b_id}",
                {"trust_level": 1},
            ),
            (
                "DELETE",
                f"/v1/trust-profiles/{trust_profile_b_id}/issuers/{relationship_b_id}",
                None,
            ),
            (
                "GET",
                f"/v1/trust-profiles/{trust_profile_a_id}/issuers/{relationship_b_id}",
                None,
            ),
        ):
            response = await reviewer.client.request(method, path, json=body)
            _assert_public_denial(
                response,
                foreign_values=(
                    organization_b_name,
                    issuer_entity_b_name,
                    issuer_entity_b_did,
                    issuer_entity_b_id,
                    relationship_b_id,
                ),
            )

        for method, path, body in (
            ("GET", f"/v1/trust-profiles/{trust_profile_b_id}", None),
            (
                "PATCH",
                f"/v1/trust-profiles/{trust_profile_b_id}",
                {"name": "foreign trust-profile substitution"},
            ),
            ("POST", f"/v1/trust-profiles/{trust_profile_b_id}/activate", None),
        ):
            response = await reviewer.client.request(
                method,
                path,
                json=body,
            )
            _assert_public_denial(
                response,
                foreign_values=(
                    organization_b_name,
                    trust_profile_b_name,
                    trust_profile_b_id,
                    issuer_did_b,
                ),
            )

        owner_relationship_delete = await admin.client.delete(
            f"/v1/trust-profiles/{trust_profile_b_id}/issuers/{relationship_b_id}"
        )
        assert owner_relationship_delete.status_code == 200, owner_relationship_delete.text
        deleted_relationship = await admin.client.get(
            f"/v1/trust-profiles/{trust_profile_b_id}/issuers/{relationship_b_id}"
        )
        assert deleted_relationship.status_code == 404, deleted_relationship.text

        owner_entity_delete = await admin.client.delete(
            f"/v1/issuer-entities/{issuer_entity_b_id}"
        )
        assert owner_entity_delete.status_code == 200, owner_entity_delete.text
        deleted_entity = await admin.client.get(
            f"/v1/issuer-entities/{issuer_entity_b_id}"
        )
        assert deleted_entity.status_code == 404, deleted_entity.text

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
        instance_b = await admin.start_flow_instance(
            organization_id=organization_b_id,
            flow_definition_id=flow_b["id"],
        )

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

        # Applications contain applicant PII and generate vetting state. The
        # self-service contract is bound to the principal's session organization,
        # so create a real A-owned application as the A reviewer and use B's
        # organization-bound API key as the foreign principal. This exercises
        # the same holder and reviewer routes as the UI without forging an
        # impossible B session for the organization-A user.
        applicant_secret = f"applicant-{uuid.uuid4().hex}@example.com"
        templates_a = await admin.list_credential_templates(organization_a_id)
        active_template_a = next(
            (
                template
                for template in templates_a
                if isinstance(template, dict)
                and template.get("id")
                and str(template.get("status") or "").upper() == "ACTIVE"
            ),
            None,
        )
        assert active_template_a is not None, (
            "Default organization has no active credential template for the "
            "current applicant journey"
        )
        application_template_a = await admin.create_application_template(
            organization_id=organization_a_id,
            name=f"Organization A applicant workflow {uuid.uuid4().hex}",
            credential_template_id=active_template_a["id"],
            form_fields=[
                {
                    "field_id": "email",
                    "field_type": "EMAIL",
                    "label": "Email",
                    "required": True,
                }
            ],
            evidence_requirements=[
                {
                    "evidence_id": "identity_scan",
                    "evidence_type": "DOCUMENT_SCAN",
                    "description": "Current government identity scan",
                    "required": True,
                    "accepted_formats": ["image/png"],
                    "max_file_size_bytes": 4096,
                }
            ],
            approval_strategy="MANUAL",
        )
        application_template_a = await admin.activate_application_template(
            application_template_a["id"]
        )
        assert str(application_template_a.get("status") or "").upper() == "ACTIVE"

        applicant_profile = await reviewer.client.patch(
            "/v1/me/applicant-profile",
            json={
                "email": applicant_secret,
                "given_name": "Boundary",
                "family_name": "Applicant",
            },
        )
        assert applicant_profile.status_code == 200, applicant_profile.text
        applicant_profile_body = applicant_profile.json()
        assert applicant_profile_body.get("organization_id") == organization_a_id
        assert applicant_profile_body.get("email") == applicant_secret

        application_create = await reviewer.client.post(
            "/v1/me/applications",
            json={
                "organization_id": organization_a_id,
                "application_template_id": application_template_a["id"],
                "form_data": {
                    "email": applicant_secret,
                },
            },
        )
        assert application_create.status_code in {200, 201}, application_create.text
        application_a = application_create.json()
        application_a_id = str(application_a["id"])

        # Submission must fail closed until the holder supplies the exact
        # application-bound evidence required by the active template.
        missing_evidence = await reviewer.client.post(
            f"/v1/me/applications/{application_a_id}/submit"
        )
        assert missing_evidence.status_code == 422, missing_evidence.text

        evidence_bytes = b"released-stack tenant-boundary identity scan"
        evidence_payload = {
            "evidence_requirement_id": "identity_scan",
            "media_type": "image/png",
            "filename": "identity-scan.png",
            "content_base64": base64.b64encode(evidence_bytes).decode("ascii"),
        }
        first_upload = await reviewer.client.post(
            f"/v1/me/applications/{application_a_id}/evidence",
            json=evidence_payload,
        )
        assert first_upload.status_code == 200, first_upload.text
        first_evidence_id = str(first_upload.json()["id"])

        # Deletion removes the bytes from the current public path and restores
        # the required-evidence submission failure before a replacement upload.
        evidence_delete = await reviewer.client.delete(
            f"/v1/me/applications/{application_a_id}/evidence/{first_evidence_id}"
        )
        assert evidence_delete.status_code == 200, evidence_delete.text
        deleted_download = await reviewer.client.get(
            f"/v1/me/applications/{application_a_id}/evidence/{first_evidence_id}/content"
        )
        assert deleted_download.status_code == 404, deleted_download.text
        missing_after_delete = await reviewer.client.post(
            f"/v1/me/applications/{application_a_id}/submit"
        )
        assert missing_after_delete.status_code == 422, missing_after_delete.text

        evidence_upload = await reviewer.client.post(
            f"/v1/me/applications/{application_a_id}/evidence",
            json=evidence_payload,
        )
        assert evidence_upload.status_code == 200, evidence_upload.text
        evidence = evidence_upload.json()
        evidence_id = str(evidence["id"])
        assert evidence["organization_id"] == organization_a_id
        assert evidence["application_id"] == application_a_id
        assert evidence["sha256"] == hashlib.sha256(evidence_bytes).hexdigest()
        assert evidence["status"] == "ACTIVE"
        assert evidence["content_url"].startswith("/v1/me/applications/")
        _assert_no_private_signing_selectors(evidence)
        for forbidden_field in (
            "storage_key",
            "storage_path",
            "bucket",
            "service_id",
            "provider_id",
            "kms_id",
        ):
            assert forbidden_field not in evidence

        owner_evidence_list = await reviewer.client.get(
            f"/v1/me/applications/{application_a_id}/evidence"
        )
        assert owner_evidence_list.status_code == 200, owner_evidence_list.text
        assert evidence_id in {
            str(item.get("id"))
            for item in owner_evidence_list.json()
            if isinstance(item, dict)
        }
        owner_evidence_download = await reviewer.client.get(evidence["content_url"])
        assert owner_evidence_download.status_code == 200, owner_evidence_download.text
        assert owner_evidence_download.content == evidence_bytes
        assert owner_evidence_download.headers["cache-control"] == "private, no-store"

        application_submit = await reviewer.client.post(
            f"/v1/me/applications/{application_a_id}/submit"
        )
        assert application_submit.status_code == 200, application_submit.text
        application_a = application_submit.json()
        assert str(application_a.get("status") or "").upper() in {
            "SUBMITTED",
            "UNDER_REVIEW",
        }, application_a

        owner_application = await reviewer.client.get(
            f"/v1/me/applications/{application_a_id}"
        )
        assert owner_application.status_code == 200, owner_application.text
        owner_application_body = owner_application.json()
        assert owner_application_body.get("form_data") == {
            "email": applicant_secret,
        }

        owner_applicant = await admin.client.get(
            f"/v1/organizations/{organization_a_id}/applicants/{application_a_id}"
        )
        assert owner_applicant.status_code == 200, owner_applicant.text
        owner_applicant_body = owner_applicant.json()
        assert owner_applicant_body.get("form_data") == {
            "email": applicant_secret,
        }
        owner_checks = await admin.client.get(
            f"/v1/organizations/{organization_a_id}/applicants/{application_a_id}/checks"
        )
        assert owner_checks.status_code == 200, owner_checks.text
        owner_checks_body = owner_checks.json()
        assert isinstance(owner_checks_body, list)
        assert owner_checks_body, "Submitted manual-review application created no vetting checks"

        owner_reviewer_evidence = await admin.client.get(
            f"/v1/organizations/{organization_a_id}/applicants/{application_a_id}/evidence"
        )
        assert owner_reviewer_evidence.status_code == 200, owner_reviewer_evidence.text
        assert evidence_id in {
            str(item.get("id"))
            for item in owner_reviewer_evidence.json()
            if isinstance(item, dict)
        }
        reviewer_download = await admin.client.get(
            f"/v1/organizations/{organization_a_id}/applicants/{application_a_id}/evidence/{evidence_id}/content"
        )
        assert reviewer_download.status_code == 200, reviewer_download.text
        assert reviewer_download.content == evidence_bytes

        # Use a second manual-review application for the notification test so
        # approval does not weaken the original application's revoked-evidence
        # fail-closed assertion below. Applications intentionally reject a
        # second active application for the same applicant and credential
        # template, so bind this independent journey to a different active
        # template already provisioned through the public catalogue.
        notification_credential_template = next(
            (
                template
                for template in templates_a
                if isinstance(template, dict)
                and template.get("id") != active_template_a["id"]
                and str(template.get("status") or "").upper() == "ACTIVE"
            ),
            None,
        )
        assert notification_credential_template is not None, (
            "Default organization needs a second active credential template "
            "for the independent notification application journey"
        )
        sse_application_template = await admin.create_application_template(
            organization_id=organization_a_id,
            name=f"Organization A notification workflow {uuid.uuid4().hex}",
            credential_template_id=notification_credential_template["id"],
            form_fields=[
                {
                    "field_id": "email",
                    "field_type": "EMAIL",
                    "label": "Email",
                    "required": True,
                }
            ],
            approval_strategy="MANUAL",
        )
        sse_application_template = await admin.activate_application_template(
            sse_application_template["id"]
        )
        sse_application_create = await reviewer.client.post(
            "/v1/me/applications",
            json={
                "organization_id": organization_a_id,
                "application_template_id": sse_application_template["id"],
                "form_data": {"email": applicant_secret},
            },
        )
        assert sse_application_create.status_code in {200, 201}, (
            sse_application_create.text
        )
        sse_application = sse_application_create.json()
        sse_application_id = str(sse_application["id"])
        sse_submit = await reviewer.client.post(
            f"/v1/me/applications/{sse_application_id}/submit"
        )
        assert sse_submit.status_code == 200, sse_submit.text

        # Open two real public SSE connections before approving the A-owned
        # notification application. The A browser session must receive the originating
        # event, while the independent B-scoped API key must receive nothing.
        async with (
            reviewer.client.stream(
                "GET",
                "/v1/notifications/events/push",
                params={
                    "organization_id": organization_a_id,
                    "subscriptions": "application.approved",
                },
            ) as organization_a_events,
            api_key_client.client.stream(
                "GET",
                "/v1/notifications/events/push",
                params={
                    "organization_id": organization_b_id,
                    "subscriptions": "application.approved",
                },
                headers=api_headers,
            ) as organization_b_events,
        ):
            assert organization_a_events.status_code == 200, (
                await organization_a_events.aread()
            ).decode(errors="replace")
            assert organization_b_events.status_code == 200, (
                await organization_b_events.aread()
            ).decode(errors="replace")
            lines_a = organization_a_events.aiter_lines()
            lines_b = organization_b_events.aiter_lines()
            assert await _next_sse_frame(lines_a) == (
                "message",
                {"type": "connected"},
            )
            assert await _next_sse_frame(lines_b) == (
                "message",
                {"type": "connected"},
            )

            lock = await admin.client.post(
                f"/v1/organizations/{organization_a_id}/applicants/"
                f"{sse_application_id}/lock",
                json={},
            )
            assert lock.status_code == 200, lock.text

            event_a_task = asyncio.create_task(_next_sse_frame(lines_a))
            event_b_task = asyncio.create_task(_next_sse_frame(lines_b, timeout=30))
            approval = await admin.client.post(
                f"/v1/organizations/{organization_a_id}/applicants/"
                f"{sse_application_id}/approve",
                json={"notes": "tenant-boundary SSE delivery"},
            )
            assert approval.status_code == 200, approval.text

            event_type_a, event_a = await event_a_task
            assert event_type_a == "application.approved"
            assert event_a["organization_id"] == organization_a_id
            assert event_a["aggregate_id"] == sse_application_id
            assert event_a["data"]["application_id"] == sse_application_id
            assert event_a["data"]["applicant_id"] == sse_application["applicant_id"]

            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.shield(event_b_task), timeout=1.0)
            event_b_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await event_b_task

        applicants_b = await api_key_client.client.get(
            f"/v1/organizations/{organization_b_id}/applicants",
            headers=api_headers,
        )
        assert applicants_b.status_code == 200, applicants_b.text
        applicants_b_body = applicants_b.json()
        assert isinstance(applicants_b_body, dict), applicants_b_body
        assert application_a_id not in {
            str(applicant.get("id") or applicant.get("application_id"))
            for applicant in applicants_b_body.get("items", [])
            if isinstance(applicant, dict)
        }

        for path in (
            f"/v1/organizations/{organization_a_id}/applicants/{application_a_id}",
            f"/v1/organizations/{organization_b_id}/applicants/{application_a_id}",
            f"/v1/organizations/{organization_b_id}/applicants/{application_a_id}/checks",
            f"/v1/organizations/{organization_b_id}/applicants/{application_a_id}/evidence",
            f"/v1/organizations/{organization_b_id}/applicants/{application_a_id}/evidence/{evidence_id}",
            f"/v1/organizations/{organization_b_id}/applicants/{application_a_id}/evidence/{evidence_id}/content",
        ):
            response = await api_key_client.client.get(path, headers=api_headers)
            _assert_public_denial(
                response,
                foreign_values=(
                    application_a_id,
                    applicant_secret,
                ),
            )

        applicant_mutation = await api_key_client.client.post(
            f"/v1/organizations/{organization_b_id}/applicants/{application_a_id}/request-information",
            json={"message": "foreign applicant substitution"},
            headers=api_headers,
        )
        _assert_public_denial(
            applicant_mutation,
            foreign_values=(
                application_a_id,
                applicant_secret,
            ),
        )

        # A reviewer can bind only same-application evidence to a check. The
        # canonical response records the evidence ID without exposing custody.
        reviewer_lock = await admin.client.post(
            f"/v1/organizations/{organization_a_id}/applicants/{application_a_id}/lock",
            json={},
        )
        assert reviewer_lock.status_code == 200, reviewer_lock.text
        check_id = str(owner_checks_body[0]["id"])
        completed_check = await admin.client.post(
            f"/v1/organizations/{organization_a_id}/applicants/{application_a_id}/checks/{check_id}/complete",
            json={
                "passed": True,
                "notes": "Released-stack evidence binding control",
                "evidence_submission_ids": [evidence_id],
            },
        )
        assert completed_check.status_code == 200, completed_check.text
        assert completed_check.json().get("evidence_refs") == [evidence_id]

        revoked_evidence = await admin.client.post(
            f"/v1/organizations/{organization_a_id}/applicants/{application_a_id}/evidence/{evidence_id}/revoke",
            json={"reason": "Released-stack revocation control"},
        )
        assert revoked_evidence.status_code == 200, revoked_evidence.text
        assert revoked_evidence.json()["status"] == "REVOKED"
        revoked_download = await admin.client.get(
            revoked_evidence.json()["content_url"]
        )
        assert revoked_download.status_code == 410, revoked_download.text
        approval_with_revoked_evidence = await admin.client.post(
            f"/v1/organizations/{organization_a_id}/applicants/{application_a_id}/approve",
            json={"notes": "must fail after evidence revocation"},
        )
        assert approval_with_revoked_evidence.status_code == 422, (
            approval_with_revoked_evidence.text
        )

        # Deployment profiles bind trust, presentation, credential, flow, API
        # key, lane, and device configuration. A leaked profile or lane ID must
        # not let an A principal read B configuration or trigger mutations.
        deployment_name = f"Organization B deployment {uuid.uuid4().hex}"
        deployment_create = await admin.client.post(
            "/v1/deployment-profiles",
            json={
                "organization_id": organization_b_id,
                "name": deployment_name,
                "environment": "development",
                "trust_profile_id": trust_profile_b_id,
                "presentation_policy_ids": [policy_b["id"]],
                "credential_template_ids": [template_b["id"]],
                "default_policy_id": policy_b["id"],
                "enabled_flow_ids": [flow_b["id"]],
                "network_mode": "ONLINE",
            },
        )
        assert deployment_create.status_code in {200, 201}, deployment_create.text
        deployment_b = deployment_create.json()
        deployment_b_id = str(deployment_b["id"])

        lane_name = f"Organization B lane {uuid.uuid4().hex}"
        lane_create = await admin.client.post(
            f"/v1/deployment-profiles/{deployment_b_id}/lanes",
            json={
                "name": lane_name,
                "description": "Foreign organization boundary lane",
                "location": "Private organization B site",
                "device_type": "kiosk",
            },
        )
        assert lane_create.status_code in {200, 201}, lane_create.text
        lane_b = lane_create.json()
        lane_b_id = str(lane_b["id"])

        owner_deployment = await admin.client.get(f"/v1/deployment-profiles/{deployment_b_id}")
        assert owner_deployment.status_code == 200, owner_deployment.text
        owner_lane = await admin.client.get(f"/v1/deployment-profiles/{deployment_b_id}/lanes/{lane_b_id}")
        assert owner_lane.status_code == 200, owner_lane.text

        deployments_a = await reviewer.client.get(
            "/v1/deployment-profiles",
            params={"organization_id": organization_a_id},
        )
        assert deployments_a.status_code == 200, deployments_a.text
        assert deployment_b_id not in {
            str(profile.get("id")) for profile in deployments_a.json() if isinstance(profile, dict)
        }

        for method, path, body in (
            ("GET", f"/v1/deployment-profiles/{deployment_b_id}", None),
            (
                "PATCH",
                f"/v1/deployment-profiles/{deployment_b_id}",
                {"name": "foreign deployment substitution"},
            ),
            ("POST", f"/v1/deployment-profiles/{deployment_b_id}/activate", None),
            (
                "POST",
                f"/v1/deployment-profiles/{deployment_b_id}/generate-api-key",
                None,
            ),
            ("GET", f"/v1/deployment-profiles/{deployment_b_id}/lanes", None),
            (
                "GET",
                f"/v1/deployment-profiles/{deployment_b_id}/lanes/{lane_b_id}",
                None,
            ),
            (
                "PUT",
                f"/v1/deployment-profiles/{deployment_b_id}/lanes/{lane_b_id}",
                {
                    "name": "foreign lane substitution",
                    "device_type": "kiosk",
                },
            ),
            (
                "POST",
                f"/v1/deployment-profiles/{deployment_b_id}/lanes/{lane_b_id}/devices",
                {
                    "device_id": f"foreign-device-{uuid.uuid4().hex}",
                    "device_name": "Foreign device substitution",
                },
            ),
        ):
            response = await reviewer.client.request(method, path, json=body)
            _assert_public_denial(
                response,
                foreign_values=(
                    organization_b_name,
                    deployment_name,
                    lane_name,
                    deployment_b_id,
                    lane_b_id,
                ),
            )

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
        await wallet.close()
        await reviewer.close()
        await api_key_client.close()
