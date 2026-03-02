"""
Integration tests for organization-scoped authorization.

Tests verify that:
1. Users cannot access organizations they are not members of
2. Users with admin role CAN perform admin actions in their own org
3. Cross-organization attacks are blocked by OrgAuthMiddleware (403)

Notes:
- For "foreign org" tests we use a random UUID the test user is NOT a member of.
  Because ``OrgAuthMiddleware`` returns 403 for any org where the user has no
  membership record, this works without needing a second pre-seeded organization.
- Tests that require a second *user* (different role) are skipped with an
  explanation — they cannot run without dedicated Keycloak test accounts.
"""

import uuid

import pytest

from .helpers.gateway_client import GatewayClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _foreign_org_id() -> str:
    """Return a random org UUID the authenticated test user is definitely not in."""
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Membership access enforcement
# ---------------------------------------------------------------------------

class TestOrganizationMembershipEnforcement:
    """Test that OrgAuthMiddleware enforces membership on org-scoped routes."""

    @pytest.mark.asyncio
    async def test_non_member_cannot_access_org_details(
        self, gateway_client: GatewayClient
    ):
        """Authenticated user accessing an org they are NOT a member of gets 403."""
        org_b_id = _foreign_org_id()
        response = await gateway_client.client.get(f"/v1/organizations/{org_b_id}")
        assert response.status_code == 403
        assert "Not a member" in response.json().get("detail", "")

    @pytest.mark.asyncio
    async def test_member_can_access_org_details(
        self,
        gateway_client: GatewayClient,
        test_organization: dict,
    ):
        """Authenticated admin user can read their own organization."""
        org_id = test_organization["id"]
        response = await gateway_client.client.get(f"/v1/organizations/{org_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == org_id

    @pytest.mark.skip(
        reason=(
            "Requires a second Keycloak test account with 'member' role in the "
            "test org.  Skip until dedicated multi-user fixture support is added."
        )
    )
    @pytest.mark.asyncio
    async def test_member_cannot_invite_others(
        self, gateway_client: GatewayClient, test_organization: dict
    ):
        """User with member role cannot invite new members (admin-only action)."""
        # This test needs a second authenticated session with member (not admin) role.
        pass

    @pytest.mark.skip(
        reason=(
            "Member invitation endpoint (POST /v1/organizations/{id}/members) is not "
            "yet implemented — returns 404.  Re-enable when the endpoint ships."
        )
    )
    @pytest.mark.asyncio
    async def test_admin_can_invite_members(
        self,
        gateway_client: GatewayClient,
        test_organization: dict,
    ):
        """Org admin can invite members to their organization."""
        org_id = test_organization["id"]
        email = f"invitee-{uuid.uuid4().hex[:8]}@example.com"
        response = await gateway_client.client.post(
            f"/v1/organizations/{org_id}/members",
            json={"email": email, "role": "member"},
        )
        # 200 (created/invited) or 201
        assert response.status_code in (200, 201), response.text
        data = response.json()
        assert data.get("email") == email or data.get("id") is not None


# ---------------------------------------------------------------------------
# Cross-organization attack prevention
# ---------------------------------------------------------------------------

class TestCrossOrganizationAttacks:
    """Users cannot perform actions across organization boundaries."""

    @pytest.mark.asyncio
    async def test_cannot_invite_to_other_org(
        self, gateway_client: GatewayClient
    ):
        """Admin in Org A cannot invite members to a foreign Org B."""
        org_b_id = _foreign_org_id()
        response = await gateway_client.client.post(
            f"/v1/organizations/{org_b_id}/members",
            json={"email": "attacker@example.com", "role": "admin"},
        )
        assert response.status_code == 403
        assert "Not a member" in response.json().get("detail", "")

    @pytest.mark.asyncio
    async def test_cannot_create_api_keys_for_other_org(
        self, gateway_client: GatewayClient
    ):
        """Admin in Org A cannot create API keys for a foreign Org B."""
        org_b_id = _foreign_org_id()
        response = await gateway_client.client.post(
            f"/v1/organizations/{org_b_id}/api-keys",
            json={"name": "Malicious Key", "description": "cross-org attack"},
        )
        assert response.status_code == 403
        assert "Not a member" in response.json().get("detail", "")

    @pytest.mark.asyncio
    async def test_cannot_access_other_org_members(
        self, gateway_client: GatewayClient
    ):
        """Authenticated user cannot list members of a foreign organization."""
        org_b_id = _foreign_org_id()
        response = await gateway_client.client.get(
            f"/v1/organizations/{org_b_id}/members"
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_cannot_create_credential_template_in_other_org(
        self, gateway_client: GatewayClient
    ):
        """User cannot create credential templates for a foreign organization.

        Two acceptable server behaviours (both block the attack):
        1. Hard block: 403 / 404 returned immediately.
        2. Silent BOLA protection: 200 returned but the ``organization_id``
           is silently overridden to the requester's own org, so the template
           is NOT created in the foreign org.
        """
        org_b_id = _foreign_org_id()
        response = await gateway_client.client.post(
            "/v1/credential-templates",
            json={
                "organization_id": org_b_id,
                "name": "Malicious Template",
                "credential_type": "test",
                "vct": "test.malicious",
                "description": "cross-org attack",
                "compliance_profile": {
                    "name": "Attack Profile",
                    "compliance_code": "AAMVA_MDL",
                    "credential_format": "mdoc",
                    "frameworks": ["aamva"],
                },
            },
        )
        if response.status_code == 200:
            # Silent BOLA protection: the service silently overrode the
            # organization_id to the requester's own org.
            data = response.json()
            assert data.get("organization_id") != org_b_id, (
                f"Template was created in foreign org {org_b_id} — BOLA not "
                f"blocked!  Response: {response.text}"
            )
        else:
            assert response.status_code in (403, 404), response.text


# ---------------------------------------------------------------------------
# Cache invalidation (requires second user — skipped)
# ---------------------------------------------------------------------------

@pytest.mark.skip(
    reason=(
        "All cache-invalidation tests require two distinct Keycloak sessions "
        "(admin + member).  Skip until multi-user fixture support is added."
    )
)
class TestCacheInvalidation:
    """Membership cache is properly invalidated on role/removal changes."""

    @pytest.mark.asyncio
    async def test_cache_invalidated_after_role_change(
        self, gateway_client: GatewayClient, test_organization: dict
    ):
        pass

    @pytest.mark.asyncio
    async def test_cache_invalidated_after_removal(
        self, gateway_client: GatewayClient, test_organization: dict
    ):
        pass
