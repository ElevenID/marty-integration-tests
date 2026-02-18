"""
Integration tests for organization-scoped authorization.

Tests verify that:
1. Users cannot access organizations they are not members of
2. Users with member role cannot perform admin actions
3. Users with admin role can perform admin actions in their org
4. Cross-organization attacks are blocked
"""

import pytest
import httpx
from typing import AsyncGenerator


@pytest.fixture
async def gateway_client() -> AsyncGenerator[httpx.AsyncClient, None]:
    """HTTP client for gateway API."""
    async with httpx.AsyncClient(
        base_url="http://localhost:8000",
        timeout=30.0,
        follow_redirects=False
    ) as client:
        yield client


class TestOrganizationMembershipEnforcement:
    """Test that organization membership is enforced at gateway and service levels."""
    
    @pytest.mark.asyncio
    async def test_non_member_cannot_access_org_details(
        self, gateway_client: httpx.AsyncClient
    ):
        """User A (not in Org B) cannot read Org B details."""
        # This test assumes:
        # - User A is authenticated with session cookie
        # - User A is NOT a member of org_b_id
        # - org_b_id is a valid organization UUID
        
        org_b_id = "00000000-0000-0000-0000-000000000002"  # Replace with actual test org ID
        
        response = await gateway_client.get(
            f"/v1/organizations/{org_b_id}",
            cookies={"sessionId": "user_a_session"}  # Replace with actual session
        )
        
        # Should be blocked by gateway OrgAuthMiddleware
        assert response.status_code == 403
        assert "Not a member of this organization" in response.json().get("detail", "")
    
    @pytest.mark.asyncio
    async def test_member_can_access_org_details(
        self, gateway_client: httpx.AsyncClient
    ):
        """User A (member of Org A) can read Org A details."""
        org_a_id = "00000000-0000-0000-0000-000000000001"  # Replace with actual test org ID
        
        response = await gateway_client.get(
            f"/v1/organizations/{org_a_id}",
            cookies={"sessionId": "user_a_session"}  # User A is a member
        )
        
        # Should succeed
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == org_a_id
    
    @pytest.mark.asyncio
    async def test_member_cannot_invite_others(
        self, gateway_client: httpx.AsyncClient
    ):
        """User B (member role in Org A) cannot invite new members."""
        org_a_id = "00000000-0000-0000-0000-000000000001"
        
        response = await gateway_client.post(
            f"/v1/organizations/{org_a_id}/members",
            json={
                "email": "newuser@example.com",
                "role": "member"
            },
            cookies={"sessionId": "user_b_session"}  # User B is a member, not admin
        )
        
        # Should be blocked by require_org_admin dependency
        assert response.status_code == 403
        assert "Admin role required" in response.json().get("detail", "") or \
               "Requires one of these roles" in response.json().get("detail", "")
    
    @pytest.mark.asyncio
    async def test_admin_can_invite_members(
        self, gateway_client: httpx.AsyncClient
    ):
        """User A (admin in Org A) can invite new members."""
        org_a_id = "00000000-0000-0000-0000-000000000001"
        
        response = await gateway_client.post(
            f"/v1/organizations/{org_a_id}/members",
            json={
                "email": f"test_{pytest.helpers.random_string()}@example.com",
                "role": "member"
            },
            cookies={"sessionId": "user_a_admin_session"}  # User A is an admin
        )
        
        # Should succeed
        assert response.status_code == 200
        data = response.json()
        assert data["email"] is not None
        assert data["role"] == "member"


class TestCrossOrganizationAttacks:
    """Test that users cannot perform actions across organization boundaries."""
    
    @pytest.mark.asyncio
    async def test_cannot_invite_to_other_org(
        self, gateway_client: httpx.AsyncClient
    ):
        """User A (admin in Org A) cannot invite members to Org B."""
        org_b_id = "00000000-0000-0000-0000-000000000002"
        
        response = await gateway_client.post(
            f"/v1/organizations/{org_b_id}/members",
            json={
                "email": "attacker@example.com",
                "role": "admin"
            },
            cookies={"sessionId": "user_a_admin_session"}  # Admin in Org A, not Org B
        )
        
        # Should be blocked by gateway OrgAuthMiddleware
        assert response.status_code == 403
        assert "Not a member of this organization" in response.json().get("detail", "")
    
    @pytest.mark.asyncio
    async def test_cannot_create_api_keys_for_other_org(
        self, gateway_client: httpx.AsyncClient
    ):
        """User A (admin in Org A) cannot create API keys for Org B."""
        org_b_id = "00000000-0000-0000-0000-000000000002"
        
        response = await gateway_client.post(
            f"/v1/organizations/{org_b_id}/api-keys",
            json={
                "name": "Malicious Key",
                "description": "Trying to create key in another org"
            },
            cookies={"sessionId": "user_a_admin_session"}
        )
        
        # Should be blocked by gateway
        assert response.status_code == 403
        assert "Not a member of this organization" in response.json().get("detail", "")
    
    @pytest.mark.asyncio
    async def test_cannot_access_other_org_members(
        self, gateway_client: httpx.AsyncClient
    ):
        """User A cannot list members of Org B."""
        org_b_id = "00000000-0000-0000-0000-000000000002"
        
        response = await gateway_client.get(
            f"/v1/organizations/{org_b_id}/members",
            cookies={"sessionId": "user_a_session"}
        )
        
        # Should be blocked
        assert response.status_code == 403
    
    @pytest.mark.asyncio
    async def test_cannot_create_credential_template_in_other_org(
        self, gateway_client: httpx.AsyncClient
    ):
        """User A cannot create credential templates for Org B."""
        org_b_id = "00000000-0000-0000-0000-000000000002"
        
        response = await gateway_client.post(
            "/v1/credential-templates",
            json={
                "organization_id": org_b_id,
                "name": "Malicious Template",
                "credential_type": "test",
                "description": "Trying to create in another org"
            },
            cookies={"sessionId": "user_a_session"}
        )
        
        # Should be blocked either by gateway (if using query param pattern)
        # or by service-level authorization
        assert response.status_code in [403, 404]


class TestCacheInvalidation:
    """Test that membership cache is properly invalidated."""
    
    @pytest.mark.asyncio
    async def test_cache_invalidated_after_role_change(
        self, gateway_client: httpx.AsyncClient
    ):
        """After role change, user's cached membership should reflect new role."""
        org_a_id = "00000000-0000-0000-0000-000000000001"
        member_id = "member-to-update-id"  # Replace with actual member ID
        
        # User B starts as member (can read)
        response = await gateway_client.get(
            f"/v1/organizations/{org_a_id}",
            cookies={"sessionId": "user_b_session"}
        )
        assert response.status_code == 200
        
        # User B cannot invite (member role)
        response = await gateway_client.post(
            f"/v1/organizations/{org_a_id}/members",
            json={"email": "test@example.com", "role": "member"},
            cookies={"sessionId": "user_b_session"}
        )
        assert response.status_code == 403
        
        # Admin promotes User B to admin
        response = await gateway_client.patch(
            f"/v1/organizations/{org_a_id}/members/{member_id}",
            json={"role": "admin"},
            cookies={"sessionId": "user_a_admin_session"}
        )
        assert response.status_code == 200
        
        # Now User B should be able to invite (after cache invalidation)
        # Note: May need a small delay for cache invalidation to propagate
        response = await gateway_client.post(
            f"/v1/organizations/{org_a_id}/members",
            json={"email": "newadmin@example.com", "role": "member"},
            cookies={"sessionId": "user_b_session"}
        )
        assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_cache_invalidated_after_removal(
        self, gateway_client: httpx.AsyncClient
    ):
        """After member removal, user should no longer have access."""
        org_a_id = "00000000-0000-0000-0000-000000000001"
        member_id = "member-to-remove-id"  # Replace with actual member ID
        
        # User C can access before removal
        response = await gateway_client.get(
            f"/v1/organizations/{org_a_id}",
            cookies={"sessionId": "user_c_session"}
        )
        assert response.status_code == 200
        
        # Admin removes User C
        response = await gateway_client.delete(
            f"/v1/organizations/{org_a_id}/members/{member_id}",
            cookies={"sessionId": "user_a_admin_session"}
        )
        assert response.status_code == 200
        
        # User C should no longer have access (cache invalidated)
        response = await gateway_client.get(
            f"/v1/organizations/{org_a_id}",
            cookies={"sessionId": "user_c_session"}
        )
        assert response.status_code == 403


@pytest.mark.skip(reason="Requires full test environment setup")
class TestEndToEndFlows:
    """End-to-end tests requiring full environment with seeded test data."""
    
    @pytest.mark.asyncio
    async def test_full_cross_org_attack_scenario(
        self, gateway_client: httpx.AsyncClient
    ):
        """
        Complete attack scenario:
        1. Create two orgs (Org A and Org B)
        2. Create two users (User A admin in Org A, User B admin in Org B)
        3. Verify User A cannot:
           - Invite members to Org B
           - Create API keys for Org B
           - Update Org B settings
           - Create credential templates for Org B
           - Access Org B member list
        """
        # Implementation would require test fixtures for creating orgs and users
        pass
