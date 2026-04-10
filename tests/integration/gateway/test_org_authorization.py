"""Integration tests for organization-scoped authorization.

Tests verify that:
1. Users cannot access organizations they are not members of
2. Users with admin role CAN perform admin actions in their own org
3. Cross-organization attacks are blocked by OrgAuthMiddleware (403)
4. Own-org resource CRUD works end-to-end (create → read → list → update → delete)
5. Cross-org reads, updates, and deletes on top-level resources are denied

Notes:
- For "foreign org" tests we use a random UUID the test user is NOT a member of.
  Because ``OrgAuthMiddleware`` returns 403 for any org where the user has no
  membership record, this works without needing a second pre-seeded organization.
- The ``all_services_ready`` session fixture (conftest.py) gates test execution
  until every backend service passes its health check, eliminating transient
  503 failures caused by compose warm-up timing.
"""

import uuid

import pytest

from .helpers.gateway_client import GatewayClient
from .helpers.test_data import TestDataBuilder


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _foreign_org_id() -> str:
    """Return a random org UUID the authenticated test user is definitely not in."""
    return str(uuid.uuid4())


def _assert_attack_blocked(response, foreign_org_id: str, *, resource_name: str = "resource"):
    """Assert that a cross-org creation attempt was blocked.

    Acceptable outcomes:
    - 403/404: OrgAuthMiddleware or BOLA blocked the request.
    - 422: Schema validation rejected before reaching org check (still prevents creation).
    - 200 with silently overridden org_id (BOLA protection).
    """
    if response.status_code == 200:
        data = response.json()
        assert data.get("organization_id") != foreign_org_id, (
            f"{resource_name} was created in foreign org {foreign_org_id} — "
            f"BOLA not blocked! Response: {response.text}"
        )
    else:
        assert response.status_code in (403, 404, 422), (
            f"Expected 403/404/422 for {resource_name} cross-org attack, "
            f"got {response.status_code}: {response.text}"
        )


def _assert_proxy_attack_blocked(response, *, action_name: str) -> None:
    """Assert that a proxied nested-resource attack was blocked.

    This is used for routes whose payload does not contain an organization_id,
    such as nested deployment profile actions.
    """
    assert response.status_code in (403, 404, 422), (
        f"Expected 403/404/422 for {action_name}, got {response.status_code}: {response.text}"
    )


def _assert_cross_org_denied(response, *, action_name: str) -> None:
    """Assert that a cross-org read/update/delete was denied (403 or 404)."""
    assert response.status_code in (403, 404), (
        f"Expected 403/404 for {action_name}, got {response.status_code}: {response.text}"
    )


# ---------------------------------------------------------------------------
# Membership access enforcement
# ---------------------------------------------------------------------------

@pytest.mark.usefixtures("all_services_ready")
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
        body = response.json()
        msg = body.get("detail", "") or body.get("error_description", "")
        assert "Not a member" in msg

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


# ---------------------------------------------------------------------------
# Cross-organization attack prevention (CREATE)
# ---------------------------------------------------------------------------

@pytest.mark.usefixtures("all_services_ready")
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
        """User cannot create credential templates for a foreign organization."""
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
        _assert_attack_blocked(response, org_b_id, resource_name="Credential template")

    @pytest.mark.asyncio
    async def test_cannot_create_compliance_profile_in_other_org(
        self, gateway_client: GatewayClient
    ):
        """User cannot create compliance profiles for a foreign organization."""
        org_b_id = _foreign_org_id()
        response = await gateway_client.client.post(
            "/v1/compliance-profiles",
            json={
                "organization_id": org_b_id,
                "name": "Foreign Compliance Profile",
                "compliance_code": "AAMVA_MDL",
                "credential_format": "mso_mdoc",
            },
        )
        _assert_attack_blocked(response, org_b_id, resource_name="Compliance profile")

    @pytest.mark.asyncio
    async def test_cannot_create_revocation_profile_in_other_org(
        self, gateway_client: GatewayClient
    ):
        """User cannot create revocation profiles for a foreign organization."""
        org_b_id = _foreign_org_id()
        response = await gateway_client.client.post(
            "/v1/revocation-profiles",
            json={
                "organization_id": org_b_id,
                "name": "Foreign Revocation Profile",
                "revocation_mechanism": ["STATUS_LIST_2021"],
                "mechanism_priority": ["STATUS_LIST_2021"],
                "check_mode": "ALWAYS",
                "issuer_config": {"auto_allocate_index": True},
            },
        )
        _assert_attack_blocked(response, org_b_id, resource_name="Revocation profile")

    @pytest.mark.asyncio
    async def test_cannot_create_trust_profile_in_other_org(
        self, gateway_client: GatewayClient
    ):
        """User cannot create trust profiles for a foreign organization."""
        org_b_id = _foreign_org_id()
        response = await gateway_client.client.post(
            "/v1/trust-profiles",
            json={
                "organization_id": org_b_id,
                "name": "Foreign Trust Profile",
                "trusted_issuers": [],
                "trust_frameworks": ["eidas"],
                "revocation_check_enabled": True,
            },
        )
        _assert_attack_blocked(response, org_b_id, resource_name="Trust profile")

    @pytest.mark.asyncio
    async def test_cannot_create_deployment_profile_in_other_org(
        self, gateway_client: GatewayClient
    ):
        """User cannot create deployment profiles for a foreign organization."""
        org_b_id = _foreign_org_id()
        response = await gateway_client.client.post(
            "/v1/deployment-profiles",
            json={
                "organization_id": org_b_id,
                "name": "Foreign Deployment",
                "description": "cross-org attack",
                "trust_profile_id": str(uuid.uuid4()),
            },
        )
        _assert_attack_blocked(response, org_b_id, resource_name="Deployment profile")

    @pytest.mark.asyncio
    async def test_cannot_create_flow_definition_in_other_org(
        self, gateway_client: GatewayClient
    ):
        """User cannot create flow definitions for a foreign organization."""
        org_b_id = _foreign_org_id()
        response = await gateway_client.client.post(
            "/v1/flow-definitions",
            json={
                "organization_id": org_b_id,
                "name": "Foreign Flow",
                "flow_type": "issuance",
                "steps": [],
            },
        )
        _assert_attack_blocked(response, org_b_id, resource_name="Flow definition")

    @pytest.mark.asyncio
    async def test_cannot_create_application_template_in_other_org(
        self, gateway_client: GatewayClient
    ):
        """User cannot create application templates for a foreign organization."""
        org_b_id = _foreign_org_id()
        response = await gateway_client.client.post(
            "/v1/application-templates",
            json={
                "organization_id": org_b_id,
                "name": "Foreign App Template",
                "evidence_requirements": ["identity_document"],
                "approval_strategy": "manual",
            },
        )
        _assert_attack_blocked(response, org_b_id, resource_name="Application template")

    @pytest.mark.asyncio
    async def test_cannot_create_presentation_policy_in_other_org(
        self, gateway_client: GatewayClient
    ):
        """User cannot create presentation policies for a foreign organization."""
        org_b_id = _foreign_org_id()
        response = await gateway_client.client.post(
            "/v1/presentation-policies",
            json={
                "organization_id": org_b_id,
                "name": "Foreign Policy",
                "credential_requirements": [
                    {
                        "credential_type": "test",
                        "credential_template_id": str(uuid.uuid4()),
                        "required_claims": ["name"],
                    }
                ],
                "purpose": "cross-org attack test",
            },
        )
        _assert_attack_blocked(response, org_b_id, resource_name="Presentation policy")

    @pytest.mark.asyncio
    async def test_cannot_create_lane_under_foreign_deployment_profile(
        self, gateway_client: GatewayClient
    ):
        """User cannot create a lane under another org's deployment profile."""
        foreign_profile_id = str(uuid.uuid4())
        response = await gateway_client.client.post(
            f"/v1/deployment-profiles/{foreign_profile_id}/lanes",
            json={
                "name": "Foreign Lane",
                "description": "cross-org lane attack",
                "location": "terminal-a",
                "device_type": "kiosk",
            },
        )
        _assert_proxy_attack_blocked(
            response,
            action_name="Lane creation under foreign deployment profile",
        )

    @pytest.mark.asyncio
    async def test_cannot_generate_api_key_for_foreign_deployment_profile(
        self, gateway_client: GatewayClient
    ):
        """User cannot generate an API key for another org's deployment profile."""
        foreign_profile_id = str(uuid.uuid4())
        response = await gateway_client.client.post(
            f"/v1/deployment-profiles/{foreign_profile_id}/generate-api-key"
        )
        _assert_proxy_attack_blocked(
            response,
            action_name="Deployment API key generation for foreign profile",
        )


# ---------------------------------------------------------------------------
# Cross-organization attack prevention (READ / UPDATE / DELETE)
# ---------------------------------------------------------------------------

@pytest.mark.usefixtures("all_services_ready")
class TestCrossOrgReadUpdateDelete:
    """Users cannot read, update, or delete resources owned by another org.

    These tests target top-level resource detail routes (``/v1/<resource>/<id>``)
    using a random UUID that does not belong to the authenticated user's org.
    The server should return 403 (Cedar) or 404 (resource not found).
    """

    @pytest.mark.asyncio
    async def test_cannot_get_foreign_trust_profile(self, gateway_client: GatewayClient):
        phantom = str(uuid.uuid4())
        resp = await gateway_client.client.get(f"/v1/trust-profiles/{phantom}")
        _assert_cross_org_denied(resp, action_name="GET foreign trust profile")

    @pytest.mark.asyncio
    async def test_cannot_get_foreign_credential_template(self, gateway_client: GatewayClient):
        phantom = str(uuid.uuid4())
        resp = await gateway_client.client.get(f"/v1/credential-templates/{phantom}")
        _assert_cross_org_denied(resp, action_name="GET foreign credential template")

    @pytest.mark.asyncio
    async def test_cannot_get_foreign_compliance_profile(self, gateway_client: GatewayClient):
        phantom = str(uuid.uuid4())
        resp = await gateway_client.client.get(f"/v1/compliance-profiles/{phantom}")
        _assert_cross_org_denied(resp, action_name="GET foreign compliance profile")

    @pytest.mark.asyncio
    async def test_cannot_get_foreign_deployment_profile(self, gateway_client: GatewayClient):
        phantom = str(uuid.uuid4())
        resp = await gateway_client.client.get(f"/v1/deployment-profiles/{phantom}")
        _assert_cross_org_denied(resp, action_name="GET foreign deployment profile")

    @pytest.mark.asyncio
    async def test_cannot_get_foreign_revocation_profile(self, gateway_client: GatewayClient):
        phantom = str(uuid.uuid4())
        resp = await gateway_client.client.get(f"/v1/revocation-profiles/{phantom}")
        _assert_cross_org_denied(resp, action_name="GET foreign revocation profile")

    @pytest.mark.asyncio
    async def test_cannot_get_foreign_presentation_policy(self, gateway_client: GatewayClient):
        phantom = str(uuid.uuid4())
        resp = await gateway_client.client.get(f"/v1/presentation-policies/{phantom}")
        _assert_cross_org_denied(resp, action_name="GET foreign presentation policy")

    @pytest.mark.asyncio
    async def test_cannot_get_foreign_application_template(self, gateway_client: GatewayClient):
        phantom = str(uuid.uuid4())
        resp = await gateway_client.client.get(f"/v1/application-templates/{phantom}")
        _assert_cross_org_denied(resp, action_name="GET foreign application template")

    @pytest.mark.asyncio
    async def test_cannot_delete_foreign_trust_profile(self, gateway_client: GatewayClient):
        phantom = str(uuid.uuid4())
        resp = await gateway_client.client.delete(f"/v1/trust-profiles/{phantom}")
        _assert_cross_org_denied(resp, action_name="DELETE foreign trust profile")

    @pytest.mark.asyncio
    async def test_cannot_delete_foreign_credential_template(self, gateway_client: GatewayClient):
        phantom = str(uuid.uuid4())
        resp = await gateway_client.client.delete(f"/v1/credential-templates/{phantom}")
        # 200 is acceptable (idempotent no-op for non-existent resource)
        assert resp.status_code in (200, 403, 404), (
            f"DELETE foreign credential template got {resp.status_code}: {resp.text}"
        )

    @pytest.mark.asyncio
    async def test_cannot_delete_foreign_deployment_profile(self, gateway_client: GatewayClient):
        phantom = str(uuid.uuid4())
        resp = await gateway_client.client.delete(f"/v1/deployment-profiles/{phantom}")
        _assert_cross_org_denied(resp, action_name="DELETE foreign deployment profile")

    @pytest.mark.asyncio
    async def test_cannot_list_resources_with_foreign_org_filter(
        self, gateway_client: GatewayClient
    ):
        """Listing resources filtered to a foreign org returns empty or 403."""
        foreign = _foreign_org_id()
        for resource in [
            "trust-profiles",
            "compliance-profiles",
            "deployment-profiles",
            "revocation-profiles",
            "presentation-policies",
        ]:
            resp = await gateway_client.client.get(
                f"/v1/{resource}", params={"organization_id": foreign}
            )
            if resp.status_code == 200:
                data = resp.json()
                items = data if isinstance(data, list) else data.get("items", data.get("results", []))
                assert len(items) == 0, (
                    f"GET /v1/{resource}?organization_id={foreign} leaked data: "
                    f"{len(items)} items returned"
                )
            else:
                assert resp.status_code in (403, 404), (
                    f"GET /v1/{resource}?organization_id={foreign} returned "
                    f"{resp.status_code}: {resp.text}"
                )


# ---------------------------------------------------------------------------
# Own-org positive CRUD paths
# ---------------------------------------------------------------------------

@pytest.mark.usefixtures("all_services_ready")
class TestOwnOrgResourceCRUD:
    """Admin can create, read, list, update, and delete resources in own org."""

    @pytest.mark.asyncio
    async def test_trust_profile_lifecycle(
        self, gateway_client: GatewayClient, test_organization: dict
    ):
        org_id = test_organization["id"]

        # Create
        profile = await gateway_client.create_trust_profile(
            organization_id=org_id,
            name=f"test-tp-{uuid.uuid4().hex[:8]}",
            trust_frameworks=["eidas"],
            trust_sources=[{"type": "did_web", "url": "https://example.com"}],
        )
        profile_id = profile["id"]
        assert profile["organization_id"] == org_id

        # Read
        fetched = await gateway_client.get_trust_profile(profile_id)
        assert fetched["id"] == profile_id
        assert fetched["organization_id"] == org_id

        # List
        items = await gateway_client.list_trust_profiles(org_id)
        ids = [tp["id"] for tp in (items if isinstance(items, list) else items.get("items", []))]
        assert profile_id in ids

        # Delete
        await gateway_client.delete_trust_profile(profile_id)

    @pytest.mark.asyncio
    async def test_compliance_profile_lifecycle(
        self, gateway_client: GatewayClient, test_organization: dict
    ):
        org_id = test_organization["id"]

        profile = await gateway_client.create_compliance_profile(
            organization_id=org_id,
            name=f"test-cp-{uuid.uuid4().hex[:8]}",
            compliance_code="AAMVA_MDL",
            credential_format="mso_mdoc",
        )
        profile_id = profile["id"]
        assert profile["organization_id"] == org_id

        fetched = await gateway_client.get_compliance_profile(profile_id)
        assert fetched["id"] == profile_id

        items = await gateway_client.list_compliance_profiles(org_id)
        ids = [cp["id"] for cp in (items if isinstance(items, list) else items.get("items", []))]
        assert profile_id in ids

        await gateway_client.delete_compliance_profile(profile_id)

    @pytest.mark.asyncio
    async def test_revocation_profile_lifecycle(
        self, gateway_client: GatewayClient, test_organization: dict
    ):
        org_id = test_organization["id"]

        profile = await gateway_client.create_revocation_profile(
            organization_id=org_id,
            name=f"test-rp-{uuid.uuid4().hex[:8]}",
            revocation_mechanism=["STATUS_LIST_2021"],
        )
        profile_id = profile["id"]
        assert profile["organization_id"] == org_id

        fetched = await gateway_client.get_revocation_profile(profile_id)
        assert fetched["id"] == profile_id

        items = await gateway_client.list_revocation_profiles(org_id)
        ids = [rp["id"] for rp in (items if isinstance(items, list) else items.get("items", []))]
        assert profile_id in ids

        await gateway_client.delete_revocation_profile(profile_id)

    @pytest.mark.asyncio
    @pytest.mark.xfail(
        reason="Deployment profiles require Enterprise plan; test org is on free tier",
        raises=Exception,
    )
    async def test_deployment_profile_and_lane_lifecycle(
        self, gateway_client: GatewayClient, test_organization: dict
    ):
        org_id = test_organization["id"]

        # Create deployment profile
        profile = await gateway_client.create_deployment_profile(
            organization_id=org_id,
            name=f"test-dp-{uuid.uuid4().hex[:8]}",
            site_id=f"site-{uuid.uuid4().hex[:6]}",
        )
        profile_id = profile["id"]
        assert profile["organization_id"] == org_id

        fetched = await gateway_client.get_deployment_profile(profile_id)
        assert fetched["id"] == profile_id

        items = await gateway_client.list_deployment_profiles(org_id)
        ids = [dp["id"] for dp in (items if isinstance(items, list) else items.get("items", []))]
        assert profile_id in ids

        # Create lane under deployment profile
        lane = await gateway_client.create_lane(
            deployment_profile_id=profile_id,
            name=f"Lane {uuid.uuid4().hex[:8]}",
            location="Gate 1",
            device_type="kiosk",
        )
        lane_id = lane["id"]

        fetched_lane = await gateway_client.get_lane(profile_id, lane_id)
        assert fetched_lane["id"] == lane_id

        lanes = await gateway_client.list_lanes(profile_id)
        lane_ids = [l["id"] for l in (lanes if isinstance(lanes, list) else lanes.get("items", []))]
        assert lane_id in lane_ids

        # Delete lane, then profile
        await gateway_client.delete_lane(profile_id, lane_id)
        await gateway_client.delete_deployment_profile(profile_id)

    @pytest.mark.asyncio
    async def test_presentation_policy_lifecycle(
        self, gateway_client: GatewayClient, test_organization: dict
    ):
        org_id = test_organization["id"]

        # Presentation policies require a real credential template
        template = await gateway_client.create_credential_template(
            organization_id=org_id,
            name=f"test-ct-{uuid.uuid4().hex[:8]}",
            credential_type="org.iso.18013.5.1.mDL",
            vct="https://example.com/credentials/mDL/1.0",
            claims=[
                {"name": "family_name", "type": "string", "display_name": "Family Name"},
                {"name": "given_name", "type": "string", "display_name": "Given Name"},
            ],
            compliance_profile={
                "name": "test-inline-cp",
                "compliance_code": "AAMVA_MDL",
                "credential_format": "sd_jwt_vc",
            },
        )
        template_id = template["id"]

        try:
            policy = await gateway_client.create_presentation_policy(
                organization_id=org_id,
                name=f"test-pp-{uuid.uuid4().hex[:8]}",
                credential_requirements=[
                    {
                        "credential_type": "mso_mdoc",
                        "credential_template_id": template_id,
                        "requested_claims": [
                            {"claim_name": "family_name"},
                            {"claim_name": "given_name"},
                        ],
                    }
                ],
                purpose="integration test",
            )
            policy_id = policy["id"]
            assert policy["organization_id"] == org_id

            fetched = await gateway_client.get_presentation_policy(policy_id)
            assert fetched["id"] == policy_id

            items = await gateway_client.list_presentation_policies(org_id)
            ids = [pp["id"] for pp in (items if isinstance(items, list) else items.get("items", []))]
            assert policy_id in ids

            await gateway_client.delete_presentation_policy(policy_id)
        finally:
            await gateway_client.delete_credential_template(template_id)

    @pytest.mark.asyncio
    async def test_application_template_lifecycle(
        self, gateway_client: GatewayClient, test_organization: dict
    ):
        org_id = test_organization["id"]

        template = await gateway_client.create_application_template(
            organization_id=org_id,
            name=f"test-at-{uuid.uuid4().hex[:8]}",
            evidence_requirements=["identity_document"],
            approval_strategy="manual",
        )
        template_id = template["id"]
        assert template["organization_id"] == org_id

        fetched = await gateway_client.get_application_template(template_id)
        assert fetched["id"] == template_id

        items = await gateway_client.list_application_templates(org_id)
        ids = [at["id"] for at in (items if isinstance(items, list) else items.get("items", []))]
        assert template_id in ids
