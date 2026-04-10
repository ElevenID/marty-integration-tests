"""
Organization Flow Integration Tests

Tests the complete organization setup flow:
1. Create organization
2. Configure trust profile
3. Create credential templates
4. Create presentation policies
5. Verify all resources are accessible
"""

import pytest
from typing import Dict, Any

from .helpers.gateway_client import GatewayClient, GatewayClientError
from .helpers.test_data import TestDataBuilder


@pytest.mark.asyncio
@pytest.mark.integration
class TestOrganizationSetupFlow:
    """Test organization creation and configuration"""
    
    async def test_create_organization(self, gateway_client: GatewayClient):
        """Test creating a new organization"""
        org_data = TestDataBuilder.organization(
            name="acme-corp",
            display_name="ACME Corporation",
        )
        
        org = await gateway_client.create_organization(**org_data)
        
        assert org is not None
        assert "id" in org
        assert org["name"] == org_data["name"]
        assert org["display_name"] == org_data["display_name"]
        assert "created_at" in org
        
    async def test_get_organization(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test retrieving an organization by ID"""
        org_id = test_organization["id"]
        
        org = await gateway_client.get_organization(org_id)
        
        assert org["id"] == org_id
        assert org["name"] == test_organization["name"]
        
    async def test_list_organizations(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test listing all organizations"""
        orgs = await gateway_client.list_organizations()
        
        assert isinstance(orgs, list)
        assert len(orgs) > 0
        # Find our test org in the list
        org_ids = [o["id"] for o in orgs]
        assert test_organization["id"] in org_ids

    @pytest.mark.xfail(reason="PATCH not supported on organizations endpoint")
    async def test_update_organization(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test updating organization metadata."""
        updated = await gateway_client.update_organization(
            test_organization["id"],
            display_name="ACME Corporation (Updated)",
            description="Updated during aggressive launch-readiness testing.",
        )

        assert updated["id"] == test_organization["id"]
        assert updated["display_name"] == "ACME Corporation (Updated)"
        assert updated["description"] == "Updated during aggressive launch-readiness testing."

    @pytest.mark.xfail(reason="DELETE not supported on organizations endpoint")
    async def test_delete_organization(
        self,
        gateway_client: GatewayClient,
    ):
        """Test deleting an organization removes it from direct retrieval."""
        org_data = TestDataBuilder.organization()
        org = await gateway_client.create_organization(**org_data)

        await gateway_client.delete_organization(org["id"])

        with pytest.raises(GatewayClientError):
            await gateway_client.get_organization(org["id"])


@pytest.mark.asyncio
@pytest.mark.integration
class TestTrustProfileFlow:
    """Test trust profile creation and management"""
    
    async def test_create_trust_profile(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test creating a trust profile"""
        trust_profile_data = TestDataBuilder.trust_profile(
            organization_id=test_organization["id"]
        )
        
        trust_profile = await gateway_client.create_trust_profile(
            **trust_profile_data
        )
        
        assert trust_profile is not None
        assert "id" in trust_profile
        assert trust_profile["organization_id"] == test_organization["id"]
        assert trust_profile["name"] == trust_profile_data["name"]
        # Note: trusted_issuers is now managed via separate endpoint
        
    async def test_get_trust_profile(
        self,
        gateway_client: GatewayClient,
        test_trust_profile: Dict[str, Any],
    ):
        """Test retrieving a trust profile by ID"""
        profile = await gateway_client.get_trust_profile(test_trust_profile["id"])
        
        assert profile["id"] == test_trust_profile["id"]
        assert profile["name"] == test_trust_profile["name"]
        
    async def test_list_trust_profiles(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        test_trust_profile: Dict[str, Any],
    ):
        """Test listing trust profiles for an organization"""
        profiles = await gateway_client.list_trust_profiles(
            organization_id=test_organization["id"]
        )
        
        assert isinstance(profiles, list)
        assert len(profiles) > 0
        profile_ids = [p["id"] for p in profiles]
        assert test_trust_profile["id"] in profile_ids

    @pytest.mark.xfail(reason="PATCH not supported on trust-profiles endpoint")
    async def test_update_trust_profile(
        self,
        gateway_client: GatewayClient,
        test_trust_profile: Dict[str, Any],
    ):
        """Test updating trust profile fields including enablement."""
        updated = await gateway_client.update_trust_profile(
            test_trust_profile["id"],
            name=f"{test_trust_profile['name']} (Updated)",
            description="Updated trust profile for launch testing.",
            enabled=False,
        )

        assert updated["id"] == test_trust_profile["id"]
        assert updated["name"].endswith("(Updated)")
        assert updated["description"] == "Updated trust profile for launch testing."
        assert updated["enabled"] is False

    async def test_delete_trust_profile(
        self,
        gateway_client: GatewayClient,
        test_trust_profile: Dict[str, Any],
    ):
        """Test deleting a trust profile."""
        await gateway_client.delete_trust_profile(test_trust_profile["id"])

        with pytest.raises(GatewayClientError):
            await gateway_client.get_trust_profile(test_trust_profile["id"])


@pytest.mark.asyncio
@pytest.mark.integration
class TestCredentialTemplateFlow:
    """Test credential template creation and management"""
    
    async def test_create_mdl_template(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test creating an mDL credential template"""
        template_data = TestDataBuilder.mdl_template(
            organization_id=test_organization["id"],
        )
        
        template = await gateway_client.create_credential_template(**template_data)
        
        assert template is not None
        assert "id" in template
        assert template["organization_id"] == test_organization["id"]
        assert template["name"] == template_data["name"]
        assert template["credential_type"] == "org.iso.18013.5.1.mDL"
        assert "vct" in template
        assert "claims" in template
        assert len(template["claims"]) > 0
        
    async def test_create_employee_badge_template(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test creating an employee badge credential template"""
        template_data = TestDataBuilder.employee_badge_template(
            organization_id=test_organization["id"],
        )
        
        template = await gateway_client.create_credential_template(**template_data)
        
        assert template is not None
        assert template["credential_type"] == "EmployeeBadge"
        assert "vct" in template
        
    async def test_get_credential_template(
        self,
        gateway_client: GatewayClient,
        mdl_template: Dict[str, Any],
    ):
        """Test retrieving a credential template by ID"""
        template = await gateway_client.get_credential_template(mdl_template["id"])
        
        assert template["id"] == mdl_template["id"]
        assert template["name"] == mdl_template["name"]
        
    async def test_list_credential_templates(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """Test listing credential templates for an organization"""
        templates = await gateway_client.list_credential_templates(
            organization_id=test_organization["id"]
        )
        
        assert isinstance(templates, list)
        assert len(templates) > 0
        template_ids = [t["id"] for t in templates]
        assert mdl_template["id"] in template_ids

    @pytest.mark.xfail(reason="PATCH not supported on credential-templates endpoint")
    async def test_update_credential_template(
        self,
        gateway_client: GatewayClient,
        mdl_template: Dict[str, Any],
    ):
        """Test updating credential template metadata and naming."""
        updated = await gateway_client.update_credential_template(
            mdl_template["id"],
            name="Updated mDL Template",
            description="Updated by the launch-readiness integration suite.",
            metadata={"test_case": "credential-template-update"},
        )

        assert updated["id"] == mdl_template["id"]
        assert updated["name"] == "Updated mDL Template"
        assert updated["description"] == "Updated by the launch-readiness integration suite."
        assert updated["metadata"]["test_case"] == "credential-template-update"

    async def test_delete_credential_template(
        self,
        gateway_client: GatewayClient,
        mdl_template: Dict[str, Any],
    ):
        """Test deleting a credential template."""
        await gateway_client.delete_credential_template(mdl_template["id"])

        with pytest.raises(GatewayClientError):
            await gateway_client.get_credential_template(mdl_template["id"])


@pytest.mark.asyncio
@pytest.mark.integration
class TestPresentationPolicyFlow:
    """Test presentation policy creation and management"""
    
    async def test_create_age_verification_policy(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """Test creating an age verification presentation policy"""
        policy_data = TestDataBuilder.presentation_policy_age_verification(
            organization_id=test_organization["id"],
            credential_template_id=mdl_template["id"],
            min_age=21,
        )
        
        policy = await gateway_client.create_presentation_policy(**policy_data)
        
        assert policy is not None
        assert "id" in policy
        assert policy["organization_id"] == test_organization["id"]
        assert policy["name"] == policy_data["name"]
        assert len(policy["credential_requirements"]) > 0
        
        # Verify age requirement
        req = policy["credential_requirements"][0]
        assert req["credential_template_id"] == mdl_template["id"]
        assert len(req["requested_claims"]) > 0
        
    async def test_create_identity_verification_policy(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """Test creating a full identity verification policy"""
        policy_data = TestDataBuilder.presentation_policy_identity_verification(
            organization_id=test_organization["id"],
            credential_template_id=mdl_template["id"],
        )
        
        policy = await gateway_client.create_presentation_policy(**policy_data)
        
        assert policy is not None
        req = policy["credential_requirements"][0]
        claim_names = [c["claim_name"] for c in req["requested_claims"]]
        assert "given_name" in claim_names
        assert "family_name" in claim_names
        assert "birth_date" in claim_names
        
    async def test_get_presentation_policy(
        self,
        gateway_client: GatewayClient,
        age_verification_policy: Dict[str, Any],
    ):
        """Test retrieving a presentation policy by ID"""
        policy = await gateway_client.get_presentation_policy(
            age_verification_policy["id"]
        )
        
        assert policy["id"] == age_verification_policy["id"]
        assert policy["name"] == age_verification_policy["name"]
        
    async def test_list_presentation_policies(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        age_verification_policy: Dict[str, Any],
    ):
        """Test listing presentation policies for an organization"""
        policies = await gateway_client.list_presentation_policies(
            organization_id=test_organization["id"]
        )
        
        assert isinstance(policies, list)
        assert len(policies) > 0
        policy_ids = [p["id"] for p in policies]
        assert age_verification_policy["id"] in policy_ids

    @pytest.mark.xfail(reason="PATCH not supported on presentation-policies endpoint")
    async def test_update_presentation_policy(
        self,
        gateway_client: GatewayClient,
        age_verification_policy: Dict[str, Any],
    ):
        """Test updating a presentation policy's purpose and metadata."""
        updated = await gateway_client.update_presentation_policy(
            age_verification_policy["id"],
            name="Updated Age Verification Policy",
            purpose="Verify patrons are at least 21 years old at the gate.",
            metadata={"test_case": "presentation-policy-update"},
        )

        assert updated["id"] == age_verification_policy["id"]
        assert updated["name"] == "Updated Age Verification Policy"
        assert updated["purpose"] == "Verify patrons are at least 21 years old at the gate."
        assert updated["metadata"]["test_case"] == "presentation-policy-update"

    @pytest.mark.xfail(reason="Only draft policies can be deleted; fixture auto-activates")
    async def test_delete_presentation_policy(
        self,
        gateway_client: GatewayClient,
        age_verification_policy: Dict[str, Any],
    ):
        """Test deleting a presentation policy."""
        await gateway_client.delete_presentation_policy(age_verification_policy["id"])

        with pytest.raises(GatewayClientError):
            await gateway_client.get_presentation_policy(age_verification_policy["id"])


@pytest.mark.asyncio
@pytest.mark.integration
class TestRevocationProfileFlow:
    """Test revocation profile creation and management."""

    async def test_create_revocation_profile(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test creating a revocation profile."""
        profile_data = TestDataBuilder.revocation_profile(
            organization_id=test_organization["id"],
        )

        profile = await gateway_client.create_revocation_profile(**profile_data)

        assert profile is not None
        assert profile["organization_id"] == test_organization["id"]
        assert profile["name"] == profile_data["name"]
        assert profile["revocation_mechanism"] == profile_data["revocation_mechanism"]

    async def test_get_revocation_profile(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test retrieving a revocation profile by ID."""
        profile_data = TestDataBuilder.revocation_profile(
            organization_id=test_organization["id"],
        )
        created = await gateway_client.create_revocation_profile(**profile_data)

        fetched = await gateway_client.get_revocation_profile(created["id"])

        assert fetched["id"] == created["id"]
        assert fetched["name"] == created["name"]

    async def test_list_revocation_profiles(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test listing revocation profiles for an organization."""
        profile_data = TestDataBuilder.revocation_profile(
            organization_id=test_organization["id"],
        )
        created = await gateway_client.create_revocation_profile(**profile_data)

        profiles = await gateway_client.list_revocation_profiles(
            organization_id=test_organization["id"],
        )

        assert isinstance(profiles, list)
        assert any(profile["id"] == created["id"] for profile in profiles)

    @pytest.mark.xfail(reason="PATCH not supported on revocation-profiles endpoint")
    async def test_update_revocation_profile(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test updating revocation profile check behavior and metadata."""
        profile_data = TestDataBuilder.revocation_profile(
            organization_id=test_organization["id"],
        )
        created = await gateway_client.create_revocation_profile(**profile_data)

        updated = await gateway_client.update_revocation_profile(
            created["id"],
            name="Updated Revocation Profile",
            check_mode="CACHED",
            cache_ttl_seconds=600,
            metadata={"test_case": "revocation-profile-update"},
        )

        assert updated["id"] == created["id"]
        assert updated["name"] == "Updated Revocation Profile"
        assert updated["check_mode"] == "CACHED"
        assert updated["cache_ttl_seconds"] == 600
        assert updated["metadata"]["test_case"] == "revocation-profile-update"

    async def test_delete_revocation_profile(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test deleting a revocation profile."""
        profile_data = TestDataBuilder.revocation_profile(
            organization_id=test_organization["id"],
        )
        created = await gateway_client.create_revocation_profile(**profile_data)

        await gateway_client.delete_revocation_profile(created["id"])

        with pytest.raises(GatewayClientError):
            await gateway_client.get_revocation_profile(created["id"])


@pytest.mark.asyncio
@pytest.mark.integration
class TestCompleteOrganizationSetup:
    """Test complete organization setup in a single flow"""
    
    async def test_end_to_end_organization_setup(
        self,
        gateway_client: GatewayClient,
    ):
        """
        Test complete organization setup flow:
        1. Create organization
        2. Create trust profile
        3. Create revocation profile
        4. Create credential template (mDL)
        5. Create presentation policy (age verification)
        6. Verify all resources are linked correctly
        """
        # Step 1: Create organization
        org_data = TestDataBuilder.organization()
        org = await gateway_client.create_organization(**org_data)
        org_id = org["id"]
        
        # Step 2: Create trust profile
        trust_profile_data = TestDataBuilder.trust_profile(organization_id=org_id)
        trust_profile = await gateway_client.create_trust_profile(
            **trust_profile_data
        )

        # Step 3: Create revocation profile
        revocation_profile_data = TestDataBuilder.revocation_profile(
            organization_id=org_id,
        )
        revocation_profile = await gateway_client.create_revocation_profile(
            **revocation_profile_data
        )
        
        # Step 4: Create credential template
        template_data = TestDataBuilder.mdl_template(
            organization_id=org_id,
            revocation_profile_id=revocation_profile["id"],
        )
        template = await gateway_client.create_credential_template(**template_data)
        
        # Step 5: Create presentation policy
        policy_data = TestDataBuilder.presentation_policy_age_verification(
            organization_id=org_id,
            credential_template_id=template["id"],
        )
        policy = await gateway_client.create_presentation_policy(**policy_data)
        
        # Step 6: Verify everything is linked
        assert trust_profile["organization_id"] == org_id
        assert revocation_profile["organization_id"] == org_id
        assert template["organization_id"] == org_id
        assert policy["organization_id"] == org_id
        # Note: revocation_profile_id may not be returned by the credential template API
        
        # Verify we can retrieve all resources
        retrieved_org = await gateway_client.get_organization(org_id)
        assert retrieved_org["id"] == org_id
        
        trust_profiles = await gateway_client.list_trust_profiles(org_id)
        assert any(tp["id"] == trust_profile["id"] for tp in trust_profiles)
        
        templates = await gateway_client.list_credential_templates(org_id)
        assert any(t["id"] == template["id"] for t in templates)

        revocation_profiles = await gateway_client.list_revocation_profiles(org_id)
        assert any(rp["id"] == revocation_profile["id"] for rp in revocation_profiles)
        
        policies = await gateway_client.list_presentation_policies(org_id)
        assert any(p["id"] == policy["id"] for p in policies)
