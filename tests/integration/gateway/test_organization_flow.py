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

from .helpers.gateway_client import GatewayClient
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
        assert trust_profile["revocation_check_enabled"] is True
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
        3. Create credential template (mDL)
        4. Create presentation policy (age verification)
        5. Verify all resources are linked correctly
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
        
        # Step 3: Create credential template
        template_data = TestDataBuilder.mdl_template(organization_id=org_id)
        template = await gateway_client.create_credential_template(**template_data)
        
        # Step 4: Create presentation policy
        policy_data = TestDataBuilder.presentation_policy_age_verification(
            organization_id=org_id,
            credential_template_id=template["id"],
        )
        policy = await gateway_client.create_presentation_policy(**policy_data)
        
        # Step 5: Verify everything is linked
        assert trust_profile["organization_id"] == org_id
        assert template["organization_id"] == org_id
        assert policy["organization_id"] == org_id
        
        # Verify we can retrieve all resources
        retrieved_org = await gateway_client.get_organization(org_id)
        assert retrieved_org["id"] == org_id
        
        trust_profiles = await gateway_client.list_trust_profiles(org_id)
        assert any(tp["id"] == trust_profile["id"] for tp in trust_profiles)
        
        templates = await gateway_client.list_credential_templates(org_id)
        assert any(t["id"] == template["id"] for t in templates)
        
        policies = await gateway_client.list_presentation_policies(org_id)
        assert any(p["id"] == policy["id"] for p in policies)
