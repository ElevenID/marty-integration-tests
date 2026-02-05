"""
Complete Credential Lifecycle Integration Test

Tests the entire credential lifecycle from creation to revocation:
1. Setup organization with all necessary resources
2. Application submission and approval
3. Credential issuance
4. Credential verification (stateless)
5. Credential revocation
6. Re-verification shows revoked status

This test validates the complete end-to-end flow that a real-world
deployment would use.
"""

import pytest
import asyncio
from typing import Dict, Any

from .helpers.gateway_client import GatewayClient
from .helpers.test_data import TestDataBuilder


@pytest.mark.asyncio
@pytest.mark.integration
class TestCompleteCredentialLifecycle:
    """Test complete credential lifecycle from creation to revocation"""
    
    async def test_full_mdl_lifecycle(
        self,
        gateway_client: GatewayClient,
    ):
        """
        Test complete mDL credential lifecycle:
        1. Create organization
        2. Setup trust profile and credential template
        3. Create application template
        4. Submit application
        5. Submit evidence
        6. Approve application (triggers issuance)
        7. Verify credential can be used
        8. TODO: Revoke credential
        9. TODO: Verify revocation is reflected
        """
        # =====================================================================
        # Phase 1: Organization Setup
        # =====================================================================
        
        # Step 1: Create organization
        org_data = TestDataBuilder.organization(
            name="state-dmv",
            display_name="State DMV",
        )
        org = await gateway_client.create_organization(**org_data)
        org_id = org["id"]
        
        # Step 2: Create trust profile
        trust_profile_data = TestDataBuilder.trust_profile(
            organization_id=org_id
        )
        trust_profile = await gateway_client.create_trust_profile(
            **trust_profile_data
        )
        
        # Step 3: Create compliance profile for mDL
        compliance_profile_data = TestDataBuilder.compliance_profile(
            organization_id=org_id,
            name="AAMVA mDL Compliance",
            compliance_code="AAMVA_MDL",
            credential_format="mso_mdoc",
        )
        compliance_profile = await gateway_client.create_compliance_profile(
            **compliance_profile_data
        )
        
        # Step 4: Create mDL credential template
        # Note: compliance_profile_id integration is a TODO - for now the template
        # uses embedded compliance rules
        mdl_template_data = TestDataBuilder.mdl_template(
            organization_id=org_id,
        )
        mdl_template = await gateway_client.create_credential_template(
            **mdl_template_data
        )
        
        # Step 5: Create presentation policy for verification
        policy_data = TestDataBuilder.presentation_policy_age_verification(
            organization_id=org_id,
            credential_template_id=mdl_template["id"],
            min_age=21,
        )
        verification_policy = await gateway_client.create_presentation_policy(
            **policy_data
        )
        
        # =====================================================================
        # Phase 2: Application Process
        # =====================================================================
        
        # Step 6: Create application template (user-facing workflow)
        app_template_data = TestDataBuilder.application_template(
            organization_id=org_id,
            name="Driver's License Application",
            evidence_requirements=["identity_document", "portrait"],
            credential_template_id=mdl_template["id"],
        )
        app_template = await gateway_client.create_application_template(
            **app_template_data
        )
        
        # Note: In the new architecture, the credential template would reference
        # the application template if this is an application-based flow.
        # For this test, we're using direct issuance after application approval.
        
        # Step 7: Applicant submits application
        applicant_data = TestDataBuilder.mdl_application_data(
            given_name="Katherine",
            family_name="Johnson",
            birth_date="1991-08-26",
        )
        application = await gateway_client.create_application(
            application_template_id=app_template["id"],
            applicant_data=applicant_data,
        )
        app_id = application["id"]
        
        assert application["status"] == "pending"
        
        # Step 7: Submit required evidence
        portrait = TestDataBuilder.portrait_evidence()
        await gateway_client.submit_evidence(
            application_id=app_id,
            evidence=portrait,
        )
        
        id_doc = TestDataBuilder.identity_document_evidence()
        await gateway_client.submit_evidence(
            application_id=app_id,
            evidence=id_doc,
        )
        
        # Step 8: Admin approves application
        approved = await gateway_client.approve_application(app_id)
        assert approved["status"] == "approved"
        
        # =====================================================================
        # Phase 3: Credential Issuance
        # =====================================================================
        
        # Step 9: Verify credential was issued
        issuances = await gateway_client.list_issuances(
            organization_id=org_id
        )

        # Find issuance linked to this application
        app_issuances = [
            i for i in issuances
            if i.get("application_id") == app_id
        ]
        assert len(app_issuances) > 0, "Credential should be issued after approval"
        
        issuance = app_issuances[0]
        assert issuance["credential_template_id"] == mdl_template["id"]
        
        # =====================================================================
        # Phase 4: Verification
        # =====================================================================
        
        # Step 10: Start verification flow
        verification_flow = await gateway_client.start_verification_flow(
            presentation_policy_id=verification_policy["id"],
            trust_profile_id=trust_profile["id"],
        )
        
        assert verification_flow is not None
        assert "instance_id" in verification_flow
        assert "request_uri" in verification_flow or "qr_code_data" in verification_flow
        
        # Step 11: Verify request can be retrieved (wallet would do this)
        request_obj = await gateway_client.get_verification_request(
            verification_flow["instance_id"]
        )
        assert request_obj is not None
        
        # =====================================================================
        # Phase 5: Lifecycle Complete
        # =====================================================================
        
        # Verify all resources are correctly linked
        assert trust_profile["organization_id"] == org_id
        assert mdl_template["organization_id"] == org_id
        assert verification_policy["organization_id"] == org_id
        assert app_template["organization_id"] == org_id
        assert issuance["organization_id"] == org_id
        
        # Verify we can retrieve everything
        retrieved_org = await gateway_client.get_organization(org_id)
        assert retrieved_org["id"] == org_id
        
        retrieved_issuance = await gateway_client.get_issuance(issuance["id"])
        assert retrieved_issuance["id"] == issuance["id"]


@pytest.mark.asyncio
@pytest.mark.integration
class TestMultipleCredentialLifecycles:
    """Test managing multiple credentials for the same organization"""
    
    async def test_multiple_applicants_lifecycle(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
        mdl_application_template: Dict[str, Any],
    ):
        """
        Test multiple applicants going through the lifecycle:
        - 3 applicants submit applications
        - 2 get approved, 1 gets rejected
        - Verify correct number of credentials issued
        """
        applicants = [
            ("Laura", "Adams", "approved"),
            ("Michael", "Brown", "approved"),
            ("Nathan", "Clark", "rejected"),
        ]
        
        applications = {}
        
        # Submit applications for all applicants
        for given_name, family_name, expected_status in applicants:
            applicant_data = TestDataBuilder.mdl_application_data(
                given_name=given_name,
                family_name=family_name,
            )
            app = await gateway_client.create_application(
                application_template_id=mdl_application_template["id"],
                applicant_data=applicant_data,
            )
            
            # Submit evidence
            evidence = TestDataBuilder.portrait_evidence()
            await gateway_client.submit_evidence(
                application_id=app["id"],
                evidence=evidence,
            )
            
            applications[given_name] = {
                "application": app,
                "expected_status": expected_status,
            }
        
        # Process applications (approve or reject)
        for name, data in applications.items():
            app = data["application"]
            expected = data["expected_status"]
            
            if expected == "approved":
                result = await gateway_client.approve_application(app["id"])
                assert result["status"] == "approved"
            else:
                result = await gateway_client.reject_application(app["id"])
                assert result["status"] == "rejected"
        
        # Verify correct number of issuances
        issuances = await gateway_client.list_issuances(
            organization_id=test_organization["id"]
        )
        
        # Verify credentials issued for approved applications
        issuances = await gateway_client.list_issuances(
            organization_id=test_organization["id"]
        )
        
        # Count issuances for our applications
        our_app_ids = [d["application"]["id"] for d in applications.values()]
        our_issuances = [
            i for i in issuances
            if i.get("application_id") in our_app_ids
        ]
        
        # Should have exactly 2 issuances (2 approved, 1 rejected)
        assert len(our_issuances) == 2


@pytest.mark.asyncio
@pytest.mark.integration
class TestEmployeeBadgeLifecycle:
    """Test complete employee badge credential lifecycle"""
    
    async def test_employee_badge_issuance_and_verification(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        employee_badge_template: Dict[str, Any],
    ):
        """
        Test employee badge lifecycle:
        1. Direct issuance (no application process)
        2. Create verification policy for building access
        3. Start verification flow
        """
        # Step 1: Issue employee badge directly
        claims = TestDataBuilder.employee_badge_claims(
            given_name="Olivia",
            family_name="Martinez",
        )
        
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=employee_badge_template["id"],
            claims=claims,
        )
        
        assert issuance is not None
        assert "id" in issuance
        
        # Step 2: Create verification policy for employee access
        access_policy_data = TestDataBuilder.presentation_policy_employee_access(
            organization_id=test_organization["id"],
            credential_template_id=employee_badge_template["id"],
            required_department="Engineering",
        )
        access_policy = await gateway_client.create_presentation_policy(
            **access_policy_data
        )
        
        # Step 3: Start verification flow for building entry
        verification_flow = await gateway_client.start_verification_flow(
            presentation_policy_id=access_policy["id"],
        )
        
        assert verification_flow is not None
        assert "instance_id" in verification_flow
        
        # Verify the flow is active
        flow_status = await gateway_client.get_verification_result(
            verification_flow["instance_id"]
        )
        assert flow_status["status"] in ["pending", "waiting", "created", "active", "waiting_user"]


@pytest.mark.asyncio
@pytest.mark.integration
class TestCrossOrganizationIsolation:
    """Test that organizations are properly isolated"""
    
    async def test_organizations_cannot_access_each_others_resources(
        self,
        gateway_client: GatewayClient,
    ):
        """
        Test that resources are isolated between organizations:
        - Create 2 organizations
        - Create resources in each
        - Verify Org A cannot list Org B's resources
        """
        # Create Organization A
        org_a_data = TestDataBuilder.organization(name="org-a")
        org_a = await gateway_client.create_organization(**org_a_data)
        
        # Create Organization B
        org_b_data = TestDataBuilder.organization(name="org-b")
        org_b = await gateway_client.create_organization(**org_b_data)
        
        # Create credential template in Org A
        template_a_data = TestDataBuilder.mdl_template(org_a["id"])
        template_a = await gateway_client.create_credential_template(
            **template_a_data
        )
        
        # Create credential template in Org B
        template_b_data = TestDataBuilder.mdl_template(org_b["id"])
        template_b = await gateway_client.create_credential_template(
            **template_b_data
        )
        
        # List templates for Org A - should NOT see Org B's template
        org_a_templates = await gateway_client.list_credential_templates(
            organization_id=org_a["id"]
        )
        org_a_template_ids = [t["id"] for t in org_a_templates]
        
        assert template_a["id"] in org_a_template_ids
        assert template_b["id"] not in org_a_template_ids
        
        # List templates for Org B - should NOT see Org A's template
        org_b_templates = await gateway_client.list_credential_templates(
            organization_id=org_b["id"]
        )
        org_b_template_ids = [t["id"] for t in org_b_templates]
        
        assert template_b["id"] in org_b_template_ids
        assert template_a["id"] not in org_b_template_ids
