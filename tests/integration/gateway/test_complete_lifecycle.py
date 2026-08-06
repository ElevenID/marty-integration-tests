"""
Complete Credential Lifecycle Integration Test

Tests the entire credential lifecycle from creation to revocation:
1. Setup organization with all necessary resources
2. Credential issuance through the public gateway
3. Credential verification
4. Credential revocation
5. Re-verification shows revoked status

This test validates the complete end-to-end flow that a real-world
deployment would use.
"""

import pytest
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
        3. Issue through the current public API
        4. Verify credential can be used
        5. Revoke credential
        6. Verify revocation is reflected
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
        await gateway_client.create_compliance_profile(
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
        # Phase 2: Credential Issuance
        # =====================================================================

        claims = TestDataBuilder.mdl_claims(
            given_name="Katherine",
            family_name="Johnson",
            birth_date="1991-08-26",
        )
        issuance = await gateway_client.issue_credential(
            organization_id=org_id,
            credential_template_id=mdl_template["id"],
            claims=claims,
        )
        assert issuance["credential_template_id"] == mdl_template["id"]
        
        # =====================================================================
        # Phase 4: Verification
        # =====================================================================
        
        # Start verification flow
        verification_flow = await gateway_client.start_verification_flow(
            presentation_policy_id=verification_policy["id"],
            trust_profile_id=trust_profile["id"],
        )
        
        assert verification_flow is not None
        assert "instance_id" in verification_flow
        assert "request_uri" in verification_flow or "qr_code_data" in verification_flow
        
        # Verify request can be retrieved (wallet would do this)
        request_obj = await gateway_client.get_verification_request(
            verification_flow["instance_id"]
        )
        assert request_obj is not None
        
        # =====================================================================
        # Phase 5: Revocation
        # =====================================================================
        
        issuance_id = issuance["id"]
        
        # Revoke the credential
        revocation_result = await gateway_client.revoke_credential(
            issuance_id=issuance_id,
            reason="License suspended - integration test",
        )
        assert revocation_result is not None
        
        # Verify issuance record reflects the revocation
        revoked_issuance = await gateway_client.get_issuance(issuance_id)
        assert revoked_issuance["status"] == "revoked"
        
        # Verify revocation status endpoint confirms it
        revocation_status = await gateway_client.get_revocation_status(issuance_id)
        assert revocation_status is not None
        assert revocation_status.get("revoked") is True or revocation_status.get("status") == "revoked"
        
        # =====================================================================
        # Phase 6: Lifecycle Complete
        # =====================================================================
        
        # Verify all resources are correctly linked
        assert trust_profile["organization_id"] == org_id
        assert mdl_template["organization_id"] == org_id
        assert verification_policy["organization_id"] == org_id
        assert issuance["organization_id"] == org_id
        
        # Verify we can retrieve everything
        retrieved_org = await gateway_client.get_organization(org_id)
        assert retrieved_org["id"] == org_id
        
        retrieved_issuance = await gateway_client.get_issuance(issuance_id)
        assert retrieved_issuance["id"] == issuance_id
        assert retrieved_issuance["status"] == "revoked"


@pytest.mark.asyncio
@pytest.mark.integration
class TestMultipleCredentialLifecycles:
    """Test managing multiple credentials for the same organization"""
    
    async def test_multiple_credential_lifecycles(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """Issue and retrieve distinct credentials for multiple subjects."""
        issued = []
        for given_name, family_name in [
            ("Laura", "Adams"),
            ("Michael", "Brown"),
        ]:
            claims = TestDataBuilder.mdl_claims(
                given_name=given_name,
                family_name=family_name,
            )
            issued.append(
                await gateway_client.issue_credential(
                    organization_id=test_organization["id"],
                    credential_template_id=mdl_template["id"],
                    claims=claims,
                )
            )

        issuances = await gateway_client.list_issuances(
            organization_id=test_organization["id"]
        )

        listed_ids = {issuance["id"] for issuance in issuances}
        assert {issuance["id"] for issuance in issued} <= listed_ids


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
        assert flow_status["status"] in ["pending", "waiting", "created", "active", "waiting_user", "AWAITING_WALLET"]


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


@pytest.mark.asyncio
@pytest.mark.integration
class TestRevocationLifecycle:
    """Test complete credential revocation lifecycle (addresses TODOs)"""
    
    async def test_credential_revocation_and_verification(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
        age_verification_policy: Dict[str, Any],
    ):
        """
        Test complete revocation lifecycle:
        1. Issue credential
        2. Verify credential works
        3. Revoke credential
        4. Verify revocation is reflected
        
        Addresses TODO at lines 42-43 in original file.
        """
        # Step 1: Issue credential
        claims = TestDataBuilder.mdl_claims(
            given_name="Sarah",
            family_name="Williams",
        )
        
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=mdl_template["id"],
            claims=claims,
        )
        
        assert issuance is not None
        assert issuance["status"] in ("pending", "issued")
        issuance_id = issuance["id"]
        
        # Step 2: Credential should be valid (start verification flow to test)
        verification_flow = await gateway_client.start_verification_flow(
            presentation_policy_id=age_verification_policy["id"],
        )
        assert verification_flow is not None
        assert "instance_id" in verification_flow
        
        # Step 3: Revoke the credential
        revocation_result = await gateway_client.revoke_credential(
            issuance_id=issuance_id,
            reason="Test revocation for integration test",
        )
        
        assert revocation_result is not None
        # Result should indicate successful revocation
        assert revocation_result.get("status") == "revoked" or "revoked" in str(revocation_result).lower()
        
        # Step 4: Verify revocation is reflected in issuance record
        issuance_after_revocation = await gateway_client.get_issuance(issuance_id)
        assert issuance_after_revocation["status"] == "revoked"
        assert "revoked_at" in issuance_after_revocation or "revocation_date" in issuance_after_revocation
        
        # Step 5: Check revocation status endpoint
        revocation_status = await gateway_client.get_revocation_status(issuance_id)
        assert revocation_status is not None
        assert revocation_status["revoked"] is True or revocation_status["status"] == "revoked"
        
    async def test_revocation_list_update(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """Test that revocation updates the revocation list"""
        # Issue credential
        claims = TestDataBuilder.mdl_claims()
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=mdl_template["id"],
            claims=claims,
        )
        
        # Revoke it
        await gateway_client.revoke_credential(
            issuance_id=issuance["id"],
            reason="Revocation list test",
        )
        
        # Check revocation status
        status = await gateway_client.get_revocation_status(issuance["id"])
        
        # Status should show credential is revoked
        assert status["revoked"] is True or status["status"] == "revoked"
        
        # If revocation index is provided, verify it's set
        if "revocation_index" in issuance or "revocation_index" in status:
            revocation_index = issuance.get("revocation_index") or status.get("revocation_index")
            assert revocation_index is not None
            
    async def test_revoke_with_reason(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        employee_badge_template: Dict[str, Any],
    ):
        """Test revoking credential with specific reason"""
        # Issue employee badge
        claims = TestDataBuilder.employee_badge_claims()
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=employee_badge_template["id"],
            claims=claims,
        )
        
        # Revoke with specific reason
        reason = "Employee terminated"
        result = await gateway_client.revoke_credential(
            issuance_id=issuance["id"],
            reason=reason,
        )
        
        # Verify revocation reason is stored
        issuance_updated = await gateway_client.get_issuance(issuance["id"])
        assert issuance_updated["status"] == "revoked"
        
        # Revocation reason might be in result or updated issuance record
        if "revocation_reason" in issuance_updated:
            assert issuance_updated["revocation_reason"] == reason
        elif "reason" in result:
            assert result["reason"] == reason
            
    async def test_cannot_revoke_twice(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """Test that revoking an already-revoked credential is idempotent or fails gracefully"""
        # Issue and revoke
        claims = TestDataBuilder.mdl_claims()
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=mdl_template["id"],
            claims=claims,
        )
        
        # First revocation
        await gateway_client.revoke_credential(issuance_id=issuance["id"])
        
        # Second revocation attempt
        # Should either succeed (idempotent) or fail with clear error
        try:
            result = await gateway_client.revoke_credential(issuance_id=issuance["id"])
            # If it succeeds, verify status is still revoked
            assert result["status"] == "revoked" or "revoked" in str(result).lower()
        except Exception as e:
            # If it fails, error should mention already revoked
            error_msg = str(e).lower()
            assert "already revoked" in error_msg or "revoked" in error_msg
            
    async def test_list_revoked_credentials(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """Test listing only revoked credentials"""
        # Issue and revoke a credential
        claims = TestDataBuilder.mdl_claims()
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=mdl_template["id"],
            claims=claims,
        )
        
        await gateway_client.revoke_credential(issuance_id=issuance["id"])
        
        # List all issuances
        all_issuances = await gateway_client.list_issuances(
            organization_id=test_organization["id"]
        )
        
        # Find our revoked one
        revoked_issuances = [
            i for i in all_issuances
            if i["id"] == issuance["id"]
        ]
        
        assert len(revoked_issuances) == 1
        assert revoked_issuances[0]["status"] == "revoked"


@pytest.mark.asyncio
@pytest.mark.integration
class TestRevocationScenarios:
    """Test various revocation scenarios"""
    
    async def test_revoke_after_direct_issuance(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """Test revoking a credential issued through the current public API."""
        claims = TestDataBuilder.mdl_claims(
            given_name="Robert",
            family_name="Johnson",
        )
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=mdl_template["id"],
            claims=claims,
        )

        await gateway_client.revoke_credential(issuance_id=issuance["id"])

        revoked_issuance = await gateway_client.get_issuance(issuance["id"])
        assert revoked_issuance["status"] == "revoked"
        
    async def test_bulk_revocation(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        employee_badge_template: Dict[str, Any],
    ):
        """Test revoking multiple credentials"""
        # Issue multiple credentials
        num_credentials = 3
        issuances = []
        
        for i in range(num_credentials):
            claims = TestDataBuilder.employee_badge_claims(
                given_name=f"Employee{i}",
                family_name=f"User{i}",
            )
            issuance = await gateway_client.issue_credential(
                organization_id=test_organization["id"],
                credential_template_id=employee_badge_template["id"],
                claims=claims,
            )
            issuances.append(issuance)
        
        # Revoke all of them
        for issuance in issuances:
            await gateway_client.revoke_credential(
                issuance_id=issuance["id"],
                reason="Bulk revocation test",
            )
        
        # Verify all are revoked
        for issuance in issuances:
            status = await gateway_client.get_revocation_status(issuance["id"])
            assert status["revoked"] is True or status["status"] == "revoked"
