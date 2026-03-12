"""
Integration tests for error paths and negative scenarios.

Tests invalid inputs, cross-organization access attempts,
expired requests, and other error handling scenarios.
"""
from typing import Any, Dict

import pytest

from .helpers.gateway_client import GatewayClient
from .helpers.test_data import TestDataBuilder


@pytest.mark.integration
@pytest.mark.asyncio
class TestInvalidPolicyErrors:
    """Test error handling for invalid policy IDs"""

    async def test_verification_with_invalid_policy_id(
        self,
        gateway_client: GatewayClient,
    ):
        """Test starting verification with non-existent policy ID"""
        with pytest.raises(Exception) as exc_info:
            await gateway_client.start_verification_flow(
                presentation_policy_id="00000000-0000-0000-0000-000000000000",
            )
        
        # Should raise 404 or similar error
        error_msg = str(exc_info.value).lower()
        assert "not found" in error_msg or "404" in error_msg or "does not exist" in error_msg
        
    async def test_create_deployment_profile_with_invalid_policy(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test creating deployment profile with non-existent presentation policy"""
        profile_data = TestDataBuilder.deployment_profile(
            organization_id=test_organization["id"],
            default_presentation_policy_id="00000000-0000-0000-0000-000000000000",
        )
        
        with pytest.raises(Exception) as exc_info:
            await gateway_client.create_deployment_profile(**profile_data)
        
        # Should raise validation error
        error_msg = str(exc_info.value).lower()
        assert "not found" in error_msg or "invalid" in error_msg or "does not exist" in error_msg
        
    async def test_create_flow_with_invalid_policy(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test creating flow definition with invalid presentation policy"""
        flow_data = {
            "organization_id": test_organization["id"],
            "name": "Invalid Policy Flow",
            "type": "verification",
            "presentation_policy_id": "00000000-0000-0000-0000-000000000000",
        }
        
        with pytest.raises(Exception) as exc_info:
            await gateway_client.create_flow_definition(**flow_data)
        
        error_msg = str(exc_info.value).lower()
        assert "not found" in error_msg or "invalid" in error_msg or "policy" in error_msg


@pytest.mark.integration
@pytest.mark.asyncio
class TestInvalidCredentialTemplateErrors:
    """Test error handling for invalid credential templates"""

    async def test_issue_with_invalid_template_id(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        test_wallet: Dict[str, Any],
    ):
        """Test issuing credential with non-existent template"""
        with pytest.raises(Exception) as exc_info:
            await gateway_client.issue_credential(
                organization_id=test_organization["id"],
                credential_template_id="00000000-0000-0000-0000-000000000000",
                subject_did=test_wallet["did"],
                claims={"test": "data"},
            )
        
        error_msg = str(exc_info.value).lower()
        assert "not found" in error_msg or "404" in error_msg or "invalid" in error_msg
        
    async def test_policy_with_invalid_template_id(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test creating presentation policy with invalid credential template"""
        policy_data = TestDataBuilder.presentation_policy_age_verification(
            organization_id=test_organization["id"],
            credential_template_id="00000000-0000-0000-0000-000000000000",
        )
        
        with pytest.raises(Exception) as exc_info:
            await gateway_client.create_presentation_policy(**policy_data)
        
        error_msg = str(exc_info.value).lower()
        assert "not found" in error_msg or "invalid" in error_msg or "template" in error_msg


@pytest.mark.integration
@pytest.mark.asyncio
class TestCrossOrganizationAccessErrors:
    """Test cross-organization access restrictions"""

    async def test_access_other_org_credential_template(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test that organization cannot access another org's credential templates"""
        org1_id = test_organization["id"]
        
        # Create second organization
        org2_data = TestDataBuilder.organization(name="Org 2 for Access Test")
        org2 = await gateway_client.create_organization(**org2_data)
        org2_id = org2["id"]
        
        try:
            # Create template in org2
            template_data = TestDataBuilder.mdl_template(organization_id=org2_id)
            org2_template = await gateway_client.create_credential_template(**template_data)
            
            # Try to issue credential from org1 using org2's template
            with pytest.raises(Exception) as exc_info:
                await gateway_client.issue_credential(
                    organization_id=org1_id,
                    credential_template_id=org2_template["id"],
                    subject_did="did:key:test123",
                    claims=TestDataBuilder.mdl_claims(),
                )
            
            error_msg = str(exc_info.value).lower()
            assert any(word in error_msg for word in ["not found", "forbidden", "unauthorized", "access denied", "permission"])
            
        finally:
            pass  # Cleanup handled by infrastructure
            
    async def test_access_other_org_presentation_policy(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """Test that organization cannot use another org's presentation policy"""
        org1_id = test_organization["id"]
        
        # Create second organization
        org2_data = TestDataBuilder.organization(name="Org 2 Policy Test")
        org2 = await gateway_client.create_organization(**org2_data)
        org2_id = org2["id"]
        
        try:
            # Create template in org2
            org2_template_data = TestDataBuilder.mdl_template(organization_id=org2_id)
            org2_template = await gateway_client.create_credential_template(**org2_template_data)
            
            # Create policy in org2
            org2_policy_data = TestDataBuilder.presentation_policy_age_verification(
                organization_id=org2_id,
                credential_template_id=org2_template["id"],
            )
            org2_policy = await gateway_client.create_presentation_policy(**org2_policy_data)
            
            # Try to use org2's policy from org1's deployment profile
            deployment_data = TestDataBuilder.deployment_profile(
                organization_id=org1_id,
                default_presentation_policy_id=org2_policy["id"],
            )
            
            with pytest.raises(Exception) as exc_info:
                await gateway_client.create_deployment_profile(**deployment_data)
            
            error_msg = str(exc_info.value).lower()
            assert any(word in error_msg for word in ["not found", "forbidden", "unauthorized", "invalid", "access"])
            
        finally:
            pass
            
    async def test_access_other_org_compliance_profile(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test that organization cannot use another org's compliance profile"""
        org1_id = test_organization["id"]
        
        # Create second organization
        org2_data = TestDataBuilder.organization(name="Org 2 Compliance Test")
        org2 = await gateway_client.create_organization(**org2_data)
        org2_id = org2["id"]
        
        try:
            # Create compliance profile in org2
            org2_profile_data = TestDataBuilder.compliance_profile(organization_id=org2_id)
            org2_profile = await gateway_client.create_compliance_profile(**org2_profile_data)
            
            # Try to create template in org1 using org2's compliance profile
            template_data = TestDataBuilder.mdl_template(
                organization_id=org1_id,
                compliance_profile_id=org2_profile["id"],
            )
            
            with pytest.raises(Exception) as exc_info:
                await gateway_client.create_credential_template(**template_data)
            
            error_msg = str(exc_info.value).lower()
            assert any(word in error_msg for word in ["not found", "forbidden", "unauthorized", "invalid", "access"])
            
        finally:
            pass


@pytest.mark.integration
@pytest.mark.asyncio
class TestInvalidIssuanceErrors:
    """Test error handling for invalid issuance operations"""

    async def test_issue_with_missing_required_claims(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
        test_wallet: Dict[str, Any],
    ):
        """Test issuing credential with missing required claims"""
        # Provide incomplete claims (missing required fields)
        incomplete_claims = {
            "given_name": "Test",
            # Missing family_name, birth_date, document_number, etc.
        }
        
        with pytest.raises(Exception) as exc_info:
            await gateway_client.issue_credential(
                organization_id=test_organization["id"],
                credential_template_id=mdl_template["id"],
                subject_did=test_wallet["did"],
                claims=incomplete_claims,
            )
        
        error_msg = str(exc_info.value).lower()
        assert any(word in error_msg for word in ["required", "missing", "invalid", "validation", "claim"])
        
    async def test_revoke_nonexistent_credential(
        self,
        gateway_client: GatewayClient,
    ):
        """Test revoking a credential that doesn't exist"""
        with pytest.raises(Exception) as exc_info:
            await gateway_client.revoke_credential(
                issuance_id="00000000-0000-0000-0000-000000000000",
                reason="Test revocation",
            )
        
        error_msg = str(exc_info.value).lower()
        assert "not found" in error_msg or "404" in error_msg or "does not exist" in error_msg
        
    async def test_revoke_already_revoked_credential(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
        test_wallet: Dict[str, Any],
    ):
        """Test revoking a credential that's already revoked"""
        # Issue credential
        claims = TestDataBuilder.mdl_claims()
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=mdl_template["id"],
            subject_did=test_wallet["did"],
            claims=claims,
        )
        
        # Revoke it
        await gateway_client.revoke_credential(
            issuance_id=issuance["id"],
            reason="First revocation",
        )
        
        # Try to revoke again
        with pytest.raises(Exception) as exc_info:
            await gateway_client.revoke_credential(
                issuance_id=issuance["id"],
                reason="Second revocation",
            )
        
        error_msg = str(exc_info.value).lower()
        # May succeed but indicate already revoked, or may throw error
        # Accept either behavior
        assert "already" in error_msg or "revoked" in error_msg or exc_info.value is None


@pytest.mark.integration
@pytest.mark.asyncio
class TestInvalidDeploymentProfileErrors:
    """Test error handling for deployment profile operations"""

    async def test_create_lane_with_invalid_deployment_profile(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test creating lane with non-existent deployment profile"""
        lane_data = TestDataBuilder.lane(
            organization_id=test_organization["id"],
            deployment_profile_id="00000000-0000-0000-0000-000000000000",
        )
        
        with pytest.raises(Exception) as exc_info:
            await gateway_client.create_lane(**lane_data)
        
        error_msg = str(exc_info.value).lower()
        assert "not found" in error_msg or "invalid" in error_msg or "profile" in error_msg
        
    async def test_assign_device_to_invalid_lane(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test assigning device to non-existent lane"""
        with pytest.raises(Exception) as exc_info:
            await gateway_client.assign_device_to_lane(
                lane_id="00000000-0000-0000-0000-000000000000",
                device_id="test-device-123",
                device_name="Test Device",
            )
        
        error_msg = str(exc_info.value).lower()
        assert "not found" in error_msg or "invalid" in error_msg or "lane" in error_msg
        
    async def test_activate_invalid_deployment_profile(
        self,
        gateway_client: GatewayClient,
    ):
        """Test activating non-existent deployment profile"""
        with pytest.raises(Exception) as exc_info:
            await gateway_client.activate_deployment_profile(
                profile_id="00000000-0000-0000-0000-000000000000"
            )
        
        error_msg = str(exc_info.value).lower()
        assert "not found" in error_msg or "404" in error_msg


@pytest.mark.integration
@pytest.mark.asyncio
class TestInvalidFlowErrors:
    """Test error handling for flow definition operations"""

    async def test_start_flow_instance_with_invalid_definition(
        self,
        gateway_client: GatewayClient,
    ):
        """Test starting flow instance with non-existent flow definition"""
        with pytest.raises(Exception) as exc_info:
            await gateway_client.start_flow_instance(
                flow_definition_id="00000000-0000-0000-0000-000000000000",
                context={"test": "data"},
            )
        
        error_msg = str(exc_info.value).lower()
        assert "not found" in error_msg or "invalid" in error_msg or "flow" in error_msg
        
    async def test_get_flow_instance_invalid_id(
        self,
        gateway_client: GatewayClient,
    ):
        """Test getting non-existent flow instance"""
        with pytest.raises(Exception) as exc_info:
            await gateway_client.get_flow_instance(
                instance_id="00000000-0000-0000-0000-000000000000"
            )
        
        error_msg = str(exc_info.value).lower()
        assert "not found" in error_msg or "404" in error_msg


@pytest.mark.integration
@pytest.mark.asyncio
class TestInvalidVerificationErrors:
    """Test error handling for verification flow errors"""

    async def test_get_verification_result_invalid_id(
        self,
        gateway_client: GatewayClient,
    ):
        """Test getting verification result with invalid instance ID"""
        with pytest.raises(Exception) as exc_info:
            await gateway_client.get_verification_result(
                instance_id="00000000-0000-0000-0000-000000000000"
            )
        
        error_msg = str(exc_info.value).lower()
        assert "not found" in error_msg or "404" in error_msg or "invalid" in error_msg
        
    async def test_wallet_present_to_invalid_verification_url(
        self,
        test_wallet: Dict[str, Any],
    ):
        """Test wallet presenting to invalid verification URL"""
        wallet_client = test_wallet["client"]
        
        with pytest.raises(Exception):
            await wallet_client.present_credential(
                presentation_request_url="https://invalid.example.com/presentation/00000000",
                credential_ids=["test-cred-id"],
                did=test_wallet["did"],
            )


@pytest.mark.integration
@pytest.mark.asyncio
class TestInvalidTrustProfileErrors:
    """Test error handling for trust profile operations"""

    async def test_create_template_with_invalid_trust_profile(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test creating credential template with non-existent trust profile"""
        template_data = TestDataBuilder.mdl_template(
            organization_id=test_organization["id"],
        )
        # Add invalid trust profile ID
        template_data["trust_profile_id"] = "00000000-0000-0000-0000-000000000000"
        
        with pytest.raises(Exception) as exc_info:
            await gateway_client.create_credential_template(**template_data)
        
        error_msg = str(exc_info.value).lower()
        # May fail with trust profile not found or may ignore if field not validated
        # Accept either behavior
        if exc_info.value:
            assert "not found" in error_msg or "invalid" in error_msg or "trust" in error_msg


@pytest.mark.integration
@pytest.mark.asyncio
class TestMalformedRequestErrors:
    """Test error handling for malformed requests"""

    async def test_create_organization_with_missing_name(
        self,
        gateway_client: GatewayClient,
    ):
        """Test creating organization without required name field"""
        with pytest.raises(Exception) as exc_info:
            await gateway_client.create_organization(
                name="",  # Empty name
                domain="test.example.com",
            )
        
        error_msg = str(exc_info.value).lower()
        assert any(word in error_msg for word in ["required", "invalid", "name", "validation", "empty"])
        
    async def test_create_template_with_invalid_format(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test creating template with invalid credential format"""
        template_data = TestDataBuilder.mdl_template(
            organization_id=test_organization["id"],
        )
        template_data["supported_formats"] = ["invalid_format_xyz"]
        
        with pytest.raises(Exception) as exc_info:
            await gateway_client.create_credential_template(**template_data)
        
        error_msg = str(exc_info.value).lower()
        assert any(word in error_msg for word in ["invalid", "format", "unsupported", "validation"])


@pytest.mark.integration
@pytest.mark.asyncio
class TestResourceLimitErrors:
    """Test error handling for resource limits and constraints"""

    async def test_create_template_with_excessively_large_schema(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test creating template with very large schema (if size limits exist)"""
        template_data = TestDataBuilder.mdl_template(
            organization_id=test_organization["id"],
        )
        
        # Add many properties to schema
        large_schema_properties = {f"field_{i}": {"type": "string"} for i in range(1000)}
        template_data["schema"]["properties"] = large_schema_properties
        
        # May succeed or fail depending on size limits
        # This test documents behavior rather than asserting specific outcome
        try:
            template = await gateway_client.create_credential_template(**template_data)
            # If successful, template should have ID
            assert template["id"] is not None
        except Exception as e:
            # If it fails, should be due to size/validation
            error_msg = str(e).lower()
            assert any(word in error_msg for word in ["too large", "limit", "size", "validation", "too many"])
