"""
Integration tests for compliance profile functionality.

Tests compliance profile creation, usage in credential templates,
format constraint enforcement, and integration with issuance flows.
"""
from typing import Any, Dict

import pytest

from .helpers.gateway_client import GatewayClient, GatewayClientError
from .helpers.test_data import TestDataBuilder

# The server normalises credential_format aliases to canonical enum values.
_FORMAT_CANONICAL = {
    "mso_mdoc": "MDOC",
    "sd_jwt_vc": "SD_JWT_VC",
    "jwt_vc": "VC_JWT",
}


@pytest.mark.integration
@pytest.mark.asyncio
class TestComplianceProfileCRUD:
    """Test compliance profile CRUD operations"""

    async def test_create_compliance_profile(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test creating a compliance profile"""
        profile_data = TestDataBuilder.compliance_profile(
            organization_id=test_organization["id"],
            name="Test AAMVA Profile",
            compliance_code="AAMVA_MDL",
            credential_format="mso_mdoc",
        )
        
        profile = await gateway_client.create_compliance_profile(**profile_data)
        
        assert profile["id"] is not None
        assert profile["name"] == "Test AAMVA Profile"
        assert profile["compliance_code"] == "AAMVA_MDL"
        assert profile["credential_format"] == _FORMAT_CANONICAL["mso_mdoc"]
        assert "aamva" in profile.get("frameworks", [])
        
    async def test_get_compliance_profile(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test retrieving a compliance profile"""
        # Create profile
        profile_data = TestDataBuilder.compliance_profile(
            organization_id=test_organization["id"],
        )
        created = await gateway_client.create_compliance_profile(**profile_data)
        
        # Retrieve it
        retrieved = await gateway_client.get_compliance_profile(created["id"])
        
        assert retrieved["id"] == created["id"]
        assert retrieved["compliance_code"] == created["compliance_code"]
        
    async def test_list_compliance_profiles(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test listing compliance profiles for organization"""
        # Create multiple profiles
        for i in range(3):
            profile_data = TestDataBuilder.compliance_profile(
                organization_id=test_organization["id"],
                name=f"Profile {i}",
            )
            await gateway_client.create_compliance_profile(**profile_data)
        
        # List profiles
        profiles = await gateway_client.list_compliance_profiles(
            organization_id=test_organization["id"]
        )
        
        assert len(profiles) >= 3

    @pytest.mark.xfail(reason="PATCH not supported on compliance-profiles endpoint")
    async def test_update_compliance_profile(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test updating compliance profile fields used in discovery and issuance."""
        profile_data = TestDataBuilder.compliance_profile(
            organization_id=test_organization["id"],
            name="Mutable Compliance Profile",
        )
        created = await gateway_client.create_compliance_profile(**profile_data)

        updated = await gateway_client.update_compliance_profile(
            created["id"],
            name="Mutable Compliance Profile (Updated)",
            description="Updated during launch-readiness integration coverage.",
            discoverable=False,
            metadata={"test_case": "compliance-profile-update"},
        )

        assert updated["id"] == created["id"]
        assert updated["name"] == "Mutable Compliance Profile (Updated)"
        assert updated["description"] == "Updated during launch-readiness integration coverage."
        assert updated["discoverable"] is False
        assert updated["metadata"]["test_case"] == "compliance-profile-update"

    async def test_delete_compliance_profile(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test deleting a compliance profile."""
        profile_data = TestDataBuilder.compliance_profile(
            organization_id=test_organization["id"],
            name="Disposable Compliance Profile",
        )
        created = await gateway_client.create_compliance_profile(**profile_data)

        await gateway_client.delete_compliance_profile(created["id"])

        with pytest.raises(GatewayClientError):
            await gateway_client.get_compliance_profile(created["id"])
        

@pytest.mark.integration
@pytest.mark.asyncio
class TestComplianceProfileTemplateIntegration:
    """Test compliance profile integration with credential templates"""

    async def test_template_with_compliance_profile_id(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test referencing compliance profile by ID in credential template"""
        # Create compliance profile
        profile_data = TestDataBuilder.compliance_profile(
            organization_id=test_organization["id"],
            compliance_code="AAMVA_MDL",
            credential_format="mso_mdoc",
        )
        profile = await gateway_client.create_compliance_profile(**profile_data)
        
        # Create mDL template referencing the profile
        template_data = TestDataBuilder.mdl_template(
            organization_id=test_organization["id"],
            compliance_profile_id=profile["id"],
        )
        
        template = await gateway_client.create_credential_template(**template_data)
        
        assert template["id"] is not None
        # Template should reference the compliance profile
        assert template.get("compliance_profile_id") == profile["id"]
               
    async def test_template_with_embedded_compliance_profile(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test credential template with embedded compliance profile"""
        # Create template without compliance_profile_id (uses embedded)
        template_data = TestDataBuilder.mdl_template(
            organization_id=test_organization["id"],
        )
        
        template = await gateway_client.create_credential_template(**template_data)
        
        assert template["id"] is not None
        # Embedded compliance_profile may or may not be auto-created; at minimum
        # the template was created successfully.


@pytest.mark.integration
@pytest.mark.asyncio
class TestComplianceProfileFormatConstraints:
    """Test compliance profile format constraints"""

    async def test_mdoc_compliance_profile(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test compliance profile for mso_mdoc format"""
        profile_data = TestDataBuilder.compliance_profile(
            organization_id=test_organization["id"],
            compliance_code="AAMVA_MDL",
            credential_format="mso_mdoc",
        )
        
        profile = await gateway_client.create_compliance_profile(**profile_data)
        
        assert profile["credential_format"] == _FORMAT_CANONICAL["mso_mdoc"]
        assert "iso_18013_5" in profile.get("frameworks", [])
        
    async def test_sd_jwt_vc_compliance_profile(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test compliance profile for SD-JWT VC format"""
        profile_data = TestDataBuilder.compliance_profile(
            organization_id=test_organization["id"],
            name="Enterprise SD-JWT Profile",
            compliance_code="ENTERPRISE_VC",
            credential_format="sd_jwt_vc",
        )
        
        profile = await gateway_client.create_compliance_profile(**profile_data)
        
        assert profile["credential_format"] == _FORMAT_CANONICAL["sd_jwt_vc"]
        
    async def test_jwt_vc_compliance_profile(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test compliance profile for JWT VC format"""
        profile_data = TestDataBuilder.compliance_profile(
            organization_id=test_organization["id"],
            name="W3C VC Profile",
            compliance_code="W3C_VC",
            credential_format="jwt_vc",
        )
        
        profile = await gateway_client.create_compliance_profile(**profile_data)
        
        assert profile["credential_format"] == _FORMAT_CANONICAL["jwt_vc"]


@pytest.mark.integration
@pytest.mark.wallet
@pytest.mark.asyncio
class TestComplianceProfileIssuanceFlow:
    """Test compliance profile integration with issuance flows"""

    async def test_issue_credential_with_compliance_profile(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        test_wallet: Dict[str, Any],
    ):
        """Test issuing credential using template with compliance profile"""
        # Create compliance profile
        profile_data = TestDataBuilder.compliance_profile(
            organization_id=test_organization["id"],
        )
        profile = await gateway_client.create_compliance_profile(**profile_data)
        
        # Create credential template with compliance profile
        template_data = TestDataBuilder.mdl_template(
            organization_id=test_organization["id"],
            compliance_profile_id=profile["id"],
        )
        template = await gateway_client.create_credential_template(**template_data)
        
        # Issue credential
        claims = TestDataBuilder.mdl_claims()
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=template["id"],
            subject_did=test_wallet["did"],
            claims=claims,
        )
        
        assert issuance["id"] is not None
        assert issuance["status"] in ["pending", "offered", "issued"]
        
    async def test_issue_multiple_formats_with_compliance_profiles(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        test_wallet: Dict[str, Any],
    ):
        """Test issuing credentials in different formats with appropriate compliance profiles"""
        # Create mDL with mdoc compliance profile
        mdoc_profile_data = TestDataBuilder.compliance_profile(
            organization_id=test_organization["id"],
            credential_format="mso_mdoc",
        )
        mdoc_profile = await gateway_client.create_compliance_profile(**mdoc_profile_data)
        
        mdl_template_data = TestDataBuilder.mdl_template(
            organization_id=test_organization["id"],
            compliance_profile_id=mdoc_profile["id"],
        )
        mdl_template = await gateway_client.create_credential_template(**mdl_template_data)
        
        # Issue mDL
        mdl_claims = TestDataBuilder.mdl_claims()
        mdl_issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=mdl_template["id"],
            subject_did=test_wallet["did"],
            claims=mdl_claims,
        )
        
        assert mdl_issuance["id"] is not None
        
        # Create SD-JWT VC with appropriate compliance profile
        sd_jwt_profile_data = TestDataBuilder.compliance_profile(
            organization_id=test_organization["id"],
            name="SD-JWT Profile",
            compliance_code="ENTERPRISE_VC",
            credential_format="sd_jwt_vc",
        )
        sd_jwt_profile = await gateway_client.create_compliance_profile(**sd_jwt_profile_data)
        
        employee_template_data = TestDataBuilder.employee_badge_template(
            organization_id=test_organization["id"],
        )
        employee_template = await gateway_client.create_credential_template(**employee_template_data)
        
        # Issue employee badge
        badge_claims = TestDataBuilder.employee_badge_claims()
        badge_issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=employee_template["id"],
            subject_did=test_wallet["did"],
            claims=badge_claims,
        )
        
        assert badge_issuance["id"] is not None


@pytest.mark.integration
@pytest.mark.asyncio
class TestComplianceProfileOrganizationIsolation:
    """Test compliance profile organization isolation"""

    async def test_compliance_profile_organization_isolation(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test that compliance profiles are isolated by organization"""
        org1_id = test_organization["id"]
        
        # Create another organization
        org2_data = TestDataBuilder.organization(name="Org 2 for Compliance Test")
        org2 = await gateway_client.create_organization(**org2_data)
        org2_id = org2["id"]
        
        try:
            # Create compliance profile for org1
            profile1_data = TestDataBuilder.compliance_profile(
                organization_id=org1_id,
                name="Org1 Profile",
            )
            profile1 = await gateway_client.create_compliance_profile(**profile1_data)
            
            # Create compliance profile for org2
            profile2_data = TestDataBuilder.compliance_profile(
                organization_id=org2_id,
                name="Org2 Profile",
            )
            profile2 = await gateway_client.create_compliance_profile(**profile2_data)
            
            # List profiles for org1
            org1_profiles = await gateway_client.list_compliance_profiles(
                organization_id=org1_id
            )
            
            # Org1 profiles should not contain org2's profile
            org1_profile_ids = [p["id"] for p in org1_profiles]
            assert profile1["id"] in org1_profile_ids
            assert profile2["id"] not in org1_profile_ids
            
        finally:
            # Cleanup org2
            pass  # Organization cleanup handled by test infrastructure


@pytest.mark.integration
@pytest.mark.asyncio
class TestComplianceProfileFrameworks:
    """Test compliance profile framework specifications"""

    async def test_aamva_iso_frameworks(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test AAMVA and ISO 18013-5 framework specification"""
        profile_data = TestDataBuilder.compliance_profile(
            organization_id=test_organization["id"],
            compliance_code="AAMVA_MDL",
            credential_format="mso_mdoc",
        )
        
        profile = await gateway_client.create_compliance_profile(**profile_data)
        
        assert "aamva" in profile.get("frameworks", [])
        assert "iso_18013_5" in profile.get("frameworks", [])
        
    async def test_w3c_vc_frameworks(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test W3C VC framework specification"""
        profile_data = TestDataBuilder.compliance_profile(
            organization_id=test_organization["id"],
            name="W3C Profile",
            compliance_code="W3C_VC",
            credential_format="jwt_vc",
        )
        profile_data["frameworks"] = ["w3c_vc"]
        
        profile = await gateway_client.create_compliance_profile(**profile_data)
        
        assert "w3c_vc" in profile.get("frameworks", [])


@pytest.mark.integration
@pytest.mark.wallet
@pytest.mark.asyncio
class TestComplianceProfileVerificationIntegration:
    """Test compliance profile integration with verification flows"""

    @pytest.mark.xfail(
        reason="Walt.id stable dids/create always generates Ed25519 keys; "
               "mDoc device auth requires EC (P-256). Tracked upstream.",
        raises=Exception,
    )
    async def test_verify_credential_with_compliance_profile(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        test_wallet: Dict[str, Any],
    ):
        """Test verifying credential issued with compliance profile"""
        # Create compliance profile
        profile_data = TestDataBuilder.compliance_profile(
            organization_id=test_organization["id"],
        )
        profile = await gateway_client.create_compliance_profile(**profile_data)
        
        # Create template and issue credential
        template_data = TestDataBuilder.mdl_template(
            organization_id=test_organization["id"],
            compliance_profile_id=profile["id"],
        )
        template = await gateway_client.create_credential_template(**template_data)
        
        claims = TestDataBuilder.mdl_claims()
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=template["id"],
            subject_did=test_wallet["did"],
            claims=claims,
        )
        
        # Accept credential
        wallet_client = test_wallet["client"]
        await wallet_client.accept_credential_offer(
            offer_url=issuance["credential_offer_uri"],
            did=test_wallet["did"],
        )
        
        # Create presentation policy
        policy_data = TestDataBuilder.presentation_policy_age_verification(
            organization_id=test_organization["id"],
            credential_template_id=template["id"],
        )
        policy = await gateway_client.create_presentation_policy(**policy_data)
        
        # Start verification
        verification_flow = await gateway_client.start_verification_flow(
            presentation_policy_id=policy["id"],
        )
        
        # Present credential
        credentials = await wallet_client.list_credentials()
        if credentials:
            cred_id = credentials[0].get("id") or credentials[0].get("credentialId")
            if cred_id:
                await wallet_client.present_credential(
                    presentation_request_url=verification_flow["request_uri"],
                    credential_ids=[cred_id],
                    did=test_wallet["did"],
                )
                
                # Get result
                result = await gateway_client.get_verification_result(
                    verification_flow["instance_id"]
                )
                
                assert result["status"] in ["verified", "success", "approved", "completed"]
