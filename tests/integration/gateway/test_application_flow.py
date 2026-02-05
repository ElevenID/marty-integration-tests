"""
Application Flow Integration Tests

Tests the application-based credential issuance flow that the UI uses:
1. Create application template
2. Submit application with applicant data
3. Submit evidence (documents, photos)
4. Admin approves/rejects application
5. Verify credential is issued (on approval)
"""

import pytest
from typing import Dict, Any

from .helpers.gateway_client import GatewayClient
from .helpers.test_data import TestDataBuilder


@pytest.mark.asyncio
@pytest.mark.integration
class TestApplicationTemplateFlow:
    """Test application template creation and management"""
    
    async def test_create_application_template(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """Test creating an application template"""
        app_template = await gateway_client.create_application_template(
            organization_id=test_organization["id"],
            name="mDL Application Process",
            credential_template_id=mdl_template["id"],
            form_fields=[
                {
                    "field_id": "given_name",
                    "field_type": "text",
                    "label": "Given Name",
                    "required": True
                }
            ],
            evidence_requirements=["drivers_license", "selfie"],
        )
        
        assert app_template is not None
        assert "id" in app_template
        assert app_template["organization_id"] == test_organization["id"]
        assert "drivers_license" in app_template["evidence_requirements"]
        assert "selfie" in app_template["evidence_requirements"]
        
    async def test_get_application_template(
        self,
        gateway_client: GatewayClient,
        mdl_application_template: Dict[str, Any],
    ):
        """Test retrieving an application template by ID"""
        template = await gateway_client.get_application_template(
            mdl_application_template["id"]
        )
        
        assert template["id"] == mdl_application_template["id"]
        assert template["name"] == mdl_application_template["name"]
        
    async def test_list_application_templates(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_application_template: Dict[str, Any],
    ):
        """Test listing application templates for an organization"""
        templates = await gateway_client.list_application_templates(
            organization_id=test_organization["id"]
        )
        
        assert isinstance(templates, list)
        assert len(templates) > 0
        template_ids = [t["id"] for t in templates]
        assert mdl_application_template["id"] in template_ids


@pytest.mark.asyncio
@pytest.mark.integration
class TestApplicationSubmissionFlow:
    """Test application submission and management"""
    
    async def test_create_application(
        self,
        gateway_client: GatewayClient,
        mdl_application_template: Dict[str, Any],
    ):
        """Test creating an application"""
        applicant_data = TestDataBuilder.mdl_application_data(
            given_name="Alice",
            family_name="Smith",
        )
        
        application = await gateway_client.create_application(
            application_template_id=mdl_application_template["id"],
            applicant_data=applicant_data,
        )
        
        assert application is not None
        assert "id" in application
        assert application["status"] == "pending"
        assert application["application_template_id"] == mdl_application_template["id"]
        assert "form_data" in application  # Backend returns form_data
        
    async def test_get_application(
        self,
        gateway_client: GatewayClient,
        mdl_application_template: Dict[str, Any],
    ):
        """Test retrieving an application by ID"""
        # Create application first
        applicant_data = TestDataBuilder.mdl_application_data()
        application = await gateway_client.create_application(
            application_template_id=mdl_application_template["id"],
            applicant_data=applicant_data,
        )
        
        # Retrieve it
        retrieved = await gateway_client.get_application(application["id"])
        
        assert retrieved["id"] == application["id"]
        assert retrieved["status"] == "pending"
        
    async def test_list_applications(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_application_template: Dict[str, Any],
    ):
        """Test listing applications for an organization"""
        # Create an application
        applicant_data = TestDataBuilder.mdl_application_data()
        application = await gateway_client.create_application(
            application_template_id=mdl_application_template["id"],
            applicant_data=applicant_data,
        )
        
        # List applications
        applications = await gateway_client.list_applications(
            organization_id=test_organization["id"]
        )
        
        assert isinstance(applications, list)
        app_ids = [a["id"] for a in applications]
        assert application["id"] in app_ids
        
    async def test_list_applications_by_status(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_application_template: Dict[str, Any],
    ):
        """Test filtering applications by status"""
        # Create an application
        applicant_data = TestDataBuilder.mdl_application_data()
        application = await gateway_client.create_application(
            application_template_id=mdl_application_template["id"],
            applicant_data=applicant_data,
        )
        
        # List pending applications
        pending_apps = await gateway_client.list_applications(
            organization_id=test_organization["id"],
            status="pending",
        )
        
        assert isinstance(pending_apps, list)
        app_ids = [a["id"] for a in pending_apps]
        assert application["id"] in app_ids


@pytest.mark.asyncio
@pytest.mark.integration
class TestEvidenceSubmissionFlow:
    """Test evidence submission for applications"""
    
    async def test_submit_portrait_evidence(
        self,
        gateway_client: GatewayClient,
        mdl_application_template: Dict[str, Any],
    ):
        """Test submitting portrait evidence"""
        # Create application
        applicant_data = TestDataBuilder.mdl_application_data()
        application = await gateway_client.create_application(
            application_template_id=mdl_application_template["id"],
            applicant_data=applicant_data,
        )
        
        # Submit evidence
        evidence = TestDataBuilder.portrait_evidence()
        updated = await gateway_client.submit_evidence(
            application_id=application["id"],
            evidence=evidence,
        )
        
        assert updated["id"] == application["id"]
        # Evidence should be recorded
        assert "evidence_submissions" in updated
        assert len(updated["evidence_submissions"]) > 0
        
    async def test_submit_identity_document_evidence(
        self,
        gateway_client: GatewayClient,
        mdl_application_template: Dict[str, Any],
    ):
        """Test submitting identity document evidence"""
        applicant_data = TestDataBuilder.mdl_application_data()
        application = await gateway_client.create_application(
            application_template_id=mdl_application_template["id"],
            applicant_data=applicant_data,
        )
        
        evidence = TestDataBuilder.identity_document_evidence()
        updated = await gateway_client.submit_evidence(
            application_id=application["id"],
            evidence=evidence,
        )
        
        assert updated["id"] == application["id"]


@pytest.mark.asyncio
@pytest.mark.integration
class TestApplicationApprovalFlow:
    """Test application approval and rejection workflows"""
    
    async def test_approve_application(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_application_template: Dict[str, Any],
    ):
        """
        Test approving an application (should trigger credential issuance).
        
        Flow:
        1. Create application
        2. Submit evidence
        3. Approve application
        4. Verify status is "approved"
        5. Verify credential was issued
        """
        # Step 1: Create application
        applicant_data = TestDataBuilder.mdl_application_data(
            given_name="Bob",
            family_name="Johnson",
        )
        application = await gateway_client.create_application(
            application_template_id=mdl_application_template["id"],
            applicant_data=applicant_data,
        )
        app_id = application["id"]
        
        # Step 2: Submit evidence
        evidence = TestDataBuilder.portrait_evidence()
        await gateway_client.submit_evidence(
            application_id=app_id,
            evidence=evidence,
        )
        
        # Step 3: Approve application
        approved = await gateway_client.approve_application(app_id)
        
        # Step 4: Verify status
        assert approved["id"] == app_id
        assert approved["status"] == "approved"
        
        # Step 5: Verify application links to issuance transaction
        assert approved.get("issuance_transaction_id") is not None
        
    async def test_reject_application(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_application_template: Dict[str, Any],
    ):
        """
        Test rejecting an application (should NOT issue credential).
        
        Flow:
        1. Create application
        2. Reject application
        3. Verify status is "rejected"
        4. Verify NO credential was issued
        """
        # Step 1: Create application
        applicant_data = TestDataBuilder.mdl_application_data(
            given_name="Charlie",
            family_name="Brown",
        )
        application = await gateway_client.create_application(
            application_template_id=mdl_application_template["id"],
            applicant_data=applicant_data,
        )
        app_id = application["id"]
        
        # Step 2: Reject application
        rejected = await gateway_client.reject_application(
            app_id,
            review_notes="Application incomplete - missing required documentation"
        )
        
        # Step 3: Verify status
        assert rejected["id"] == app_id
        assert rejected["status"] == "rejected"
        
        # Step 4: Verify NO issuance transaction was created
        assert rejected.get("issuance_transaction_id") is None
class TestCompleteApplicationFlow:
    """Test complete application flow end-to-end"""
    
    async def test_mdl_application_full_flow(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """
        Test complete mDL application flow as UI would use it:
        1. Create application template
        2. Submit application
        3. Submit all required evidence
        4. Admin approves
        5. Credential is issued
        6. Verify credential details
        """
        # Step 1: Create application template
        app_template = await gateway_client.create_application_template(
            organization_id=test_organization["id"],
            name="Driver's License Application",
            credential_template_id=mdl_template["id"],
            evidence_requirements=["drivers_license", "selfie"],
        )
        
        # Step 2: Submit application
        applicant_data = TestDataBuilder.mdl_application_data(
            given_name="Diana",
            family_name="Prince",
            birth_date="1985-03-22",
        )
        application = await gateway_client.create_application(
            application_template_id=app_template["id"],
            applicant_data=applicant_data,
        )
        
        assert application["status"] == "pending"
        app_id = application["id"]
        
        # Step 3: Submit evidence
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
        
        # Step 4: Admin approves
        approved = await gateway_client.approve_application(app_id)
        assert approved["status"] == "approved"
        
        # Step 5: Verify issuance transaction was created and linked
        assert approved.get("issuance_transaction_id") is not None
        issuance_tx_id = approved["issuance_transaction_id"]
        
        # Step 6: Verify we can retrieve the issuance transaction
        retrieved = await gateway_client.get_issuance(issuance_tx_id)
        assert retrieved["id"] == issuance_tx_id
        assert retrieved["organization_id"] == test_organization["id"]
        assert retrieved["credential_template_id"] == mdl_template["id"]
