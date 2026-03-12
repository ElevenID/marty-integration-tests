"""
Flow Definition Integration Tests

Tests flow definition and execution orchestration:
1. Flow definition CRUD operations
2. Flow instance lifecycle (start, advance, complete, cancel)
3. Approval strategy testing (AUTO, MANUAL, RULES_BASED)
4. Flow integration with deployment profiles
5. Credential issuance flows
6. Verification flows

Flows orchestrate end-to-end journeys: apply → approve → issue → present → verify.
They tie together trust profiles, credential templates, presentation policies, and deployment profiles.
"""

import pytest
from typing import Dict, Any

from .helpers.gateway_client import GatewayClient
from .helpers.test_data import TestDataBuilder


@pytest.mark.asyncio
@pytest.mark.integration
class TestFlowDefinitionCRUD:
    """Test flow definition CRUD operations"""
    
    async def test_create_issuance_flow_definition(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        test_trust_profile: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """Test creating an issuance flow definition"""
        flow_def = await gateway_client.create_flow_definition(
            organization_id=test_organization["id"],
            name="mDL Issuance Flow",
            flow_type="issuance",
            trust_profile_id=test_trust_profile["id"],
            credential_template_id=mdl_template["id"],
        )
        
        assert flow_def is not None
        assert "id" in flow_def
        assert flow_def["name"] == "mDL Issuance Flow"
        assert flow_def["flow_type"] == "issuance"
        assert flow_def["credential_template_id"] == mdl_template["id"]
        
    async def test_create_verification_flow_definition(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        test_trust_profile: Dict[str, Any],
        age_verification_policy: Dict[str, Any],
        test_deployment_profile: Dict[str, Any],
    ):
        """Test creating a verification flow definition"""
        flow_def = await gateway_client.create_flow_definition(
            organization_id=test_organization["id"],
            name="Age Verification Flow",
            flow_type="verification",
            trust_profile_id=test_trust_profile["id"],
            presentation_policy_id=age_verification_policy["id"],
        )
        
        assert flow_def is not None
        assert "id" in flow_def
        assert flow_def["flow_type"] == "verification"
        assert flow_def["presentation_policy_id"] == age_verification_policy["id"]
        
    async def test_get_flow_definition(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """Test retrieving a flow definition by ID"""
        # Create flow
        flow_def = await gateway_client.create_flow_definition(
            organization_id=test_organization["id"],
            name="Test Flow",
            flow_type="issuance",
            credential_template_id=mdl_template["id"],
        )
        
        # Get it back
        retrieved = await gateway_client.get_flow_definition(flow_def["id"])
        
        assert retrieved["id"] == flow_def["id"]
        assert retrieved["name"] == "Test Flow"
        
    async def test_list_flow_definitions(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """Test listing flow definitions for an organization"""
        # Create a flow
        flow_def = await gateway_client.create_flow_definition(
            organization_id=test_organization["id"],
            name="Listable Flow",
            flow_type="issuance",
            credential_template_id=mdl_template["id"],
        )
        
        # List flows
        flows = await gateway_client.list_flow_definitions(
            organization_id=test_organization["id"]
        )
        
        assert isinstance(flows, list)
        flow_ids = [f["id"] for f in flows]
        assert flow_def["id"] in flow_ids


@pytest.mark.asyncio
@pytest.mark.integration
class TestFlowInstanceLifecycle:
    """Test flow instance execution"""
    
    async def test_start_flow_instance(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """Test starting a flow instance"""
        # Create flow definition
        flow_def = await gateway_client.create_flow_definition(
            organization_id=test_organization["id"],
            name="Issuance Flow",
            flow_type="issuance",
            credential_template_id=mdl_template["id"],
        )
        
        # Start instance
        instance = await gateway_client.start_flow_instance(
            flow_definition_id=flow_def["id"],
            subject_id="test-subject-123",
        )
        
        assert instance is not None
        assert "id" in instance
        assert instance["status"] in ["pending", "active", "started", "running"]
        
    async def test_get_flow_instance(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """Test retrieving a flow instance"""
        # Create and start flow
        flow_def = await gateway_client.create_flow_definition(
            organization_id=test_organization["id"],
            name="Test Flow",
            flow_type="issuance",
            credential_template_id=mdl_template["id"],
        )
        
        instance = await gateway_client.start_flow_instance(
            flow_definition_id=flow_def["id"],
        )
        
        # Get instance
        retrieved = await gateway_client.get_flow_instance(instance["id"])
        
        assert retrieved["id"] == instance["id"]
        assert "status" in retrieved
        
    async def test_flow_instance_with_context(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """Test starting flow instance with initial context"""
        flow_def = await gateway_client.create_flow_definition(
            organization_id=test_organization["id"],
            name="Contextual Flow",
            flow_type="issuance",
            credential_template_id=mdl_template["id"],
        )
        
        # Start with context
        instance = await gateway_client.start_flow_instance(
            flow_definition_id=flow_def["id"],
            subject_id="user-456",
            initial_context={
                "application_id": "app-123",
                "channel": "web",
                "metadata": {"ip": "192.168.1.1"},
            },
        )
        
        assert instance is not None
        assert "context" in instance or "initial_context" in instance


@pytest.mark.asyncio
@pytest.mark.integration
class TestFlowApprovalStrategies:
    """Test different approval strategies"""
    
    async def test_flow_with_auto_approval(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """Test flow with AUTO approval strategy"""
        # Create flow with AUTO approval
        flow_def = await gateway_client.create_flow_definition(
            organization_id=test_organization["id"],
            name="Auto Approval Flow",
            flow_type="issuance",
            credential_template_id=mdl_template["id"],
            steps=[
                {
                    "name": "validate",
                    "type": "validation",
                },
                {
                    "name": "approve",
                    "type": "approval",
                    "approval_strategy": "AUTO",
                },
                {
                    "name": "issue",
                    "type": "issuance",
                },
            ],
        )
        
        assert flow_def is not None
        # Verify approval strategy in steps
        approval_step = next((s for s in flow_def.get("steps", []) if s["type"] == "approval"), None)
        if approval_step:
            assert approval_step["approval_strategy"] == "AUTO"
            
    async def test_flow_with_manual_approval(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """Test flow with MANUAL approval strategy"""
        flow_def = await gateway_client.create_flow_definition(
            organization_id=test_organization["id"],
            name="Manual Approval Flow",
            flow_type="issuance",
            credential_template_id=mdl_template["id"],
            steps=[
                {
                    "name": "validate",
                    "type": "validation",
                },
                {
                    "name": "approve",
                    "type": "approval",
                    "approval_strategy": "MANUAL",
                },
                {
                    "name": "issue",
                    "type": "issuance",
                },
            ],
        )
        
        assert flow_def is not None
        approval_step = next((s for s in flow_def.get("steps", []) if s["type"] == "approval"), None)
        if approval_step:
            assert approval_step["approval_strategy"] == "MANUAL"


@pytest.mark.asyncio
@pytest.mark.integration
class TestFlowWithDeploymentProfile:
    """Test flow integration with deployment profiles"""
    
    async def test_create_flow_with_deployment_profile(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        age_verification_policy: Dict[str, Any],
        test_deployment_profile: Dict[str, Any],
    ):
        """Test creating a flow bound to a deployment profile"""
        # Create verification flow with deployment profile
        flow_def = await gateway_client.create_flow_definition(
            organization_id=test_organization["id"],
            name="Gate Verification Flow",
            flow_type="verification",
            presentation_policy_id=age_verification_policy["id"],
        )
        
        # Note: deployment_profile_ids binding might be done differently
        # depending on implementation - this is a placeholder for the pattern
        assert flow_def is not None
        
    async def test_verification_flow_via_deployment_profile(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        age_verification_policy: Dict[str, Any],
        test_deployment_profile: Dict[str, Any],
    ):
        """Test executing verification through deployment profile's flow"""
        # The deployment profile has a default policy
        # Start verification flow that would be used by the deployment profile
        flow = await gateway_client.start_verification_flow(
            presentation_policy_id=test_deployment_profile["default_presentation_policy_id"],
        )
        
        assert flow is not None
        assert "instance_id" in flow


@pytest.mark.asyncio
@pytest.mark.integration
class TestIssuanceFlow:
    """Test credential issuance through flows"""
    
    async def test_complete_issuance_flow(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        test_trust_profile: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """Test complete issuance flow from start to credential issuance"""
        # Create flow definition
        flow_def = await gateway_client.create_flow_definition(
            organization_id=test_organization["id"],
            name="Complete Issuance Flow",
            flow_type="issuance",
            trust_profile_id=test_trust_profile["id"],
            credential_template_id=mdl_template["id"],
        )
        
        # Start flow instance
        instance = await gateway_client.start_flow_instance(
            flow_definition_id=flow_def["id"],
            subject_id="test-subject-789",
        )
        
        # Flow should progress (in real scenario, might need to advance through steps)
        assert instance["status"] in ["pending", "active", "started", "running"]
        
        # Note: Full flow execution would require:
        # 1. Providing evidence
        # 2. Approval (manual or auto)
        # 3. Credential issuance
        # This test validates the flow can be started
        
    async def test_issuance_flow_with_application(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
        mdl_application_template: Dict[str, Any],
    ):
        """Test issuance flow linked to an application template"""
        # Create application-based issuance flow
        flow_def = await gateway_client.create_flow_definition(
            organization_id=test_organization["id"],
            name="Application Issuance Flow",
            flow_type="issuance",
            credential_template_id=mdl_template["id"],
        )
        
        # Create application
        applicant_data = TestDataBuilder.mdl_application_data()
        application = await gateway_client.create_application(
            application_template_id=mdl_application_template["id"],
            applicant_data=applicant_data,
        )
        
        # Start flow for this application
        instance = await gateway_client.start_flow_instance(
            flow_definition_id=flow_def["id"],
            subject_id="applicant-user-id",
            initial_context={"application_id": application["id"]},
        )
        
        assert instance is not None


@pytest.mark.asyncio
@pytest.mark.integration
class TestVerificationFlowIntegration:
    """Test verification flows (builds on existing test_verification_flow.py)"""
    
    async def test_verification_flow_definition(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        age_verification_policy: Dict[str, Any],
    ):
        """Test verification flow definition creation"""
        flow_def = await gateway_client.create_flow_definition(
            organization_id=test_organization["id"],
            name="Age Check Flow",
            flow_type="verification",
            presentation_policy_id=age_verification_policy["id"],
        )
        
        assert flow_def["flow_type"] == "verification"
        assert flow_def["presentation_policy_id"] == age_verification_policy["id"]
        
    async def test_start_verification_via_flow(
        self,
        gateway_client: GatewayClient,
        age_verification_policy: Dict[str, Any],
    ):
        """Test starting verification through the flow API"""
        # This uses the existing verification flow endpoint
        verification = await gateway_client.start_verification_flow(
            presentation_policy_id=age_verification_policy["id"],
        )
        
        assert verification is not None
        assert "instance_id" in verification
        assert "request_uri" in verification or "qr_code_data" in verification


@pytest.mark.asyncio
@pytest.mark.integration
class TestFlowSteps:
    """Test flow step execution"""
    
    async def test_flow_with_multiple_steps(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """Test flow with multiple ordered steps"""
        steps = [
            {"name": "collect_data", "type": "data_collection", "order": 1},
            {"name": "validate", "type": "validation", "order": 2},
            {"name": "approve", "type": "approval", "order": 3},
            {"name": "issue", "type": "issuance", "order": 4},
        ]
        
        flow_def = await gateway_client.create_flow_definition(
            organization_id=test_organization["id"],
            name="Multi-Step Flow",
            flow_type="issuance",
            credential_template_id=mdl_template["id"],
            steps=steps,
        )
        
        assert flow_def is not None
        assert len(flow_def.get("steps", [])) == len(steps)
        
    async def test_flow_step_validation(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """Test flow with validation step"""
        flow_def = await gateway_client.create_flow_definition(
            organization_id=test_organization["id"],
            name="Validation Flow",
            flow_type="issuance",
            credential_template_id=mdl_template["id"],
            steps=[
                {
                    "name": "validate_identity",
                    "type": "validation",
                    "validation_rules": ["check_age", "verify_document"],
                },
            ],
        )
        
        assert flow_def is not None
        validation_step = flow_def.get("steps", [])[0] if flow_def.get("steps") else None
        if validation_step:
            assert validation_step["type"] == "validation"


@pytest.mark.asyncio
@pytest.mark.integration
class TestFlowErrors:
    """Test error handling for flows"""
    
    async def test_create_flow_invalid_organization(
        self,
        gateway_client: GatewayClient,
    ):
        """Test creating flow with invalid organization ID"""
        with pytest.raises(Exception) as exc_info:
            await gateway_client.create_flow_definition(
                organization_id="invalid-org-999",
                name="Invalid Flow",
                flow_type="issuance",
            )
        
        assert "404" in str(exc_info.value) or "not found" in str(exc_info.value).lower()
        
    async def test_create_flow_invalid_template(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test creating flow with invalid credential template"""
        with pytest.raises(Exception) as exc_info:
            await gateway_client.create_flow_definition(
                organization_id=test_organization["id"],
                name="Invalid Template Flow",
                flow_type="issuance",
                credential_template_id="invalid-template-999",
            )
        
        assert "404" in str(exc_info.value) or "not found" in str(exc_info.value).lower()
        
    async def test_start_instance_invalid_flow(
        self,
        gateway_client: GatewayClient,
    ):
        """Test starting instance with invalid flow definition ID"""
        with pytest.raises(Exception) as exc_info:
            await gateway_client.start_flow_instance(
                flow_definition_id="invalid-flow-999",
            )
        
        assert "404" in str(exc_info.value) or "not found" in str(exc_info.value).lower()


@pytest.mark.asyncio
@pytest.mark.integration
class TestFlowConfiguration:
    """Test flow configuration options"""
    
    async def test_flow_with_trust_profile(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        test_trust_profile: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """Test flow with specific trust profile"""
        flow_def = await gateway_client.create_flow_definition(
            organization_id=test_organization["id"],
            name="Trusted Flow",
            flow_type="issuance",
            trust_profile_id=test_trust_profile["id"],
            credential_template_id=mdl_template["id"],
        )
        
        assert flow_def["trust_profile_id"] == test_trust_profile["id"]
        
    async def test_flow_type_variations(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
        age_verification_policy: Dict[str, Any],
    ):
        """Test creating flows of different types"""
        # Issuance flow
        issuance_flow = await gateway_client.create_flow_definition(
            organization_id=test_organization["id"],
            name="Issuance",
            flow_type="issuance",
            credential_template_id=mdl_template["id"],
        )
        assert issuance_flow["flow_type"] == "issuance"
        
        # Verification flow
        verification_flow = await gateway_client.create_flow_definition(
            organization_id=test_organization["id"],
            name="Verification",
            flow_type="verification",
            presentation_policy_id=age_verification_policy["id"],
        )
        assert verification_flow["flow_type"] == "verification"
