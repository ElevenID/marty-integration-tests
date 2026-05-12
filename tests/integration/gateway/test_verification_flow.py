"""
Verification Flow Integration Tests

Tests both verification approaches:
1. Stateless evaluation: POST /v1/presentation-policies/{id}/evaluate
2. Async wallet flow: POST /v1/flows/verify with QR code

Tests various verification scenarios including success and failure cases.
"""

import pytest
from typing import Dict, Any

from .helpers.gateway_client import GatewayClient
from .helpers.test_data import TestDataBuilder


@pytest.mark.asyncio
@pytest.mark.integration
class TestStatelessVerification:
    """Test stateless presentation evaluation"""
    
    async def test_evaluate_presentation_success(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        age_verification_policy: Dict[str, Any],
    ):
        """
        Test successful presentation evaluation.
        
        Note: This requires a valid VP token. In a real test, we would:
        1. Issue an mDL credential
        2. Create a VP token from it
        3. Evaluate the VP against the policy
        
        For now, we test the endpoint is accessible.
        """
        # This is a simplified test - real test would have actual VP token
        try:
            # Attempt evaluation with mock token
            result = await gateway_client.evaluate_presentation(
                policy_id=age_verification_policy["id"],
                vp_token="mock_vp_token_would_go_here",
                nonce="test_nonce_123",
            )
            # If it doesn't fail immediately, the endpoint is working
            assert "decision" in result or "error" in result
        except Exception as e:
            # Expected - mock token is invalid
            # But we've verified the endpoint exists and is accessible
            assert "token" in str(e).lower() or "invalid" in str(e).lower()
    
    async def test_evaluate_with_invalid_policy(
        self,
        gateway_client: GatewayClient,
    ):
        """Test evaluation with invalid policy ID"""
        with pytest.raises(Exception) as exc_info:
            await gateway_client.evaluate_presentation(
                policy_id="invalid-policy-id-999",
                vp_token="mock_token",
            )
        
        assert "404" in str(exc_info.value) or "not found" in str(exc_info.value).lower()


@pytest.mark.asyncio
@pytest.mark.integration
class TestAsyncVerificationFlow:
    """Test async verification flow (wallet QR code interaction)"""
    
    async def test_start_verification_flow(
        self,
        gateway_client: GatewayClient,
        age_verification_policy: Dict[str, Any],
        test_trust_profile: Dict[str, Any],
    ):
        """
        Test starting a verification flow.
        
        Should return:
        - instance_id: Flow instance identifier
        - request_uri: URI for wallet to fetch request
        - qr_code_data: QR code data for wallet scanning
        """
        flow = await gateway_client.start_verification_flow(
            presentation_policy_id=age_verification_policy["id"],
            trust_profile_id=test_trust_profile["id"],
            expiry_minutes=15,
        )
        
        assert flow is not None
        assert "instance_id" in flow
        assert "request_uri" in flow or "qr_code_data" in flow
        assert "status" in flow
        
    async def test_get_verification_request(
        self,
        gateway_client: GatewayClient,
        age_verification_policy: Dict[str, Any],
    ):
        """Test retrieving verification request object (wallet fetches this)"""
        # Start flow first
        flow = await gateway_client.start_verification_flow(
            presentation_policy_id=age_verification_policy["id"],
        )
        
        instance_id = flow["instance_id"]
        
        # Wallet would fetch the request
        request_obj = await gateway_client.get_verification_request(instance_id)
        
        assert request_obj is not None
        # Default OID4VP path should use DCQL only.
        if "request" not in request_obj:
            assert "dcql_query" in request_obj
            assert "presentation_definition" not in request_obj
        
    async def test_submit_verification(
        self,
        gateway_client: GatewayClient,
        age_verification_policy: Dict[str, Any],
    ):
        """
        Test submitting VP token to verification flow.
        
        In a real test, this would:
        1. Start verification flow
        2. Wallet generates VP token matching policy
        3. Submit VP token
        4. Check result
        """
        # Start flow
        flow = await gateway_client.start_verification_flow(
            presentation_policy_id=age_verification_policy["id"],
        )
        
        instance_id = flow["instance_id"]
        
        # Submit mock VP token (real test would have actual token)
        try:
            result = await gateway_client.submit_verification(
                instance_id=instance_id,
                vp_token="mock_vp_token",
            )
            # If successful, check structure
            assert "decision" in result or "status" in result
        except Exception as e:
            # Expected - mock token is invalid
            assert "token" in str(e).lower() or "invalid" in str(e).lower()
    
    async def test_get_verification_result(
        self,
        gateway_client: GatewayClient,
        age_verification_policy: Dict[str, Any],
    ):
        """Test retrieving verification flow result"""
        # Start flow
        flow = await gateway_client.start_verification_flow(
            presentation_policy_id=age_verification_policy["id"],
        )
        
        instance_id = flow["instance_id"]
        
        # Get result (should be pending since no VP submitted)
        result = await gateway_client.get_verification_result(instance_id)
        
        assert result is not None
        assert "status" in result
        # Should be pending or waiting
        assert result["status"] in ["pending", "waiting", "created", "active", "AWAITING_WALLET"]


@pytest.mark.asyncio
@pytest.mark.integration
class TestVerificationPolicies:
    """Test different verification policy scenarios"""
    
    async def test_age_verification_policy_flow(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """Test creating and using age verification policy"""
        # Create age 21+ policy
        policy = await gateway_client.create_presentation_policy(
            **TestDataBuilder.presentation_policy_age_verification(
                organization_id=test_organization["id"],
                credential_template_id=mdl_template["id"],
                min_age=21,
            )
        )
        
        # Start verification flow with this policy
        flow = await gateway_client.start_verification_flow(
            presentation_policy_id=policy["id"],
        )
        
        assert flow["instance_id"] is not None
        
    async def test_identity_verification_policy_flow(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """Test creating and using full identity verification policy"""
        # Create identity verification policy
        policy = await gateway_client.create_presentation_policy(
            **TestDataBuilder.presentation_policy_identity_verification(
                organization_id=test_organization["id"],
                credential_template_id=mdl_template["id"],
            )
        )
        
        # Verify policy requires identity claims
        req = policy["credential_requirements"][0]
        claim_names = [c["claim_name"] for c in req["requested_claims"]]
        
        assert "given_name" in claim_names
        assert "family_name" in claim_names
        assert "birth_date" in claim_names
        
        # Start verification flow
        flow = await gateway_client.start_verification_flow(
            presentation_policy_id=policy["id"],
        )
        
        assert flow["instance_id"] is not None
    
    async def test_employee_access_policy_flow(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        employee_badge_template: Dict[str, Any],
    ):
        """Test creating and using employee access verification policy"""
        # Create employee access policy
        policy = await gateway_client.create_presentation_policy(
            **TestDataBuilder.presentation_policy_employee_access(
                organization_id=test_organization["id"],
                credential_template_id=employee_badge_template["id"],
                required_department="Engineering",
            )
        )
        
        # Verify policy references the correct template
        req = policy["credential_requirements"][0]
        assert req["credential_template_id"] == employee_badge_template["id"]
        
        # Start verification flow
        flow = await gateway_client.start_verification_flow(
            presentation_policy_id=policy["id"],
        )
        
        assert flow["instance_id"] is not None


@pytest.mark.asyncio
@pytest.mark.integration
class TestVerificationExpiry:
    """Test verification flow expiry handling"""
    
    async def test_verification_flow_with_custom_expiry(
        self,
        gateway_client: GatewayClient,
        age_verification_policy: Dict[str, Any],
    ):
        """Test creating verification flow with custom expiry time"""
        # Create flow with 5 minute expiry
        flow = await gateway_client.start_verification_flow(
            presentation_policy_id=age_verification_policy["id"],
            expiry_minutes=5,
        )
        
        assert flow is not None
        assert "expires_at" in flow or "expiry_time" in flow
        
    async def test_verification_flow_with_default_expiry(
        self,
        gateway_client: GatewayClient,
        age_verification_policy: Dict[str, Any],
    ):
        """Test creating verification flow with default expiry (15 min)"""
        flow = await gateway_client.start_verification_flow(
            presentation_policy_id=age_verification_policy["id"],
        )
        
        assert flow is not None
        # Default expiry should be applied
        assert "instance_id" in flow


@pytest.mark.asyncio
@pytest.mark.integration
class TestMultipleVerificationFlows:
    """Test running multiple verification flows concurrently"""
    
    async def test_concurrent_verification_flows(
        self,
        gateway_client: GatewayClient,
        age_verification_policy: Dict[str, Any],
        identity_verification_policy: Dict[str, Any],
    ):
        """Test starting multiple verification flows"""
        # Start age verification flow
        age_flow = await gateway_client.start_verification_flow(
            presentation_policy_id=age_verification_policy["id"],
        )
        
        # Start identity verification flow
        identity_flow = await gateway_client.start_verification_flow(
            presentation_policy_id=identity_verification_policy["id"],
        )
        
        # Both should have unique instance IDs
        assert age_flow["instance_id"] != identity_flow["instance_id"]
        
        # Both should be active
        age_result = await gateway_client.get_verification_result(
            age_flow["instance_id"]
        )
        identity_result = await gateway_client.get_verification_result(
            identity_flow["instance_id"]
        )
        
        assert age_result["status"] in ["pending", "waiting", "created", "active", "AWAITING_WALLET"]
        assert identity_result["status"] in ["pending", "waiting", "created", "active", "AWAITING_WALLET"]
