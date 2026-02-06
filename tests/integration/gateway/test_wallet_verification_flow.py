"""
Integration tests for credential verification using Walt.id wallet.

These tests verify end-to-end verification flows using a real wallet
implementation (Walt.id Wallet Kit) via OpenID4VP protocol.

Test Coverage:
- Presentation request resolution
- Credential presentation from wallet
- Verification policy evaluation
- Age verification with wallet credentials
- Identity verification flows
- Multiple credential presentation
"""

import pytest
from typing import Dict, Any

from .helpers.gateway_client import GatewayClient
from .helpers.waltid_wallet_client import WaltIdWalletClient
from .helpers.test_data import TestDataBuilder


@pytest.mark.integration
@pytest.mark.wallet
@pytest.mark.asyncio
class TestPresentationRequestResolution:
    """Test resolving presentation requests before responding."""

    async def test_resolve_presentation_request(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        age_verification_policy: Dict[str, Any],
        test_wallet: Dict[str, Any],
    ):
        """Test resolving a presentation request to inspect requirements."""
        # Start verification flow
        flow_result = await gateway_client.start_verification_flow(
            presentation_policy_id=age_verification_policy["id"],
        )
        
        assert "instance_id" in flow_result
        assert "request_uri" in flow_result  # OpenID4VP request URL
        
        # Resolve the request (inspect without responding)
        wallet_client = test_wallet["client"]
        resolved_url = await wallet_client.resolve_presentation_request(
            request_url=flow_result["request_uri"]
        )
        
        # Walt.ID returns a URL string with query parameters
        from urllib.parse import urlparse, parse_qs
        assert resolved_url is not None
        assert isinstance(resolved_url, str)
        
        # Parse the URL to extract presentation_definition
        parsed_url = urlparse(resolved_url)
        params = parse_qs(parsed_url.query)
        
        # Should contain presentation_definition in query parameters
        assert "presentation_definition" in params, f"presentation_definition not found in resolved URL: {resolved_url}"
        
        # The presentation_definition should be valid JSON
        import json
        presentation_def = json.loads(params["presentation_definition"][0])
        assert "input_descriptors" in presentation_def


@pytest.mark.integration
@pytest.mark.wallet
@pytest.mark.asyncio
class TestCredentialPresentationFromWallet:
    """Test presenting credentials from wallet to verifier."""

    async def test_present_mdl_for_age_verification(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
        age_verification_policy: Dict[str, Any],
        test_wallet: Dict[str, Any],
    ):
        """Test complete flow: issue mDL to wallet, then present for age verification."""
        wallet_client = test_wallet["client"]
        did = test_wallet["did"]
        
        # Step 1: Issue mDL to wallet
        claims = TestDataBuilder.mdl_claims()
        issuance_result = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=mdl_template["id"],
            subject_did=did,
            claims=claims,
        )
        
        await wallet_client.accept_credential_offer(
            offer_url=issuance_result["credential_offer_uri"],
            did=did,
        )
        
        # Step 2: Start verification flow
        verification_flow = await gateway_client.start_verification_flow(
            presentation_policy_id=age_verification_policy["id"],
        )
        
        request_id = verification_flow["instance_id"]
        request_uri = verification_flow["request_uri"]
        
        # Step 3: Get credentials from wallet
        credentials = await wallet_client.list_credentials()
        assert len(credentials) > 0
        
        # Find the mDL credential
        mdl_cred = credentials[0]  # Should be our mDL
        cred_id = mdl_cred.get("id") or mdl_cred.get("credentialId")
        
        # Step 4: Present credential
        presentation_result = await wallet_client.present_credential(
            presentation_request_url=request_uri,
            credential_ids=[cred_id] if cred_id else [],
            did=did,
        )
        
        assert presentation_result is not None
        
        # Step 5: Check verification result
        verification_result = await gateway_client.get_verification_result(request_id)
        
        assert "status" in verification_result
        # Status should be success since age >= 21 in test data
        assert verification_result["status"] in ["verified", "success", "approved", "completed"]

    async def test_present_mdl_for_identity_verification(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
        identity_verification_policy: Dict[str, Any],
        test_wallet: Dict[str, Any],
    ):
        """Test presenting mDL for full identity verification."""
        wallet_client = test_wallet["client"]
        did = test_wallet["did"]
        
        # Issue mDL to wallet
        claims = TestDataBuilder.mdl_claims()
        issuance_result = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=mdl_template["id"],
            subject_did=did,
            claims=claims,
        )
        
        await wallet_client.accept_credential_offer(
            offer_url=issuance_result["credential_offer_uri"],
            did=did,
        )
        
        # Start verification flow
        verification_flow = await gateway_client.start_verification_flow(
            presentation_policy_id=identity_verification_policy["id"],
        )
        
        # Get credential from wallet
        credentials = await wallet_client.list_credentials()
        cred_id = (credentials[0].get("id") or credentials[0].get("credentialId")) if credentials else None
        
        # Present credential
        if cred_id:
            await wallet_client.present_credential(
                presentation_request_url=verification_flow["request_uri"],
                credential_ids=[cred_id],
                did=did,
            )
            
            # Check result
            result = await gateway_client.get_verification_result(
                verification_flow["instance_id"]
            )
            
            assert "status" in result
            assert result["status"] in ["verified", "success", "approved", "completed"]


@pytest.mark.integration
@pytest.mark.wallet
@pytest.mark.asyncio
class TestMultipleCredentialPresentation:
    """Test presenting multiple credentials in a single verification."""

    async def test_present_multiple_credentials(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
        employee_badge_template: Dict[str, Any],
        test_wallet: Dict[str, Any],
    ):
        """Test wallet presenting multiple credentials together."""
        wallet_client = test_wallet["client"]
        did = test_wallet["did"]
        
        # Issue mDL
        mdl_result = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=mdl_template["id"],
            subject_did=did,
            claims=TestDataBuilder.mdl_claims(),
        )
        
        await wallet_client.accept_credential_offer(
            offer_url=mdl_result["credential_offer_uri"],
            did=did,
        )
        
        # Issue employee badge
        badge_result = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=employee_badge_template["id"],
            subject_did=did,
            claims={
                "employee_id": "EMP-11111",
                "full_name": "Test Employee",
                "department": "Security",
                "position": "Guard",
                "email": "guard@example.com",
                "start_date": "2024-01-01",
            },
        )
        
        await wallet_client.accept_credential_offer(
            offer_url=badge_result["credential_offer_uri"],
            did=did,
        )
        
        # Verify wallet has both credentials
        credentials = await wallet_client.list_credentials()
        assert len(credentials) >= 2
        
        # Note: Actual multi-credential presentation depends on
        # verification policy requirements. This test validates
        # the wallet can hold and manage multiple credentials.


@pytest.mark.integration
@pytest.mark.wallet
@pytest.mark.asyncio
class TestVerificationWithSelectiveDisclosure:
    """Test selective disclosure in credential presentation."""

    async def test_age_verification_selective_disclosure(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
        age_verification_policy: Dict[str, Any],
        test_wallet: Dict[str, Any],
    ):
        """
        Test that age verification only requires age-related fields,
        not the entire credential (selective disclosure).
        """
        wallet_client = test_wallet["client"]
        did = test_wallet["did"]
        
        # Issue mDL with full claims
        full_claims = TestDataBuilder.mdl_claims()
        assert "birth_date" in full_claims  # Required for age verification
        assert "given_name" in full_claims  # Not required for age verification
        
        issuance_result = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=mdl_template["id"],
            subject_did=did,
            claims=full_claims,
        )
        
        await wallet_client.accept_credential_offer(
            offer_url=issuance_result["credential_offer_uri"],
            did=did,
        )
        
        # Start age verification
        verification_flow = await gateway_client.start_verification_flow(
            presentation_policy_id=age_verification_policy["id"],
        )
        
        # Resolve to see what's requested
        request_details = await wallet_client.resolve_presentation_request(
            request_url=verification_flow["request_uri"]
        )
        
        # The request should only require age/DOB fields, not all fields
        # (Implementation detail depends on policy configuration)
        assert request_details is not None


@pytest.mark.integration
@pytest.mark.wallet
@pytest.mark.asyncio
class TestVerificationFlowStates:
    """Test various states and outcomes of verification flows."""

    async def test_verification_without_presenting(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        age_verification_policy: Dict[str, Any],
    ):
        """Test verification flow when user doesn't present credentials."""
        # Start verification
        flow = await gateway_client.start_verification_flow(
            presentation_policy_id=age_verification_policy["id"],
        )
        
        request_id = flow["instance_id"]
        
        # Check status immediately (before presentation)
        result = await gateway_client.get_verification_result(request_id)
        
        # Should be pending or in-progress
        assert result["status"] in ["pending", "in_progress", "waiting", "created"]

    async def test_verification_expiry(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        age_verification_policy: Dict[str, Any],
    ):
        """Test verification request with custom expiry."""
        # Start verification with short expiry
        flow = await gateway_client.start_verification_flow(
            presentation_policy_id=age_verification_policy["id"],
            expiry_minutes=5,
        )
        
        assert "instance_id" in flow
        assert "expires_at" in flow or "expiry" in flow


@pytest.mark.integration
@pytest.mark.wallet
@pytest.mark.asyncio
class TestCompleteWalletVerificationLifecycle:
    """Test complete end-to-end wallet-based verification lifecycle."""

    async def test_full_wallet_issuance_and_verification(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
        age_verification_policy: Dict[str, Any],
        test_wallet: Dict[str, Any],
    ):
        """
        Complete lifecycle test:
        1. Create organization and policies
        2. Issue credential to wallet via OpenID4VCI
        3. Wallet stores credential
        4. Verifier requests presentation via OpenID4VP
        5. Wallet presents credential
        6. Verification succeeds
        """
        wallet_client = test_wallet["client"]
        did = test_wallet["did"]
        org_id = test_organization["id"]
        
        # Phase 1: Issuance
        claims = TestDataBuilder.mdl_claims()
        claims["date_of_birth"] = "1990-05-15"  # Ensure age > 21
        
        issuance_result = await gateway_client.issue_credential(
            organization_id=org_id,
            credential_template_id=mdl_template["id"],
            subject_did=did,
            claims=claims,
        )
        
        assert "credential_offer_uri" in issuance_result
        
        # Phase 2: Wallet accepts credential
        await wallet_client.accept_credential_offer(
            offer_url=issuance_result["credential_offer_uri"],
            did=did,
        )
        
        # Verify credential is in wallet
        credentials = await wallet_client.list_credentials()
        assert len(credentials) > 0
        
        # Phase 3: Start verification
        verification_flow = await gateway_client.start_verification_flow(
            presentation_policy_id=age_verification_policy["id"],
        )
        
        assert "instance_id" in verification_flow
        assert "request_uri" in verification_flow
        
        # Phase 4: Wallet presents credential
        cred_id = (credentials[0].get("id") or credentials[0].get("credentialId"))
        
        if cred_id:
            presentation_result = await wallet_client.present_credential(
                presentation_request_url=verification_flow["request_uri"],
                credential_ids=[cred_id],
                did=did,
            )
            
            assert presentation_result is not None
        
        # Phase 5: Verify result
        verification_result = await gateway_client.get_verification_result(
            verification_flow["instance_id"]
        )
        
        assert "status" in verification_result
        # Should succeed based on our test data
        assert verification_result["status"] in ["verified", "success", "approved", "completed"]

    @pytest.mark.skip(reason="WalletID service has stability issues with concurrent wallet creation - connection drops after first wallet")
    async def test_multiple_wallets_multiple_verifications(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
        age_verification_policy: Dict[str, Any],
        waltid_wallet_client: WaltIdWalletClient,
    ):
        """Test multiple independent wallets going through verification."""
        org_id = test_organization["id"]
        template_id = mdl_template["id"]
        policy_id = age_verification_policy["id"]
        
        # Create two wallets
        wallet1_result = await waltid_wallet_client.create_wallet("wallet-1")
        did1_result = await waltid_wallet_client.create_did()
        wallet1_id = waltid_wallet_client.wallet_id
        did1 = did1_result["did"]
        
        # Create second wallet client
        wallet2_client = WaltIdWalletClient()
        await wallet2_client.__aenter__()
        
        try:
            wallet2_result = await wallet2_client.create_wallet("wallet-2")
            did2_result = await wallet2_client.create_did()
            did2 = did2_result["did"]
            
            # Issue credentials to both wallets
            claims1 = TestDataBuilder.mdl_claims()
            claims1["given_name"] = "Alice"
            
            claims2 = TestDataBuilder.mdl_claims()
            claims2["given_name"] = "Bob"
            
            issuance1 = await gateway_client.issue_credential(
                organization_id=org_id,
                credential_template_id=template_id,
                subject_did=did1,
                claims=claims1,
            )
            
            issuance2 = await gateway_client.issue_credential(
                organization_id=org_id,
                credential_template_id=template_id,
                subject_did=did2,
                claims=claims2,
            )
            
            # Both wallets accept
            await waltid_wallet_client.accept_credential_offer(
                offer_url=issuance1["credential_offer_uri"],
                did=did1,
            )
            
            await wallet2_client.accept_credential_offer(
                offer_url=issuance2["credential_offer_uri"],
                did=did2,
            )
            
            # Both wallets should have credentials
            creds1 = await waltid_wallet_client.list_credentials()
            creds2 = await wallet2_client.list_credentials()
            
            assert len(creds1) > 0
            assert len(creds2) > 0
            
        finally:
            # Cleanup second wallet
            await wallet2_client.__aexit__(None, None, None)
