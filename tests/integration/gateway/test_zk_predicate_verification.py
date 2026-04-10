"""
Zero-Knowledge Predicate Verification Tests

Tests ZK (zero-knowledge) predicate verification flows:
1. ZK credential issuance (zk_mdoc format)
2. Presentation policies with predicate specifications
3. ZK verification flows (age proofs without revealing birth_date)
4. Fallback policy behavior (accept_raw, require_predicate, deny)
5. Multiple predicate types (range_proof, membership, inequality)

ZK predicates allow proving claims without revealing the actual values.
Example: Prove age >= 21 without revealing the birth date.
"""

import pytest
from typing import Dict, Any

from .helpers.gateway_client import GatewayClient
from .helpers.test_data import TestDataBuilder


@pytest.mark.asyncio
@pytest.mark.integration
class TestZKCredentialIssuance:
    """Test issuing ZK-enabled credentials"""
    
    async def test_create_zk_mdoc_template(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test creating a ZK mDoc credential template"""
        template_data = TestDataBuilder.zk_mdoc_template(
            organization_id=test_organization["id"],
            zk_predicate_claims=["birth_date", "age_over_18", "age_over_21"],
        )
        
        template = await gateway_client.create_credential_template(**template_data)
        
        assert template is not None
        assert "id" in template
        assert template["supported_formats"] == ["ZK_MDOC"]
        assert "zk_predicate_claims" in template
        assert "age_over_21" in template["zk_predicate_claims"]
        
    async def test_issue_zk_credential(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        zk_mdoc_template: Dict[str, Any],
    ):
        """Test issuing a ZK-enabled credential"""
        claims = TestDataBuilder.zk_mdoc_claims(
            given_name="Alice",
            family_name="Zhang",
            birth_date="1995-03-15",
        )
        
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=zk_mdoc_template["id"],
            claims=claims,
        )
        
        assert issuance is not None
        assert "id" in issuance
        assert issuance["status"] in ("pending", "issued")
        
        # Credential should be issued with ZK capabilities
        assert issuance["credential_template_id"] == zk_mdoc_template["id"]


@pytest.mark.asyncio
@pytest.mark.integration
class TestZKPredicatePolicy:
    """Test presentation policies with ZK predicate specifications"""
    
    async def test_create_zk_age_verification_policy(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        zk_mdoc_template: Dict[str, Any],
    ):
        """Test creating a presentation policy with ZK age predicate"""
        policy_data = TestDataBuilder.presentation_policy_zk_age_verification(
            organization_id=test_organization["id"],
            credential_template_id=zk_mdoc_template["id"],
            min_age=21,
            fallback_policy="accept_raw",
        )
        
        policy = await gateway_client.create_presentation_policy(**policy_data)
        
        assert policy is not None
        assert "id" in policy
        assert policy["prefer_predicates"] is True
        assert "supported_circuits" in policy
        
        # Check predicate specification in requested claims
        req = policy["credential_requirements"][0]
        birth_date_claim = next(
            (c for c in req["requested_claims"] if c["claim_name"] == "birth_date"),
            None
        )
        
        assert birth_date_claim is not None
        assert "predicate_spec" in birth_date_claim
        assert birth_date_claim["predicate_spec"]["predicate_type"] == "range_proof"
        assert birth_date_claim["predicate_spec"]["params"]["threshold"] == 21
        
    async def test_zk_policy_with_different_thresholds(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        zk_mdoc_template: Dict[str, Any],
    ):
        """Test ZK policies with different age thresholds"""
        # Age 18+ policy
        policy_18 = await gateway_client.create_presentation_policy(
            **TestDataBuilder.presentation_policy_zk_age_verification(
                organization_id=test_organization["id"],
                credential_template_id=zk_mdoc_template["id"],
                min_age=18,
            )
        )
        
        # Age 21+ policy
        policy_21 = await gateway_client.create_presentation_policy(
            **TestDataBuilder.presentation_policy_zk_age_verification(
                organization_id=test_organization["id"],
                credential_template_id=zk_mdoc_template["id"],
                min_age=21,
            )
        )
        
        # Verify different thresholds
        req_18 = policy_18["credential_requirements"][0]["requested_claims"][0]
        req_21 = policy_21["credential_requirements"][0]["requested_claims"][0]
        
        assert req_18["predicate_spec"]["params"]["threshold"] == 18
        assert req_21["predicate_spec"]["params"]["threshold"] == 21
        
    async def test_zk_policy_supported_circuits(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        zk_mdoc_template: Dict[str, Any],
    ):
        """Test ZK policy specifies supported ZK circuits"""
        policy_data = TestDataBuilder.presentation_policy_zk_age_verification(
            organization_id=test_organization["id"],
            credential_template_id=zk_mdoc_template["id"],
            min_age=21,
        )
        
        policy = await gateway_client.create_presentation_policy(**policy_data)
        
        # Policy should specify which ZK circuits are accepted
        assert "supported_circuits" in policy
        circuits = policy["supported_circuits"]
        
        # Should include age verification circuits
        assert any("ligero" in c.lower() or "age" in c.lower() for c in circuits)


@pytest.mark.asyncio
@pytest.mark.integration
class TestZKVerificationFlow:
    """Test ZK predicate verification flows"""
    
    async def test_start_zk_verification_flow(
        self,
        gateway_client: GatewayClient,
        zk_age_verification_policy: Dict[str, Any],
    ):
        """Test starting a verification flow with ZK predicate policy"""
        flow = await gateway_client.start_verification_flow(
            presentation_policy_id=zk_age_verification_policy["id"],
        )
        
        assert flow is not None
        assert "instance_id" in flow
        assert "request_uri" in flow or "qr_code_data" in flow
        
    async def test_zk_verification_request_structure(
        self,
        gateway_client: GatewayClient,
        zk_age_verification_policy: Dict[str, Any],
    ):
        """Test that ZK verification request includes predicate requirements"""
        flow = await gateway_client.start_verification_flow(
            presentation_policy_id=zk_age_verification_policy["id"],
        )
        
        # Get the verification request
        request_obj = await gateway_client.get_verification_request(
            flow["instance_id"]
        )
        
        assert request_obj is not None
        
        # Request should include presentation_definition with input_descriptors
        if "presentation_definition" in request_obj:
            pres_def = request_obj["presentation_definition"]
            assert "input_descriptors" in pres_def
            
            # Input descriptors should specify predicates
            # (Structure depends on OpenID4VP implementation)
            assert len(pres_def["input_descriptors"]) > 0
            
    async def test_zk_verification_with_trust_profile(
        self,
        gateway_client: GatewayClient,
        zk_age_verification_policy: Dict[str, Any],
        test_trust_profile: Dict[str, Any],
    ):
        """Test ZK verification flow with trust profile"""
        flow = await gateway_client.start_verification_flow(
            presentation_policy_id=zk_age_verification_policy["id"],
            trust_profile_id=test_trust_profile["id"],
        )
        
        assert flow is not None
        # Trust profile should validate the ZK proof issuer
        assert "instance_id" in flow


@pytest.mark.asyncio
@pytest.mark.integration
class TestZKFallbackBehavior:
    """Test ZK predicate fallback policies"""
    
    async def test_fallback_accept_raw(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        zk_mdoc_template: Dict[str, Any],
    ):
        """Test fallback_policy='accept_raw' allows raw claim if ZK unavailable"""
        policy_data = TestDataBuilder.presentation_policy_zk_age_verification(
            organization_id=test_organization["id"],
            credential_template_id=zk_mdoc_template["id"],
            min_age=21,
            fallback_policy="accept_raw",
        )
        
        policy = await gateway_client.create_presentation_policy(**policy_data)
        
        # Verify fallback policy is set
        assert policy["fallback_policy"] == "accept_raw"
        
        # Verification flow should start successfully
        flow = await gateway_client.start_verification_flow(
            presentation_policy_id=policy["id"],
        )
        assert flow is not None
        
    async def test_fallback_require_predicate(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        zk_mdoc_template: Dict[str, Any],
    ):
        """Test fallback_policy='require_predicate' rejects non-ZK proofs"""
        policy_data = TestDataBuilder.presentation_policy_zk_age_verification(
            organization_id=test_organization["id"],
            credential_template_id=zk_mdoc_template["id"],
            min_age=21,
            fallback_policy="require_predicate",
        )
        
        policy = await gateway_client.create_presentation_policy(**policy_data)
        
        assert policy["fallback_policy"] == "require_predicate"
        
        # Policy should strictly require ZK proofs
        req = policy["credential_requirements"][0]["requested_claims"][0]
        assert req["predicate_spec"]["fallback_policy"] == "require_predicate"
        
    async def test_fallback_deny(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        zk_mdoc_template: Dict[str, Any],
    ):
        """Test fallback_policy='deny' blocks verification if ZK unavailable"""
        policy_data = TestDataBuilder.presentation_policy_zk_age_verification(
            organization_id=test_organization["id"],
            credential_template_id=zk_mdoc_template["id"],
            min_age=21,
            fallback_policy="deny",
        )
        
        policy = await gateway_client.create_presentation_policy(**policy_data)
        
        assert policy["fallback_policy"] == "deny"


@pytest.mark.asyncio
@pytest.mark.integration
class TestZKPredicateTypes:
    """Test different ZK predicate types"""
    
    async def test_range_proof_predicate(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        zk_mdoc_template: Dict[str, Any],
    ):
        """Test range_proof predicate (age >= threshold)"""
        # This is the standard age verification predicate
        policy_data = TestDataBuilder.presentation_policy_zk_age_verification(
            organization_id=test_organization["id"],
            credential_template_id=zk_mdoc_template["id"],
            min_age=21,
        )
        
        policy = await gateway_client.create_presentation_policy(**policy_data)
        
        req = policy["credential_requirements"][0]["requested_claims"][0]
        predicate = req["predicate_spec"]
        
        assert predicate["predicate_type"] == "range_proof"
        assert predicate["params"]["threshold"] == 21
        assert predicate["params"]["comparison"] == "gte"
        
    async def test_membership_predicate(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        zk_mdoc_template: Dict[str, Any],
    ):
        """Test membership predicate (value in allowed set)"""
        # Create policy with membership predicate
        # Example: country must be in [US, CA, MX]
        policy_data = {
            "organization_id": test_organization["id"],
            "name": "Country Membership Check",
            "purpose": "Verify issuing country is in allowed list",
            "prefer_predicates": True,
            "credential_requirements": [
                {
                    "credential_template_id": zk_mdoc_template["id"],
                    "requested_claims": [
                        {
                            "claim_name": "issuing_country",
                            "required": True,
                            "predicate_spec": {
                                "predicate_type": "membership",
                                "params": {
                                    "allowed_values": ["US", "CA", "MX"],
                                },
                            },
                        }
                    ],
                }
            ],
        }
        
        policy = await gateway_client.create_presentation_policy(**policy_data)
        
        req = policy["credential_requirements"][0]["requested_claims"][0]
        predicate = req["predicate_spec"]
        
        assert predicate["predicate_type"] == "membership"
        assert "US" in predicate["params"]["allowed_values"]


@pytest.mark.asyncio
@pytest.mark.integration
class TestZKCredentialLifecycle:
    """Test complete ZK credential lifecycle"""
    
    async def test_zk_credential_end_to_end(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        zk_mdoc_template: Dict[str, Any],
        zk_age_verification_policy: Dict[str, Any],
    ):
        """Test complete ZK credential lifecycle: issue → present → verify"""
        # Step 1: Issue ZK credential
        claims = TestDataBuilder.zk_mdoc_claims(
            given_name="Bob",
            family_name="Martinez",
            birth_date="1998-05-20",
        )
        
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=zk_mdoc_template["id"],
            claims=claims,
        )
        
        assert issuance["status"] in ("pending", "issued")
        
        # Step 2: Start ZK verification flow
        verification = await gateway_client.start_verification_flow(
            presentation_policy_id=zk_age_verification_policy["id"],
        )
        
        assert verification is not None
        assert "instance_id" in verification
        
        # Step 3: Get verification request (wallet would fetch this)
        request = await gateway_client.get_verification_request(
            verification["instance_id"]
        )
        
        assert request is not None
        
        # In a real flow, wallet would:
        # 1. Parse the presentation_definition
        # 2. Generate ZK proof for age >= 21
        # 3. Submit VP token with ZK proof
        # 4. Verifier validates without seeing birth_date
        
    async def test_zk_multiple_predicates(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        zk_mdoc_template: Dict[str, Any],
    ):
        """Test policy with multiple ZK predicates"""
        policy_data = {
            "organization_id": test_organization["id"],
            "name": "Multi-Predicate ZK Policy",
            "purpose": "Multiple ZK predicates in one policy",
            "prefer_predicates": True,
            "credential_requirements": [
                {
                    "credential_template_id": zk_mdoc_template["id"],
                    "requested_claims": [
                        {
                            "claim_name": "birth_date",
                            "required": True,
                            "predicate_spec": {
                                "predicate_type": "range_proof",
                                "params": {"threshold": 21, "comparison": "gte"},
                            },
                        },
                        {
                            "claim_name": "issuing_country",
                            "required": True,
                            "predicate_spec": {
                                "predicate_type": "membership",
                                "params": {"allowed_values": ["US"]},
                            },
                        },
                    ],
                }
            ],
        }
        
        policy = await gateway_client.create_presentation_policy(**policy_data)
        
        # Verify both predicates are configured
        claims = policy["credential_requirements"][0]["requested_claims"]
        assert len(claims) == 2
        assert all("predicate_spec" in c for c in claims)


@pytest.mark.asyncio
@pytest.mark.integration
class TestZKConfiguration:
    """Test ZK configuration options"""
    
    async def test_zk_template_configuration(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test ZK template with custom ZK predicate claims"""
        custom_zk_claims = [
            "birth_date",
            "age_over_18",
            "age_over_21",
            "age_over_25",
            "expiry_date",
        ]
        
        template_data = TestDataBuilder.zk_mdoc_template(
            organization_id=test_organization["id"],
            zk_predicate_claims=custom_zk_claims,
        )
        
        template = await gateway_client.create_credential_template(**template_data)
        
        assert set(template["zk_predicate_claims"]) == set(custom_zk_claims)
        
    async def test_zk_policy_circuit_selection(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        zk_mdoc_template: Dict[str, Any],
    ):
        """Test ZK policy with specific circuit selection"""
        policy_data = TestDataBuilder.presentation_policy_zk_age_verification(
            organization_id=test_organization["id"],
            credential_template_id=zk_mdoc_template["id"],
            min_age=21,
        )
        
        # Modify to specify only certain circuits
        policy_data["supported_circuits"] = ["ligero_age_over_21"]
        
        policy = await gateway_client.create_presentation_policy(**policy_data)
        
        # Should accept only the specified circuit
        assert "ligero_age_over_21" in policy["supported_circuits"]
