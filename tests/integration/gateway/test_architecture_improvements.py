"""
Integration tests for architecture improvements made during remediation.

Validates that server-side fixes and new response fields round-trip
correctly through the gateway API.

Test Coverage:
- Presentation policy credential_requirements round-trip with predicate_spec
- Deployment profile lane metadata (description, location, device_type)
- Credential template key management fields
- Credential type format diversity (reverse-domain, dotted, PascalCase)
- Credential template wallet_configs and supported_formats
- Compliance profile frameworks round-trip
- Issuance through gateway proxy (inject_headers / API key)
- vct URI not required for non-SD-JWT-VC formats
"""

import pytest
from typing import Dict, Any

from .helpers.gateway_client import GatewayClient
from .helpers.test_data import TestDataBuilder


# =============================================================================
# Presentation Policy Response Fields
# =============================================================================


@pytest.mark.integration
@pytest.mark.asyncio
class TestPresentationPolicyResponseFields:
    """Validate that credential_requirements round-trip including predicate_spec."""

    async def test_policy_credential_requirements_round_trip(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """credential_requirements should appear in the GET response."""
        org_id = test_organization["id"]

        # Create template first (needed for credential_template_id reference)
        tmpl_data = TestDataBuilder.mdl_template(organization_id=org_id)
        template = await gateway_client.create_credential_template(**tmpl_data)

        policy_data = TestDataBuilder.presentation_policy_age_verification(
            organization_id=org_id,
            credential_template_id=template["id"],
        )
        policy = await gateway_client.create_presentation_policy(**policy_data)

        fetched = await gateway_client.get_presentation_policy(policy["id"])
        reqs = fetched.get("credential_requirements")
        assert reqs is not None, "credential_requirements missing from response"
        assert len(reqs) >= 1
        assert "requested_claims" in reqs[0]

    async def test_predicate_spec_persisted_in_policy(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """predicate_spec inside requested_claims should survive round-trip."""
        org_id = test_organization["id"]

        tmpl_data = TestDataBuilder.zk_mdoc_template(organization_id=org_id)
        template = await gateway_client.create_credential_template(**tmpl_data)

        policy_data = TestDataBuilder.presentation_policy_zk_age_verification(
            organization_id=org_id,
            credential_template_id=template["id"],
            min_age=21,
        )
        policy = await gateway_client.create_presentation_policy(**policy_data)

        fetched = await gateway_client.get_presentation_policy(policy["id"])
        reqs = fetched.get("credential_requirements", [])
        assert len(reqs) >= 1
        claims = reqs[0].get("requested_claims", [])
        birth_claim = next((c for c in claims if c["claim_name"] == "birth_date"), None)
        assert birth_claim is not None, "birth_date claim missing"
        pred = birth_claim.get("predicate_spec")
        assert pred is not None, "predicate_spec missing from birth_date claim"
        assert pred["predicate_type"] == "range_proof"

    async def test_policy_purpose_round_trip(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """purpose field should appear on GET response."""
        org_id = test_organization["id"]
        tmpl_data = TestDataBuilder.mdl_template(organization_id=org_id)
        template = await gateway_client.create_credential_template(**tmpl_data)

        policy = await gateway_client.create_presentation_policy(
            organization_id=org_id,
            name="Purpose Test Policy",
            credential_requirements=[
                {
                    "credential_template_id": template["id"],
                    "display_name": "mDL",
                    "requested_claims": [
                        {"claim_name": "given_name", "display_name": "Name", "required": True},
                    ],
                }
            ],
            purpose="Verify identity for building access",
        )

        fetched = await gateway_client.get_presentation_policy(policy["id"])
        assert fetched.get("purpose") == "Verify identity for building access"


# =============================================================================
# Deployment Profile Lane Metadata
# =============================================================================


@pytest.mark.integration
@pytest.mark.asyncio
class TestDeploymentProfileLaneMetadata:
    """Validate lane description, location, and device_type in response."""

    async def test_lane_metadata_round_trip(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        test_deployment_profile: Dict[str, Any],
    ):
        """Lane description, location, and device_type should appear in GET."""
        profile_id = test_deployment_profile["id"]

        lane = await gateway_client.create_lane(
            profile_id=profile_id,
            name="Gate 5 Lane",
            description="Primary verification lane at Gate 5",
            location="Terminal B, Gate 5",
            device_type="tablet",
        )

        fetched = await gateway_client.get_lane(profile_id, lane["id"])

        assert fetched.get("description") == "Primary verification lane at Gate 5"
        assert fetched.get("location") == "Terminal B, Gate 5"
        assert fetched.get("device_type") == "tablet"

    async def test_lane_update_metadata(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        test_deployment_profile: Dict[str, Any],
    ):
        """Lane metadata should be updatable."""
        profile_id = test_deployment_profile["id"]

        lane = await gateway_client.create_lane(
            profile_id=profile_id,
            name="Kiosk Lane",
            description="Self-service kiosk",
            location="Lobby",
            device_type="kiosk",
        )

        updated = await gateway_client.update_lane(
            profile_id=profile_id,
            lane_id=lane["id"],
            name="Kiosk Lane",
            description="Updated self-service kiosk",
            location="Main Lobby, Floor 1",
            device_type="kiosk",
        )

        fetched = await gateway_client.get_lane(profile_id, updated["id"])
        assert fetched.get("description") == "Updated self-service kiosk"
        assert fetched.get("location") == "Main Lobby, Floor 1"

    async def test_deployment_profile_status_in_response(
        self,
        gateway_client: GatewayClient,
        test_deployment_profile: Dict[str, Any],
    ):
        """Deployment profile should include status field."""
        fetched = await gateway_client.get_deployment_profile(
            test_deployment_profile["id"]
        )
        assert "status" in fetched, "status field missing from deployment profile"


# =============================================================================
# Credential Template Improvements
# =============================================================================


@pytest.mark.integration
@pytest.mark.asyncio
class TestCredentialTemplateImprovements:
    """Validate template response fields added during remediation."""

    async def test_supported_formats_in_response(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """supported_formats should appear in template GET response."""
        org_id = test_organization["id"]
        tmpl_data = TestDataBuilder.mdl_template(organization_id=org_id)
        template = await gateway_client.create_credential_template(**tmpl_data)

        fetched = await gateway_client.get_credential_template(template["id"])
        sf = fetched.get("supported_formats")
        assert sf is not None, "supported_formats missing from response"
        assert "mdoc" in [f.lower() for f in sf] or "MDOC" in sf

    async def test_zk_predicate_claims_in_response(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """zk_predicate_claims should persist on ZK templates."""
        org_id = test_organization["id"]
        tmpl_data = TestDataBuilder.zk_mdoc_template(organization_id=org_id)
        template = await gateway_client.create_credential_template(**tmpl_data)

        fetched = await gateway_client.get_credential_template(template["id"])
        zkpc = fetched.get("zk_predicate_claims")
        assert zkpc is not None, "zk_predicate_claims missing from response"
        assert len(zkpc) > 0

    async def test_wallet_configs_in_response(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """wallet_configs should persist on JWT VC v2 templates."""
        org_id = test_organization["id"]
        tmpl_data = TestDataBuilder.jwt_vc_v2_template(
            organization_id=org_id,
            wallet_configs=[
                {
                    "wallet_id": "test-wallet",
                    "deep_link_scheme": "openid-credential-offer://",
                    "format_variant": "test-variant",
                }
            ],
        )
        template = await gateway_client.create_credential_template(**tmpl_data)

        fetched = await gateway_client.get_credential_template(template["id"])
        wc = fetched.get("wallet_configs")
        assert wc is not None, "wallet_configs missing from response"
        assert len(wc) >= 1
        assert wc[0].get("wallet_id") == "test-wallet"

    async def test_reverse_domain_credential_type(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Reverse-domain credential types (e.g. org.iso.18013.5.1.mDL) should be accepted."""
        org_id = test_organization["id"]
        tmpl_data = TestDataBuilder.mdl_template(organization_id=org_id)
        # mDL uses org.iso.18013.5.1.mDL which is reverse-domain format
        template = await gateway_client.create_credential_template(**tmpl_data)
        assert template.get("credential_type") == "org.iso.18013.5.1.mDL"

    async def test_pascal_case_credential_type(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """PascalCase credential types (e.g. EmployeeBadge) should be accepted."""
        org_id = test_organization["id"]
        tmpl_data = TestDataBuilder.employee_badge_template(organization_id=org_id)
        template = await gateway_client.create_credential_template(**tmpl_data)
        assert template.get("credential_type") == "EmployeeBadge"

    async def test_credential_payload_format_stored(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """credential_payload_format should persist when set."""
        org_id = test_organization["id"]
        tmpl_data = TestDataBuilder.jwt_vc_v2_template(organization_id=org_id)
        template = await gateway_client.create_credential_template(**tmpl_data)

        fetched = await gateway_client.get_credential_template(template["id"])
        cpf = fetched.get("credential_payload_format")
        # Server may normalize the payload format to its enum form
        assert cpf is not None, "credential_payload_format missing from response"

    async def test_vct_not_required_for_mdoc(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """mDL template should accept vct for mDoc (not a URI), since vct
        URI enforcement only applies to SD-JWT-VC format."""
        org_id = test_organization["id"]
        tmpl_data = TestDataBuilder.mdl_template(organization_id=org_id)
        # vct is "org.iso.18013.5.1.mDL" - not a URI, but valid for mDoc
        template = await gateway_client.create_credential_template(**tmpl_data)
        assert template is not None
        assert template.get("id") is not None


# =============================================================================
# Compliance Profile Frameworks
# =============================================================================


@pytest.mark.integration
@pytest.mark.asyncio
class TestComplianceProfileFrameworksRoundTrip:
    """Validate frameworks field persists on compliance profiles."""

    async def test_frameworks_in_response(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """frameworks list should appear in GET response."""
        org_id = test_organization["id"]
        profile_data = TestDataBuilder.compliance_profile(
            organization_id=org_id,
        )
        profile = await gateway_client.create_compliance_profile(**profile_data)

        fetched = await gateway_client.get_compliance_profile(profile["id"])
        fw = fetched.get("frameworks")
        assert fw is not None, "frameworks missing from compliance profile response"
        assert "aamva" in fw or "iso_18013_5" in fw

    async def test_w3c_frameworks(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """W3C-specific frameworks should persist."""
        org_id = test_organization["id"]
        profile = await gateway_client.create_compliance_profile(
            organization_id=org_id,
            name="W3C Test Profile",
            compliance_code="W3C_VC",
            credential_format="jwt_vc",
            frameworks=["w3c_vc"],
        )

        fetched = await gateway_client.get_compliance_profile(profile["id"])
        assert "w3c_vc" in fetched.get("frameworks", [])


# =============================================================================
# Issuance Through Gateway Proxy
# =============================================================================


@pytest.mark.integration
@pytest.mark.asyncio
class TestIssuanceGatewayProxy:
    """Validate that issuance works through the gateway proxy with inject_headers."""

    async def test_issue_credential_via_gateway(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Issuing a credential through gateway should succeed (validates API key proxy)."""
        org_id = test_organization["id"]

        tmpl_data = TestDataBuilder.mdl_template(organization_id=org_id)
        template = await gateway_client.create_credential_template(**tmpl_data)

        claims = TestDataBuilder.mdl_claims()
        result = await gateway_client.issue_credential(
            organization_id=org_id,
            credential_template_id=template["id"],
            claims=claims,
        )

        assert result is not None
        assert result.get("credential_id") or result.get("id") or result.get("credential")

    async def test_issue_multiple_formats_via_gateway(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Issuing credentials in multiple formats should work."""
        org_id = test_organization["id"]

        # mDL (mDoc)
        mdl_tmpl = TestDataBuilder.mdl_template(organization_id=org_id)
        mdl_template = await gateway_client.create_credential_template(**mdl_tmpl)
        mdl_result = await gateway_client.issue_credential(
            organization_id=org_id,
            credential_template_id=mdl_template["id"],
            claims=TestDataBuilder.mdl_claims(),
        )
        assert mdl_result is not None

        # SD-JWT-VC (employee badge template uses sd_jwt_vc format)
        sd_tmpl = TestDataBuilder.employee_badge_template(organization_id=org_id)
        sd_template = await gateway_client.create_credential_template(**sd_tmpl)
        sd_result = await gateway_client.issue_credential(
            organization_id=org_id,
            credential_template_id=sd_template["id"],
            claims=TestDataBuilder.employee_badge_claims(),
        )
        assert sd_result is not None

        # JWT VC
        jwt_tmpl = TestDataBuilder.jwt_vc_template(organization_id=org_id)
        jwt_template = await gateway_client.create_credential_template(**jwt_tmpl)
        jwt_result = await gateway_client.issue_credential(
            organization_id=org_id,
            credential_template_id=jwt_template["id"],
            claims=TestDataBuilder.jwt_vc_claims(),
        )
        assert jwt_result is not None


# =============================================================================
# Flow Type Canonical Mappings
# =============================================================================


@pytest.mark.integration
@pytest.mark.asyncio
class TestFlowTypeCanonicalMappings:
    """Validate that flow type aliases resolve correctly."""

    async def test_issuance_flow_type_alias(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """'issuance' flow_type should be accepted and resolve."""
        org_id = test_organization["id"]
        tmpl_data = TestDataBuilder.mdl_template(organization_id=org_id)
        template = await gateway_client.create_credential_template(**tmpl_data)

        flow_def = await gateway_client.create_flow_definition(
            organization_id=org_id,
            name="Issuance Alias Test",
            flow_type="issuance",
            credential_template_id=template["id"],
        )

        fetched = await gateway_client.get_flow_definition(flow_def["id"])
        ft = fetched.get("flow_type", "")
        # Server may normalize to canonical form
        assert ft in ("issuance", "oid4vci_pre_authorized"), f"Unexpected flow_type: {ft}"

    async def test_verification_flow_type_alias(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """'verification' flow_type should be accepted and resolve."""
        org_id = test_organization["id"]
        tmpl_data = TestDataBuilder.mdl_template(organization_id=org_id)
        template = await gateway_client.create_credential_template(**tmpl_data)

        policy_data = TestDataBuilder.presentation_policy_age_verification(
            organization_id=org_id,
            credential_template_id=template["id"],
        )
        policy = await gateway_client.create_presentation_policy(**policy_data)

        flow_def = await gateway_client.create_flow_definition(
            organization_id=org_id,
            name="Verification Alias Test",
            flow_type="verification",
            presentation_policy_id=policy["id"],
        )

        fetched = await gateway_client.get_flow_definition(flow_def["id"])
        ft = fetched.get("flow_type", "")
        assert ft in ("verification", "oid4vp_presentation"), f"Unexpected flow_type: {ft}"


# =============================================================================
# Credential Format Normalization
# =============================================================================


@pytest.mark.integration
@pytest.mark.asyncio
class TestCredentialFormatNormalization:
    """Test that supported_formats values normalize correctly."""

    async def test_mdoc_format_normalized(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """mDL template should have MDOC in supported_formats."""
        org_id = test_organization["id"]
        tmpl_data = TestDataBuilder.mdl_template(organization_id=org_id)
        template = await gateway_client.create_credential_template(**tmpl_data)

        fetched = await gateway_client.get_credential_template(template["id"])
        sf = [f.upper() for f in fetched.get("supported_formats", [])]
        assert "MDOC" in sf or "MSO_MDOC" in sf, f"Unexpected formats: {fetched.get('supported_formats')}"

    async def test_sd_jwt_vc_format_normalized(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Employee badge template should have SD_JWT_VC in supported_formats."""
        org_id = test_organization["id"]
        tmpl_data = TestDataBuilder.employee_badge_template(organization_id=org_id)
        template = await gateway_client.create_credential_template(**tmpl_data)

        fetched = await gateway_client.get_credential_template(template["id"])
        sf = [f.upper() for f in fetched.get("supported_formats", [])]
        assert "SD_JWT_VC" in sf, f"Unexpected formats: {fetched.get('supported_formats')}"

    async def test_jwt_vc_format_normalized(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """JWT VC template should have VC_JWT in supported_formats."""
        org_id = test_organization["id"]
        tmpl_data = TestDataBuilder.jwt_vc_template(organization_id=org_id)
        template = await gateway_client.create_credential_template(**tmpl_data)

        fetched = await gateway_client.get_credential_template(template["id"])
        sf = [f.upper() for f in fetched.get("supported_formats", [])]
        assert "VC_JWT" in sf or "JWT_VC" in sf, f"Unexpected formats: {fetched.get('supported_formats')}"


# =============================================================================
# Trust Profile Integration
# =============================================================================


@pytest.mark.integration
@pytest.mark.asyncio
class TestTrustProfileIntegration:
    """Validate trust profile integration that was fixed during remediation."""

    async def test_deployment_profile_with_trust_profile(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Deployment profile should accept and store trust_profile_id."""
        org_id = test_organization["id"]

        trust_data = TestDataBuilder.trust_profile(organization_id=org_id)
        trust_profile = await gateway_client.create_trust_profile(**trust_data)

        # Create a template + policy for the required presentation_policy_ids
        tmpl_data = TestDataBuilder.mdl_template(organization_id=org_id)
        template = await gateway_client.create_credential_template(**tmpl_data)
        policy_data = TestDataBuilder.presentation_policy_age_verification(
            organization_id=org_id,
            credential_template_id=template["id"],
        )
        policy = await gateway_client.create_presentation_policy(**policy_data)

        profile_data = TestDataBuilder.deployment_profile(
            organization_id=org_id,
            trust_profile_id=trust_profile["id"],
            default_presentation_policy_id=policy["id"],
        )
        profile = await gateway_client.create_deployment_profile(**profile_data)

        fetched = await gateway_client.get_deployment_profile(profile["id"])
        assert fetched.get("trust_profile_id") == trust_profile["id"]
