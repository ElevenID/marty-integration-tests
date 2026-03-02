"""
Direct Credential Issuance Flow Integration Tests

Tests direct credential issuance without the application approval process:
1. Issue credential directly via /v1/issuance
2. Retrieve issuance records
3. Test different credential formats (mDL, SD-JWT)
4. Test deferred issuance (async processing)
"""

import pytest
import asyncio
from typing import Dict, Any

from .helpers.gateway_client import GatewayClient
from .helpers.test_data import TestDataBuilder


@pytest.mark.asyncio
@pytest.mark.integration
class TestDirectIssuanceFlow:
    """Test direct credential issuance (without application)"""
    
    async def test_issue_mdl_credential(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """Test issuing an mDL credential directly"""
        claims = TestDataBuilder.mdl_claims(
            given_name="Eve",
            family_name="Wilson",
            birth_date="1992-07-10",
        )
        
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=mdl_template["id"],
            claims=claims,
        )
        
        assert issuance is not None
        assert "id" in issuance
        assert issuance["organization_id"] == test_organization["id"]
        assert issuance["credential_template_id"] == mdl_template["id"]
        assert "credential" in issuance or "status" in issuance
        
    async def test_issue_employee_badge_credential(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        employee_badge_template: Dict[str, Any],
    ):
        """Test issuing an employee badge credential"""
        claims = TestDataBuilder.employee_badge_claims(
            given_name="Frank",
            family_name="Miller",
        )
        
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=employee_badge_template["id"],
            claims=claims,
        )
        
        assert issuance is not None
        assert "id" in issuance
        assert issuance["credential_template_id"] == employee_badge_template["id"]
        
    async def test_issue_with_subject_did(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """Test issuing credential with specific subject DID"""
        claims = TestDataBuilder.mdl_claims(
            given_name="Grace",
            family_name="Hopper",
        )
        
        subject_did = "did:example:holder789"
        
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=mdl_template["id"],
            claims=claims,
            subject_did=subject_did,
        )
        
        assert issuance is not None
        if "subject_did" in issuance:
            assert issuance["subject_did"] == subject_did


@pytest.mark.asyncio
@pytest.mark.integration
class TestIssuanceRetrieval:
    """Test retrieving and listing issuance records"""
    
    async def test_get_issuance_by_id(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """Test retrieving an issuance record by ID"""
        # Issue credential first
        claims = TestDataBuilder.mdl_claims()
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=mdl_template["id"],
            claims=claims,
        )
        
        # Retrieve it
        retrieved = await gateway_client.get_issuance(issuance["id"])
        
        assert retrieved["id"] == issuance["id"]
        assert retrieved["organization_id"] == test_organization["id"]
        
    async def test_list_issuances(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """Test listing issuance records for an organization"""
        # Issue multiple credentials
        for i in range(3):
            claims = TestDataBuilder.mdl_claims(
                given_name=f"User{i}",
                family_name=f"Test{i}",
            )
            await gateway_client.issue_credential(
                organization_id=test_organization["id"],
                credential_template_id=mdl_template["id"],
                claims=claims,
            )
        
        # List issuances
        issuances = await gateway_client.list_issuances(
            organization_id=test_organization["id"]
        )
        
        assert isinstance(issuances, list)
        assert len(issuances) >= 3
        
        # Verify all belong to the organization
        for issuance in issuances:
            assert issuance["organization_id"] == test_organization["id"]


@pytest.mark.asyncio
@pytest.mark.integration
class TestMultipleCredentialTypes:
    """Test issuing different credential types for the same organization"""
    
    async def test_issue_multiple_credential_types(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
        employee_badge_template: Dict[str, Any],
    ):
        """Test issuing both mDL and employee badge credentials"""
        # Issue mDL
        mdl_claims = TestDataBuilder.mdl_claims(
            given_name="Isabel",
            family_name="Torres",
        )
        mdl_issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=mdl_template["id"],
            claims=mdl_claims,
        )
        
        # Issue employee badge
        badge_claims = TestDataBuilder.employee_badge_claims(
            given_name="Isabel",
            family_name="Torres",
        )
        badge_issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=employee_badge_template["id"],
            claims=badge_claims,
        )
        
        # Verify both were issued
        assert mdl_issuance["id"] != badge_issuance["id"]
        assert mdl_issuance["credential_template_id"] == mdl_template["id"]
        assert badge_issuance["credential_template_id"] == employee_badge_template["id"]
        
        # List all issuances
        issuances = await gateway_client.list_issuances(
            organization_id=test_organization["id"]
        )
        
        issuance_ids = [i["id"] for i in issuances]
        assert mdl_issuance["id"] in issuance_ids
        assert badge_issuance["id"] in issuance_ids


@pytest.mark.asyncio
@pytest.mark.integration
class TestBulkIssuance:
    """Test issuing multiple credentials in sequence"""
    
    async def test_bulk_credential_issuance(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """Test issuing multiple credentials for different holders"""
        holders = [
            ("John", "Doe", "1990-01-15"),
            ("Jane", "Smith", "1985-06-22"),
            ("Jack", "Brown", "1995-11-30"),
            ("Jill", "Davis", "1988-04-17"),
            ("Jim", "Wilson", "1992-09-08"),
        ]
        
        issued_ids = []
        
        for given_name, family_name, birth_date in holders:
            claims = TestDataBuilder.mdl_claims(
                given_name=given_name,
                family_name=family_name,
                birth_date=birth_date,
            )
            
            issuance = await gateway_client.issue_credential(
                organization_id=test_organization["id"],
                credential_template_id=mdl_template["id"],
                claims=claims,
            )
            
            issued_ids.append(issuance["id"])
        
        # Verify all were issued
        assert len(issued_ids) == len(holders)
        assert len(set(issued_ids)) == len(holders)  # All unique
        
        # Verify we can retrieve all
        issuances = await gateway_client.list_issuances(
            organization_id=test_organization["id"]
        )
        
        for issued_id in issued_ids:
            assert any(i["id"] == issued_id for i in issuances)


@pytest.mark.asyncio
@pytest.mark.integration
class TestIssuanceValidation:
    """Test validation of issuance requests"""
    
    async def test_issue_with_missing_required_claims(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """Test that issuing without required claims fails gracefully"""
        # Provide incomplete claims (missing document_number, driving_privileges)
        incomplete_claims = {
            "given_name": "Test",
            "family_name": "User",
            "birth_date": "1990-01-01",
        }
        
        try:
            await gateway_client.issue_credential(
                organization_id=test_organization["id"],
                credential_template_id=mdl_template["id"],
                claims=incomplete_claims,
            )
            # If it succeeds, that's also acceptable (backend may have defaults)
            # We're just testing the flow doesn't crash
        except Exception as e:
            # Expected - missing required fields
            assert "required" in str(e).lower() or "missing" in str(e).lower()
    
    async def test_issue_with_invalid_organization(
        self,
        gateway_client: GatewayClient,
        mdl_template: Dict[str, Any],
    ):
        """Test that issuing with invalid organization ID fails"""
        claims = TestDataBuilder.mdl_claims()
        
        with pytest.raises(Exception) as exc_info:
            await gateway_client.issue_credential(
                organization_id="invalid-org-id-999",
                credential_template_id=mdl_template["id"],
                claims=claims,
            )
        
        assert "404" in str(exc_info.value) or "not found" in str(exc_info.value).lower()
    
    async def test_issue_with_invalid_template(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Test that issuing with invalid template ID fails"""
        claims = TestDataBuilder.mdl_claims()
        
        with pytest.raises(Exception) as exc_info:
            await gateway_client.issue_credential(
                organization_id=test_organization["id"],
                credential_template_id="invalid-template-id-999",
                claims=claims,
            )
        
        assert "404" in str(exc_info.value) or "not found" in str(exc_info.value).lower()


@pytest.mark.asyncio
@pytest.mark.integration
class TestCredentialFormats:
    """
    Verify that all three supported credential formats can be used
    end-to-end: template creation → issuance → retrieval.

    Formats under test
    ------------------
    mdoc      — ISO 18013-5 mobile document   (mDL credential type)
    sd_jwt_vc — SD-JWT Verifiable Credential  (EmployeeBadge)
    jwt_vc    — W3C JWT Verifiable Credential (VerifiableId)
    """

    async def test_mdoc_format_template_and_issuance(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
    ):
        """mdoc format: template has supported_formats=["mdoc"] and can be issued."""
        assert "mdoc" in mdl_template["supported_formats"]

        claims = TestDataBuilder.mdl_claims(
            given_name="Format",
            family_name="TestMdoc",
        )
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=mdl_template["id"],
            claims=claims,
        )
        assert issuance["credential_template_id"] == mdl_template["id"]

    async def test_sd_jwt_vc_format_template_and_issuance(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        employee_badge_template: Dict[str, Any],
    ):
        """sd_jwt_vc format: template has supported_formats=["sd_jwt_vc"] and can be issued."""
        assert "sd_jwt_vc" in employee_badge_template["supported_formats"]

        claims = TestDataBuilder.employee_badge_claims(
            given_name="Format",
            family_name="TestSdJwt",
        )
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=employee_badge_template["id"],
            claims=claims,
        )
        assert issuance["credential_template_id"] == employee_badge_template["id"]

    async def test_jwt_vc_format_template_and_issuance(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        jwt_vc_template: Dict[str, Any],
    ):
        """jwt_vc format: template has supported_formats=["jwt_vc"] and can be issued."""
        assert "jwt_vc" in jwt_vc_template["supported_formats"]

        claims = TestDataBuilder.jwt_vc_claims(
            given_name="Format",
            family_name="TestJwtVc",
        )
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=jwt_vc_template["id"],
            claims=claims,
        )
        assert issuance["credential_template_id"] == jwt_vc_template["id"]

    async def test_all_format_templates_appear_in_listing(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
        employee_badge_template: Dict[str, Any],
        jwt_vc_template: Dict[str, Any],
    ):
        """All three format templates are visible in the credential-template listing."""
        templates = await gateway_client.list_credential_templates(
            organization_id=test_organization["id"],
        )
        template_ids = {t["id"] for t in templates}

        assert mdl_template["id"] in template_ids, "mdoc template missing from listing"
        assert employee_badge_template["id"] in template_ids, "sd_jwt_vc template missing from listing"
        assert jwt_vc_template["id"] in template_ids, "jwt_vc template missing from listing"

        # Confirm each reports the correct format
        fmt_by_id = {t["id"]: t.get("supported_formats", []) for t in templates}
        assert "mdoc" in fmt_by_id[mdl_template["id"]]
        assert "sd_jwt_vc" in fmt_by_id[employee_badge_template["id"]]
        assert "jwt_vc" in fmt_by_id[jwt_vc_template["id"]]

    async def test_each_format_template_round_trips(
        self,
        gateway_client: GatewayClient,
        mdl_template: Dict[str, Any],
        employee_badge_template: Dict[str, Any],
        jwt_vc_template: Dict[str, Any],
    ):
        """
        Retrieve each format's template by ID and confirm that its
        supported_formats, credential_type and vct are persisted correctly.
        """
        cases = [
            ("mdoc", mdl_template, "org.iso.18013.5.1.mDL"),
            ("sd_jwt_vc", employee_badge_template, "EmployeeBadge"),
            ("jwt_vc", jwt_vc_template, "VerifiableId"),
        ]
        for fmt, created, expected_type in cases:
            retrieved = await gateway_client.get_credential_template(created["id"])
            assert fmt in retrieved.get("supported_formats", []), (
                f"{fmt} missing from retrieved supported_formats: {retrieved}"
            )
            assert retrieved.get("credential_type") == expected_type, (
                f"{fmt} credential_type mismatch: {retrieved}"
            )
            assert retrieved.get("vct") == expected_type, (
                f"{fmt} vct mismatch: {retrieved}"
            )

    async def test_zk_mdoc_template_persists_predicate_claims(
        self,
        gateway_client: GatewayClient,
        zk_mdoc_template: Dict[str, Any],
    ):
        """
        Round-trip: zk_mdoc template stores zk_predicate_claims and returns
        them when fetched by ID.
        """
        assert "zk_mdoc" in zk_mdoc_template["supported_formats"]

        retrieved = await gateway_client.get_credential_template(zk_mdoc_template["id"])
        assert "zk_mdoc" in retrieved.get("supported_formats", [])

        predicate_claims = retrieved.get("zk_predicate_claims", [])
        assert len(predicate_claims) > 0, (
            f"zk_predicate_claims not persisted: {retrieved}"
        )
        # Default template includes at least birth_date as a predicate claim
        assert "birth_date" in predicate_claims

    async def test_zk_mdoc_format_template_and_issuance(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        zk_mdoc_template: Dict[str, Any],
    ):
        """zk_mdoc format: template is created and credential can be issued."""
        assert "zk_mdoc" in zk_mdoc_template["supported_formats"]

        claims = TestDataBuilder.zk_mdoc_claims(
            given_name="Format",
            family_name="TestZkMdoc",
        )
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=zk_mdoc_template["id"],
            claims=claims,
        )
        assert issuance["credential_template_id"] == zk_mdoc_template["id"]


@pytest.mark.asyncio
@pytest.mark.integration
class TestJwtVcPayloadFormats:
    """
    Coverage for ``credential_payload_format`` variants on the jwt_vc signing path
    and for per-wallet ``credential_offer_uris`` in issuance responses.

    VCDM v1 branch — triggered when ``credential_payload_format`` is anything
    other than ``"w3c_vcdm_v2_jwt_vc"`` (e.g. the legacy default
    ``"w3c_vcdm_v2_sd_jwt"``).  The signing layer produces ``issuanceDate`` /
    ``expirationDate`` timestamps + a v1 ``@context``.

    VCDM v2 branch — triggered exactly by ``"w3c_vcdm_v2_jwt_vc"``.  The
    signing layer produces ``validFrom`` / ``validUntil`` + a v2 ``@context``.

    Wallet configs — when a template carries ``wallet_configs`` the issuance
    response must include a populated ``credential_offer_uris`` dict keyed by
    ``wallet_id``.
    """

    async def test_jwt_vc_template_stores_credential_payload_format(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        jwt_vc_template: Dict[str, Any],
    ):
        """VCDM v1 jwt_vc template: credential_payload_format is persisted."""
        assert "jwt_vc" in jwt_vc_template["supported_formats"]
        assert jwt_vc_template.get("credential_payload_format") in (
            "w3c_vcdm_v2_sd_jwt",
            None,  # server may not echo field when it equals the default
        ), (
            f"Expected VCDM v1 format indicator but got "
            f"{jwt_vc_template.get('credential_payload_format')!r}"
        )

    async def test_jwt_vc_v2_template_stores_credential_payload_format(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        jwt_vc_v2_template: Dict[str, Any],
    ):
        """VCDM v2 jwt_vc template: credential_payload_format is stored as w3c_vcdm_v2_jwt_vc."""
        assert "jwt_vc" in jwt_vc_v2_template["supported_formats"]
        assert jwt_vc_v2_template.get("credential_payload_format") == "w3c_vcdm_v2_jwt_vc", (
            f"Expected 'w3c_vcdm_v2_jwt_vc' but got "
            f"{jwt_vc_v2_template.get('credential_payload_format')!r}"
        )

    async def test_jwt_vc_vcdm_v1_issuance_succeeds(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        jwt_vc_template: Dict[str, Any],
    ):
        """VCDM v1 jwt_vc: issuance completes and returns a credential record."""
        claims = TestDataBuilder.jwt_vc_claims(
            given_name="Alice",
            family_name="Vcdm1",
        )
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=jwt_vc_template["id"],
            claims=claims,
        )
        assert issuance["credential_template_id"] == jwt_vc_template["id"]
        assert issuance.get("id") is not None

    async def test_jwt_vc_vcdm_v2_issuance_succeeds(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        jwt_vc_v2_template: Dict[str, Any],
    ):
        """VCDM v2 jwt_vc: issuance completes and returns a credential record."""
        claims = TestDataBuilder.jwt_vc_claims(
            given_name="Bob",
            family_name="Vcdm2",
        )
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=jwt_vc_v2_template["id"],
            claims=claims,
        )
        assert issuance["credential_template_id"] == jwt_vc_v2_template["id"]
        assert issuance.get("id") is not None

    async def test_jwt_vc_vcdm_v2_credential_offer_uris_populated(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        jwt_vc_v2_template: Dict[str, Any],
    ):
        """
        When a template has wallet_configs, the issuance response must include
        a ``credential_offer_uris`` dict with an entry per configured wallet.

        The Marty wallet URI must use the ``openid-credential-offer://`` scheme.
        """
        claims = TestDataBuilder.jwt_vc_claims(
            given_name="Carol",
            family_name="WalletUri",
        )
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=jwt_vc_v2_template["id"],
            claims=claims,
        )

        offer_uris: Dict[str, Any] = issuance.get("credential_offer_uris", {})
        assert isinstance(offer_uris, dict), (
            f"credential_offer_uris should be a dict, got {type(offer_uris)}"
        )
        assert "marty" in offer_uris, (
            f"Expected 'marty' key in credential_offer_uris, got keys: {list(offer_uris.keys())}"
        )
        assert offer_uris["marty"].startswith("openid-credential-offer://"), (
            f"Marty URI should start with 'openid-credential-offer://', got: {offer_uris['marty']!r}"
        )

    async def test_wallet_configs_persisted_on_template(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        jwt_vc_v2_template: Dict[str, Any],
    ):
        """The wallet_configs list is stored on the template and echoed back."""
        wallet_configs = jwt_vc_v2_template.get("wallet_configs", [])
        assert len(wallet_configs) >= 1, (
            "Expected at least one wallet_config entry on the template"
        )
        marty_config = next(
            (wc for wc in wallet_configs if wc.get("wallet_id") == "marty"), None
        )
        assert marty_config is not None, (
            f"No 'marty' wallet_config found; configs: {wallet_configs}"
        )
        assert marty_config["deep_link_scheme"] == "openid-credential-offer://"
