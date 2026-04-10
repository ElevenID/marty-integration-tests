"""
Integration tests for credential issuance and verification using the
headless Marty Authenticator wallet.

These tests mirror the Walt.id-based verification flow tests but use the
protocol-level headless wallet client which supports P-256 keys natively.
This enables SD-JWT credential flows that are blocked by Walt.id's
Ed25519-only DID generation in the VP layer.

mDoc (mso_mdoc) specific tests are marked as xfail because the Rust mDoc
signing engine does not yet support EC (P-256) holder keys — it only accepts
Ed25519. Once the Rust engine is updated, remove the xfail markers.

Test Coverage:
- Pre-authorized code issuance via OID4VCI v1 (SD-JWT format)
- Credential presentation via OID4VP v1
- Age verification with mDL credentials
- Identity verification flows
- Multiple credential management
- Full issuance → verification lifecycle
"""

import pytest
from typing import Dict, Any

from .helpers.gateway_client import GatewayClient
from .helpers.marty_wallet_client import MartyHeadlessWalletClient
from .helpers.test_data import TestDataBuilder


_RUST_MDOC_EC_XFAIL = pytest.mark.xfail(
    reason="Rust mDoc signing engine does not support P-256 holder keys "
           "(premature end of stream / Incorrect padding). Tracked upstream.",
    raises=Exception,
)


@pytest.mark.integration
@pytest.mark.wallet
@pytest.mark.asyncio
class TestHeadlessIssuance:
    """Test credential issuance via the headless wallet."""

    async def test_issue_sd_jwt_mdl_to_headless_wallet(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        sd_jwt_mdl_template: Dict[str, Any],
        marty_test_wallet: Dict[str, Any],
    ):
        """Issue an mDL (SD-JWT format) and accept it with the headless wallet."""
        wallet_client = marty_test_wallet["client"]
        did = marty_test_wallet["did"]

        claims = TestDataBuilder.mdl_claims()
        issuance_result = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=sd_jwt_mdl_template["id"],
            subject_did=did,
            claims=claims,
        )

        assert "credential_offer_uri" in issuance_result

        result = await wallet_client.accept_credential_offer(
            offer_url=issuance_result["credential_offer_uri"],
            did=did,
        )

        assert result["status"] == "accepted"
        creds = await wallet_client.list_credentials()
        assert len(creds) >= 1

    async def test_issue_employee_badge_to_headless_wallet(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        employee_badge_template: Dict[str, Any],
        marty_test_wallet: Dict[str, Any],
    ):
        """Issue an employee badge and accept it with the headless wallet."""
        wallet_client = marty_test_wallet["client"]
        did = marty_test_wallet["did"]

        claims = {
            "employee_id": "EMP-99999",
            "full_name": "Headless Tester",
            "department": "Engineering",
            "position": "QA",
            "email": "headless@example.com",
            "start_date": "2024-06-01",
        }

        issuance_result = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=employee_badge_template["id"],
            subject_did=did,
            claims=claims,
        )

        result = await wallet_client.accept_credential_offer(
            offer_url=issuance_result["credential_offer_uri"],
            did=did,
        )

        assert result["status"] == "accepted"

    @_RUST_MDOC_EC_XFAIL
    async def test_issue_mdoc_mdl_to_headless_wallet(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
        marty_test_wallet: Dict[str, Any],
    ):
        """Issue an mDL (mDoc format) to the headless wallet.

        Currently xfail: Rust mDoc signing rejects P-256 holder keys.
        """
        wallet_client = marty_test_wallet["client"]
        did = marty_test_wallet["did"]

        claims = TestDataBuilder.mdl_claims()
        issuance_result = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=mdl_template["id"],
            subject_did=did,
            claims=claims,
        )

        result = await wallet_client.accept_credential_offer(
            offer_url=issuance_result["credential_offer_uri"],
            did=did,
        )
        assert result["status"] == "accepted"


@pytest.mark.integration
@pytest.mark.wallet
@pytest.mark.asyncio
class TestHeadlessPresentation:
    """Test credential presentation via the headless wallet (OID4VP).

    Uses SD-JWT format to bypass the Rust mDoc signing limitation
    with P-256 holder keys.
    """

    async def test_present_mdl_for_age_verification(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        sd_jwt_mdl_template: Dict[str, Any],
        sd_jwt_age_verification_policy: Dict[str, Any],
        marty_test_wallet: Dict[str, Any],
    ):
        """Issue SD-JWT mDL → present for age verification via headless wallet."""
        wallet_client = marty_test_wallet["client"]
        did = marty_test_wallet["did"]

        # Step 1: Issue mDL (SD-JWT)
        claims = TestDataBuilder.mdl_claims()
        issuance_result = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=sd_jwt_mdl_template["id"],
            subject_did=did,
            claims=claims,
        )

        await wallet_client.accept_credential_offer(
            offer_url=issuance_result["credential_offer_uri"],
            did=did,
        )

        # Step 2: Start verification flow
        verification_flow = await gateway_client.start_verification_flow(
            presentation_policy_id=sd_jwt_age_verification_policy["id"],
        )
        assert "instance_id" in verification_flow
        assert "request_uri" in verification_flow

        # Step 3: Get credentials from wallet
        credentials = await wallet_client.list_credentials()
        assert len(credentials) > 0
        cred_id = credentials[0]["id"]

        # Step 4: Present credential
        presentation_result = await wallet_client.present_credential(
            presentation_request_url=verification_flow["request_uri"],
            credential_ids=[cred_id],
            did=did,
        )
        assert presentation_result is not None

        # Step 5: Check verification result
        verification_result = await gateway_client.get_verification_result(
            verification_flow["instance_id"]
        )
        assert "status" in verification_result
        assert verification_result["status"] in [
            "verified", "success", "approved", "completed", "COMPLETED",
        ]

    async def test_present_mdl_for_identity_verification(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        sd_jwt_mdl_template: Dict[str, Any],
        sd_jwt_identity_verification_policy: Dict[str, Any],
        marty_test_wallet: Dict[str, Any],
    ):
        """Issue SD-JWT mDL → present for identity verification via headless wallet."""
        wallet_client = marty_test_wallet["client"]
        did = marty_test_wallet["did"]

        # Issue mDL (SD-JWT)
        claims = TestDataBuilder.mdl_claims()
        issuance_result = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=sd_jwt_mdl_template["id"],
            subject_did=did,
            claims=claims,
        )

        await wallet_client.accept_credential_offer(
            offer_url=issuance_result["credential_offer_uri"],
            did=did,
        )

        # Start verification
        verification_flow = await gateway_client.start_verification_flow(
            presentation_policy_id=sd_jwt_identity_verification_policy["id"],
        )

        # Present credential
        credentials = await wallet_client.list_credentials()
        cred_id = credentials[0]["id"]

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
        assert result["status"] in ["verified", "success", "approved", "completed", "COMPLETED"]


@pytest.mark.integration
@pytest.mark.wallet
@pytest.mark.asyncio
class TestHeadlessMultipleCredentials:
    """Test managing multiple credentials in the headless wallet."""

    async def test_hold_multiple_credentials(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        sd_jwt_mdl_template: Dict[str, Any],
        employee_badge_template: Dict[str, Any],
        marty_test_wallet: Dict[str, Any],
    ):
        """Issue both an SD-JWT mDL and employee badge to the same headless wallet."""
        wallet_client = marty_test_wallet["client"]
        did = marty_test_wallet["did"]

        # Issue mDL (SD-JWT)
        mdl_result = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=sd_jwt_mdl_template["id"],
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
                "employee_id": "EMP-77777",
                "full_name": "Headless Multi",
                "department": "Engineering",
                "position": "Lead",
                "email": "multi@example.com",
                "start_date": "2024-01-15",
            },
        )
        await wallet_client.accept_credential_offer(
            offer_url=badge_result["credential_offer_uri"],
            did=did,
        )

        # Wallet should hold both
        credentials = await wallet_client.list_credentials()
        assert len(credentials) >= 2


@pytest.mark.integration
@pytest.mark.wallet
@pytest.mark.asyncio
class TestHeadlessFullLifecycle:
    """End-to-end lifecycle: issuance → storage → verification."""

    async def test_full_headless_issuance_and_verification(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        sd_jwt_mdl_template: Dict[str, Any],
        sd_jwt_age_verification_policy: Dict[str, Any],
        marty_test_wallet: Dict[str, Any],
    ):
        """
        Complete lifecycle:
        1. Issue mDL credential (SD-JWT) via OID4VCI
        2. Headless wallet stores credential
        3. Verifier requests presentation via OID4VP
        4. Headless wallet presents credential
        5. Verification succeeds
        """
        wallet_client = marty_test_wallet["client"]
        did = marty_test_wallet["did"]
        org_id = test_organization["id"]

        # Phase 1: Issuance
        claims = TestDataBuilder.mdl_claims()
        claims["date_of_birth"] = "1990-05-15"  # Ensure age > 21

        issuance_result = await gateway_client.issue_credential(
            organization_id=org_id,
            credential_template_id=sd_jwt_mdl_template["id"],
            subject_did=did,
            claims=claims,
        )
        assert "credential_offer_uri" in issuance_result

        # Phase 2: Wallet accepts credential
        await wallet_client.accept_credential_offer(
            offer_url=issuance_result["credential_offer_uri"],
            did=did,
        )

        credentials = await wallet_client.list_credentials()
        assert len(credentials) > 0

        # Phase 3: Start verification
        verification_flow = await gateway_client.start_verification_flow(
            presentation_policy_id=sd_jwt_age_verification_policy["id"],
        )
        assert "instance_id" in verification_flow
        assert "request_uri" in verification_flow

        # Phase 4: Wallet presents credential
        cred_id = credentials[0]["id"]
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
        assert verification_result["status"] in [
            "verified", "success", "approved", "completed", "COMPLETED",
        ]
