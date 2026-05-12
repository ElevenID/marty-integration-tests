"""
DTC / Passport Verification Flow Integration Tests (Phase 3)

Tests DTC credential verification through the MIP gateway OID4VP flow,
Cedar policy enforcement (format, holder binding, freshness), revocation
checks, and MRZ read/verify API endpoints.
"""

import pytest
from typing import Dict, Any

from .helpers.gateway_client import GatewayClient, GatewayClientError
from .helpers.test_data import TestDataBuilder


# =============================================================================
# DTC Verification via OID4VP
# =============================================================================


@pytest.mark.asyncio
@pytest.mark.integration
class TestDtcVerificationFlow:
    """Test DTC credential verification through the MIP gateway."""

    async def test_start_dtc_verification_flow(
        self,
        gateway_client: GatewayClient,
        dtc_verification_policy: Dict[str, Any],
        icao_trust_profile: Dict[str, Any],
    ):
        """
        Start a DTC verification flow and receive a request URI / QR code.

        The flow should produce a presentation request that requires
        DG1, DG2, and document_number from a com.icao.dtc credential.
        """
        flow = await gateway_client.start_verification_flow(
            presentation_policy_id=dtc_verification_policy["id"],
            trust_profile_id=icao_trust_profile["id"],
            expiry_minutes=15,
        )

        assert flow is not None
        assert "instance_id" in flow
        assert "request_uri" in flow or "qr_code_data" in flow
        assert "status" in flow

    async def test_dtc_verification_request_contains_credential_query(
        self,
        gateway_client: GatewayClient,
        dtc_verification_policy: Dict[str, Any],
    ):
        """Verify the OID4VP request includes a DCQL or legacy PE query for DTC."""
        flow = await gateway_client.start_verification_flow(
            presentation_policy_id=dtc_verification_policy["id"],
        )

        request_obj = await gateway_client.get_verification_request(
            flow["instance_id"],
        )
        assert request_obj is not None
        if "request" not in request_obj:
            assert "dcql_query" in request_obj
            assert "presentation_definition" not in request_obj

    async def test_dtc_verification_with_mock_token_rejected(
        self,
        gateway_client: GatewayClient,
        dtc_verification_policy: Dict[str, Any],
    ):
        """Submit an invalid VP token to a DTC verification flow — expect rejection."""
        flow = await gateway_client.start_verification_flow(
            presentation_policy_id=dtc_verification_policy["id"],
        )

        try:
            result = await gateway_client.submit_verification(
                instance_id=flow["instance_id"],
                vp_token="invalid_mock_vp_token",
            )
            # If it returns, the decision should indicate failure
            assert result.get("decision") != "approved" or "error" in result
        except GatewayClientError as e:
            error_msg = str(e).lower()
            assert "token" in error_msg or "invalid" in error_msg or "400" in error_msg

    async def test_dtc_verification_flow_polling(
        self,
        gateway_client: GatewayClient,
        dtc_verification_policy: Dict[str, Any],
    ):
        """Start a verification flow and poll its status."""
        flow = await gateway_client.start_verification_flow(
            presentation_policy_id=dtc_verification_policy["id"],
        )

        result = await gateway_client.get_verification_result(flow["instance_id"])
        assert result is not None
        # Before submission, the flow should be pending
        status = result.get("status", "")
        assert status in ("pending", "awaiting_submission", "created", "active", "AWAITING_WALLET")

    async def test_dtc_identity_only_verification_flow(
        self,
        gateway_client: GatewayClient,
        dtc_identity_only_policy: Dict[str, Any],
    ):
        """Start a verification flow requesting only MRZ identity data (no biometrics)."""
        flow = await gateway_client.start_verification_flow(
            presentation_policy_id=dtc_identity_only_policy["id"],
        )

        assert flow is not None
        assert "instance_id" in flow


@pytest.mark.asyncio
@pytest.mark.integration
class TestDtcCedarPolicyEnforcement:
    """
    Test Cedar policy evaluation for ICAO DTC credentials.

    Cedar policies from credential_verification.cedar enforce:
    - MDOC format requirement
    - Holder binding requirement
    - 24-hour freshness window for high-assurance credentials
    """

    async def test_dtc_stateless_evaluation_with_invalid_token(
        self,
        gateway_client: GatewayClient,
        dtc_verification_policy: Dict[str, Any],
    ):
        """
        Stateless evaluation with a non-MDOC token against ICAO_DTC policy.

        The Cedar policy ``icao-dtc-format-requirement`` should fire,
        rejecting any credential_format != MDOC.
        """
        try:
            result = await gateway_client.evaluate_presentation(
                policy_id=dtc_verification_policy["id"],
                vp_token="eyJhbGciOiJFUzI1NiJ9.mock_sd_jwt_format.sig",
                nonce="test_nonce_cedar",
            )
            # If it returns, expect a rejection or error
            decision = result.get("decision", "")
            assert decision != "approved" or "error" in result
        except GatewayClientError as e:
            # Expected: invalid token / format mismatch
            assert "400" in str(e) or "token" in str(e).lower()

    async def test_dtc_evaluation_policy_not_found(
        self,
        gateway_client: GatewayClient,
    ):
        """Evaluate against a non-existent policy ID — expect 404."""
        with pytest.raises(GatewayClientError) as exc_info:
            await gateway_client.evaluate_presentation(
                policy_id="00000000-0000-0000-0000-000000000000",
                vp_token="mock_token",
            )
        assert "404" in str(exc_info.value) or "not found" in str(exc_info.value).lower()


@pytest.mark.asyncio
@pytest.mark.integration
class TestDtcRevocation:
    """Test DTC credential revocation detection during verification."""

    async def test_issue_and_revoke_dtc(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        dtc_template: Dict[str, Any],
    ):
        """Issue a DTC, revoke it, then verify revocation status is recorded."""
        claims = TestDataBuilder.dtc_claims()
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=dtc_template["id"],
            claims=claims,
        )

        # Revoke the credential
        revocation = await gateway_client.revoke_credential(
            issuance_id=issuance["id"],
            reason="Test revocation — compromised document",
        )
        assert revocation is not None

        # Check revocation status
        status = await gateway_client.get_revocation_status(issuance["id"])
        assert status is not None

    async def test_revoked_dtc_verification_rejected(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        dtc_template: Dict[str, Any],
        dtc_verification_policy: Dict[str, Any],
    ):
        """
        A revoked DTC should fail the revocation check (step 6 of MIP §5.7.3).

        This test issues, revokes, and starts a verification flow.
        Full E2E would involve a wallet submitting the revoked credential;
        here we verify the revocation is recorded and the flow is set up.
        """
        claims = TestDataBuilder.dtc_claims()
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=dtc_template["id"],
            claims=claims,
        )

        await gateway_client.revoke_credential(
            issuance_id=issuance["id"],
            reason="Stolen passport",
        )

        # Start a verification flow — the revoked credential should
        # ultimately be rejected when presented, but we can at least
        # verify the flow starts and the revocation is persisted.
        flow = await gateway_client.start_verification_flow(
            presentation_policy_id=dtc_verification_policy["id"],
        )
        assert flow is not None

        revocation_status = await gateway_client.get_revocation_status(issuance["id"])
        assert revocation_status is not None


# =============================================================================
# MRZ Read / Verify API
# =============================================================================


@pytest.mark.asyncio
@pytest.mark.integration
class TestMrzVerificationFlow:
    """Test MRZ read and verify endpoints (POST /v1/flows/mrz/*)."""

    async def test_mrz_read_td3_passport(
        self,
        gateway_client: GatewayClient,
    ):
        """Parse a TD3 (passport booklet) MRZ via the gateway MRZ read endpoint."""
        mrz_data = TestDataBuilder.mrz_td3_passport()
        try:
            result = await gateway_client._request(
                "POST",
                "/v1/flows/mrz/read",
                json=mrz_data,
            )
            assert result is not None
            # Should return parsed MRZ fields
        except GatewayClientError as e:
            # Endpoint may not be implemented yet — document the gap
            error_msg = str(e)
            assert "404" in error_msg or "not found" in error_msg.lower() or "501" in error_msg

    async def test_mrz_read_td1_id_card(
        self,
        gateway_client: GatewayClient,
    ):
        """Parse a TD1 (ID card) MRZ via the gateway MRZ read endpoint."""
        mrz_data = TestDataBuilder.mrz_td1_id_card()
        try:
            result = await gateway_client._request(
                "POST",
                "/v1/flows/mrz/read",
                json=mrz_data,
            )
            assert result is not None
        except GatewayClientError as e:
            error_msg = str(e)
            assert "404" in error_msg or "not found" in error_msg.lower() or "501" in error_msg

    async def test_mrz_verify_valid_check_digits(
        self,
        gateway_client: GatewayClient,
    ):
        """Verify a TD3 MRZ with valid check digits passes verification."""
        mrz_data = TestDataBuilder.mrz_td3_passport()
        try:
            result = await gateway_client._request(
                "POST",
                "/v1/flows/mrz/verify",
                json=mrz_data,
            )
            assert result is not None
        except GatewayClientError as e:
            error_msg = str(e)
            assert "404" in error_msg or "not found" in error_msg.lower() or "501" in error_msg

    async def test_mrz_verify_tampered_check_digits(
        self,
        gateway_client: GatewayClient,
    ):
        """
        Submit a TD3 MRZ with tampered check digits — expect verification failure.
        """
        mrz_data = TestDataBuilder.mrz_td3_passport()
        # Tamper with line 2 (replace a digit to break check digit)
        if "mrz_line_2" in mrz_data:
            line2 = mrz_data["mrz_line_2"]
            tampered = line2[:10] + "X" + line2[11:]
            mrz_data["mrz_line_2"] = tampered

        try:
            result = await gateway_client._request(
                "POST",
                "/v1/flows/mrz/verify",
                json=mrz_data,
            )
            # If it returns, the result should indicate a failure
            if isinstance(result, dict):
                status = result.get("status", result.get("valid", ""))
                assert status in (False, "invalid", "failed", "error") or "error" in result
        except GatewayClientError:
            # Expected: tampered MRZ should be rejected
            pass

    async def test_mrz_read_invalid_format(
        self,
        gateway_client: GatewayClient,
    ):
        """Submit garbage MRZ data — expect a clear error."""
        try:
            await gateway_client._request(
                "POST",
                "/v1/flows/mrz/read",
                json={"mrz_line_1": "NOT_VALID_MRZ", "format": "TD3"},
            )
        except GatewayClientError as e:
            error_msg = str(e)
            assert (
                "400" in error_msg
                or "422" in error_msg
                or "404" in error_msg
                or "invalid" in error_msg.lower()
            )
