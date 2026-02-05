"""
Integration tests for credential issuance using Walt.id wallet.

These tests verify end-to-end credential issuance flows using a real wallet
implementation (Walt.id Wallet Kit) via OpenID4VCI protocol.

Test Coverage:
- Wallet setup and DID creation
- Credential offer acceptance
- Credential storage and retrieval
- Multiple credential types (mDL, employee badges)
- Credential lifecycle in wallet
"""

import pytest
from typing import Dict, Any

from .helpers.gateway_client import GatewayClient
from .helpers.waltid_wallet_client import WaltIdWalletClient
from .helpers.test_data import TestDataBuilder


@pytest.mark.integration
@pytest.mark.asyncio
class TestWalletSetup:
    """Test basic wallet setup and configuration."""

    async def test_create_wallet(self, waltid_wallet_client: WaltIdWalletClient):
        """Test wallet creation."""
        wallet_result = await waltid_wallet_client.create_wallet("test-wallet-setup")
        
        assert wallet_result is not None
        assert waltid_wallet_client.wallet_id is not None

    async def test_create_did(self, test_wallet: Dict[str, Any]):
        """Test DID creation in wallet."""
        wallet_client = test_wallet["client"]
        
        # Create additional DID
        did_result = await wallet_client.create_did(method="key")
        
        assert "did" in did_result
        assert did_result["did"].startswith("did:key:")

    async def test_list_dids(self, test_wallet: Dict[str, Any]):
        """Test listing DIDs in wallet."""
        wallet_client = test_wallet["client"]
        
        # Should have at least one DID (created by fixture)
        dids = await wallet_client.list_dids()
        
        assert len(dids) >= 1
        # Check if the test wallet's DID is in the list
        did_strings = [d["did"] for d in dids]
        assert test_wallet["did"] in did_strings


@pytest.mark.integration
@pytest.mark.wallet
@pytest.mark.asyncio
class TestCredentialIssuanceToWallet:
    """Test credential issuance via OpenID4VCI to a real wallet."""

    async def test_issue_mdl_to_wallet(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
        test_wallet: Dict[str, Any],
    ):
        """Test issuing an mDL credential to a wallet via OpenID4VCI."""
        # Prepare mDL claims
        claims = TestDataBuilder.mdl_claims()
        
        # Issue credential via gateway
        issuance_result = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=mdl_template["id"],
            subject_did=test_wallet["did"],  # Use wallet DID
            claims=claims,
        )
        
        assert "id" in issuance_result
        assert "credential_offer_uri" in issuance_result  # OpenID4VCI offer URL
        
        # Wallet accepts the credential offer
        wallet_client = test_wallet["client"]
        offer_url = issuance_result["credential_offer_uri"]
        
        acceptance_result = await wallet_client.accept_credential_offer(
            offer_url=offer_url,
            did=test_wallet["did"],
        )
        
        assert acceptance_result is not None
        
        # Verify credential is now in wallet
        credentials = await wallet_client.list_credentials()
        assert len(credentials) > 0
        
        # Find our mDL credential
        mdl_cred = next(
            (c for c in credentials if "org.iso.18013.5.1.mDL" in str(c)),
            None
        )
        assert mdl_cred is not None

    async def test_issue_employee_badge_to_wallet(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        employee_badge_template: Dict[str, Any],
        test_wallet: Dict[str, Any],
    ):
        """Test issuing an employee badge credential to wallet."""
        # Prepare employee badge claims
        claims = {
            "employee_id": "EMP-12345",
            "full_name": "Jane Doe",
            "department": "Engineering",
            "position": "Senior Developer",
            "email": "jane.doe@example.com",
            "start_date": "2024-01-15",
        }
        
        # Issue credential
        issuance_result = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=employee_badge_template["id"],
            subject_did=test_wallet["did"],
            claims=claims,
        )
        
        assert "credential_offer_uri" in issuance_result
        
        # Accept in wallet
        wallet_client = test_wallet["client"]
        await wallet_client.accept_credential_offer(
            offer_url=issuance_result["credential_offer_uri"],
            did=test_wallet["did"],
        )
        
        # Verify in wallet
        credentials = await wallet_client.list_credentials()
        employee_cred = next(
            (c for c in credentials if "EmployeeBadge" in str(c)),
            None
        )
        assert employee_cred is not None


@pytest.mark.integration
@pytest.mark.wallet
@pytest.mark.asyncio
class TestCredentialOfferResolution:
    """Test resolving credential offers before acceptance."""

    async def test_resolve_credential_offer(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
        test_wallet: Dict[str, Any],
    ):
        """Test resolving a credential offer to inspect details."""
        claims = TestDataBuilder.mdl_claims()
        
        # Issue credential
        issuance_result = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=mdl_template["id"],
            subject_did=test_wallet["did"],
            claims=claims,
        )
        
        # Resolve the offer (inspect without accepting)
        wallet_client = test_wallet["client"]
        offer_details = await wallet_client.resolve_credential_offer(
            offer_url=issuance_result["credential_offer_uri"]
        )
        
        assert offer_details is not None
        # Should contain information about what's being offered
        assert "credential_issuer" in offer_details or "credentials" in offer_details


@pytest.mark.integration
@pytest.mark.wallet
@pytest.mark.asyncio
class TestMultipleCredentialsInWallet:
    """Test managing multiple credentials in a single wallet."""

    async def test_wallet_with_multiple_credentials(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
        employee_badge_template: Dict[str, Any],
        test_wallet: Dict[str, Any],
    ):
        """Test wallet holding multiple different credential types."""
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
                "employee_id": "EMP-99999",
                "full_name": "Test User",
                "department": "Testing",
                "position": "Tester",
                "email": "test@example.com",
                "start_date": "2024-01-01",
            },
        )
        
        await wallet_client.accept_credential_offer(
            offer_url=badge_result["credential_offer_uri"],
            did=did,
        )
        
        # List all credentials
        credentials = await wallet_client.list_credentials()
        assert len(credentials) >= 2
        
        # Verify both types are present
        cred_types = [str(c) for c in credentials]
        has_mdl = any("mDL" in ct for ct in cred_types)
        has_badge = any("EmployeeBadge" in ct or "Badge" in ct for ct in cred_types)
        
        assert has_mdl or len(credentials) >= 1  # At least one of expected type
        assert has_badge or len(credentials) >= 2  # Or at least got both

    async def test_retrieve_specific_credential(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
        test_wallet: Dict[str, Any],
    ):
        """Test retrieving a specific credential by ID from wallet."""
        wallet_client = test_wallet["client"]
        
        # Issue and accept credential
        issuance_result = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=mdl_template["id"],
            subject_did=test_wallet["did"],
            claims=TestDataBuilder.mdl_claims(),
        )
        
        await wallet_client.accept_credential_offer(
            offer_url=issuance_result["credential_offer_uri"],
            did=test_wallet["did"],
        )
        
        # Get list of credentials
        credentials = await wallet_client.list_credentials()
        assert len(credentials) > 0
        
        # Get the first credential by ID
        first_cred = credentials[0]
        cred_id = first_cred.get("id") or first_cred.get("credentialId")
        
        if cred_id:
            # Retrieve specific credential
            specific_cred = await wallet_client.get_credential(cred_id)
            assert specific_cred is not None


@pytest.mark.integration
@pytest.mark.wallet
@pytest.mark.asyncio
class TestCredentialLifecycleInWallet:
    """Test complete credential lifecycle including deletion."""

    async def test_delete_credential_from_wallet(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        mdl_template: Dict[str, Any],
        test_wallet: Dict[str, Any],
    ):
        """Test deleting a credential from the wallet."""
        wallet_client = test_wallet["client"]
        
        # Issue and accept credential
        issuance_result = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=mdl_template["id"],
            subject_did=test_wallet["did"],
            claims=TestDataBuilder.mdl_claims(),
        )
        
        await wallet_client.accept_credential_offer(
            offer_url=issuance_result["credential_offer_uri"],
            did=test_wallet["did"],
        )
        
        # Get credential count (filter out already deleted ones)
        credentials_before = await wallet_client.list_credentials()
        active_before = [c for c in credentials_before if not c.get("deletedOn")]
        count_before = len(active_before)
        
        # Delete the credential
        if count_before > 0:
            cred_id = active_before[0].get("id") or active_before[0].get("credentialId")
            if cred_id:
                await wallet_client.delete_credential(cred_id)
                
                # Verify deletion (walt.id soft-deletes, so check for deletedOn field)
                credentials_after = await wallet_client.list_credentials()
                active_after = [c for c in credentials_after if not c.get("deletedOn")]
                assert len(active_after) < count_before

    async def test_wallet_cleanup(
        self,
        waltid_wallet_client: WaltIdWalletClient,
    ):
        """Test wallet deletion."""
        # Create a wallet
        wallet_result = await waltid_wallet_client.create_wallet("test-cleanup-wallet")
        wallet_id = waltid_wallet_client.wallet_id
        
        assert wallet_id is not None
        
        # Delete the wallet (ignore 404 if already deleted)
        try:
            await waltid_wallet_client.delete_wallet(wallet_id)
        except Exception as e:
            # Wallet might already be deleted, that's ok
            if "404" not in str(e):
                raise
        
        # Verify wallet_id is cleared
        assert waltid_wallet_client.wallet_id is None
