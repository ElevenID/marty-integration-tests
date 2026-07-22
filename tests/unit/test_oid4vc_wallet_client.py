from unittest.mock import AsyncMock

import pytest

from tests.integration.gateway.helpers.oid4vc_wallet_client import (
    OID4VCIWalletClient,
)


@pytest.mark.asyncio
async def test_preauth_flow_fetches_final_nonce_before_credential_request() -> None:
    wallet = OID4VCIWalletClient(issuer_base_url="https://issuer.example")
    wallet.resolve_offer = AsyncMock(
        return_value={
            "credential_issuer": "https://issuer.example/org/org-1",
            "credential_configuration_ids": ["pid#sd-jwt"],
        }
    )
    wallet.fetch_issuer_metadata = AsyncMock(return_value={})
    wallet.request_token = AsyncMock(return_value={"access_token": "opaque"})
    wallet.request_nonce = AsyncMock(return_value="fresh-proof-nonce")
    wallet.request_credential = AsyncMock(return_value={"credentials": []})

    try:
        result = await wallet.run_preauth_issuance(
            "openid-credential-offer://fixture", org_id="org-1"
        )
    finally:
        await wallet.close()

    wallet.request_nonce.assert_awaited_once_with()
    wallet.request_credential.assert_awaited_once_with("pid#sd-jwt")
    assert result["token"] == {"access_token": "opaque"}


@pytest.mark.asyncio
async def test_preauth_flow_does_not_request_credential_when_nonce_fails() -> None:
    wallet = OID4VCIWalletClient(issuer_base_url="https://issuer.example")
    wallet.resolve_offer = AsyncMock(
        return_value={"credential_configuration_ids": ["pid#sd-jwt"]}
    )
    wallet.fetch_issuer_metadata = AsyncMock(return_value={})
    wallet.request_token = AsyncMock(return_value={"access_token": "opaque"})
    wallet.request_nonce = AsyncMock(side_effect=RuntimeError("nonce unavailable"))
    wallet.request_credential = AsyncMock()

    try:
        with pytest.raises(RuntimeError, match="nonce unavailable"):
            await wallet.run_preauth_issuance(
                "openid-credential-offer://fixture", org_id="org-1"
            )
    finally:
        await wallet.close()

    wallet.request_credential.assert_not_awaited()
