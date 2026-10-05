"""Ensure the released-stack issuance candidate cannot pass without a credential."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from tests.oss_stack import test_positive_credential_issuance as journey


@pytest.mark.asyncio
@pytest.mark.parametrize("credential_response", [{"transaction_id": "pending"}, {"credentials": []}])
async def test_missing_issued_credential_fails_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch, credential_response: dict[str, object]
) -> None:
    operations: list[str] = []
    monkeypatch.setattr(journey, "_deactivate_disposable_application_flows", lambda: operations.append("deactivate"))
    monkeypatch.setattr(journey, "_install_disposable_application_flow", lambda _flow_id: operations.append("install"))
    monkeypatch.setattr(
        journey,
        "post_json",
        lambda *_args: {
            "status": 200,
            "body": {
                "flows_triggered": 1,
                "offers": [{
                    "flow_definition_id": operations[-1],
                    "credential_offer_transaction_id": "transaction-1",
                    "credential_offer_uri": "openid-credential-offer://?credential_offer=%7B%7D",
                }],
            },
        },
    )

    class FakeWallet:
        def __init__(self, **_kwargs: object) -> None:
            self.run_preauth_issuance = AsyncMock(return_value={
                "offer": {"credential_issuer": "https://issuer.example"},
                "token": {"access_token": "opaque"},
                "credentials": [credential_response],
            })

        async def close(self) -> None:
            operations.append("close")

    monkeypatch.setattr(journey, "OID4VCIWalletClient", FakeWallet)
    # Keep the generated Flow ID while making the mock response use it.
    def install(flow_id: str) -> None:
        operations.append(flow_id)

    monkeypatch.setattr(journey, "_install_disposable_application_flow", install)
    with pytest.raises(AssertionError):
        await journey.test_application_offer_redeems_to_issued_credential()
    assert operations[0] == "deactivate"
    assert operations[-2:] == ["close", "deactivate"]
