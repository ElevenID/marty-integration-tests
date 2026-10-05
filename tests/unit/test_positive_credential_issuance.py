"""Ensure the released-stack issuance candidate cannot pass without a credential."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from tests.oss_stack import test_application_offer_recovery as recovery
from tests.oss_stack import test_positive_credential_issuance as journey


def _record_cleanup(operations: list[str], *, extension_uri: str) -> None:
    operations.append(f"deactivate:{extension_uri}")


@pytest.mark.asyncio
@pytest.mark.parametrize("credential_response", [{"transaction_id": "pending"}, {"credentials": []}])
async def test_missing_issued_credential_fails_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch, credential_response: dict[str, object]
) -> None:
    operations: list[str] = []
    gateway_url = "http://127.0.0.1:38541"
    monkeypatch.setattr(journey, "GATEWAY_URL", gateway_url)
    monkeypatch.setattr(
        journey,
        "_deactivate_disposable_application_flows",
        lambda *, extension_uri: _record_cleanup(operations, extension_uri=extension_uri),
    )
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
        def __init__(self, *, issuer_base_url: str) -> None:
            assert issuer_base_url == gateway_url
            self.run_preauth_issuance = AsyncMock(return_value={
                "offer": {"credential_issuer": "https://issuer.example"},
                "token": {"access_token": "opaque"},
                "credentials": [credential_response],
            })

        async def close(self) -> None:
            operations.append("close")

    monkeypatch.setattr(journey, "OID4VCIWalletClient", FakeWallet)
    # Keep the generated Flow ID while making the mock response use it.
    def install(flow_id: str, *, extension_uri: str) -> None:
        assert extension_uri.endswith(flow_id)
        operations.append(flow_id)

    monkeypatch.setattr(journey, "_install_disposable_application_flow", install)
    with pytest.raises(AssertionError):
        await journey.test_application_offer_redeems_to_issued_credential()
    assert operations[0] == operations[-1].rsplit(":", 1)[-1]
    assert operations[-2] == "close"
    assert operations[-1].startswith("deactivate:urn:elevenid:test:released-stack-positive-issuance:")


@pytest.mark.asyncio
async def test_uncertain_flow_insert_still_cleans_up(monkeypatch: pytest.MonkeyPatch) -> None:
    cleanup_uris: list[str] = []

    def fail_install(_flow_id: str, *, extension_uri: str) -> None:
        raise RuntimeError(f"insert uncertain for {extension_uri}")

    def cleanup(*, extension_uri: str) -> None:
        cleanup_uris.append(extension_uri)

    monkeypatch.setattr(journey, "_install_disposable_application_flow", fail_install)
    monkeypatch.setattr(journey, "_deactivate_disposable_application_flows", cleanup)
    with pytest.raises(RuntimeError, match="insert uncertain"):
        await journey.test_application_offer_redeems_to_issued_credential()
    assert len(cleanup_uris) == 1
    assert cleanup_uris[0].startswith("urn:elevenid:test:released-stack-positive-issuance:")


def test_disposable_flow_cleanup_uses_only_its_extension_uri(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: list[dict[str, str] | None] = []
    monkeypatch.setattr(recovery, "_psql", lambda _sql, *, variables=None: observed.append(variables))
    extension_uri = "urn:elevenid:test:released-stack-positive-issuance:one"
    recovery._install_disposable_application_flow("one", extension_uri=extension_uri)
    recovery._deactivate_disposable_application_flows(extension_uri=extension_uri)
    assert observed[0] is not None
    assert extension_uri in observed[0]["extension"]
    assert observed[1] == {"extension_uri": extension_uri}
