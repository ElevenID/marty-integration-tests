"""Ensure the released-stack issuance candidate cannot pass without a credential."""

from __future__ import annotations

import base64
import json
from unittest.mock import AsyncMock

import pytest

from tests.integration.gateway.helpers.oid4vc_wallet_client import OID4VCIWalletClient
from tests.oss_stack import test_application_offer_recovery as recovery
from tests.oss_stack import test_positive_credential_issuance as journey


class FormatValidator:
    def validate_credential_format(self, raw_credential: str, expected_format: str) -> dict[str, object]:
        return OID4VCIWalletClient.validate_credential_format(self, raw_credential, expected_format)


def synthetic_jwt(subject: dict[str, object], *, typ: str = "vc+jwt") -> str:
    def encode(value: dict[str, object]) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()

    header = {"typ": typ, "alg": "ES256"}
    payload = {
        "iss": "did:web:issuer.example",
        "vc": {
            "type": ["VerifiableCredential", "OpenBadgeCredential"],
            "credentialSubject": subject,
        },
    }
    return f"{encode(header)}.{encode(payload)}.synthetic-signature"


def subject(member_id: str, name: str, description: str) -> dict[str, object]:
    return {"member_id": member_id, "achievement": {"name": name, "description": description}}


@pytest.mark.parametrize(
    "credential",
    [
        "opaque-garbage",
        synthetic_jwt(subject("wrong", "Expected", "Expected description")),
        synthetic_jwt(subject("expected", "Wrong", "Expected description")),
        synthetic_jwt(subject("expected", "Expected", "Wrong")),
        synthetic_jwt(subject("expected", "Expected", "Expected description"), typ="plain-jwt"),
    ],
)
def test_bad_credential_shape_or_correlation_fails(credential: str) -> None:
    with pytest.raises(AssertionError):
        journey.assert_member_badge_credential(
            FormatValidator(),
            credential,
            member_id="expected",
            achievement_name="Expected",
            achievement_description="Expected description",
        )


def test_structural_credential_correlation_does_not_claim_signature_verification() -> None:
    credential = synthetic_jwt(subject("expected", "Expected", "Expected description"))
    journey.assert_member_badge_credential(
        FormatValidator(),
        credential,
        member_id="expected",
        achievement_name="Expected",
        achievement_description="Expected description",
    )


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

    def post_offer(_url: str, event: dict[str, object], _headers: dict[str, str]) -> dict[str, object]:
        data = event["data"]
        assert isinstance(data, dict)
        claims = data["claims"]
        assert isinstance(claims, dict)
        assert {
            "member_id",
            "email",
            "organization_id",
            "role",
            "achievement_name",
            "achievement_description",
            "issued_at",
        } <= claims.keys()
        return {
            "status": 200,
            "body": {
                "flows_triggered": 2,
                "offers": [
                    {
                        "flow_definition_id": "seeded-production-flow",
                        "credential_offer_transaction_id": "seeded-transaction",
                        "credential_offer_uri": "openid-credential-offer://?credential_offer=seeded",
                    },
                    {
                        "flow_definition_id": operations[-1],
                        "credential_offer_transaction_id": "transaction-1",
                        "credential_offer_uri": f"openid-credential-offer://?credential_offer={operations[-1]}",
                    },
                ],
            },
        }

    monkeypatch.setattr(
        journey,
        "post_json",
        post_offer,
    )

    class FakeWallet:
        def __init__(self, *, issuer_base_url: str) -> None:
            assert issuer_base_url == gateway_url
            async def redeem(offer_uri: str, *, org_id: str) -> dict[str, object]:
                assert offer_uri == f"openid-credential-offer://?credential_offer={operations[-1]}"
                assert org_id == journey._ORGANIZATION_ID
                return {
                    "offer": {"credential_issuer": "https://issuer.example"},
                    "token": {"access_token": "opaque"},
                    "credentials": [credential_response],
                }

            self.run_preauth_issuance = AsyncMock(side_effect=redeem)

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


@pytest.mark.asyncio
@pytest.mark.parametrize("own_count", [0, 2])
async def test_missing_or_duplicate_own_offer_fails_with_cleanup(
    monkeypatch: pytest.MonkeyPatch, own_count: int
) -> None:
    flow_ids: list[str] = []
    cleanup_uris: list[str] = []

    def install(flow_id: str, *, extension_uri: str) -> None:
        assert extension_uri.endswith(flow_id)
        flow_ids.append(flow_id)

    def post_offer(_url: str, _event: dict[str, object], _headers: dict[str, str]) -> dict[str, object]:
        offers = [
            {"flow_definition_id": "seeded-flow", "credential_offer_uri": "openid-credential-offer://?seeded"},
            *(
                {"flow_definition_id": flow_ids[0], "credential_offer_uri": f"openid-credential-offer://?own={index}"}
                for index in range(own_count)
            ),
        ]
        return {"status": 200, "body": {"flows_triggered": len(offers), "offers": offers}}

    monkeypatch.setattr(journey, "_install_disposable_application_flow", install)
    monkeypatch.setattr(journey, "post_json", post_offer)
    monkeypatch.setattr(
        journey, "_deactivate_disposable_application_flows", lambda *, extension_uri: cleanup_uris.append(extension_uri)
    )
    monkeypatch.setattr(journey, "OID4VCIWalletClient", lambda **_kwargs: pytest.fail("wallet must not run"))
    with pytest.raises(AssertionError):
        await journey.test_application_offer_redeems_to_issued_credential()
    assert len(cleanup_uris) == 1
    assert cleanup_uris[0].endswith(flow_ids[0])


def test_disposable_flow_cleanup_uses_only_its_extension_uri(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: list[dict[str, str] | None] = []
    monkeypatch.setattr(recovery, "_psql", lambda _sql, *, variables=None: observed.append(variables))
    extension_uri = "urn:elevenid:test:released-stack-positive-issuance:one"
    recovery._install_disposable_application_flow("one", extension_uri=extension_uri)
    recovery._deactivate_disposable_application_flows(extension_uri=extension_uri)
    assert observed[0] is not None
    assert extension_uri in observed[0]["extension"]
    assert observed[1] == {"extension_uri": extension_uri}
