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
    return {
        "member_id": member_id,
        "achievement": {
            "name": name,
            "description": description,
            "criteria": {"narrative": "Expected criteria"},
        },
    }


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
            achievement_criteria_narrative="Expected criteria",
        )


def test_structural_credential_correlation_does_not_claim_signature_verification() -> None:
    credential = synthetic_jwt(subject("expected", "Expected", "Expected description"))
    journey.assert_member_badge_credential(
        FormatValidator(),
        credential,
        member_id="expected",
        achievement_name="Expected",
        achievement_description="Expected description",
        achievement_criteria_narrative="Expected criteria",
    )


@pytest.mark.parametrize(
    ("present", "criteria"),
    [(False, None), (True, None), (True, "criteria"), (True, {}), (True, {"narrative": "Wrong criteria"})],
)
def test_missing_malformed_or_uncorrelated_criteria_fails(present: bool, criteria: object) -> None:
    badge_subject = subject("expected", "Expected", "Expected description")
    achievement = badge_subject["achievement"]
    assert isinstance(achievement, dict)
    if present:
        achievement["criteria"] = criteria
    else:
        del achievement["criteria"]
    with pytest.raises(AssertionError):
        journey.assert_member_badge_credential(
            FormatValidator(),
            synthetic_jwt(badge_subject),
            member_id="expected",
            achievement_name="Expected",
            achievement_description="Expected description",
            achievement_criteria_narrative="Expected criteria",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["missing_credential", "empty_credentials", "wrong_transaction"])
async def test_invalid_issuance_fails_and_deprecates_template(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    operations: list[str] = []
    gateway_url = "http://127.0.0.1:38541"
    offer_uri = "openid-credential-offer://?credential_offer=bound"
    monkeypatch.setattr(journey, "GATEWAY_URL", gateway_url)

    def post_issuance(url: str, payload: dict[str, object], headers: dict[str, str]) -> dict[str, object]:
        assert url.startswith("http://issuance-native:8005/")
        path = url.removeprefix("http://issuance-native:8005")
        assert headers["x-organization-id"] == journey._ORGANIZATION_ID
        operations.append(path)
        match path:
            case "/v1/application-templates":
                assert headers["idempotency-key"] == payload["name"]
                body = {"id": "template-1"}
            case "/v1/application-templates/template-1/activate":
                body = {"status": "active"}
            case "/internal/applications":
                assert payload["application_template_id"] == "template-1"
                claims = payload["applicant_data"]
                assert isinstance(claims, dict)
                assert claims["member_id"].startswith("artifact-issuance-")
                assert claims["achievement_criteria"]["narrative"]
                body = {"id": "app-1", "organization_id": journey._ORGANIZATION_ID}
            case "/internal/applications/app-1/approve":
                body = {"id": "app-1", "status": "approved", "issuance_transaction_id": "bound"}
            case "/internal/applications/app-1/issuance-offer":
                transaction = "unrelated" if failure == "wrong_transaction" else "bound"
                body = {"status": "active", "transaction_id": transaction, "offer_url": offer_uri}
            case "/v1/application-templates/template-1/deprecate":
                body = {"status": "deprecated"}
            case _:
                pytest.fail(f"unexpected Issuance path {path}")
        return {"status": 200, "body": body}

    monkeypatch.setattr(journey, "post_json", post_issuance)

    class FakeWallet:
        def __init__(self, *, issuer_base_url: str) -> None:
            assert issuer_base_url == gateway_url
            if failure == "wrong_transaction":
                pytest.fail("wallet must not redeem an unrelated offer")

            async def redeem(uri: str, *, org_id: str) -> dict[str, object]:
                assert uri == offer_uri
                assert org_id == journey._ORGANIZATION_ID
                credential_response = {"transaction_id": "pending"} if failure == "missing_credential" else {
                    "credentials": []
                }
                return {
                    "offer": {"credential_issuer": "https://issuer.example"},
                    "token": {"access_token": "opaque"},
                    "credentials": [credential_response],
                }

            self.run_preauth_issuance = AsyncMock(side_effect=redeem)

        async def close(self) -> None:
            operations.append("close")

    monkeypatch.setattr(journey, "OID4VCIWalletClient", FakeWallet)
    with pytest.raises(AssertionError):
        await journey.test_application_offer_redeems_to_issued_credential()
    assert operations[:5] == [
        "/v1/application-templates",
        "/v1/application-templates/template-1/activate",
        "/internal/applications",
        "/internal/applications/app-1/approve",
        "/internal/applications/app-1/issuance-offer",
    ]
    expected_cleanup = ["/v1/application-templates/template-1/deprecate"]
    if failure != "wrong_transaction":
        expected_cleanup.insert(0, "close")
    assert operations[5:] == expected_cleanup


def test_disposable_flow_cleanup_uses_only_its_extension_uri(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: list[dict[str, str] | None] = []
    monkeypatch.setattr(recovery, "_psql", lambda _sql, *, variables=None: observed.append(variables))
    extension_uri = "urn:elevenid:test:released-stack-positive-issuance:one"
    recovery._install_disposable_application_flow("one", extension_uri=extension_uri)
    recovery._deactivate_disposable_application_flows(extension_uri=extension_uri)
    assert observed[0] is not None
    assert extension_uri in observed[0]["extension"]
    assert observed[1] == {"extension_uri": extension_uri}
