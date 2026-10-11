"""The opt-in customer journey never falls back to demo auth or tenant data."""

import pytest

from tests.oss_stack.selfhost_customer_journey import required_inputs


def test_missing_operator_credentials_fail_before_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "SELFHOST_GATEWAY_URL", "SELFHOST_KEYCLOAK_URL",
        "SELFHOST_PUBLIC_DOMAIN", "SELFHOST_TEST_USERNAME",
        "SELFHOST_TEST_PASSWORD", "SELFHOST_ORG_ID", "SELFHOST_ISSUER_DID",
    ):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ValueError, match="SELFHOST_TEST_PASSWORD"):
        required_inputs()


def test_fixture_accepts_only_explicit_public_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {
        "SELFHOST_GATEWAY_URL": "http://127.0.0.1:19080",
        "SELFHOST_KEYCLOAK_URL": "http://127.0.0.1:18180",
        "SELFHOST_PUBLIC_DOMAIN": "selfhost.example.invalid",
        "SELFHOST_TEST_USERNAME": "operator@example.invalid",
        "SELFHOST_TEST_PASSWORD": "synthetic-only",
        "SELFHOST_ORG_ID": "00000000-0000-0000-0000-000000000001",
        "SELFHOST_ISSUER_DID": "did:web:selfhost.example.invalid:orgs:00000000-0000-0000-0000-000000000001",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    assert required_inputs() == values
    monkeypatch.setenv("SELFHOST_ORG_ID", "not-a-uuid")
    with pytest.raises(ValueError, match="organization ID is not canonical"):
        required_inputs()
