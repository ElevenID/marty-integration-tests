"""Hermetic controls for the opt-in machine journey, not live acceptance."""

import json
import os
from pathlib import Path

import httpx
import pytest

from tests.integration.gateway.helpers.gateway_client import GatewayClient
from tests.oss_stack.selfhost_machine_customer_journey import (
    CONSUMER_SCOPES,
    machine_client,
    operator_key,
    owned_consumer_key,
    required_inputs,
)

ORG = "11111111-1111-1111-1111-111111111111"
KEY_ID = "22222222-2222-2222-2222-222222222222"


def test_machine_inputs_do_not_depend_on_browser_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {
        "SELFHOST_GATEWAY_URL": "http://127.0.0.1:19080",
        "SELFHOST_ORG_ID": ORG,
        "SELFHOST_ISSUER_DID": "did:web:issuer.example.invalid",
        "SELFHOST_VERIFIER_DID": "did:web:verifier.example.invalid",
        "SELFHOST_OPERATOR_API_KEY_FILE": "/private/operator-key",
    }
    for name in ("SELFHOST_TEST_USERNAME", "SELFHOST_TEST_PASSWORD", "SELFHOST_KEYCLOAK_URL"):
        monkeypatch.delenv(name, raising=False)
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    assert required_inputs() == values
    monkeypatch.delenv("SELFHOST_OPERATOR_API_KEY_FILE")
    with pytest.raises(ValueError, match="SELFHOST_OPERATOR_API_KEY_FILE"):
        required_inputs()


def test_operator_key_requires_private_file_and_valid_token(tmp_path: Path) -> None:
    path = tmp_path / "operator-key"
    path.write_text("mk_test_operator-fixture\n", encoding="ascii")
    path.chmod(0o600)
    assert operator_key(path) == "mk_test_operator-fixture"
    with pytest.raises(ValueError, match="private regular file"):
        operator_key(Path("relative-key"))
    path.write_text("mk_test_invalid token", encoding="ascii")
    with pytest.raises(ValueError, match="Marty API key"):
        operator_key(path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX private-file permission control")
def test_operator_key_rejects_group_readable_file(tmp_path: Path) -> None:
    path = tmp_path / "operator-key"
    path.write_text("mk_test_operator-fixture", encoding="ascii")
    path.chmod(0o640)
    with pytest.raises(ValueError, match="private regular file"):
        operator_key(path)


@pytest.mark.asyncio
async def test_switching_to_machine_key_discards_previous_browser_auth() -> None:
    async with GatewayClient(base_url="http://example.invalid") as gateway:
        gateway.set_session("previous-session")
        gateway.client.headers["Authorization"] = "Bearer old-oauth-token"
        gateway.client.headers["Cookie"] = "other=old-cookie"
        gateway.set_api_key("mk_test_machine-fixture")
        assert not gateway.client.cookies
        assert "cookie" not in gateway.client.headers
        assert "authorization" not in gateway.client.headers
        assert gateway._session_id is None
        assert gateway._auth_token is None
        gateway.set_session("next-session")
        assert "x-api-key" not in gateway.client.headers


@pytest.mark.asyncio
async def test_machine_requests_refuse_server_cookie_fallback() -> None:
    calls = []

    def respond(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, headers={"set-cookie": "sessionId=must-not-use; Path=/"})

    async with machine_client(
        "http://example.invalid", "mk_test_machine-fixture",
        transport=httpx.MockTransport(respond),
    ) as gateway:
        await gateway.client.get("/health")
        with pytest.raises(AssertionError, match="credential fallback"):
            await gateway.client.get("/v1/issuance")
    assert len(calls) == 1
    assert calls[0].headers["x-api-key"] == "mk_test_machine-fixture"
    assert "cookie" not in calls[0].headers


@pytest.mark.asyncio
async def test_owned_key_is_retired_when_the_business_journey_fails() -> None:
    calls = []

    def respond(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        assert request.url.params["organization_id"] == ORG
        assert "cookie" not in request.headers
        if request.method == "POST":
            body = json.loads(request.content)
            assert body["scopes"] == CONSUMER_SCOPES
            assert "admin:full" not in body["scopes"]
            return httpx.Response(200, json={
                "id": KEY_ID, "organization_id": ORG,
                "key": "mk_test_consumer-fixture", "scopes": CONSUMER_SCOPES,
            })
        assert request.method == "DELETE"
        assert request.url.path == "/v1/api-keys/" + KEY_ID
        return httpx.Response(200, json={"success": True})

    async with machine_client(
        "http://example.invalid", "mk_test_operator-fixture",
        transport=httpx.MockTransport(respond),
    ) as gateway:
        with pytest.raises(RuntimeError, match="business journey failed"):
            async with owned_consumer_key(gateway, ORG):
                raise RuntimeError("business journey failed")
    assert [request.method for request in calls] == ["POST", "DELETE"]
