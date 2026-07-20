from __future__ import annotations

import base64
import json
from unittest.mock import AsyncMock

import httpx
import pytest

from tests.integration.gateway.helpers.eudi_client import EUDIVerifierClient


def _unsigned_jwt(payload: dict[str, str]) -> str:
    encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=").decode()
    return f"e30.{encoded}.signature"


@pytest.mark.asyncio
async def test_get_request_object_uses_same_origin_absolute_uri_unchanged() -> None:
    client = EUDIVerifierClient("https://verifier.example:8443")
    request_uri = "https://verifier.example:8443/wallet/request.jwt/request-1?transaction_data=one%2Ftwo"
    response = httpx.Response(
        200,
        text=_unsigned_jwt({"state": "state-1", "nonce": "nonce-1"}),
        request=httpx.Request("GET", request_uri),
    )
    get = AsyncMock(return_value=response)
    client.client.get = get

    try:
        payload = await client.get_request_object(request_uri)
    finally:
        await client.close()

    get.assert_awaited_once_with(request_uri)
    assert payload["state"] == "state-1"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "request_uri",
    [
        "http://verifier.example:8443/wallet/request.jwt/request-1",
        "https://other.example:8443/wallet/request.jwt/request-1",
        "https://verifier.example:9443/wallet/request.jwt/request-1",
    ],
)
async def test_get_request_object_rejects_a_different_origin(request_uri: str) -> None:
    client = EUDIVerifierClient("https://verifier.example:8443")
    get = AsyncMock()
    client.client.get = get

    try:
        with pytest.raises(ValueError, match="request_uri origin"):
            await client.get_request_object(request_uri)
    finally:
        await client.close()

    get.assert_not_awaited()


@pytest.mark.asyncio
async def test_submit_wallet_response_uses_same_origin_absolute_uri_unchanged() -> None:
    client = EUDIVerifierClient("https://verifier.example:8443")
    response_uri = "https://verifier.example:8443/wallet/direct_post/request-1?response_code=one%2Ftwo"
    response = httpx.Response(
        200,
        json={"redirect_uri": "https://wallet.example/complete"},
        request=httpx.Request("POST", response_uri),
    )
    post = AsyncMock(return_value=response)
    client.client.post = post

    try:
        result = await client.submit_wallet_response(
            state="state-1",
            vp_token={"credential": "vp-token"},
            response_uri=response_uri,
        )
    finally:
        await client.close()

    assert post.await_args.args[0] == response_uri
    assert result["status_code"] == 200


@pytest.mark.asyncio
async def test_submit_wallet_response_rejects_a_different_origin() -> None:
    client = EUDIVerifierClient("https://verifier.example:8443")
    post = AsyncMock()
    client.client.post = post

    try:
        with pytest.raises(ValueError, match="response_uri origin"):
            await client.submit_wallet_response(
                state="state-1",
                vp_token="vp-token",
                response_uri="https://attacker.example/direct_post/request-1",
            )
    finally:
        await client.close()

    post.assert_not_awaited()
