from __future__ import annotations

import base64
import json

import pytest

from tests.integration.gateway.helpers.eudi_client import dcql_query_for_sd_jwt


def jwt(payload: dict[str, object]) -> str:
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"header.{encoded}.signature"


def test_dcql_query_uses_vct_signed_into_issued_credential() -> None:
    credential = jwt({"vct": "https://issuer.example/credentials/OpenBadge"}) + "~disclosure~"

    assert dcql_query_for_sd_jwt(credential, requested_claims=["given_name"]) == {
        "credentials": [
            {
                "id": "sd-jwt-query",
                "format": "dc+sd-jwt",
                "meta": {"vct_values": ["https://issuer.example/credentials/OpenBadge"]},
                "claims": [{"path": ["given_name"]}],
            }
        ]
    }


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"vct": ""},
        {"vct": "relative/type"},
        {"vct": 42},
    ],
)
def test_dcql_query_rejects_missing_or_non_uri_vct(payload: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="absolute vct URI"):
        dcql_query_for_sd_jwt(jwt(payload), requested_claims=["given_name"])
