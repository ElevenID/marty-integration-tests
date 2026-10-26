"""Opt-in machine-client component; installation/bootstrap evidence is separate.

Run this exact path only against an owned disposable, digest-pinned stack.
The caller provisions an organization operator key through approved bootstrap.
No browser credential is accepted or created by this component.
"""

from __future__ import annotations

import os
import stat
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import pytest

from tests.integration.gateway.helpers.gateway_client import GatewayClient
from tests.oss_stack.selfhost_customer_journey import (
    exercise_customer_journey,
    validate_public_inputs,
)

CONSUMER_SCOPES = [
    "credentials:issue", "credentials:read", "credentials:revoke", "flows:execute",
]


def required_inputs() -> dict[str, str]:
    names = (
        "SELFHOST_GATEWAY_URL", "SELFHOST_ORG_ID", "SELFHOST_ISSUER_DID",
        "SELFHOST_VERIFIER_DID", "SELFHOST_OPERATOR_API_KEY_FILE",
    )
    values = {name: os.environ.get(name, "").strip() for name in names}
    missing = sorted(name for name, value in values.items() if not value)
    if missing:
        raise ValueError("machine journey fixture missing: " + ", ".join(missing))
    validate_public_inputs(values)
    return values


def operator_key(path: Path) -> str:
    if not path.is_absolute():
        raise ValueError("machine operator key file must be a private regular file")
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode)
            or not 1 <= metadata.st_size <= 1024
            or (os.name == "posix" and stat.S_IMODE(metadata.st_mode) & 0o077)):
        raise ValueError("machine operator key file must be a private regular file")
    value = path.read_text(encoding="ascii").rstrip("\r\n")
    if (not value.startswith(("mk_live_", "mk_test_", "pk_live_", "pk_test_"))
            or any(character.isspace() for character in value)):
        raise ValueError("machine operator key file does not contain a Marty API key")
    return value


async def refuse_browser_auth(request: httpx.Request) -> None:
    if "cookie" in request.headers or "authorization" in request.headers:
        raise AssertionError("machine journey attempted browser/bearer credential fallback")


@asynccontextmanager
async def machine_client(
    base_url: str, key: str, *, transport: httpx.AsyncBaseTransport | None = None,
) -> AsyncIterator[GatewayClient]:
    async with GatewayClient(base_url=base_url) as gateway:
        await gateway.client.aclose()
        gateway.client = httpx.AsyncClient(
            base_url=base_url, timeout=90.0, follow_redirects=False, trust_env=False,
            event_hooks={"request": [refuse_browser_auth]}, transport=transport,
        )
        gateway.set_api_key(key)
        yield gateway


@asynccontextmanager
async def owned_consumer_key(
    operator: GatewayClient, organization_id: str,
) -> AsyncIterator[str]:
    response = await operator.client.post(
        "/v1/api-keys", params={"organization_id": organization_id},
        json={
            "name": "Machine journey " + uuid4().hex,
            "scopes": CONSUMER_SCOPES,
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            "is_test": True,
        },
    )
    response.raise_for_status()
    created = response.json()
    if (created.get("organization_id") != organization_id
            or not isinstance(created.get("id"), str)
            or not isinstance(created.get("key"), str)):
        raise AssertionError("created machine key has invalid tenant/identity metadata")
    key_id = created["id"]
    if key_id != str(UUID(key_id)):
        raise AssertionError("created machine key ID is not canonical")
    try:
        if set(created.get("scopes", [])) != set(CONSUMER_SCOPES):
            raise AssertionError("created machine key does not have the requested scopes")
        yield created["key"]
    finally:
        retired = await operator.client.delete(
            "/v1/api-keys/" + key_id, params={"organization_id": organization_id},
        )
        retired.raise_for_status()
        if retired.json() != {"success": True}:
            raise AssertionError("owned machine key retirement was not acknowledged")


@pytest.mark.asyncio
async def test_machine_issue_present_verify_and_retire_key() -> None:
    fixture = required_inputs()
    key = operator_key(Path(fixture["SELFHOST_OPERATOR_API_KEY_FILE"]))
    organization_id = fixture["SELFHOST_ORG_ID"]
    base_url = fixture["SELFHOST_GATEWAY_URL"].rstrip("/")
    async with machine_client(base_url, key) as operator:
        async with (
            owned_consumer_key(operator, organization_id) as consumer_key,
            machine_client(base_url, consumer_key) as consumer,
        ):
            denied = await consumer.client.get(
                "/v1/api-keys", params={"organization_id": organization_id},
            )
            assert denied.status_code == 403, "consumer key could manage API credentials"
            allowed = await consumer.client.get(
                "/v1/issuance", params={"organization_id": organization_id},
            )
            assert allowed.status_code == 200, "consumer could not read its own tenant"
            other_organization = str(uuid4())
            denied = await consumer.client.get(
                "/v1/issuance", params={"organization_id": other_organization},
            )
            assert denied.status_code == 403, "consumer key escaped its organization"
            await exercise_customer_journey(fixture, operator, consumer=consumer)
        async with machine_client(base_url, consumer_key) as retired:
            rejected = await retired.client.get(
                "/v1/issuance", params={"organization_id": organization_id},
            )
            assert rejected.status_code == 401, "revoked consumer key still authenticated"
