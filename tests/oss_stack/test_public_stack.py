"""Artifact-only acceptance tests for the public Marty stack."""

from __future__ import annotations

import os

import httpx
import pytest

pytestmark = [pytest.mark.integration, pytest.mark.oss_stack]

GATEWAY_URL = os.environ.get("MARTY_GATEWAY_URL", "http://127.0.0.1:28000").rstrip("/")
UI_URL = os.environ.get("MARTY_UI_URL", "http://127.0.0.1:23000").rstrip("/")


def get_json(path: str) -> dict:
    response = httpx.get(f"{GATEWAY_URL}{path}", timeout=10.0)
    response.raise_for_status()
    return response.json()


def test_gateway_is_healthy() -> None:
    assert get_json("/health") == {"status": "healthy", "service": "api-gateway"}


def test_required_public_services_are_healthy() -> None:
    services = get_json("/health/services")["services"]
    required = {
        "auth",
        "organizations",
        "credential-templates",
        "trust-profiles",
        "issuance",
        "compliance-profiles",
        "presentation-policies",
        "deployment-profiles",
        "flows",
        "revocation-profiles",
    }
    unhealthy = {
        name: services.get(name) for name in sorted(required) if services.get(name, {}).get("status") != "healthy"
    }
    assert not unhealthy, f"required public services are unhealthy: {unhealthy}"


def test_oid4vci_metadata_is_available() -> None:
    issuer_metadata = get_json("/.well-known/openid-credential-issuer")
    assert issuer_metadata["credential_endpoint"].endswith("/v1/issuance/credential")
    assert issuer_metadata["credential_configurations_supported"]

    authorization_servers = issuer_metadata.get("authorization_servers")
    if authorization_servers is not None:
        assert isinstance(authorization_servers, list)
        assert authorization_servers
        assert all(isinstance(origin, str) and origin.startswith("https://") for origin in authorization_servers)
        expected_authorization_server = authorization_servers[0]
    else:
        expected_authorization_server = issuer_metadata["credential_issuer"]

    # OID4VCI 1.0 Final keeps OAuth endpoints in RFC 8414 Authorization
    # Server metadata, not in Credential Issuer metadata.
    authorization_metadata = get_json("/.well-known/oauth-authorization-server")
    assert authorization_metadata["issuer"] == expected_authorization_server
    assert authorization_metadata["token_endpoint"].endswith("/v1/issuance/token")


def test_ui_is_served() -> None:
    response = httpx.get(f"{UI_URL}/", timeout=10.0)
    response.raise_for_status()
    assert response.headers["content-type"].startswith("text/html")
    assert "<html" in response.text.lower()


def test_public_api_has_no_commerce_routes() -> None:
    paths = {path.lower() for path in get_json("/openapi.json")["paths"]}
    forbidden = ("/billing", "/square", "/product-catalog", "/product_catalog")
    leaked = sorted(path for path in paths if any(marker in path for marker in forbidden))
    assert not leaked, f"commerce routes leaked into public API: {leaked}"
