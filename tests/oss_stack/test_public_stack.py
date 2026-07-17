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
        name: services.get(name)
        for name in sorted(required)
        if services.get(name, {}).get("status") != "healthy"
    }
    assert not unhealthy, f"required public services are unhealthy: {unhealthy}"


def test_oid4vci_metadata_is_available() -> None:
    metadata = get_json("/.well-known/openid-credential-issuer")
    assert metadata["credential_endpoint"].endswith("/v1/issuance/credential")
    assert metadata["token_endpoint"].endswith("/v1/issuance/token")
    assert metadata["credential_configurations_supported"]


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
