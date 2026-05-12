"""Signing-key gateway integration tests.

These tests exercise the gateway signing-key endpoints over HTTP,
matching how the UI interacts with the platform.
"""

from typing import Any, Dict

import pytest

from .helpers.gateway_client import GatewayClient


@pytest.mark.asyncio
@pytest.mark.integration
class TestSigningKeysFlow:
    """Integration tests for signing-key management endpoints."""

    async def test_list_signing_key_purposes(self, gateway_client: GatewayClient):
        """Purpose catalog should expose known signing intents and constraints."""
        response = await gateway_client.list_signing_key_purposes()

        purposes = response.get("purposes")
        assert isinstance(purposes, list)
        assert len(purposes) > 0

        purpose_by_id = {
            item["id"]: item
            for item in purposes
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        }

        assert "vc_jwt_issuer" in purpose_by_id
        assert "mdoc_dsc" in purpose_by_id
        assert "jwks_signing" in purpose_by_id
        assert "allowed_algorithms" in purpose_by_id["vc_jwt_issuer"]

    async def test_list_signing_key_service_capabilities(self, gateway_client: GatewayClient):
        """Capability catalog should advertise known KMS provider service-types."""
        response = await gateway_client.list_signing_key_service_capabilities()

        capabilities = response.get("service_capabilities")
        assert isinstance(capabilities, list)
        assert len(capabilities) > 0

        service_type_ids = {
            entry.get("service_type_id")
            for entry in capabilities
            if isinstance(entry, dict)
        }

        assert "openbao-transit" in service_type_ids
        assert "aws-kms" in service_type_ids
        assert "azure-key-vault" in service_type_ids
        assert "gcp-cloud-kms" in service_type_ids

    async def test_update_and_resolve_signing_service(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
    ):
        """Registry update should persist and resolver should return matching service."""
        org_id = test_organization["id"]
        service_id = "svc-it-signing-jwt"

        update_result = await gateway_client.update_signing_key_config(
            organization_id=org_id,
            services=[
                {
                    "id": service_id,
                    "name": "Integration Test JWT Signer",
                    "service_type": "custom-transit-compatible",
                    "provider": "integration-custom",
                    "protocol": "vault-transit-compatible",
                    "endpoint": "https://kms.example.local",
                    "auth_mode": "api_key",
                    "auth_reference": "test-secret-ref",
                    "key_reference": "issuer-key-1",
                    "algorithms": ["ES256"],
                    "key_purposes": ["vc_jwt_issuer"],
                    "credential_formats": ["jwt_vc_json"],
                }
            ],
            default_service_id=service_id,
            format_defaults={"jwt_vc_json": service_id},
            type_defaults={"vc_jwt_issuer": service_id},
        )

        assert "services" in update_result

        resolved = await gateway_client.resolve_signing_service(
            organization_id=org_id,
            credential_format="jwt_vc_json",
            key_purpose="vc_jwt_issuer",
            algorithm="ES256",
        )

        service = resolved.get("service")
        assert isinstance(service, dict)
        assert service.get("id") == service_id
