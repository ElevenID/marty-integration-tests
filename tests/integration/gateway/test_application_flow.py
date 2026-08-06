"""Application-template integration tests for the current public gateway API.

Applicant submission, evidence, review, and issuance are intentionally covered by
the authenticated ``/v1/me`` and organization-scoped reviewer tests in
``test_two_organization_isolation.py``.  Do not reintroduce the retired generic
application routes here.
"""

from typing import Any

import pytest

from .helpers.gateway_client import GatewayClient


@pytest.mark.asyncio
@pytest.mark.integration
class TestApplicationTemplateFlow:
    """Test application-template creation and management."""

    async def test_create_application_template(
        self,
        gateway_client: GatewayClient,
        test_organization: dict[str, Any],
        mdl_template: dict[str, Any],
    ):
        app_template = await gateway_client.create_application_template(
            organization_id=test_organization["id"],
            name="mDL Application Process",
            credential_template_id=mdl_template["id"],
            form_fields=[
                {
                    "field_id": "given_name",
                    "field_type": "TEXT",
                    "label": "Given Name",
                    "required": True,
                }
            ],
            evidence_requirements=[
                {
                    "evidence_id": "drivers_license",
                    "evidence_type": "DOCUMENT_SCAN",
                    "description": "Driver license document",
                    "required": True,
                },
                {
                    "evidence_id": "selfie",
                    "evidence_type": "SELFIE",
                    "description": "Current applicant selfie",
                    "required": True,
                },
            ],
        )

        assert "id" in app_template
        assert app_template["organization_id"] == test_organization["id"]
        evidence_ids = {
            requirement["evidence_id"]
            for requirement in app_template["evidence_requirements"]
        }
        assert {"drivers_license", "selfie"} <= evidence_ids

    async def test_get_application_template(
        self,
        gateway_client: GatewayClient,
        mdl_application_template: dict[str, Any],
    ):
        template = await gateway_client.get_application_template(
            mdl_application_template["id"]
        )

        assert template["id"] == mdl_application_template["id"]
        assert template["name"] == mdl_application_template["name"]

    async def test_list_application_templates(
        self,
        gateway_client: GatewayClient,
        test_organization: dict[str, Any],
        mdl_application_template: dict[str, Any],
    ):
        templates = await gateway_client.list_application_templates(
            organization_id=test_organization["id"]
        )

        assert isinstance(templates, list)
        assert mdl_application_template["id"] in {
            template["id"] for template in templates
        }
