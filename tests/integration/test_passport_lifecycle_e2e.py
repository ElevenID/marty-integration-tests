"""
End-to-End Passport Lifecycle Test Skeleton

Exercises the complete physical passport lifecycle through the gateway:
  Application → Evidence Validation → Approval → DG Generation →
  SOD Signing → Bureau Submission → Production Tracking →
  Quality Verification → Activation

This test skeleton marks each phase with ``pytest.skip`` where the
corresponding API endpoint has not yet been deployed.  As endpoints
come online, remove the skips to enable the full flow.

Markers:
  @pytest.mark.e2e
  @pytest.mark.passport
  @pytest.mark.slow
"""

import base64
import os
from uuid import uuid4

import pytest

from gateway.helpers.gateway_client import GatewayClient, GatewayClientError
from gateway.helpers.test_data import TestDataBuilder


pytestmark = [pytest.mark.e2e, pytest.mark.passport, pytest.mark.slow]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
async def e2e_org(gateway_client: GatewayClient):
    """Module-scoped organisation for E2E passport tests."""
    org = await gateway_client.create_organization(
        **TestDataBuilder.organization(name=f"passport-e2e-{uuid4().hex[:8]}")
    )
    yield org


@pytest.fixture(scope="module")
async def e2e_trust_profile(gateway_client: GatewayClient, e2e_org):
    org_id = e2e_org["id"]
    profile_data = TestDataBuilder.icao_trust_profile(organization_id=org_id)
    return await gateway_client.create_trust_profile(**profile_data)


# ---------------------------------------------------------------------------
# Full lifecycle
# ---------------------------------------------------------------------------

class TestPassportLifecycleE2E:
    """
    Full end-to-end passport lifecycle.

    Each step stores its result in class-level state so subsequent steps
    can reference IDs from earlier phases.
    """

    _application_id: str | None = None
    _sod_blob: str | None = None
    _bureau_job_id: str | None = None

    # ---- Phase 1: Submit application ----

    async def test_01_submit_application(
        self,
        gateway_client: GatewayClient,
        e2e_org,
    ):
        """Step 1 — Submit passport application with applicant data + DG1/DG2."""
        resp = await gateway_client.client.post(
            "/v1/passport/applications",
            json={
                "organization_id": e2e_org["id"],
                "document_type": "TD3",
                "applicant": {
                    "surname": "TESTPERSON",
                    "given_names": "LIFECYCLE",
                    "date_of_birth": "1990-01-15",
                    "nationality": "UTO",
                    "sex": "M",
                },
                "mrz": {
                    "line_1": "P<UTOTESTPERSON<<LIFECYCLE<<<<<<<<<<<<<<<<<<",
                    "line_2": "X123456780UTO9001159M3001015<<<<<<<<<<<<<<00",
                },
                "data_groups": {
                    "DG1": base64.b64encode(b"FAKE_DG1").decode(),
                    "DG2": base64.b64encode(b"FAKE_DG2_FACIAL").decode(),
                },
            },
        )
        if resp.status_code == 404:
            pytest.skip("Passport application endpoint not deployed")

        assert resp.status_code in (200, 201, 202)
        data = resp.json()
        TestPassportLifecycleE2E._application_id = data["id"]

    # ---- Phase 2: Generate SOD ----

    async def test_02_generate_sod(self, gateway_client: GatewayClient):
        """Step 2 — Request server-side EF.SOD generation."""
        app_id = self._application_id
        if not app_id:
            pytest.skip("Application not created (previous step skipped)")

        resp = await gateway_client.client.post(
            f"/v1/passport/applications/{app_id}/generate-sod",
            json={},
        )
        if resp.status_code == 404:
            pytest.skip("SOD generation endpoint not deployed")

        assert resp.status_code in (200, 201)
        data = resp.json()
        assert "sod" in data or "sod_der_base64" in data
        TestPassportLifecycleE2E._sod_blob = data.get("sod") or data.get("sod_der_base64")

    # ---- Phase 3: Submit to personalization bureau ----

    async def test_03_submit_personalization(self, gateway_client: GatewayClient):
        """Step 3 — Submit signed data to personalization bureau."""
        app_id = self._application_id
        if not app_id:
            pytest.skip("Application not created")

        resp = await gateway_client.client.post(
            f"/v1/passport/applications/{app_id}/submit-personalization",
            json={},
        )
        if resp.status_code == 404:
            pytest.skip("Personalization endpoint not deployed")

        assert resp.status_code in (200, 201, 202)
        data = resp.json()
        TestPassportLifecycleE2E._bureau_job_id = data.get("bureau_job_id")

    # ---- Phase 4: Poll production status ----

    async def test_04_poll_production_status(self, gateway_client: GatewayClient):
        """Step 4 — Check production status."""
        app_id = self._application_id
        if not app_id:
            pytest.skip("Application not created")

        resp = await gateway_client.client.get(
            f"/v1/passport/applications/{app_id}/production-status",
        )
        if resp.status_code == 404:
            pytest.skip("Production status endpoint not deployed")

        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data

    # ---- Phase 5: Activate ----

    async def test_05_activate(self, gateway_client: GatewayClient):
        """Step 5 — Activate the passport credential after production."""
        app_id = self._application_id
        if not app_id:
            pytest.skip("Application not created")

        resp = await gateway_client.client.post(
            f"/v1/passport/applications/{app_id}/activate",
            json={},
        )
        if resp.status_code == 404:
            pytest.skip("Activation endpoint not deployed")

        assert resp.status_code in (200, 201)
        data = resp.json()
        assert data.get("status") in ("ACTIVE", "ACTIVATED", None)
