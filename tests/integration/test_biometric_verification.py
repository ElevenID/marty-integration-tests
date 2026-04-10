"""
Integration tests for the biometric verification service.

These tests exercise the full stack: FastAPI router → use case → adapter.
The mock adapter is used by default; set ``BIOMETRIC_MODELS_DIR`` to run
against the real ONNX-backed Rust FFI adapter.
"""

import os

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from mmf.services.biometric.config import (
    BiometricConfig,
    BiometricProviderType,
    create_testing_config,
)
from mmf.services.biometric.di_config import BiometricDIContainer
from mmf.services.biometric.infrastructure.adapters.web_router import create_app


# ── Fixtures ────────────────────────────────────────────────────────────

@pytest.fixture()
def biometric_config() -> BiometricConfig:
    models_dir = os.getenv("BIOMETRIC_MODELS_DIR", "")
    if models_dir:
        return BiometricConfig(
            provider_type=BiometricProviderType.LOCAL_ONNX,
            models_dir=models_dir,
        )
    return create_testing_config()


@pytest.fixture()
def container(biometric_config: BiometricConfig) -> BiometricDIContainer:
    c = BiometricDIContainer(biometric_config)
    c.initialize()
    yield c
    c.cleanup()


@pytest_asyncio.fixture()
async def client(container: BiometricDIContainer) -> AsyncClient:
    app = create_app(container)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ── Health ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_health(client: AsyncClient):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ── Face Verification ──────────────────────────────────────────────────

# Tiny 1×1 white JPEG encoded as base64 (valid enough for mock)
_TINY_IMAGE = (
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkS"
    "Ew8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJ"
    "CQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIy"
    "MjIyMjIyMjIyMjIyMjL/wAARCAABAAEDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEA"
    "AAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIh"
    "MUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6"
    "Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZ"
    "mqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx"
    "8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREA"
    "AgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAV"
    "YnLRChYkNOEl8RcYI4Q/RFhHRUMnRicoKSo1Njc4OTpDREVGR0hJSlNUVVZXWFla"
    "Y2RlZmdoaWpzdHV2d3h5eoKDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2"
    "t7i5usLDxMXGx8jJytLT1NXW19jZ2uLj5OXm5+jp6vLz9PX29/j5+v/aAAwDAQAC"
    "EQMRAD8A9+ooooA//9k="
)


@pytest.mark.asyncio
async def test_verify_faces_mock(client: AsyncClient):
    resp = await client.post("/v1/biometrics/verify", json={
        "reference_image": _TINY_IMAGE,
        "probe_image": _TINY_IMAGE,
        "threshold": 0.7,
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["verified"] is True
    assert body["similarity"] >= 0.7
    assert "provider" in body


@pytest.mark.asyncio
async def test_verify_faces_below_threshold(client: AsyncClient):
    resp = await client.post("/v1/biometrics/verify", json={
        "reference_image": _TINY_IMAGE,
        "probe_image": _TINY_IMAGE,
        "threshold": 0.99,
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["verified"] is False


@pytest.mark.asyncio
async def test_verify_missing_fields(client: AsyncClient):
    resp = await client.post("/v1/biometrics/verify", json={
        "reference_image": _TINY_IMAGE,
    })
    assert resp.status_code == 422  # validation error


# ── Quality Assessment ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_quality_assessment(client: AsyncClient):
    resp = await client.post("/v1/biometrics/quality", json={
        "image": _TINY_IMAGE,
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["face_detected"] is True
    assert 0.0 <= body["overall_score"] <= 1.0
    assert "sharpness" in body
