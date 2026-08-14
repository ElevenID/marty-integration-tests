from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OVERLAY = ROOT / "docker-compose.rust-revocation.yml"


def _service_block(compose: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\n(?P<body>.*?)(?=^  [a-z0-9][a-z0-9-]*:\n|\Z)",
        compose,
    )
    assert match is not None, f"missing Compose service {name}"
    return match.group("body")


def test_overlay_uses_only_the_attested_shared_service_artifact() -> None:
    compose = OVERLAY.read_text(encoding="utf-8")

    migrator = _service_block(compose, "revocation-profile-migrations")
    assert "image: ${MARTY_SERVICES_IMAGE:" in migrator
    assert "build:" not in compose
    assert 'RP_MIGRATE_ONLY: "true"' in migrator
    assert "SERVICE_NAME: revocation_profile" in migrator
    assert "postgres:" in migrator
    assert "condition: service_healthy" in migrator


def test_rust_migration_precedes_the_shared_migration_graph() -> None:
    compose = OVERLAY.read_text(encoding="utf-8")

    migrations = _service_block(compose, "migrations")
    assert "revocation-profile-migrations:" in migrations
    assert "condition: service_completed_successfully" in migrations


def test_rust_runtime_has_fail_closed_auth_and_complete_topology() -> None:
    compose = OVERLAY.read_text(encoding="utf-8")
    runtime = _service_block(compose, "revocation-profile-service")

    required_runtime_contract = (
        "*rust-revocation-service-auth",
        "ENVIRONMENT: test",
        'REVOCATION_PROFILE_SERVICE_PORT: "8013"',
        "ORG_GRPC_TARGET: organization-service:9002",
        "PUBLIC_API_URL:",
        "STATUS_LIST_BASE_URL:",
        'RP_GRPC_ENABLED: "true"',
        'RP_GRPC_PORT: "9013"',
        "revocation-profile-migrations:",
        "migrations:",
        "condition: service_completed_successfully",
        "http://localhost:8013/health",
    )
    for contract in required_runtime_contract:
        assert contract in runtime
    assert re.search(r"^      SERVICE_PORT:", runtime, re.MULTILINE) is None


def test_all_grpc_participants_share_the_disposable_auth_boundary() -> None:
    compose = OVERLAY.read_text(encoding="utf-8")
    participants = (
        "auth-service",
        "organization-service",
        "credential-template-service",
        "trust-profile-service",
        "issuance-service",
        "applicant-service",
        "compliance-profile-service",
        "presentation-policy-service",
        "deployment-profile-service",
        "flow-service",
        "revocation-profile-service",
        "gateway",
    )

    for participant in participants:
        assert "*rust-revocation-service-auth" in _service_block(compose, participant)

    assert 'ORG_GRPC_PORT: "9002"' in _service_block(compose, "organization-service")
    assert 'CT_GRPC_PORT: "9003"' in _service_block(compose, "credential-template-service")
    assert 'PP_GRPC_PORT: "9009"' in _service_block(compose, "presentation-policy-service")


def test_issuance_waits_for_authenticated_rust_revocation() -> None:
    compose = OVERLAY.read_text(encoding="utf-8")
    issuance = _service_block(compose, "issuance-service")

    assert "*rust-revocation-service-auth" in issuance
    assert "revocation-profile-service:" in issuance
    assert "condition: service_healthy" in issuance
