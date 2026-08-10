"""Release contracts for the artifact-only public stack."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_flow_webhook_secret_is_scoped_to_auth_and_flow() -> None:
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    auth = compose.split("  auth-service:\n", 1)[1].split(
        "\n  organization-service:\n", 1
    )[0]
    flow = compose.split("  flow-service:\n", 1)[1].split(
        "\n  revocation-profile-service:\n", 1
    )[0]
    default_secret = "oss-ci-flow-webhook-secret-32-bytes"
    setting = f"FLOW_WEBHOOK_SECRET: ${{FLOW_WEBHOOK_SECRET:-{default_secret}}}"

    secret_mounts = [
        line
        for line in compose.splitlines()
        if line.strip().startswith("FLOW_WEBHOOK_SECRET:")
    ]
    assert len(default_secret.encode("utf-8")) >= 32
    assert len(secret_mounts) == 2
    assert setting in auth
    assert setting in flow


def test_application_event_key_is_scoped_to_applicant_and_flow() -> None:
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    applicant = compose.split("  applicant-service:\n", 1)[1].split(
        "\n  compliance-profile-service:\n", 1
    )[0]
    flow = compose.split("  flow-service:\n", 1)[1].split(
        "\n  revocation-profile-service:\n", 1
    )[0]

    key_mounts = [
        line
        for line in compose.splitlines()
        if line.strip().startswith("FLOW_APPLICATION_EVENT_HMAC_KEY:")
    ]
    assert len(key_mounts) == 2
    assert "FLOW_APPLICATION_EVENT_HMAC_KEY:" in applicant
    assert "FLOW_APPLICATION_EVENT_HMAC_KEY:" in flow
    assert "FLOW_GRPC_TARGET: flow-service:9011" in applicant
    assert "FLOW_GRPC_PORT: \"9011\"" in flow
    assert "CT_GRPC_TARGET: credential-template-service:9003" in flow
    assert "CT_GRPC_TARGET: credential-template:9003" not in flow


def test_migrations_never_seed_an_internal_public_origin() -> None:
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    migrations = compose.split("  migrations:\n", 1)[1].split("\n  auth-service:\n", 1)[0]

    assert "PUBLIC_API_URL: ${ISSUER_BASE_URL:-https://oss-ci.elevenid.dev}" in migrations
    assert "PUBLIC_API_URL: ${ISSUER_BASE_URL:-http://gateway:8000}" not in migrations


def test_oid4vci_services_share_one_external_https_issuer_identifier() -> None:
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    issuance = compose.split("  issuance-service:\n", 1)[1].split(
        "\n  compliance-profile-service:\n", 1
    )[0]
    gateway = compose.split("  gateway:\n", 1)[1].split("\n  ui:\n", 1)[0]
    public_issuer = "ISSUER_BASE_URL: ${ISSUER_BASE_URL:-https://oss-ci.elevenid.dev}"

    assert public_issuer in issuance
    assert public_issuer in gateway
    assert "ISSUER_BASE_URL: ${ISSUER_BASE_URL:-http://gateway:8000}" not in compose
