"""Release contracts for the artifact-only public stack."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def service_section(compose: str, service: str, next_service: str) -> str:
    return compose.split(f"  {service}:\n", 1)[1].split(
        f"\n  {next_service}:\n", 1
    )[0]


def test_native_services_receive_explicit_artifact_test_configuration() -> None:
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    shared = compose.split("x-service: &service\n", 1)[1].split("\nservices:\n", 1)[0]
    auth = service_section(compose, "auth-service", "organization-service")
    trust = service_section(
        compose, "trust-profile-service", "issuance-service"
    )
    flow = service_section(compose, "flow-service", "revocation-profile-service")
    public_origin = "${ISSUER_BASE_URL:-https://oss-ci.elevenid.dev}"

    assert "ENVIRONMENT: test" in shared
    assert 'ALLOW_PLAINTEXT_GRPC: "true"' in auth
    assert "CREDENTIAL_LOGIN_POLICY_ID: oss-ci-credential-login" in auth
    assert "CREDENTIAL_LOGIN_ORGANIZATION_ID:" in auth
    assert "CREDENTIAL_LOGIN_ISSUER_DID: did:web:oss-ci.elevenid.dev" in auth
    assert f"MARTY_ISSUER_BASE_URL: {public_origin}" in trust
    assert f"PUBLIC_BASE_URL: {public_origin}" in flow
    assert 'GRPC_INSECURE_ALLOWED: "true"' in flow


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


def test_rust_cutover_overlay_runs_authenticated_signing_service() -> None:
    overlay = (ROOT / "docker-compose.rust-revocation.yml").read_text(
        encoding="utf-8"
    )
    signing = overlay.split("  signing-keys:\n", 1)[1].split(
        "\n  # Rust owns this schema", 1
    )[0]
    gateway = overlay.split("  gateway:\n", 1)[1]
    signing_key = (
        "SIGNING_KEYS_INTERNAL_API_KEY: "
        "${SIGNING_KEYS_INTERNAL_API_KEY:-oss-ci-rust-signing-internal-key-32-bytes}"
    )

    assert "image: ${MARTY_SERVICES_IMAGE:?run scripts/render_stack_env.py first}" in signing
    assert "SERVICE_NAME: signing_keys" in signing
    assert 'SIGNING_KEYS_SERVICE_PORT: "8017"' in signing
    assert "SIGNING_KEYS_REDIS_URL: redis://redis:6379/2" in signing
    assert "<<: *rust-signing-service-auth" in signing
    assert 'http://localhost:8017/health' in signing
    assert "SIGNING_KEYS_SERVICE_URL: http://signing-keys:8017" in gateway
    assert signing_key in gateway
    assert "signing-keys:\n        condition: service_healthy" in gateway


def test_rust_signing_secret_reaches_every_internal_signing_caller() -> None:
    overlay = (ROOT / "docker-compose.rust-revocation.yml").read_text(
        encoding="utf-8"
    )
    signing_key = (
        "SIGNING_KEYS_INTERNAL_API_KEY: "
        "${SIGNING_KEYS_INTERNAL_API_KEY:-oss-ci-rust-signing-internal-key-32-bytes}"
    )

    for service, next_service in (
        ("credential-template-service", "trust-profile-service"),
        ("trust-profile-service", "issuance-service"),
        ("issuance-service", "applicant-service"),
        ("flow-service", "revocation-profile-service"),
    ):
        section = overlay.split(f"  {service}:\n", 1)[1].split(
            f"\n  {next_service}:\n", 1
        )[0]
        assert signing_key in section
