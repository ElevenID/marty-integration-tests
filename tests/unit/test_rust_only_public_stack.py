"""The released artifact stack uses one signed Rust issuance image."""

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SERVICES = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "a" * 64


def test_default_stack_commands_include_required_rust_wiring() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "COMPOSE_FILES := --file docker-compose.yml --file docker-compose.rust-revocation.yml" in makefile
    assert "docker compose --env-file .env.stack $(COMPOSE_FILES) up -d --wait" in makefile
    assert "docker compose --env-file .env.stack $(COMPOSE_FILES) down" in makefile
    conformance = (ROOT / "scripts/conformance_compose.py").read_text(encoding="utf-8")
    assert '"--file", "docker-compose.rust-revocation.yml"' in conformance


def test_public_stack_uses_shared_rust_issuance_runtime_and_migrator() -> None:
    env = os.environ.copy()
    env.update({
        "MARTY_UI_IMAGE": "ghcr.io/elevenid/marty-ui-oss/ui@sha256:" + "b" * 64,
        "MARTY_SERVICES_IMAGE": SERVICES,
        "MARTY_ISSUANCE_IMAGE": SERVICES,
        "MARTY_MIGRATIONS_IMAGE": "ghcr.io/elevenid/marty-ui-oss/migrations@sha256:" + "c" * 64,
        "MARTY_OPENBAO_DIDCOMM_IMAGE": "ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:" + "f" * 64,
        "BAO_DEV_ROOT_TOKEN": "disposable-custom-openbao-token",
        "POSTGRES_IMAGE": "postgres@sha256:" + "d" * 64,
        "REDIS_IMAGE": "redis@sha256:" + "e" * 64,
    })
    rendered = subprocess.run(
        ["docker", "compose", "-f", "docker-compose.yml", "-f",
         "docker-compose.rust-revocation.yml", "config", "--format", "json"],
        cwd=ROOT, env=env, text=True, capture_output=True, check=True,
    )
    services = json.loads(rendered.stdout)["services"]
    migrations = services["migrations"]["environment"]
    assert migrations["BAO_ADDR"] == "https://openbao:8200"
    assert migrations["BAO_CACERT"] == "/run/openbao-ca/ca.crt"
    assert migrations["NOTIFICATION_OPENBAO_CA_CERT_FILE"] == migrations["BAO_CACERT"]
    assert migrations["BAO_TOKEN"] == "disposable-custom-openbao-token"
    assert migrations["NOTIFICATION_OPENBAO_TOKEN"] == migrations["BAO_TOKEN"]
    assert services["openbao"]["hostname"] == "openbao"
    assert "-dev-tls" in services["openbao"]["command"]
    signing = services["signing-keys"]
    signing_env = signing["environment"]
    assert "SIGNING_KEYS_INTEGRATION_SECRET_TLS_KEY_FILE" not in signing_env
    assert signing_env["SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_ADDR"] == migrations["BAO_ADDR"]
    assert signing_env["SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_CA_CERT_FILE"] == migrations["BAO_CACERT"]
    assert signing_env["SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_KEY_NAME"] == "workload-tls-signing-keys-server"
    assert signing_env["SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_KEY_VERSION"] == "1"
    assert signing["depends_on"]["signing-integration-tls-bootstrap"]["condition"] == (
        "service_completed_successfully"
    )
    bootstrap = services["signing-integration-tls-bootstrap"]
    assert bootstrap["environment"]["MARTY_TLS_BOOTSTRAP_PROFILE"] == "selfhost-disposable"
    assert bootstrap["environment"]["MARTY_SELFHOST_DISPOSABLE_OPENBAO"] == "1"
    assert bootstrap["environment"]["BAO_ROOT_TOKEN_FILE"] == "/bootstrap-input/root.token"
    assert "SIGNING_KEYS_INTEGRATION_SECRET_TLS_KEY_FILE" not in (
        ROOT / "docker-compose.rust-revocation.yml"
    ).read_text(encoding="utf-8")
    for name, service in services.items():
        environment = service.get("environment", {})
        mounts = service.get("volumes", [])
        if name not in ("openbao", "openbao-ca-publish"):
            assert not any(mount["source"].endswith("openbao-tls") for mount in mounts), name
        if "BAO_ADDR" in environment:
            assert environment["BAO_ADDR"] == "https://openbao:8200", name
            assert environment["BAO_CACERT"] == "/run/openbao-ca/ca.crt", name
            assert any(
                mount["source"].endswith("openbao-public-ca")
                and mount["target"] == "/run/openbao-ca"
                for mount in mounts
            ), name
    for name in ("issuance-service", "issuance-native", "issuance-migrations"):
        assert services[name]["image"] == SERVICES
    for name in ("issuance-service", "issuance-native"):
        environment = services[name]["environment"]
        assert environment["SERVICE_NAME"] == "issuance_native"
        assert environment["MARTY_SCHEMA_STARTUP_MODE"] == "validate"
        assert environment["DATABASE_URL"].startswith("postgresql://")
        assert services[name]["healthcheck"]["test"][-1].endswith("/health")
        assert services[name]["depends_on"]["issuance-migrations"]["condition"] == (
            "service_completed_successfully"
        )
    migrator = services["issuance-migrations"]
    assert migrator["entrypoint"] == ["/usr/local/bin/marty-issuance-service"]
    assert migrator["command"] == ["migrate"]
    assert migrator["environment"]["DATABASE_URL"].startswith("postgresql://")
