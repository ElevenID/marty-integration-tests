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
        "POSTGRES_IMAGE": "postgres@sha256:" + "d" * 64,
        "REDIS_IMAGE": "redis@sha256:" + "e" * 64,
    })
    rendered = subprocess.run(
        ["docker", "compose", "-f", "docker-compose.yml", "-f",
         "docker-compose.rust-revocation.yml", "config", "--format", "json"],
        cwd=ROOT, env=env, text=True, capture_output=True, check=True,
    )
    services = json.loads(rendered.stdout)["services"]
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
