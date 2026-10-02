"""The public release stack must start the same Rust issuance owner as beta."""

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEST_IMAGE = "example.invalid/disposable@sha256:" + "a" * 64


def test_public_stack_selects_healthy_native_issuance() -> None:
    env = os.environ.copy()
    env.update(
        dict.fromkeys(
            (
                "MARTY_SERVICES_IMAGE",
                "MARTY_ISSUANCE_IMAGE",
                "MARTY_MIGRATIONS_IMAGE",
                "MARTY_UI_IMAGE",
                "POSTGRES_IMAGE",
                "REDIS_IMAGE",
            ),
            TEST_IMAGE,
        )
    )
    result = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            "docker-compose.yml",
            "-f",
            "docker-compose.rust-revocation.yml",
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )
    services = json.loads(result.stdout)["services"]
    native = services["issuance-native"]
    assert native["image"] == TEST_IMAGE
    assert native["environment"]["SERVICE_NAME"] == "issuance_native"
    assert native["environment"]["ISSUANCE_GRPC_ENABLED"] == "true"
    assert native["environment"]["INTEGRATION_SECRET_MASTER_KEY"]
    assert native["depends_on"]["issuance-migrations"]["condition"] == "service_completed_successfully"
    assert native["depends_on"]["revocation-profile-service"]["condition"] == "service_healthy"
    assert native["healthcheck"]["test"][-1] == "http://localhost:8005/health"

    retained = services["issuance-service"]
    assert retained["environment"]["DIDCOMM_DELIVERY_OWNER"] == "native"
    assert retained["environment"]["ISSUANCE_NATIVE_SERVICE_URL"] == "http://issuance-native:8005"
    for name in ("auth-service", "issuance-service", "applicant-service", "flow-service", "gateway"):
        assert services[name]["depends_on"]["issuance-native"]["condition"] == "service_healthy"
    assert services["auth-service"]["environment"]["ISSUANCE_NATIVE_SERVICE_URL"] == "http://issuance-native:8005"
    assert services["flow-service"]["environment"]["ISSUANCE_GRPC_TARGET"] == "issuance-native:9005"
    assert services["gateway"]["environment"]["ISSUANCE_NATIVE_SERVICE_URL"] == "http://issuance-native:8005"
    assert "issuance-native" in services["gateway"]["environment"]["GATEWAY_REQUIRED_READY_SERVICES"].split(",")
