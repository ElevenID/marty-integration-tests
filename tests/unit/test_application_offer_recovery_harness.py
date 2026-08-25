from __future__ import annotations

import json
import subprocess

import pytest

from tests.oss_stack import test_application_offer_recovery as recovery
from tests.oss_stack.compose import stack_compose_command


def test_stack_compose_command_pins_rust_overlay_and_optional_project(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MARTY_OSS_STACK_PROJECT", "candidate-stack")

    assert stack_compose_command() == (
        "docker",
        "compose",
        "--env-file",
        ".env.stack",
        "--file",
        "docker-compose.yml",
        "--file",
        "docker-compose.rust-revocation.yml",
        "--project-name",
        "candidate-stack",
    )


def test_stack_compose_command_uses_default_project_when_unspecified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MARTY_OSS_STACK_PROJECT", raising=False)

    assert "--project-name" not in stack_compose_command()


def test_psql_streams_sql_for_client_variable_expansion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    def fake_compose(
        *arguments: str,
        timeout: int = 45,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        observed.update(
            arguments=arguments,
            timeout=timeout,
            input_text=input_text,
        )
        return subprocess.CompletedProcess(arguments, 0, stdout="expanded\n", stderr="")

    monkeypatch.setattr(recovery, "_compose", fake_compose)

    sql = "SELECT :'bound_value';"
    result = recovery._psql(sql, variables={"bound_value": "safe-value"})

    arguments = observed["arguments"]
    assert isinstance(arguments, tuple)
    assert arguments[-2:] == ("-f", "-")
    assert "-c" not in arguments
    assert arguments[-4:-2] == ("--set", "bound_value=safe-value")
    assert observed["input_text"] == sql
    assert result == "expanded"


def test_durable_state_accepts_every_flow_in_a_multi_flow_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flows = [
        {
            "flow_definition_id": f"flow-{index}",
            "instance_id": f"instance-{index}",
            "artifact_id": f"artifact-{index}",
            "transaction_id": f"transaction-{index}",
            "offer_sha256": str(index) * 64,
            "pre_auth_sha256": str(index + 2) * 64,
        }
        for index in (1, 2)
    ]
    state = {"receipt_count": 1, "planned_flows": 2, "flows": flows}
    monkeypatch.setattr(recovery, "_psql", lambda *_args, **_kwargs: json.dumps(state))

    assert recovery._durable_state("application-1") == state


def test_durable_state_rejects_an_incomplete_multi_flow_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = {
        "receipt_count": 1,
        "planned_flows": 2,
        "flows": [
            {
                "flow_definition_id": "flow-1",
                "instance_id": "instance-1",
                "artifact_id": "artifact-1",
                "transaction_id": "transaction-1",
                "offer_sha256": "a" * 64,
                "pre_auth_sha256": "b" * 64,
            }
        ],
    }
    monkeypatch.setattr(recovery, "_psql", lambda *_args, **_kwargs: json.dumps(state))

    assert recovery._durable_state("application-1") is None


def test_retry_event_preserves_the_language_neutral_error_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        recovery,
        "post_json",
        lambda *_args, **_kwargs: {
            "status": 409,
            "body": {
                "error": "APPLICATION_OFFER_CONFLICT",
                "detail": "conflicting application offer",
            },
        },
    )

    result = recovery._retry_event({}, {})

    assert result == {
        "status": 409,
        "body": {
            "error": "APPLICATION_OFFER_CONFLICT",
            "detail": "conflicting application offer",
        },
    }


def test_disposable_flow_uses_canonical_definition_status_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    statements: list[str] = []

    def capture(sql: str, **_kwargs: object) -> str:
        statements.append(sql)
        return ""

    monkeypatch.setattr(recovery, "_psql", capture)
    recovery._install_disposable_application_flow("flow-id")
    recovery._deactivate_disposable_application_flows()

    assert "'ACTIVE', 'custom'" in statements[0]
    assert "SET status = 'ARCHIVED'" in statements[1]
    assert "'INACTIVE'" not in "".join(statements)
