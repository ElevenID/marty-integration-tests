from __future__ import annotations

import json
import subprocess

import pytest

from tests.oss_stack import test_application_offer_recovery as recovery


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
