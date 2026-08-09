from __future__ import annotations

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
