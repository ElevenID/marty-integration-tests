"""Tests for the Compose-project Docker isolation boundary."""

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("docker_context", ROOT / "scripts" / "docker_context.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load Docker context helper")
context = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(context)


def test_current_local_context_is_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(context.CONTEXT_ENV, raising=False)
    assert context.docker_command(["ps"]) == ["docker", "ps"]


def test_optional_remote_context_is_validated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(context.CONTEXT_ENV, "conformance-vm")
    monkeypatch.setattr(
        context.subprocess,
        "run",
        lambda *args, **_kwargs: subprocess.CompletedProcess(args[0], 0, "[]", ""),
    )
    assert context.docker_command(["ps"]) == ["docker", "--context", "conformance-vm", "ps"]


def inspected(endpoint: str) -> str:
    return json.dumps([{"Endpoints": {"docker": {"Host": endpoint}}}])


def test_named_local_context_is_recognized_by_its_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(
        context.subprocess,
        "run",
        lambda command, **_kwargs: (
            calls.append(command)
            or subprocess.CompletedProcess(command, 0, inspected("npipe:////./pipe/docker_engine"), "")
        ),
    )

    assert context.docker_endpoint_is_local({context.CONTEXT_ENV: "desktop-linux"}) is True
    assert calls == [["docker", "context", "inspect", "desktop-linux"]]


@pytest.mark.parametrize(
    ("environment", "expected"),
    [
        ({"DOCKER_HOST": "unix:///var/run/docker.sock"}, True),
        ({"DOCKER_HOST": "tcp://127.0.0.1:2375"}, False),
        ({"DOCKER_HOST": "ssh://runner@example.test"}, False),
        ({"DOCKER_HOST": "tcp://192.0.2.10:2376"}, False),
    ],
)
def test_docker_host_locality_is_not_inferred_from_context_name(
    environment: dict[str, str],
    expected: bool,
) -> None:
    assert context.docker_endpoint_is_local(environment) is expected


def test_standard_or_active_context_endpoint_controls_locality(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(
        context.subprocess,
        "run",
        lambda command, **_kwargs: (
            calls.append(command) or subprocess.CompletedProcess(command, 0, inspected("ssh://docker.example.test"), "")
        ),
    )

    assert context.docker_endpoint_is_local({"DOCKER_CONTEXT": "remote-builder"}) is False
    assert context.docker_endpoint_is_local({}) is False
    assert calls == [
        ["docker", "context", "inspect", "remote-builder"],
        ["docker", "context", "inspect"],
    ]


def test_network_endpoint_requires_explicit_shared_bind_override() -> None:
    environment = {
        "DOCKER_HOST": "tcp://127.0.0.1:2375",
        context.NETWORK_BIND_OVERRIDE_ENV: "1",
    }

    assert context.docker_endpoint_is_local(environment) is True


def test_marty_project_must_be_explicit_and_scoped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(context.PROJECT_ENV, raising=False)
    with pytest.raises(ValueError, match="is required"):
        context.project_name()
    monkeypatch.setenv(context.PROJECT_ENV, "production")
    with pytest.raises(ValueError, match="must start"):
        context.project_name()
    monkeypatch.setenv(context.PROJECT_ENV, "marty-conformance-run1")
    assert context.project_name() == "marty-conformance-run1"


def test_exec_target_must_belong_to_expected_project(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(context.PROJECT_ENV, "marty-conformance-run1")
    monkeypatch.setattr(
        context.subprocess,
        "run",
        lambda *args, **_kwargs: subprocess.CompletedProcess(args[0], 0, "marty-conformance-run1\n", ""),
    )
    context.require_project_container("marty-conformance-run1-issuance-1")


def test_exec_target_rejects_foreign_project(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(context.PROJECT_ENV, "marty-conformance-run1")
    monkeypatch.setattr(
        context.subprocess,
        "run",
        lambda *args, **_kwargs: subprocess.CompletedProcess(args[0], 0, "elevenid-beta\n", ""),
    )
    with pytest.raises(ValueError, match="belongs to Compose project"):
        context.require_project_container("marty-issuance")
