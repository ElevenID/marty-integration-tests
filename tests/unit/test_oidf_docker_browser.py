"""Unit tests for the project-scoped OIDF browser transport."""

from __future__ import annotations

import subprocess

import pytest

from scripts import oidf_docker_browser as browser


def test_docker_curl_defaults_to_the_active_compose_project(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    monkeypatch.setenv(browser.OIDF_PROJECT_ENV, "oidf-runner-reviewed")
    monkeypatch.delenv("OIDF_CONFORMANCE_CONTAINER", raising=False)
    monkeypatch.setattr(
        browser,
        "require_project_container",
        lambda container, project_env: observed.update(
            {"container": container, "project_env": project_env}
        ),
    )
    monkeypatch.setattr(
        browser,
        "docker_command",
        lambda arguments: arguments,
    )

    def fake_run(
        command: list[str],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        observed["command"] = command
        return subprocess.CompletedProcess(command, 0, "ok", "")

    monkeypatch.setattr(browser.subprocess, "run", fake_run)

    assert browser.docker_curl(["https://example.test"]) == "ok"
    assert observed["container"] == "oidf-runner-reviewed-server-1"
    assert observed["project_env"] == browser.OIDF_PROJECT_ENV
    assert observed["command"][:3] == [
        "exec",
        "oidf-runner-reviewed-server-1",
        "curl",
    ]
