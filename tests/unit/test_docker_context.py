"""Tests for the disposable-Docker isolation boundary."""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("docker_context", ROOT / "scripts" / "docker_context.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load Docker context helper")
context = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(context)


def test_requires_explicit_context(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(context.CONTEXT_ENV, raising=False)
    with pytest.raises(ValueError, match="is required"):
        context.isolated_context_name()


@pytest.mark.parametrize("name", ["default", "desktop-linux"])
def test_rejects_local_context_names(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    monkeypatch.setenv(context.CONTEXT_ENV, name)
    with pytest.raises(ValueError, match="not isolated"):
        context.isolated_context_name()


def test_rejects_local_named_pipe_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(context.CONTEXT_ENV, "shared")
    monkeypatch.setattr(
        context.subprocess,
        "run",
        lambda *args, **_kwargs: subprocess.CompletedProcess(args[0], 0, '"npipe:////./pipe/docker_engine"', ""),
    )
    with pytest.raises(ValueError, match="local daemon"):
        context.isolated_context_name()


def test_builds_command_for_remote_context(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(context.CONTEXT_ENV, "conformance-vm")
    monkeypatch.setattr(
        context.subprocess,
        "run",
        lambda *args, **_kwargs: subprocess.CompletedProcess(args[0], 0, '"ssh://runner@example.test"', ""),
    )
    assert context.docker_command(["ps"]) == ["docker", "--context", "conformance-vm", "ps"]
