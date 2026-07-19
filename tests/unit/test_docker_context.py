"""Tests for the Compose-project Docker isolation boundary."""

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
