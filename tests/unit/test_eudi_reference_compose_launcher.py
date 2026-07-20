"""Tests for the separate EUDI reference Compose launcher."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "eudi_reference_compose", ROOT / "scripts" / "eudi_reference_compose.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load EUDI reference Compose launcher")
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)


def test_launcher_requires_an_exact_marty_project() -> None:
    with pytest.raises(SystemExit, match="MARTY_CONFORMANCE_PROJECT"):
        launcher.main(["--", "ps"])


def test_launcher_rejects_an_unscoped_eudi_project() -> None:
    with pytest.raises(SystemExit, match="eudi-reference"):
        launcher.main(["--marty-project", "marty-conformance-run1", "--project", "default", "--", "ps"])


def test_launcher_uses_only_the_existing_marty_tls_bridge(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[list[str], dict]] = []

    def fake_run(command: list[str], **kwargs):  # type: ignore[no-untyped-def]
        calls.append((command, kwargs))
        return type("Result", (), {"returncode": 0})()

    monkeypatch.setattr(launcher.subprocess, "run", fake_run)
    assert launcher.main([
        "--marty-project", "marty-conformance-run1",
        "--project", "eudi-reference-run1",
        "--", "up", "--detach",
    ]) == 0

    assert calls[0][0] == ["docker", "network", "inspect", "marty-conformance-run1_oidf-runner"]
    assert calls[1][0][:6] == [
        "docker", "compose", "--project-name", "eudi-reference-run1", "--file", str(launcher.COMPOSE),
    ]
    assert calls[1][1]["env"]["OIDF_MARTY_BRIDGE_NETWORK"] == "marty-conformance-run1_oidf-runner"
