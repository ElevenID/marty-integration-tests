"""Unit tests for the ElevenID-owned public tenant-boundary dispatcher."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "public_boundary_lane",
    SCRIPTS / "public_boundary_lane.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load public tenant-boundary lane")
lane = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lane)


def test_product_lane_selects_explicit_marty_only_compose_mode(
    tmp_path: Path,
) -> None:
    command = lane.compose_command(
        SimpleNamespace(
            run_id="product-boundary",
            marty_ui=tmp_path / "marty-ui",
        ),
        "up",
        marty_only=True,
    )

    assert "--marty-only" in command
    assert "--oidf" not in command
    assert "--eudi" not in command


def test_public_session_uses_public_login_adapter_without_logging_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        observed["command"] = command
        observed.update(kwargs)
        return subprocess.CompletedProcess(command, 0, "browser-session\n", "")

    monkeypatch.setattr(lane.subprocess, "run", fake_run)
    result = lane.public_session(
        {"OIDF_MARTY_GATEWAY_URL": "https://marty.test"},
        email="reviewer@example.test",
        password="never-log-this",
    )

    assert result == "browser-session"
    assert observed["command"] == [sys.executable, str(lane.PUBLIC_LOGIN)]
    child_environment = observed["env"]
    assert isinstance(child_environment, dict)
    assert child_environment["OIDF_MARTY_OPERATOR_EMAIL"] == "reviewer@example.test"
    assert child_environment["OIDF_MARTY_OPERATOR_PASSWORD"] == "never-log-this"
    assert "never-log-this" not in str(observed["command"])


def test_public_session_rejects_failed_or_malformed_login(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        lane.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [],
            2,
            "",
            "public login failed",
        ),
    )
    with pytest.raises(RuntimeError, match="public OIDC login failed"):
        lane.public_session({}, email="reviewer@example.test", password="secret")

    monkeypatch.setattr(
        lane.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [],
            0,
            "two tokens\n",
            "",
        ),
    )
    with pytest.raises(RuntimeError, match="malformed"):
        lane.public_session({}, email="reviewer@example.test", password="secret")
