from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from support import slugify

DEFAULT_UI_HOST = "127.0.0.1"
DEFAULT_UI_PORT = int(os.getenv("MARTY_UI_PORT", "4173"))


def _integration_repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _workspace_root() -> Path:
    return Path(__file__).resolve().parents[4]


def _reports_root() -> Path:
    return _integration_repo_root() / "reports" / "ui-contracts"


def _default_ui_dir() -> Path:
    configured = os.getenv("MARTY_UI_DIR")
    if configured:
        return Path(configured)
    return _workspace_root() / "marty-ui" / "ui"


def _default_ui_url() -> str:
    return os.getenv("MARTY_UI_URL", f"http://{DEFAULT_UI_HOST}:{DEFAULT_UI_PORT}")


def _npm_executable() -> str:
    return "npm.cmd" if os.name == "nt" else "npm"


def _tail_text(path: Path, max_lines: int = 40) -> str:
    if not path.exists():
        return ""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(lines[-max_lines:])


def _wait_for_ui(url: str, process: subprocess.Popen[str], log_path: Path, timeout_seconds: int = 90) -> None:
    deadline = time.monotonic() + timeout_seconds
    with httpx.Client(follow_redirects=True, timeout=5.0) as client:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(
                    f"Marty UI dev server exited before it became ready.\n{_tail_text(log_path)}"
                )

            try:
                response = client.get(url)
                if response.status_code < 500:
                    return
            except httpx.HTTPError:
                pass

            time.sleep(1)

    raise RuntimeError(f"Timed out waiting for Marty UI at {url}.\n{_tail_text(log_path)}")


@pytest.fixture(scope="session")
def ui_base_url() -> str:
    return _default_ui_url()


@pytest.fixture(scope="session")
def marty_ui_server(ui_base_url: str) -> dict[str, Any]:
    reports_root = _reports_root()
    reports_root.mkdir(parents=True, exist_ok=True)

    reused_server: dict[str, Any] | None = None

    try:
        with httpx.Client(follow_redirects=True, timeout=5.0) as client:
            response = client.get(ui_base_url)
            if response.status_code < 500:
                reused_server = {
                    "base_url": ui_base_url,
                    "started": False,
                }
    except httpx.HTTPError:
        pass

    if reused_server is not None:
        yield reused_server
        return

    ui_dir = _default_ui_dir()
    if not ui_dir.exists():
        pytest.skip(
            f"Marty UI checkout not found at {ui_dir}. Set MARTY_UI_DIR or MARTY_UI_URL to run UI contract tests."
        )

    if not (ui_dir / "node_modules").exists():
        pytest.skip(
            f"Marty UI dependencies are missing at {ui_dir}. Run npm install in the UI checkout first."
        )

    log_path = reports_root / "ui-dev-server.log"
    command = [
        _npm_executable(),
        "run",
        "dev",
        "--",
        "--host",
        DEFAULT_UI_HOST,
        "--port",
        str(DEFAULT_UI_PORT),
        "--strictPort",
    ]

    environment = os.environ.copy()
    environment.setdefault("CI", "1")
    environment.setdefault("BROWSER", "none")
    environment.setdefault("VITE_PORT", str(DEFAULT_UI_PORT))
    environment.setdefault("PORT", str(DEFAULT_UI_PORT))

    with log_path.open("w", encoding="utf-8") as log_file:
        process = subprocess.Popen(
            command,
            cwd=ui_dir,
            env=environment,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            _wait_for_ui(ui_base_url, process, log_path)
            yield {
                "base_url": ui_base_url,
                "started": True,
                "log_path": log_path,
                "ui_dir": ui_dir,
            }
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)


@pytest.fixture()
def ui_artifact_dir(request: pytest.FixtureRequest) -> Path:
    artifact_dir = _reports_root() / slugify(request.node.name)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    return artifact_dir


