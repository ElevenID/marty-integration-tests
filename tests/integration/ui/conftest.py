from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest

CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from support import slugify


def _integration_repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _reports_root() -> Path:
    return _integration_repo_root() / "reports" / "ui-contracts"


def _default_ui_url() -> str:
    return os.getenv("MARTY_UI_URL", "http://127.0.0.1:23000")


@pytest.fixture(scope="session")
def ui_base_url() -> str:
    return _default_ui_url()


@pytest.fixture(scope="session")
def marty_ui_server(ui_base_url: str) -> dict[str, Any]:
    _reports_root().mkdir(parents=True, exist_ok=True)

    try:
        with httpx.Client(follow_redirects=True, timeout=5.0) as client:
            response = client.get(ui_base_url)
            if response.status_code < 500:
                yield {"base_url": ui_base_url, "started": False}
                return
    except httpx.HTTPError:
        pass

    pytest.fail(
        f"Marty UI is not reachable at {ui_base_url}. Start the manifest-pinned "
        "stack with `make start` or set MARTY_UI_URL to a running release artifact."
    )


@pytest.fixture()
def ui_artifact_dir(request: pytest.FixtureRequest) -> Path:
    artifact_dir = _reports_root() / slugify(request.node.name)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    return artifact_dir
