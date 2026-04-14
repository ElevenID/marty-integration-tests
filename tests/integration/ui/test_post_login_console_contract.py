from __future__ import annotations

from pathlib import Path
import sys
from urllib.parse import urlparse

import pytest
from playwright.sync_api import Page, expect

CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from support import get_scenario, install_console_backend_mock, load_contract, managed_ui_page

CONTRACT_PATH = Path(__file__).with_name("contracts") / "post_login_console.yaml"
CONTRACT = load_contract(CONTRACT_PATH)
SCENARIO_NAMES = [scenario["name"] for scenario in CONTRACT["scenarios"]]


def _wait_for_path(page: Page, expected_path: str) -> None:
    page.wait_for_function(
        "expectedPath => window.location.pathname === expectedPath",
        arg=expected_path,
        timeout=15_000,
    )
    assert urlparse(page.url).path == expected_path


def _assert_expectation(page: Page, expectation: dict) -> None:
    expected_path = expectation.get("path")
    if expected_path:
        _wait_for_path(page, expected_path)

    for test_id in expectation.get("visible_testids", []):
        expect(page.get_by_test_id(test_id)).to_be_visible()

    for text in expectation.get("visible_texts", []):
        expect(page.get_by_text(text)).to_be_visible()

    for test_id in expectation.get("hidden_testids", []):
        expect(page.locator(f'[data-testid="{test_id}"]')).to_have_count(0)

    for test_id in expectation.get("disabled_testids", []):
        expect(page.get_by_test_id(test_id)).to_be_disabled()


def _run_steps(page: Page, steps: list[dict]) -> None:
    for step in steps:
        if step.get("action") == "click":
            if step.get("testid"):
                locator = page.get_by_test_id(step["testid"])
            else:
                locator = page.get_by_role(step["role"], name=step["name"])
            expect(locator).to_be_visible()
            locator.click()
            continue

        if "assert" in step:
            _assert_expectation(page, step["assert"])
            continue

        raise AssertionError(f"Unsupported UI contract step: {step}")


@pytest.mark.ui_contract
@pytest.mark.parametrize("scenario_name", SCENARIO_NAMES, ids=SCENARIO_NAMES)
def test_post_login_console_contracts(
    scenario_name: str,
    ui_artifact_dir: Path,
    marty_ui_server: dict,
    ui_base_url: str,
) -> None:
    scenario = get_scenario(CONTRACT, scenario_name)

    with managed_ui_page(ui_artifact_dir) as ui_page:
        install_console_backend_mock(ui_page, scenario["persona"])

        if "start_path" in scenario:
            ui_page.goto(f"{ui_base_url}{scenario['start_path']}", wait_until="domcontentloaded")
            if "expect" in scenario:
                _assert_expectation(ui_page, scenario["expect"])
            _run_steps(ui_page, scenario.get("steps", []))

        for check in scenario.get("checks", []):
            ui_page.goto(f"{ui_base_url}{check['path']}", wait_until="domcontentloaded")
            _assert_expectation(ui_page, check)
