from __future__ import annotations

import pytest

from tests.integration.gateway.helpers.playwright_browser import hosted_browser_launch_options


def test_local_browser_launch_keeps_playwright_managed_default() -> None:
    assert hosted_browser_launch_options({}) == {}


def test_released_stack_browser_uses_reviewed_hosted_chrome_channel() -> None:
    assert hosted_browser_launch_options({"MARTY_PLAYWRIGHT_BROWSER_CHANNEL": "chrome"}) == {
        "channel": "chrome"
    }


@pytest.mark.parametrize(
    "channel",
    ["chromium", "msedge", "chrome-beta", "unreviewed-browser"],
)
def test_released_stack_browser_rejects_unreviewed_channel(channel: str) -> None:
    with pytest.raises(ValueError, match="must be 'chrome'"):
        hosted_browser_launch_options({"MARTY_PLAYWRIGHT_BROWSER_CHANNEL": channel})
