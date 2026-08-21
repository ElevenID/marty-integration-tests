"""Fail-closed Playwright launch policy for released-stack evidence lanes."""

from __future__ import annotations

import os
from collections.abc import Mapping

HOSTED_BROWSER_CHANNEL_ENV = "MARTY_PLAYWRIGHT_BROWSER_CHANNEL"
HOSTED_BROWSER_CHANNEL = "chrome"


def hosted_browser_launch_options(
    environment: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Select the reviewed runner-provided browser without downloading one."""
    source = os.environ if environment is None else environment
    channel = source.get(HOSTED_BROWSER_CHANNEL_ENV, "").strip()
    if not channel:
        return {}
    if channel != HOSTED_BROWSER_CHANNEL:
        raise ValueError(
            f"{HOSTED_BROWSER_CHANNEL_ENV} must be {HOSTED_BROWSER_CHANNEL!r}, got {channel!r}"
        )
    return {"channel": channel}
