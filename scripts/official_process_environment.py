"""Keep GitHub authority out of imported official-suite subprocesses."""
from __future__ import annotations

import os
from collections.abc import Mapping

GITHUB_AUTH_KEYS = frozenset({
    "GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN",
})


def subprocess_environment(
    environment: Mapping[str, str], *, native_attestation: bool = False,
) -> dict[str, str]:
    result = {key: value for key, value in environment.items() if key not in GITHUB_AUTH_KEYS}
    if native_attestation:
        # Only the trusted lifecycle adapter and released native launcher opt in.
        # They use this same boundary again before invoking any upstream code.
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if token:
            result["GH_TOKEN"] = token
    return result
