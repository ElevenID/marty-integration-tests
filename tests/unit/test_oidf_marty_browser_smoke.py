from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "oidf_marty_browser_smoke",
    ROOT / "scripts" / "oidf_marty_browser_smoke.py",
)
assert SPEC
assert SPEC.loader
browser_smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(browser_smoke)


def test_public_selector_guard_accepts_did_first_payload() -> None:
    browser_smoke.assert_no_private_selectors(
        {
            "organization_id": "org-1",
            "issuer_did": "did:web:issuer.example",
            "presentation_policy_id": "policy-1",
        }
    )


@pytest.mark.parametrize("selector", sorted(browser_smoke.FORBIDDEN_PUBLIC_SELECTORS))
def test_public_selector_guard_rejects_internal_coordinates(selector: str) -> None:
    with pytest.raises(AssertionError, match=selector):
        browser_smoke.assert_no_private_selectors({"outer": [{"nested": {selector: "internal-value"}}]})
