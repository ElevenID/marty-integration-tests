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


def test_browser_issuance_binding_requires_one_public_did_bound_template() -> None:
    binding = browser_smoke.issuance_binding(
        [
            {
                "id": "credential-1",
                "name": browser_smoke.ISSUANCE_TEMPLATE_NAME,
                "status": "active",
                "organization_id": "org-1",
                "issuer_did": "did:web:issuer.example:orgs:org-1",
            }
        ],
        {
            "items": [
                {
                    "id": "application-template-1",
                    "credential_template_id": "credential-1",
                    "organization_id": "org-1",
                    "status": "ACTIVE",
                }
            ]
        },
    )

    assert binding == {
        "credential_template_id": "credential-1",
        "application_template_id": "application-template-1",
        "organization_id": "org-1",
        "issuer_did": "did:web:issuer.example:orgs:org-1",
    }
    browser_smoke.assert_application_request(
        {
            "organization_id": "org-1",
            "application_template_id": "application-template-1",
            "form_data": {},
        },
        binding,
    )


@pytest.mark.parametrize(
    ("credential_change", "application_change", "message"),
    [
        ({"issuer_did": ""}, {}, "public issuer_did"),
        ({"issuer_did": "did:web:issuer.example"}, {"organization_id": "org-2"}, "another organization"),
        ({"issuer_profile_id": "profile-1"}, {}, "issuer_profile_id"),
    ],
)
def test_browser_issuance_binding_fails_closed(
    credential_change: dict[str, str],
    application_change: dict[str, str],
    message: str,
) -> None:
    credential = {
        "id": "credential-1",
        "name": browser_smoke.ISSUANCE_TEMPLATE_NAME,
        "status": "active",
        "organization_id": "org-1",
        "issuer_did": "did:web:issuer.example:orgs:org-1",
        **credential_change,
    }
    application = {
        "id": "application-template-1",
        "credential_template_id": "credential-1",
        "organization_id": "org-1",
        "status": "ACTIVE",
        **application_change,
    }

    with pytest.raises(AssertionError, match=message):
        browser_smoke.issuance_binding([credential], [application])


@pytest.mark.parametrize(
    "body",
    [
        {
            "organization_id": "org-2",
            "application_template_id": "application-template-1",
        },
        {
            "organization_id": "org-1",
            "application_template_id": "application-template-2",
        },
        {
            "organization_id": "org-1",
            "application_template_id": "application-template-1",
            "kms_provider": "test",
        },
    ],
)
def test_browser_issuance_application_request_cannot_change_binding(
    body: dict[str, str],
) -> None:
    binding = {
        "credential_template_id": "credential-1",
        "application_template_id": "application-template-1",
        "organization_id": "org-1",
        "issuer_did": "did:web:issuer.example:orgs:org-1",
    }

    with pytest.raises(AssertionError):
        browser_smoke.assert_application_request(body, binding)
