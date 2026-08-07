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


def test_browser_resolver_maps_only_the_disposable_public_hostname() -> None:
    assert browser_smoke.browser_resolver_args(
        "https://marty-oidf.test:18443",
        "127.0.0.1",
    ) == ["--host-resolver-rules=MAP marty-oidf.test 127.0.0.1"]
    assert browser_smoke.browser_resolver_args("https://marty-oidf.test:18443", "") == []


def test_browser_resolver_rejects_argument_injection() -> None:
    with pytest.raises(ValueError, match="does not appear to be an IPv4 or IPv6 address"):
        browser_smoke.browser_resolver_args(
            "https://marty-oidf.test:18443",
            "127.0.0.1,MAP outside.test 127.0.0.1",
        )


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
                "name": "Official Browser Member Credential run-1",
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
        expected_credential_template_id="credential-1",
        expected_application_template_id="application-template-1",
    )

    assert binding == {
        "credential_template_id": "credential-1",
        "application_template_id": "application-template-1",
        "credential_template_name": "Official Browser Member Credential run-1",
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


def test_browser_policy_binding_requires_exact_active_organization_policy() -> None:
    assert browser_smoke.presentation_policy_binding(
        [
            {
                "id": "policy-1",
                "organization_id": "org-1",
                "name": "Official OID4VP policy",
                "status": "ACTIVE",
            },
            {
                "id": "policy-other",
                "organization_id": "org-2",
                "name": "Other policy",
                "status": "ACTIVE",
            },
        ],
        expected_policy_id="policy-1",
        expected_organization_id="org-1",
    ) == {"id": "policy-1", "name": "Official OID4VP policy"}


def test_browser_policy_binding_rejects_cross_tenant_policy() -> None:
    with pytest.raises(AssertionError, match="exactly one expected active policy"):
        browser_smoke.presentation_policy_binding(
            [
                {
                    "id": "policy-1",
                    "organization_id": "org-2",
                    "name": "Foreign policy",
                    "status": "ACTIVE",
                }
            ],
            expected_policy_id="policy-1",
            expected_organization_id="org-1",
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
        "name": "Official Browser Member Credential run-1",
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
        browser_smoke.issuance_binding(
            [credential],
            [application],
            expected_credential_template_id="credential-1",
            expected_application_template_id="application-template-1",
        )


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
        "credential_template_name": "Official Browser Member Credential run-1",
        "organization_id": "org-1",
        "issuer_did": "did:web:issuer.example:orgs:org-1",
    }

    with pytest.raises(AssertionError):
        browser_smoke.assert_application_request(body, binding)


def test_browser_verification_request_requires_exact_public_identity() -> None:
    assert browser_smoke.assert_verification_request(
        {
            "organization_id": "org-1",
            "issuer_did": "did:web:marty-oidf.test:orgs:org-1",
        },
        expected_organization_id="org-1",
        expected_issuer_did="did:web:marty-oidf.test:orgs:org-1",
    ) == {
        "organization_id": "org-1",
        "issuer_did": "did:web:marty-oidf.test:orgs:org-1",
    }


@pytest.mark.parametrize(
    "body",
    [
        {"organization_id": "org-2", "issuer_did": "did:web:marty-oidf.test:orgs:org-1"},
        {"organization_id": "org-1", "issuer_did": "did:web:marty-oidf.test:orgs:org-2"},
        {
            "organization_id": "org-1",
            "issuer_did": "did:web:marty-oidf.test:orgs:org-1",
            "issuer_profile_id": "private-selector",
        },
    ],
)
def test_browser_verification_request_rejects_substitution_and_private_selectors(
    body: dict[str, str],
) -> None:
    with pytest.raises(AssertionError):
        browser_smoke.assert_verification_request(
            body,
            expected_organization_id="org-1",
            expected_issuer_did="did:web:marty-oidf.test:orgs:org-1",
        )


class _Button:
    def __init__(self, page: _Page, enable_after: int) -> None:
        self.page = page
        self.enable_after = enable_after

    def is_enabled(self) -> bool:
        return self.page.waits >= self.enable_after


class _Alerts:
    def __init__(self, page: _Page) -> None:
        self.page = page

    def all_inner_texts(self) -> list[str]:
        return self.page.alerts


class _Page:
    def __init__(self, *, alerts: list[str] | None = None) -> None:
        self.alerts = alerts or []
        self.waits = 0

    def locator(self, selector: str) -> _Alerts:
        assert selector == "[role=alert]"
        return _Alerts(self)

    def wait_for_timeout(self, timeout_ms: int) -> None:
        assert timeout_ms == 250
        self.waits += 1


def test_browser_verification_waits_for_async_did_identity_lookup() -> None:
    page = _Page()

    browser_smoke.wait_for_verification_identity(page, _Button(page, enable_after=2))

    assert page.waits == 2


def test_browser_verification_reports_real_did_identity_error() -> None:
    page = _Page(alerts=["No active OID4VP issuer DID"])

    with pytest.raises(AssertionError, match="No active OID4VP issuer DID"):
        browser_smoke.wait_for_verification_identity(page, _Button(page, enable_after=1))
