#!/usr/bin/env python3
"""Exercise released Marty issuance and verification through the real browser UI.

This is an ElevenID-owned product-path test, not an adapter or modification of
an imported compliance suite. Authentication uses Marty's public OIDC flow;
all application, issuance, DID discovery, and verification calls originate
from the exact released UI artifact through the public HTTPS gateway.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from playwright.sync_api import Locator, Page, Request, Response

sys.path.insert(0, str(Path(__file__).resolve().parent))
from oidf_marty_public_login import login, public_origin, required_env  # noqa: E402

FORBIDDEN_PUBLIC_SELECTORS = {
    "issuer_profile_id",
    "issuerProfileId",
    "signing_service_id",
    "signingServiceId",
    "signing_key_reference",
    "signingKeyReference",
    "key_reference",
    "keyReference",
    "kms_provider",
    "kmsProvider",
    "provider_selector",
    "providerSelector",
}
VERIFICATION_PURPOSE = "Released-stack browser DID-first smoke"


def wait_for_verification_identity(page: Page, button: Locator, *, timeout_ms: int = 30_000) -> None:
    """Wait for the released UI's asynchronous DID-first identity lookup."""

    deadline = time.monotonic() + (timeout_ms / 1000)
    while not button.is_enabled():
        alerts = " | ".join(page.locator("[role=alert]").all_inner_texts()).strip()
        if alerts:
            raise AssertionError(f"verification DID did not resolve: {alerts}")
        if time.monotonic() >= deadline:
            raise AssertionError("verification DID identity lookup did not finish before the timeout")
        page.wait_for_timeout(250)


def public_path(url: str) -> str:
    return urlsplit(url).path


def assert_no_private_selectors(value: object, *, location: str = "request") -> None:
    """Reject internal profile/custody selectors anywhere in a public payload."""
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key) in FORBIDDEN_PUBLIC_SELECTORS:
                raise AssertionError(f"{location} exposes forbidden selector {key}")
            assert_no_private_selectors(child, location=f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            assert_no_private_selectors(child, location=f"{location}[{index}]")


def request_json(request: Request) -> object:
    try:
        return request.post_data_json
    except Exception:  # noqa: BLE001 - Playwright raises for empty/non-JSON bodies
        return request.post_data or {}


def require_success(response: Response, *, operation: str) -> None:
    if not 200 <= response.status < 300:
        raise AssertionError(f"{operation} returned HTTP {response.status} at {public_path(response.url)}")


def collection_items(value: object, *, location: str) -> list[dict[str, object]]:
    """Return a public list response without accepting malformed collection shapes."""
    if isinstance(value, list):
        items = value
    elif isinstance(value, Mapping):
        candidate = value.get("items", value.get("templates"))
        if not isinstance(candidate, list):
            raise AssertionError(f"{location} has no items collection")
        items = candidate
    else:
        raise AssertionError(f"{location} is not a collection")
    if not all(isinstance(item, dict) for item in items):
        raise AssertionError(f"{location} contains a non-object item")
    return items


def issuance_binding(
    credential_templates: object,
    application_templates: object,
    *,
    expected_credential_template_id: str,
    expected_application_template_id: str,
) -> dict[str, str]:
    """Resolve the exact disposable public DID binding used by the browser."""
    assert_no_private_selectors(credential_templates, location="credential templates")
    assert_no_private_selectors(application_templates, location="application templates")
    credentials = collection_items(credential_templates, location="credential templates")
    matches = [
        item
        for item in credentials
        if str(item.get("id") or "").strip() == expected_credential_template_id
        and str(item.get("status") or "").strip().upper() == "ACTIVE"
    ]
    if len(matches) != 1:
        raise AssertionError(
            "browser catalog did not resolve exactly one active disposable "
            f"credential template {expected_credential_template_id}"
        )
    credential = matches[0]
    credential_template_id = str(credential.get("id") or "").strip()
    credential_template_name = str(credential.get("name") or "").strip()
    organization_id = str(credential.get("organization_id") or "").strip()
    issuer_did = str(credential.get("issuer_did") or "").strip()
    if not credential_template_id:
        raise AssertionError("browser issuance template has no public id")
    if not credential_template_name:
        raise AssertionError("browser issuance template has no public name")
    if not organization_id:
        raise AssertionError("browser issuance template has no organization_id")
    if not issuer_did.startswith("did:"):
        raise AssertionError("browser issuance template has no public issuer_did")

    applications = collection_items(application_templates, location="application templates")
    application_matches = [
        item
        for item in applications
        if str(item.get("id") or "").strip() == expected_application_template_id
        and str(item.get("credential_template_id") or "").strip() == credential_template_id
        and str(item.get("status") or "").strip().upper() == "ACTIVE"
    ]
    if len(application_matches) != 1:
        raise AssertionError(
            f"browser catalog resolved {len(application_matches)} active application templates "
            f"for credential template {credential_template_id}"
        )
    application_template = application_matches[0]
    application_template_id = str(application_template.get("id") or "").strip()
    application_organization_id = str(application_template.get("organization_id") or "").strip()
    if not application_template_id:
        raise AssertionError("browser issuance application template has no public id")
    if application_organization_id and application_organization_id != organization_id:
        raise AssertionError("browser issuance application template belongs to another organization")
    return {
        "credential_template_id": credential_template_id,
        "application_template_id": application_template_id,
        "credential_template_name": credential_template_name,
        "organization_id": organization_id,
        "issuer_did": issuer_did,
    }


def assert_application_request(body: object, binding: Mapping[str, str]) -> None:
    """Prove the UI submits the application bound to the public organization and DID."""
    assert_no_private_selectors(body, location="issuance application")
    if not isinstance(body, dict):
        raise AssertionError("browser issuance application request is not a JSON object")
    if str(body.get("organization_id") or "").strip() != binding["organization_id"]:
        raise AssertionError("browser issuance application request changed organization_id")
    if str(body.get("application_template_id") or "").strip() != binding["application_template_id"]:
        raise AssertionError("browser issuance application request changed application_template_id")


def open_org_console(page: Page, base_url: str) -> None:
    page.goto(
        f"{base_url}/console/org/operate/verify",
        wait_until="domcontentloaded",
        timeout=30_000,
    )
    page.wait_for_timeout(1_000)
    if public_path(page.url) != "/console/org/setup":
        return

    select = page.get_by_role("button", name="Open Org Console")
    select.wait_for(timeout=30_000)
    select.click()
    page.wait_for_url("**/console/org", timeout=15_000)
    page.goto(
        f"{base_url}/console/org/operate/verify",
        wait_until="domcontentloaded",
        timeout=30_000,
    )


def exercise_issuance(
    page: Page,
    base_url: str,
    *,
    credential_template_id: str,
    application_template_id: str,
) -> dict[str, object]:
    with (
        page.expect_response(
            lambda response: (
                response.request.method == "GET" and public_path(response.url) == "/v1/credential-templates"
            ),
            timeout=30_000,
        ) as credential_templates_info,
        page.expect_response(
            lambda response: (
                response.request.method == "GET" and public_path(response.url) == "/v1/application-templates"
            ),
            timeout=30_000,
        ) as application_templates_info,
    ):
        page.goto(
            f"{base_url}/console/applicant/catalog",
            wait_until="domcontentloaded",
            timeout=30_000,
        )
    credential_templates_response = credential_templates_info.value
    application_templates_response = application_templates_info.value
    require_success(
        credential_templates_response,
        operation="browser credential-template discovery",
    )
    require_success(
        application_templates_response,
        operation="browser application-template discovery",
    )
    binding = issuance_binding(
        credential_templates_response.json(),
        application_templates_response.json(),
        expected_credential_template_id=credential_template_id,
        expected_application_template_id=application_template_id,
    )

    card = page.locator(".MuiCard-root").filter(has_text=binding["credential_template_name"]).first
    card.wait_for(timeout=30_000)
    card.get_by_role("button", name="Apply").click()
    page.wait_for_url("**/console/applicant/apply/**", timeout=15_000)

    issue = page.get_by_role("button", name="Add to Wallet")
    issue.wait_for(timeout=30_000)
    with (
        page.expect_response(
            lambda response: response.request.method == "POST" and public_path(response.url) == "/v1/me/applications",
            timeout=30_000,
        ) as application_info,
        page.expect_response(
            lambda response: response.request.method == "POST" and public_path(response.url).endswith("/submit"),
            timeout=30_000,
        ) as submit_info,
        page.expect_response(
            lambda response: response.request.method == "POST" and public_path(response.url).endswith("/claim"),
            timeout=30_000,
        ) as claim_info,
    ):
        issue.click()
    application_response = application_info.value
    submit_response = submit_info.value
    claim_response = claim_info.value
    require_success(application_response, operation="browser issuance application")
    require_success(submit_response, operation="browser issuance submission")
    require_success(claim_response, operation="browser issuance claim")
    assert_application_request(request_json(application_response.request), binding)
    submit_body = request_json(submit_response.request)
    claim_body = request_json(claim_response.request)
    assert_no_private_selectors(submit_body, location="issuance submission")
    assert_no_private_selectors(claim_body, location="issuance claim")
    claim_payload = claim_response.json()
    assert_no_private_selectors(claim_payload, location="issuance claim response")
    if not isinstance(claim_payload, dict):
        raise AssertionError("browser issuance claim response is not a JSON object")
    offer_present = any(
        isinstance(claim_payload.get(field), str) and bool(str(claim_payload[field]).strip())
        for field in ("credential_offer_uri", "offer_url")
    ) or bool(claim_payload.get("credential_offer_uris"))
    if not offer_present:
        raise AssertionError("browser issuance claim response has no public credential offer")
    page.get_by_role("dialog").get_by_text("Receive Credential").wait_for(timeout=15_000)

    return {
        **binding,
        "application_path": public_path(application_response.url),
        "application_status": application_response.status,
        "submit_path": public_path(submit_response.url),
        "submit_status": submit_response.status,
        "claim_path": public_path(claim_response.url),
        "claim_status": claim_response.status,
        "credential_offer_present": True,
    }


def exercise_verification(page: Page, base_url: str) -> dict[str, object]:
    open_org_console(page, base_url)
    create = page.get_by_role("button", name="New Verification")
    create.wait_for(timeout=30_000)
    wait_for_verification_identity(page, create)

    create.click()
    policy = page.get_by_label("Presentation Policy")
    policy.wait_for(timeout=15_000)
    policy.click()
    options = page.get_by_role("option")
    if options.count() < 1:
        raise AssertionError("released stack exposes no presentation policy to the UI")
    options.first.click()
    page.get_by_role("button", name="Next").click()
    page.get_by_label("Verification Purpose").fill(VERIFICATION_PURPOSE)
    issuer_did = page.get_by_label("Issuer DID")
    if issuer_did.count() > 0:
        issuer_did.click()
        public_dids = page.get_by_role("option").filter(has_text="did:")
        if public_dids.count() < 1:
            raise AssertionError("released stack exposes no public issuer DID choice")
        public_dids.first.click()

    with page.expect_response(
        lambda response: response.request.method == "POST" and public_path(response.url) == "/v1/flows/verify",
        timeout=30_000,
    ) as verification_info:
        page.get_by_role("button", name="Start Session").click()
    response = verification_info.value
    require_success(response, operation="browser verification start")
    body = request_json(response.request)
    assert_no_private_selectors(body, location="verification")
    if not isinstance(body, dict):
        raise AssertionError("verification request body is not a JSON object")
    organization_id = str(body.get("organization_id") or "").strip()
    issuer_did = str(body.get("issuer_did") or "").strip()
    if not organization_id:
        raise AssertionError("verification request has no organization_id")
    if not issuer_did.startswith("did:"):
        raise AssertionError("verification request has no public issuer_did")
    page.get_by_text("Scan & Verify").wait_for(timeout=15_000)

    return {
        "organization_id": organization_id,
        "issuer_did": issuer_did,
        "status": response.status,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "--output",
        type=Path,
        help="Optional public-safe JSON evidence destination",
    )
    return result


def main(argv: list[str] | None = None) -> int:
    from playwright.sync_api import sync_playwright

    args = parser().parse_args(argv)
    base_url = public_origin(required_env("OIDF_MARTY_GATEWAY_URL"))
    email = required_env("OIDF_MARTY_OPERATOR_EMAIL")
    password = required_env("OIDF_MARTY_OPERATOR_PASSWORD")
    credential_template_id = required_env("OIDF_MARTY_BROWSER_CREDENTIAL_TEMPLATE_ID")
    application_template_id = required_env("OIDF_MARTY_BROWSER_APPLICATION_TEMPLATE_ID")
    session_id = login(base_url, email, password)

    request_records: list[dict[str, object]] = []
    response_records: list[dict[str, object]] = []
    browser_errors: list[str] = []

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        context.add_cookies(
            [
                {
                    "name": "sessionId",
                    "value": session_id,
                    "url": base_url,
                    "secure": True,
                    "httpOnly": True,
                    "sameSite": "Lax",
                }
            ]
        )
        page = context.new_page()

        def record_request(request: Request) -> None:
            path = public_path(request.url)
            if not path.startswith("/v1/"):
                return
            body = request_json(request) if request.method in {"POST", "PUT", "PATCH"} else {}
            assert_no_private_selectors(body, location=f"{request.method} {path}")
            request_records.append({"method": request.method, "path": path, "body": body})

        def record_response(response: Response) -> None:
            path = public_path(response.url)
            if path.startswith(("/v1/", "/locales/")) or path == "/config.json":
                response_records.append({"method": response.request.method, "path": path, "status": response.status})

        page.on("request", record_request)
        page.on("response", record_response)
        page.on("pageerror", lambda error: browser_errors.append(f"pageerror: {error}"))
        page.on(
            "console",
            lambda message: browser_errors.append(f"console: {message.text}") if message.type == "error" else None,
        )

        try:
            issuance = exercise_issuance(
                page,
                base_url,
                credential_template_id=credential_template_id,
                application_template_id=application_template_id,
            )
            verification = exercise_verification(page, base_url)
        finally:
            context.close()
            browser.close()

    required_issuance_suffixes = ("/applications", "/submit", "/claim")
    post_paths = [record["path"] for record in request_records if record["method"] == "POST"]
    for suffix in required_issuance_suffixes:
        if not any(path.endswith(suffix) for path in post_paths):
            raise AssertionError(f"browser issuance did not call a public {suffix} endpoint")

    requested_paths = {record["path"] for record in request_records}
    if "/v1/signing-keys/issuer-identities" not in requested_paths:
        raise AssertionError("browser verification did not use the DID-only identity endpoint")
    if any(path.endswith("/issuer-profiles") for path in requested_paths):
        raise AssertionError("browser verification fetched internal issuer profiles")

    failed_static = [
        record
        for record in response_records
        if (record["path"].startswith("/locales/") or record["path"] == "/config.json") and record["status"] != 200
    ]
    if failed_static:
        raise AssertionError(f"released UI static assets failed: {failed_static}")
    observed_static = {record["path"] for record in response_records}
    for required_static in ("/config.json", "/locales/en/common.json"):
        if required_static not in observed_static:
            raise AssertionError(f"released UI did not load {required_static}")
    csp_errors = [error for error in browser_errors if "Content Security Policy" in error]
    if csp_errors:
        raise AssertionError(f"released UI violates its script policy: {csp_errors}")

    evidence = {
        "schema": "elevenid.released-browser-smoke/v1",
        "issuance": issuance,
        "verification": verification,
        "public_post_paths": sorted(set(post_paths)),
        "private_selectors_observed": False,
        "status": "passed",
    }
    rendered = json.dumps(evidence, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, OSError, RuntimeError, ValueError) as exc:
        print(f"Released browser smoke failed: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
