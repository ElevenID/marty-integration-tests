#!/usr/bin/env python3
"""Exercise released Marty issuance and verification through the real browser UI.

This is an ElevenID-owned product-path test, not an adapter or modification of
an imported compliance suite. Authentication uses Marty's public OIDC flow;
all application, issuance, DID discovery, and verification calls originate
from the exact released UI artifact through the public HTTPS gateway.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from playwright.sync_api import Page, Request, Response

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
ISSUANCE_TEMPLATE_NAME = "Member Login Credential"
VERIFICATION_PURPOSE = "Released-stack browser DID-first smoke"


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


def exercise_issuance(page: Page, base_url: str) -> dict[str, object]:
    page.goto(
        f"{base_url}/console/applicant/catalog",
        wait_until="domcontentloaded",
        timeout=30_000,
    )
    card = page.locator(".MuiCard-root").filter(has_text=ISSUANCE_TEMPLATE_NAME).first
    card.wait_for(timeout=30_000)
    card.get_by_role("button", name="Apply").click()
    page.wait_for_url("**/console/applicant/apply/**", timeout=15_000)

    issue = page.get_by_role("button", name="Add to Wallet")
    issue.wait_for(timeout=30_000)
    with page.expect_response(
        lambda response: response.request.method == "POST" and public_path(response.url).endswith("/claim"),
        timeout=30_000,
    ) as claim_info:
        issue.click()
    claim_response = claim_info.value
    require_success(claim_response, operation="browser issuance claim")
    page.get_by_role("dialog").get_by_text("Receive Credential").wait_for(timeout=15_000)

    return {
        "claim_path": public_path(claim_response.url),
        "claim_status": claim_response.status,
    }


def exercise_verification(page: Page, base_url: str) -> dict[str, object]:
    open_org_console(page, base_url)
    create = page.get_by_role("button", name="New Verification")
    create.wait_for(timeout=30_000)
    if not create.is_enabled():
        alerts = " | ".join(page.locator("[role=alert]").all_inner_texts())
        raise AssertionError(f"verification DID did not resolve: {alerts}")

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


def main() -> int:
    from playwright.sync_api import sync_playwright

    base_url = public_origin(required_env("OIDF_MARTY_GATEWAY_URL"))
    email = required_env("OIDF_MARTY_OPERATOR_EMAIL")
    password = required_env("OIDF_MARTY_OPERATOR_PASSWORD")
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
            issuance = exercise_issuance(page, base_url)
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

    print(
        json.dumps(
            {
                "schema": "elevenid.released-browser-smoke/v1",
                "issuance": issuance,
                "verification": verification,
                "public_post_paths": sorted(set(post_paths)),
                "private_selectors_observed": False,
                "status": "passed",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, OSError, RuntimeError, ValueError) as exc:
        print(f"Released browser smoke failed: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
