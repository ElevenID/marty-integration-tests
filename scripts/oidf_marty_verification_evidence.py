#!/usr/bin/env python3
"""Capture actual Marty verifier outcomes and UI evidence before lane teardown.

Official module results remain unchanged. Screenshots need review; collecting
them never promotes REVIEW to PASSED. Raw results and images stay private.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

from official_fixture_bootstrap import write_private_json  # noqa: E402
from oidf_marty_browser_smoke import (  # noqa: E402
    authenticated_browser_context,
    browser_resolver_args,
    hosted_browser_launch_options,
    open_org_console,
)
from oidf_marty_public_login import (  # noqa: E402
    PublicGatewayHttpError,
    authenticated_json_request,
    public_origin,
    required_env,
)
from oidf_marty_start_verification import gateway_session_id  # noqa: E402
from oidf_sd_jwt_diagnostic_audit import FLOW_ID, _private_mappings  # noqa: E402

if TYPE_CHECKING:
    from playwright.sync_api import Page


def outcome_projection(result: object, flow_id: str, *, instance_readback: bool = False) -> dict[str, str]:
    """Expose only bounded server facts, with an exact instance binding."""
    identity_field = "id" if instance_readback else "instance_id"
    if not FLOW_ID.fullmatch(flow_id) or not isinstance(result, dict) or result.get(identity_field) != flow_id:
        raise ValueError("verification evidence belongs to a different flow")
    projected = {
        key: value
        if isinstance(value := result.get(key), str)
        and (value := value.lower() if key == "status" else value) in allowed
        else "UNKNOWN"
        for key, allowed in {
            "status": {
                "completed",
                "failed",
                "pending",
                "in_progress",
                "awaiting_wallet",
                "awaiting_approval",
                "awaiting_evidence",
                "expired",
                "cancelled",
            },
            "result": {"passed", "failed", "partial"},
            "decision": {"allow", "deny", "manual_review"},
        }.items()
    }
    if instance_readback:
        projected.update(result="UNKNOWN", decision="UNKNOWN")
    return projected


def read_flow_evidence(
    base_url: str,
    session_id: str,
    flow_id: str,
    *,
    review_required: bool,
) -> tuple[object, dict[str, str], str]:
    try:
        result = authenticated_json_request(base_url, session_id, f"/v1/flows/instances/{flow_id}/result")
        return result, outcome_projection(result, flow_id), "verification_result"
    except PublicGatewayHttpError as error:
        if error.status != 409 or review_required:
            raise
        # Invalid wallet submissions can leave the transaction awaiting a new
        # attempt. Record that state; do not invent a terminal deny decision.
        result = authenticated_json_request(base_url, session_id, f"/v1/flows/instances/{flow_id}")
        return result, outcome_projection(result, flow_id, instance_readback=True), "instance_result_pending"


def capture_success_page(
    page: Page,
    flow_id: str,
    outcome: dict[str, str],
    destination: Path,
    *,
    progress: dict[str, str] | None = None,
) -> str:
    """Capture the real console dialog only after correlated successful results."""
    if outcome != {"status": "completed", "result": "passed", "decision": "allow"}:
        raise ValueError("a successful verifier screenshot requires a completed allow result")
    if progress is None:
        progress = {}
    progress["stage"] = "history_tab"
    page.get_by_role("tab", name="History").click()
    progress["stage"] = "history_flow_row"
    row = page.locator(f'[data-flow-instance-id="{flow_id}"]')
    row.wait_for(timeout=30_000)
    result_path = f"/v1/flows/instances/{flow_id}/result"
    progress["stage"] = "dialog_result_readback"
    with page.expect_response(lambda response: urlsplit(response.url).path == result_path) as readback:
        row.get_by_role("button", name="View session details").click()
    response = readback.value
    if response.status != 200 or outcome_projection(response.json(), flow_id) != outcome:
        raise ValueError("browser verification evidence does not match the public result")
    dialog = page.get_by_role("dialog")
    progress["stage"] = "dialog_flow_identity"
    dialog.get_by_text(flow_id, exact=True).wait_for(timeout=30_000)
    progress["stage"] = "dialog_result_loaded"
    dialog.get_by_label("Loading verification result").wait_for(state="hidden", timeout=30_000)
    progress["stage"] = "dialog_verified_outcome"
    dialog.get_by_text("Verified", exact=True).first.wait_for(timeout=30_000)
    if dialog.get_by_role("alert").count():
        raise ValueError("verification evidence dialog contains an error")
    progress["stage"] = "success_screenshot"
    page.screenshot(path=str(destination), full_page=True)
    destination.chmod(0o600)
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    dialog.get_by_role("button", name="Close", exact=True).click()
    return digest


def capture_failure_diagnostics(page: Page, destination: Path, error: Exception, stage: str) -> None:
    """Retain real failure state privately, never as successful review evidence."""
    write_private_json(
        destination.with_suffix(".json"),
        {"stage": stage, "error_class": type(error).__name__, "error": str(error), "url": page.url},
    )
    html = destination.with_suffix(".html")
    html.touch(mode=0o600, exist_ok=False)
    html.write_text(page.content(), encoding="utf-8")
    screenshot = destination.with_suffix(".png")
    screenshot.touch(mode=0o600, exist_ok=False)
    page.screenshot(path=str(screenshot), full_page=True, timeout=10_000)


def main() -> int:
    from playwright.sync_api import sync_playwright

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--flow-audit-dir", type=Path, required=True)
    parser.add_argument("--module-results", type=Path, required=True)
    parser.add_argument("--private-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    correlations = _private_mappings(args.flow_audit_dir)
    if len(set(correlations.values())) != len(correlations):
        raise ValueError("verification evidence has ambiguous module-to-flow bindings")
    modules = json.loads(args.module_results.read_text(encoding="utf-8"))
    pending = modules["pending_review"]
    if not isinstance(pending, list) or not set(pending).issubset(correlations.values()):
        raise ValueError("review modules have no correlated Marty flows")
    if not set(correlations.values()).issubset(row["test_name"] for row in modules["modules"]):
        raise ValueError("Marty flows do not belong to this official module export")
    base_url = public_origin(required_env("OIDF_MARTY_GATEWAY_URL"))
    session_id = gateway_session_id()
    args.private_output.mkdir(mode=0o700, parents=True, exist_ok=False)
    rows: list[dict[str, object]] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True,
            args=browser_resolver_args(base_url, os.environ.get("OIDF_MARTY_RESOLVE_IP", "")),
            **hosted_browser_launch_options(),
        )
        try:
            context = authenticated_browser_context(browser, base_url, session_id)
            page = context.new_page()
            page.set_viewport_size({"width": 1440, "height": 1080})
            open_org_console(page, base_url)
            for flow_id, name in correlations.items():
                row: dict[str, object] = {"test_name": name, "capture_status": "PENDING", "screenshot": None}
                rows.append(row)
                progress = {"stage": "public_result_readback"}
                digest = hashlib.sha256(name.encode()).hexdigest()
                try:
                    result, outcome, source = read_flow_evidence(
                        base_url,
                        session_id,
                        flow_id,
                        review_required=name in pending,
                    )
                    row["readback_source"] = source
                    row.update(outcome)
                    write_private_json(args.private_output / f"{digest}.json", result)
                    if name in pending:
                        destination = args.private_output / f"{digest}.png"
                        row["screenshot"] = {
                            "sha256": capture_success_page(page, flow_id, outcome, destination, progress=progress),
                            "private_file": destination.name,
                            "review_status": "PENDING",
                        }
                    row["capture_status"] = "CAPTURED" if name in pending else "RESULT_RECORDED"
                except Exception as error:  # noqa: BLE001 - retain other modules without exporting private exceptions
                    row.update(
                        capture_status="FAILED", error_class=type(error).__name__, failure_stage=progress["stage"]
                    )
                    try:
                        capture_failure_diagnostics(
                            page, args.private_output / f"{digest}-failure", error, progress["stage"]
                        )
                    except Exception as diagnostic_error:  # noqa: BLE001 - private diagnostic failure is not evidence
                        row["diagnostic_error_class"] = type(diagnostic_error).__name__
                    # A failed dialog must not contaminate the next module.
                    open_org_console(page, base_url)
        finally:
            browser.close()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(
            {
                "schema": "elevenid.marty-verification-evidence/v1",
                "official_results_modified": False,
                "review_pending": pending,
                "modules": rows,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return 2 if any(row["capture_status"] == "FAILED" for row in rows) else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:  # noqa: BLE001 - private API/browser exceptions can contain credentials
        print(f"Marty verifier evidence unavailable: {type(error).__name__}", file=sys.stderr)
        raise SystemExit(2) from None
