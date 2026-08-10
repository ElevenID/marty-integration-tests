from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "sanitize_official_evidence", ROOT / "scripts" / "sanitize_official_evidence.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load official evidence sanitizer")
sanitizer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sanitizer)


def test_sanitizer_emits_only_safe_structured_summary(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    secret = "eyJabcdefghijk.abcdefghijklmnop.signature"
    (raw / "runner.log").write_text("must never be copied " + secret, encoding="utf-8")
    (raw / "evidence.json").write_text(
        json.dumps(
            {
                "authorization": "Bearer secret",
                "endpoint": "https://user:pass@example.test/path?code=secret",
                "configuration": "C:\\private\\marty-verifier.json",
                "jwt": secret,
                "result": {"passed": False},
            }
        ),
        encoding="utf-8",
    )
    (raw / "junit.xml").write_text(
        '<testsuite tests="3" failures="1" errors="0" skipped="1"><testcase name="secret-name"/></testsuite>',
        encoding="utf-8",
    )
    summary = sanitizer.build_summary(raw, lane="haip", harness_commit="a" * 40, exit_code=1)
    serialized = json.dumps(summary)
    assert "Bearer secret" not in serialized
    assert secret not in serialized
    assert "?code=" not in serialized
    assert "secret-name" not in serialized
    assert summary["junit"][0]["tests"] == 3
    assert summary["result"] == {"exit_code": 1, "passed": False}


def test_main_writes_no_raw_files(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "runner.log").write_text("private", encoding="utf-8")
    output = tmp_path / "public"
    assert (
        sanitizer.main(
            [
                "--input",
                str(raw),
                "--output",
                str(output),
                "--lane",
                "eudi",
                "--harness-commit",
                "b" * 40,
                "--exit-code",
                "0",
            ]
        )
        == 0
    )
    assert [path.name for path in output.iterdir()] == ["summary.json"]


def test_summary_records_public_safe_eudi_harness_image_digest(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    report = tmp_path / "harness-image.json"
    report.write_text(
        json.dumps(
            {
                "schema": "elevenid.eudi-harness-build/v1",
                "component": "eudi-wallet-harness",
                "image_digest": "sha256:" + "a" * 64,
                "recipe": {"gradle.lockfile": "sha256:" + "b" * 64},
            }
        ),
        encoding="utf-8",
    )
    summary = sanitizer.build_summary(
        raw,
        lane="eudi",
        harness_commit="c" * 40,
        exit_code=0,
        harness_image_report=report,
    )
    assert summary["eudi_harness_image"]["image_digest"] == "sha256:" + "a" * 64


def test_summary_records_public_safe_browser_issuance_and_verification(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    browser = raw / "browser"
    browser.mkdir(parents=True)
    (browser / "browser-evidence.json").write_text(
        json.dumps(
            {
                "schema": "elevenid.released-browser-smoke/v1",
                "issuance": {
                    "organization_id": "org-1",
                    "issuer_did": "did:web:issuer.example:orgs:org-1",
                    "credential_offer_present": True,
                },
                "verification": {
                    "organization_id": "org-1",
                    "issuer_did": "did:web:issuer.example:orgs:org-1",
                },
                "public_post_paths": [
                    "/v1/me/applications",
                    "/v1/me/applications/application-1/submit",
                    "/v1/me/applications/application-1/claim",
                    "/v1/flows/verify",
                ],
                "private_selectors_observed": False,
                "status": "passed",
            }
        ),
        encoding="utf-8",
    )

    summary = sanitizer.build_summary(
        raw,
        lane="oid4vp-final",
        harness_commit="d" * 40,
        exit_code=0,
    )

    assert summary["browser_evidence"]["issuance"]["issuer_did"].startswith("did:")
    assert summary["browser_evidence"]["issuance"]["credential_offer_present"] is True
    assert summary["browser_evidence"]["private_selectors_observed"] is False


def test_summary_rejects_nonpassing_or_misplaced_browser_evidence(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    browser = {
        "schema": "elevenid.released-browser-smoke/v1",
        "status": "failed",
        "private_selectors_observed": False,
    }
    (raw / "browser-evidence.json").write_text(json.dumps(browser), encoding="utf-8")

    with pytest.raises(ValueError, match="permitted only"):
        sanitizer.build_summary(
            raw,
            lane="haip",
            harness_commit="e" * 40,
            exit_code=1,
        )
    with pytest.raises(ValueError, match="passing"):
        sanitizer.build_summary(
            raw,
            lane="oid4vp-final",
            harness_commit="e" * 40,
            exit_code=1,
        )


def test_summary_preserves_only_validated_sd_jwt_diagnostic_categories(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    report = {
        "schema": "elevenid.oidf-sd-jwt-diagnostic-audit/v2",
        "source_policy": "unmodified",
        "modules": [
            {
                "test_name": "oid4vp-1final-verifier-happy-flow",
                "marty_flow_result": "failed",
                "marty_flow_decision": "deny",
                "marty_flow_category": "issuer-audience-invalid",
                "official_failure_stage": "direct-post-callback-response",
                "official_http_status": 400,
            }
        ],
    }
    (raw / "oidf-sd-jwt-diagnostic-audit.json").write_text(
        json.dumps(report),
        encoding="utf-8",
    )

    summary = sanitizer.build_summary(
        raw,
        lane="oid4vp-final",
        harness_commit="f" * 40,
        exit_code=1,
    )

    assert summary["verifier_diagnostics"] == report


def test_summary_rejects_unvalidated_or_misplaced_sd_jwt_diagnostics(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    report = {
        "schema": "elevenid.oidf-sd-jwt-diagnostic-audit/v2",
        "source_policy": "unmodified",
        "modules": [
            {
                "test_name": "oid4vp-1final-verifier-happy-flow",
                "marty_flow_result": "failed",
                "marty_flow_decision": "deny",
                "marty_flow_category": "raw error: must-not-leak",
                "official_failure_stage": "direct-post-callback-response",
                "official_http_status": 400,
            }
        ],
    }
    path = raw / "oidf-sd-jwt-diagnostic-audit.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="category is unsafe"):
        sanitizer.build_summary(
            raw,
            lane="oid4vp-final",
            harness_commit="f" * 40,
            exit_code=1,
        )

    report["modules"][0]["marty_flow_category"] = "issuer-audience-invalid"
    path.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(ValueError, match="not permitted"):
        sanitizer.build_summary(
            raw,
            lane="w3c-v2",
            harness_commit="f" * 40,
            exit_code=1,
        )


@pytest.mark.parametrize(
    ("result", "decision", "category"),
    [
        ("failed", "deny", "made-up-safe-category"),
        ("passed", "allow", "issuer-audience-invalid"),
        ("failed", "allow", "issuer-audience-invalid"),
        ("unavailable", "unavailable", "issuer-audience-invalid"),
    ],
)
def test_summary_rejects_unallowlisted_or_inconsistent_sd_jwt_outcomes(
    tmp_path: Path,
    result: str,
    decision: str,
    category: str,
) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "oidf-sd-jwt-diagnostic-audit.json").write_text(
        json.dumps(
            {
                "schema": "elevenid.oidf-sd-jwt-diagnostic-audit/v2",
                "source_policy": "unmodified",
                "modules": [
                    {
                        "test_name": "oid4vp-1final-verifier-happy-flow",
                        "marty_flow_result": result,
                        "marty_flow_decision": decision,
                        "marty_flow_category": category,
                        "official_failure_stage": "direct-post-callback-response",
                        "official_http_status": 400,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="inconsistent or not allowlisted"):
        sanitizer.build_summary(
            raw,
            lane="oid4vp-final",
            harness_commit="f" * 40,
            exit_code=1,
        )
