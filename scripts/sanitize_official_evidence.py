#!/usr/bin/env python3
"""Create a public-safe summary of private official-suite run evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ElementTree
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from eudi_runtime_diagnostic_contract import (  # noqa: E402
    EUDI_RUNTIME_DIAGNOSTIC_CATEGORIES,
    EUDI_RUNTIME_DIAGNOSTIC_SCHEMA,
)
from oidf_conformance import (  # noqa: E402
    exported_module_info,
    load_manifest,
    recorded_plan_coverage,
    strict_module_summary,
)

SCHEMA = "elevenid.sanitized-official-interop/v1"
BROWSER_SCHEMA = "elevenid.released-browser-smoke/v1"
SD_JWT_DIAGNOSTIC_SCHEMA = "elevenid.oidf-sd-jwt-diagnostic-audit/v2"
SD_JWT_DIAGNOSTIC_LANES = {"oid4vp-final", "oid4vp-url-query", "haip"}
LANES = {
    "oid4vci-issuer",
    "oid4vp-final",
    "oid4vp-url-query",
    "oid4vp-mdoc",
    "haip",
    "w3c-v2",
    "eudi",
}
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SAFE_DIAGNOSTIC_MODULE = re.compile(r"^oid4vp-[A-Za-z0-9_.:\[\]=,+/-]{1,292}$")
SAFE_DIAGNOSTIC_CATEGORY = re.compile(r"^[a-z0-9-]{1,100}$")
SD_JWT_FAILURE_CATEGORIES = {
    "did-resolution-failed",
    "disclosure-invalid",
    "holder-key-missing-or-invalid",
    "issuer-audience-invalid",
    "issuer-key-invalid",
    "issuer-required-claim-missing",
    "issuer-signature-invalid",
    "issuer-token-expired",
    "issuer-token-invalid",
    "issuer-trust-material-missing",
    "key-binding-audience-invalid",
    "key-binding-hash-invalid",
    "key-binding-nonce-invalid",
    "key-binding-required",
    "key-binding-signature-invalid",
    "key-binding-time-invalid",
    "key-binding-type-invalid",
    "native-verifier-unavailable",
    "sd-jwt-verification-unclassified",
    "unsupported-format",
    "verification-denied-unclassified",
}
SENSITIVE_KEY = re.compile(
    r"(?:^|_)(?:authorization|cookie|password|secret|session|signing_jwk|private_key|access_token|refresh_token)(?:$|_)",
    re.IGNORECASE,
)
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)?\b")
SECRET_MARKERS = ("-----BEGIN PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----", "sessionId=")
HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
OFFICIAL_ID = re.compile(r"[A-Za-z0-9]{1,180}\Z")


def _safe_string(value: str) -> tuple[str, int]:
    if any(marker in value for marker in SECRET_MARKERS) or JWT.search(value):
        return "[REDACTED]", 1
    if value.startswith(("http://", "https://")):
        parsed = urlsplit(value)
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            return urlunsplit((parsed.scheme, parsed.hostname or "", parsed.path, "", "")), 1
    if Path(value).is_absolute():
        return Path(value).name, 1
    return value, 0


def sanitize(value: object, *, key: str = "") -> tuple[object, int]:
    if key and SENSITIVE_KEY.search(key):
        return "[REDACTED]", 1
    if isinstance(value, dict):
        result: dict[str, object] = {}
        redactions = 0
        for child_key, child_value in value.items():
            clean, count = sanitize(child_value, key=str(child_key))
            result[str(child_key)] = clean
            redactions += count
        return result, redactions
    if isinstance(value, list):
        result_list: list[object] = []
        redactions = 0
        for item in value:
            clean, count = sanitize(item)
            result_list.append(clean)
            redactions += count
        return result_list, redactions
    if isinstance(value, str):
        return _safe_string(value)
    return value, 0


def junit_summary(path: Path) -> dict[str, int]:
    root = ElementTree.parse(path).getroot()
    totals = dict.fromkeys(("tests", "failures", "errors", "skipped"), 0)
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    for suite in suites:
        for name in totals:
            totals[name] += int(suite.attrib.get(name, "0"))
    return totals


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def pending_review_request(evidence_path: Path, evidence: dict) -> dict | None:
    """Project hash-bound review inputs, never an approval or a passing verdict.

    Raw exports, API results and pixels stay private. A later authenticated
    disposition must bind the complete summary bytes as well as these hashes.
    Reuse the runner's export/coverage readers instead of trusting a capture's
    self-reported module list. Historical receipts without IDs are joined to
    their exact original export; newer receipts must agree with those IDs.
    """
    receipt_path = evidence_path.parent / "official-real-ui-images.json"
    if not receipt_path.exists():
        return None
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise ValueError("review receipt must be a regular owned file")
    receipt_bytes = receipt_path.read_bytes()
    if len(receipt_bytes) > 512 * 1024:
        raise ValueError("review receipt exceeds its size limit")
    receipt = json.loads(receipt_bytes)
    if not isinstance(receipt, dict):
        raise ValueError("review receipt is malformed")
    # Preserve failed runs' ordinary diagnostics without offering review inputs
    # that an approval could accidentally treat as complete.
    if receipt.get("state") == "FAILED":
        return None
    if receipt.get("state") == "NO_REVIEW_IMAGES_REQUIRED":
        if evidence.get("module_results", {}).get("pending_review"):
            raise ValueError("review receipt omits pending modules")
        return None
    receipt_sha = hashlib.sha256(receipt_bytes).hexdigest()
    artifacts = evidence.get("artifacts", [])
    bindings = [row for row in artifacts if row.get("path") == receipt_path.name]
    if len(bindings) != 1 or bindings[0].get("sha256") != "sha256:" + receipt_sha:
        raise ValueError("review receipt is not bound to the original evidence inventory")
    if (
        receipt.get("schema") != "elevenid.official-real-ui-images/v1"
        or receipt.get("state") != "ATTACHED"
        or receipt.get("review_status") != "PENDING"
        or receipt.get("original_exports_unchanged") is not True
        or receipt.get("module_outcomes_unchanged") is not True
        or not isinstance(receipt.get("official_export_sha256"), str)
        or not HEX_DIGEST.fullmatch(receipt["official_export_sha256"])
    ):
        raise ValueError("review receipt does not establish unchanged pending evidence")
    manifest = load_manifest()
    if (
        evidence.get("schema") != "elevenid.official-interop-evidence/v1"
        or evidence.get("execution_mode") != "active"
        or evidence.get("official_runner") != manifest["official_runner"]
    ):
        raise ValueError("review evidence does not use the pinned unmodified official runner")
    profile = manifest["profiles"].get(evidence.get("profile"))
    if not isinstance(profile, dict):
        raise ValueError("review evidence has an unknown official profile")
    archives = sorted(evidence_path.parent.glob("*.zip"))
    export_bindings = [row for row in artifacts if str(row.get("path", "")).endswith(".zip")]
    if not archives or {p.name for p in archives} != {row.get("path") for row in export_bindings}:
        raise ValueError("review evidence has missing or foreign original exports")
    for archive in archives:
        entries = [row for row in export_bindings if row["path"] == archive.name]
        if (
            archive.is_symlink()
            or not archive.is_file()
            or len(entries) != 1
            or entries[0].get("sha256") != "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest()
        ):
            raise ValueError("review original export differs from its evidence hash")
    expected_skips = evidence.get("exclusions", {}).get("expected_skips", [])
    observed = strict_module_summary(evidence_path.parent, expected_skips)
    coverage = recorded_plan_coverage(
        evidence_path.parent, evidence.get("module_results", {}).get("plan_coverage"), profile["test_plan"]
    )
    observed["plan_coverage"] = coverage
    if evidence.get("module_results") != observed or not coverage["complete"]:
        raise ValueError("review evidence differs from its complete original module export")
    if receipt.get("plan_binding_sha256") != coverage["binding_sha256"]:
        raise ValueError("review receipt belongs to another official plan")
    infos = {row["testName"]: row for row in exported_module_info(evidence_path.parent)}
    pending = set(observed["pending_review"])
    rows = receipt.get("modules")
    if (
        not pending
        or not isinstance(rows, list)
        or any(not isinstance(row, dict) for row in rows)
        or any(not isinstance(row.get("test_name"), str) for row in rows)
        or len(rows) != len(pending)
        or {row.get("test_name") for row in rows} != pending
    ):
        raise ValueError("review images do not cover the exact pending module set")
    modules = []
    for row in rows:
        info = infos[row["test_name"]]
        if (
            row.get("readback_hash_matched") is not True
            or row.get("review_status") != "PENDING"
            or not isinstance(row.get("screenshot_sha256"), str)
            or not HEX_DIGEST.fullmatch(row["screenshot_sha256"])
            or any(
                not isinstance(info.get(key), str) or not OFFICIAL_ID.fullmatch(info[key])
                for key in ["testId", "planId"]
            )
            or info.get("_id") != info["testId"]
            or row.get("test_id", info["testId"]) != info["testId"]
            or row.get("plan_id", info["planId"]) != info["planId"]
        ):
            raise ValueError("review image lacks its exact official identity and readback")
        modules.append(
            {
                "test_name": info["testName"],
                "test_id": info["testId"],
                "plan_id": info["planId"],
                "official_result": "REVIEW",
                "screenshot_sha256": "sha256:" + row["screenshot_sha256"],
            }
        )
    return {
        "schema": "elevenid.official-review-request/v1",
        "status": "PENDING",
        "original_evidence_sha256": "sha256:" + hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
        "capture_receipt_sha256": "sha256:" + receipt_sha,
        "official_export_sha256": "sha256:" + receipt["official_export_sha256"],
        "plan_binding_sha256": "sha256:" + coverage["binding_sha256"],
        "modules": sorted(modules, key=lambda item: item["test_name"]),
    }


def sd_jwt_diagnostic_report(value: object) -> dict[str, object]:
    """Validate the fixed-field public-safe SD-JWT diagnostic contract."""
    if not isinstance(value, dict) or set(value) != {"schema", "source_policy", "modules"}:
        raise ValueError("SD-JWT diagnostic report has an invalid shape")
    if value.get("schema") != SD_JWT_DIAGNOSTIC_SCHEMA:
        raise ValueError("SD-JWT diagnostic report has an unsupported schema")
    if value.get("source_policy") != "unmodified":
        raise ValueError("SD-JWT diagnostic report does not preserve the upstream source policy")
    modules = value.get("modules")
    if not isinstance(modules, list) or not modules:
        raise ValueError("SD-JWT diagnostic report must contain at least one module")
    allowed_results = {"passed", "failed", "partial", "unavailable"}
    allowed_decisions = {"allow", "deny", "manual_review", "unavailable"}
    allowed_stages = {
        "direct-post-callback-response",
        "no-official-failure-observed",
        "other-official-failure",
    }
    for module in modules:
        if not isinstance(module, dict) or set(module) != {
            "test_name",
            "marty_flow_result",
            "marty_flow_decision",
            "marty_flow_category",
            "official_failure_stage",
            "official_http_status",
        }:
            raise ValueError("SD-JWT diagnostic module has an invalid shape")
        if (
            not isinstance(module["test_name"], str)
            or SAFE_DIAGNOSTIC_MODULE.fullmatch(module["test_name"]) is None
        ):
            raise ValueError("SD-JWT diagnostic module name is unsafe")
        if module["marty_flow_result"] not in allowed_results:
            raise ValueError("SD-JWT diagnostic Marty flow result is not allowlisted")
        if module["marty_flow_decision"] not in allowed_decisions:
            raise ValueError("SD-JWT diagnostic Marty flow decision is not allowlisted")
        if (
            not isinstance(module["marty_flow_category"], str)
            or SAFE_DIAGNOSTIC_CATEGORY.fullmatch(module["marty_flow_category"])
            is None
        ):
            raise ValueError("SD-JWT diagnostic Marty flow category is unsafe")
        stage = module["official_failure_stage"]
        status = module["official_http_status"]
        if stage not in allowed_stages:
            raise ValueError("SD-JWT diagnostic Official failure stage is not allowlisted")
        if (
            status is not None
            and (
                isinstance(status, bool)
                or not isinstance(status, int)
                or not 100 <= status <= 599
            )
        ):
            raise ValueError("SD-JWT diagnostic Official HTTP status is invalid")
        if (stage == "direct-post-callback-response") != (status is not None):
            raise ValueError(
                "SD-JWT diagnostic Official stage and HTTP status are inconsistent"
            )
        outcome = (
            module["marty_flow_result"],
            module["marty_flow_decision"],
            module["marty_flow_category"],
        )
        if outcome == ("passed", "allow", "accepted"):
            continue
        if outcome == ("unavailable", "unavailable", "runtime-outcome-unavailable"):
            continue
        if (
            module["marty_flow_result"] in {"failed", "partial"}
            and module["marty_flow_decision"] in {"deny", "manual_review"}
            and module["marty_flow_category"] in SD_JWT_FAILURE_CATEGORIES
        ):
            continue
        raise ValueError("SD-JWT diagnostic outcome is inconsistent or not allowlisted")
    return value


def eudi_runtime_diagnostic_report(value: object) -> dict[str, object]:
    """Validate the fixed-category public-safe EUDI diagnostic contract."""
    if not isinstance(value, dict) or set(value) != {"schema", "categories"}:
        raise ValueError("EUDI runtime diagnostic report has an invalid shape")
    if value.get("schema") != EUDI_RUNTIME_DIAGNOSTIC_SCHEMA:
        raise ValueError("EUDI runtime diagnostic report has an unsupported schema")
    categories = value.get("categories")
    if not isinstance(categories, list) or not categories:
        raise ValueError("EUDI runtime diagnostic report must contain categories")
    if len(categories) != len(set(map(str, categories))):
        raise ValueError("EUDI runtime diagnostic categories must be unique")
    if any(
        not isinstance(category, str)
        or category not in EUDI_RUNTIME_DIAGNOSTIC_CATEGORIES
        for category in categories
    ):
        raise ValueError("EUDI runtime diagnostic category is not allowlisted")
    return value


def build_summary(
    input_dir: Path,
    *,
    lane: str,
    harness_commit: str,
    exit_code: int,
    stack_metadata: Path | None = None,
    material_report: Path | None = None,
    harness_image_report: Path | None = None,
) -> dict[str, object]:
    if lane not in LANES:
        raise ValueError(f"unknown official interoperability lane: {lane}")
    if not COMMIT.fullmatch(harness_commit):
        raise ValueError("harness commit must be a full lowercase SHA")

    redactions = 0
    stack: object | None = None
    if stack_metadata and stack_metadata.is_file():
        stack, count = sanitize(load_json(stack_metadata))
        redactions += count
    material: object | None = None
    if material_report and material_report.is_file():
        material, count = sanitize(load_json(material_report))
        redactions += count
    harness_image: object | None = None
    if harness_image_report and harness_image_report.is_file():
        harness_image, count = sanitize(load_json(harness_image_report))
        redactions += count

    evidence: list[dict[str, object]] = []
    review_requests: list[dict[str, object]] = []
    junit: list[dict[str, object]] = []
    browser_evidence: object | None = None
    verifier_diagnostics: object | None = None
    if input_dir.is_dir():
        browser_paths = sorted(input_dir.rglob("browser-evidence.json"))
        if len(browser_paths) > 1:
            raise ValueError("official evidence contains multiple browser evidence files")
        if browser_paths:
            if lane != "oid4vp-final":
                raise ValueError("browser evidence is permitted only for the oid4vp-final lane")
            browser_raw = load_json(browser_paths[0])
            if not isinstance(browser_raw, dict):
                raise ValueError("browser evidence must be a JSON object")
            if browser_raw.get("schema") != BROWSER_SCHEMA:
                raise ValueError("browser evidence has an unsupported schema")
            if browser_raw.get("status") != "passed":
                raise ValueError("browser evidence does not record a passing run")
            if browser_raw.get("private_selectors_observed") is not False:
                raise ValueError("browser evidence does not prove private-selector absence")
            browser_evidence, count = sanitize(browser_raw)
            redactions += count
        diagnostic_paths = sorted(input_dir.rglob("oidf-sd-jwt-diagnostic-audit.json"))
        if len(diagnostic_paths) > 1:
            raise ValueError("official evidence contains multiple SD-JWT diagnostic reports")
        if diagnostic_paths:
            if lane not in SD_JWT_DIAGNOSTIC_LANES:
                raise ValueError("SD-JWT diagnostic evidence is not permitted for this lane")
            verifier_diagnostics, count = sanitize(
                sd_jwt_diagnostic_report(load_json(diagnostic_paths[0]))
            )
            redactions += count
        eudi_diagnostic_paths = sorted(
            input_dir.rglob("eudi-runtime-diagnostics.json")
        )
        if len(eudi_diagnostic_paths) > 1:
            raise ValueError("official evidence contains multiple EUDI diagnostic reports")
        if eudi_diagnostic_paths:
            if lane != "eudi":
                raise ValueError(
                    "EUDI runtime diagnostic evidence is permitted only for the eudi lane"
                )
            verifier_diagnostics, count = sanitize(
                eudi_runtime_diagnostic_report(load_json(eudi_diagnostic_paths[0]))
            )
            redactions += count
        for path in sorted(input_dir.rglob("evidence.json")):
            raw_evidence = load_json(path)
            if isinstance(raw_evidence, dict):
                request = pending_review_request(path, raw_evidence)
                if request is not None:
                    if lane in {"w3c-v2", "eudi", "oid4vci-issuer"}:
                        raise ValueError("review image evidence is not permitted for this lane")
                    review_requests.append({"source": path.relative_to(input_dir).as_posix(), **request})
            clean, count = sanitize(raw_evidence)
            redactions += count
            evidence.append({"source": path.relative_to(input_dir).as_posix(), "evidence": clean})
        for path in sorted(input_dir.rglob("*.xml")):
            try:
                counts = junit_summary(path)
            except (ElementTree.ParseError, ValueError):
                continue
            junit.append({"source": path.relative_to(input_dir).as_posix(), **counts})

    return {
        "schema": SCHEMA,
        "lane": lane,
        "harness_commit": harness_commit,
        "result": {"exit_code": exit_code, "passed": exit_code == 0},
        "stack": stack,
        "material": material,
        "eudi_harness_image": harness_image,
        "browser_evidence": browser_evidence,
        "verifier_diagnostics": verifier_diagnostics,
        "official_evidence": evidence,
        "review_requests": review_requests,
        "junit": junit,
        "redactions": redactions,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--input", type=Path, required=True)
    result.add_argument("--output", type=Path, required=True)
    result.add_argument("--lane", choices=sorted(LANES), required=True)
    result.add_argument("--harness-commit", required=True)
    result.add_argument("--exit-code", type=int, required=True)
    result.add_argument("--stack-metadata", type=Path)
    result.add_argument("--material-report", type=Path)
    result.add_argument("--harness-image-report", type=Path)
    result.add_argument("--github-output", type=Path)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    summary = build_summary(
        args.input.resolve(),
        lane=args.lane,
        harness_commit=args.harness_commit,
        exit_code=args.exit_code,
        stack_metadata=args.stack_metadata.resolve() if args.stack_metadata else None,
        material_report=args.material_report.resolve() if args.material_report else None,
        harness_image_report=args.harness_image_report.resolve() if args.harness_image_report else None,
    )
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    destination = output / "summary.json"
    destination.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as outputs:
            outputs.write(f"has_reviews={str(bool(summary['review_requests'])).lower()}\n")
    print(destination)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError, ElementTree.ParseError) as exc:
        print(f"Official evidence sanitization error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
