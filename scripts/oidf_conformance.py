#!/usr/bin/env python3
"""Run a pinned OpenID Foundation conformance plan against Marty.

The helper owns only the reproducibility boundary. The OpenID Foundation's
``run-test-plan.py`` remains the test runner and determines pass/fail.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from collections import Counter
from hashlib import sha256
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "conformance" / "oidf-runner.json"
SHA = re.compile(r"^[0-9a-f]{40}$")
OIDF_VERIFIER_ALIAS = "oidf-vp-test-wallet"
VERIFICATION_EVIDENCE_BROWSER_AUTOMATION = [
    {
        "comment": (
            "Capture the suite-served verification-evidence page so an automated "
            "official run can satisfy OIDF's required review screenshot"
        ),
        "match": "https://*/test/a/*/verification-evidence",
        "tasks": [
            {
                "task": "Capture verification evidence",
                "match": "https://*/test/a/*/verification-evidence",
                "commands": [
                    [
                        "wait",
                        "xpath",
                        "//*",
                        10,
                        ".*Deferred verification evidence.*",
                        "update-image-placeholder",
                    ]
                ],
            }
        ],
    }
]


def load_manifest(path: Path = MANIFEST) -> dict[str, Any]:
    raw: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("OIDF runner manifest must be a JSON object")
    data = cast(dict[str, Any], raw)
    if data.get("schema") != "elevenid.oidf-conformance-runner/v1":
        raise ValueError("unsupported OIDF runner manifest schema")
    runner = data.get("official_runner", {})
    if runner.get("repository") != "https://gitlab.com/openid/conformance-suite.git":
        raise ValueError("official runner repository must be the OIDF conformance suite")
    if not SHA.fullmatch(runner.get("commit", "")):
        raise ValueError("official runner commit must be a full lowercase SHA")
    if runner.get("source_policy") != "unmodified":
        raise ValueError("official runner source policy must be unmodified")
    if not runner.get("release", "").startswith("release-v"):
        raise ValueError("official runner release must be an immutable release tag")
    return data


def validate_expected_failures() -> None:
    entries = json.loads((ROOT / "conformance" / "expected-failures.json").read_text(encoding="utf-8"))
    if not isinstance(entries, list):
        raise ValueError("expected failures must be a JSON list")
    if entries:
        raise ValueError("official OIDF evidence must not accept expected failures")

    skips = json.loads((ROOT / "conformance" / "expected-skips.json").read_text(encoding="utf-8"))
    if not isinstance(skips, list):
        raise ValueError("expected skips must be a JSON list")
    for entry in skips:
        required = {"test-name", "configuration-filename", "variant", "reason", "owner", "expires"}
        if not isinstance(entry, dict) or required - entry.keys():
            raise ValueError(
                "each expected skip requires test-name, configuration-filename, variant, reason, owner, and expires"
            )


def git_revision(path: Path) -> str:
    return subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()


def validate_runner(path: Path, manifest: dict) -> None:
    runner_script = path / "scripts" / "run-test-plan.py"
    if not runner_script.is_file():
        raise ValueError(f"OIDF runner script is missing: {runner_script}")
    actual = git_revision(path)
    expected = manifest["official_runner"]["commit"]
    if actual != expected:
        raise ValueError(f"OIDF runner is {actual}; expected pinned {expected}")
    changed = subprocess.check_output(
        [
            "git",
            "-C",
            str(path),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ],
        text=True,
    ).splitlines()
    if changed:
        paths = ", ".join(line[3:] for line in changed)
        raise ValueError(f"OIDF runner source is not byte-for-byte clean: {paths}")


def _validate_absolute_url(value: object, field: str) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an absolute http(s) URL")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"{field} must be an absolute http(s) URL")
    if "example.invalid" in parsed.netloc or "REPLACE_" in value:
        raise ValueError("OIDF configuration still contains example values")


def validate_config(path: Path, profile_name: str = "oid4vci-issuer") -> None:
    """Validate only the profile-specific, non-secret runner configuration.

    OIDF verifier tests create their own wallet response.  Marty is started by
    the deployment-owned interaction command, so this file deliberately
    contains neither gateway credentials nor a test bypass.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("OIDF configuration must be a JSON object")
    if profile_name == "oid4vci-issuer":
        vci = data.get("vci", {})
        issuer = vci.get("credential_issuer_url", "")
        _validate_absolute_url(issuer, "vci.credential_issuer_url")
        for field in ("authorization_server", "credential_configuration_id"):
            if not vci.get(field):
                raise ValueError(f"vci.{field} is required by the official issuer plan")
        return

    if profile_name not in {
        "oid4vp-verifier",
        "oid4vp-url-query-verifier",
        "oid4vp-mdoc-verifier",
        "oid4vp-haip-verifier",
    }:
        raise ValueError(f"unknown OIDF configuration profile: {profile_name}")
    # The official BrowserControl matcher is scoped to /test/a/{alias}/... .
    # Without an alias the suite serves /test/{id}/..., so its own configured
    # verification-evidence task is never invoked and positive tests wait
    # indefinitely for the screenshot placeholder.
    if data.get("alias") != OIDF_VERIFIER_ALIAS:
        raise ValueError(f"verifier configuration alias must be {OIDF_VERIFIER_ALIAS!r}")
    signing_jwk = data.get("credential", {}).get("signing_jwk")
    if not isinstance(signing_jwk, dict) or not all(
        isinstance(signing_jwk.get(field), str) and signing_jwk[field] for field in ("kty", "crv", "x", "y", "d")
    ):
        raise ValueError(
            "credential.signing_jwk must contain the complete private EC JWK required by the official verifier plans"
        )
    if signing_jwk["kty"] != "EC" or signing_jwk["crv"] != "P-256":
        raise ValueError("credential.signing_jwk must be an EC P-256 private JWK")
    verifier = data.get("verifier", {})
    _validate_absolute_url(verifier.get("gateway_url"), "verifier.gateway_url")
    expected_profile = {
        "oid4vp-verifier": "oid4vp-1.0-final",
        "oid4vp-url-query-verifier": "oid4vp-1.0-final",
        "oid4vp-mdoc-verifier": "oid4vp-1.0-final",
        "oid4vp-haip-verifier": "oid4vp-haip-1.0",
    }[profile_name]
    if verifier.get("profile") != expected_profile:
        raise ValueError(
            f"verifier.profile must be {expected_profile!r} for {profile_name}; "
            "a mismatched profile cannot produce authoritative evidence"
        )
    if profile_name != "oid4vp-url-query-verifier":
        anchor = data.get("client", {}).get("request_object_trust_anchor_pem")
        if not isinstance(anchor, str) or not anchor.strip() or "REPLACE_" in anchor:
            raise ValueError(
                "client.request_object_trust_anchor_pem is required by the signed request_uri verifier plan"
            )
    if data.get("browser") != VERIFICATION_EVIDENCE_BROWSER_AUTOMATION:
        raise ValueError(
            "verifier configuration must use only the reviewed OIDF verification-evidence screenshot automation"
        )


def runner_relative_path(path: Path, runner: Path) -> str:
    """Return a runner-relative path safe for the suite's positional parser.

    The upstream runner uses ``:`` in its test-plan grammar.  On Windows an
    absolute drive path therefore looks like a malformed test-plan argument.
    A relative path works on every platform and keeps the config outside the
    runner checkout when desired.
    """
    resolved_path = path.resolve()
    resolved_runner = runner.resolve()
    if resolved_path.is_relative_to(resolved_runner):
        return str(resolved_path.relative_to(resolved_runner))
    # The upstream plan grammar treats backslashes as separators outside the
    # configuration-file token.  Normalize the relative path for Windows as
    # well as POSIX hosts before passing it as a positional argument.
    return Path(os.path.relpath(resolved_path, resolved_runner)).as_posix()


def file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def applicable_expected_skips(config: Path) -> list[dict]:
    """Return only skip declarations that can apply to this configuration.

    The upstream runner treats every entry in its expected-skips file as a
    promise that a matching skip will occur. Passing issuer-only declarations
    to a verifier plan therefore makes an otherwise clean verifier run fail.
    Preserve the centrally reviewed declarations, but give the runner the
    configuration-scoped subset it can actually observe.
    """
    entries = json.loads((ROOT / "conformance" / "expected-skips.json").read_text(encoding="utf-8"))
    return [entry for entry in entries if fnmatch.fnmatchcase(config.name, str(entry["configuration-filename"]))]


def requires_interaction_hook(test_name: str, expected_skips: list[dict]) -> bool:
    """Return whether an official module may receive a product interaction.

    Expected skips are reviewed, configuration-scoped declarations that the
    upstream runner enforces independently. Starting an asynchronous issuer or
    browser hook for one of those modules can race the runner after it has
    already skipped the module, creating a false harness failure. Unexpected
    skips and every active module remain untouched and blocking.
    """
    return not any(entry.get("test-name") == test_name for entry in expected_skips)


def write_failure_diagnostics(output: Path) -> list[dict[str, object]]:
    """Extract a deliberately small, public-safe view of failures and blocking warnings.

    The official export ZIPs remain byte-for-byte unchanged and authoritative.
    This owned diagnostic records only module/condition/block identifiers plus
    allow-listed HTTP status and protocol error-code facts. It never copies
    request bodies, response bodies, headers, URLs, tokens, keys, or free-form
    messages from the upstream result.
    """
    diagnostics: list[dict[str, object]] = []
    allowed_detail_keys = {
        "http_status",
        "expected_status_codes",
        "error",
        "expected_error",
    }

    def error_category(description: str) -> str | None:
        """Map owned product descriptions to non-sensitive stable categories."""
        normalized = description.casefold()
        categories = (
            ("key attestation nonce", "key-attestation-nonce"),
            ("has no resolved tenant issuer policy", "key-attestation-policy-unresolved"),
            ("issuer profile requires a key-attestation-bound proof", "key-attestation-missing"),
            ("proof key_attestation header", "key-attestation-header"),
            ("certificate chain is not trusted", "key-attestation-untrusted-certificate"),
            ("key attestation certificate", "key-attestation-certificate"),
            ("key attestation algorithm", "key-attestation-algorithm"),
            ("key attestation typ", "key-attestation-type"),
            ("key attestation signature", "key-attestation-signature"),
            ("key-storage requirements", "key-attestation-storage"),
            ("user-authentication requirements", "key-attestation-user-authentication"),
            ("attested public key", "key-attestation-holder-binding"),
            ("proof signature", "proof-signature"),
            ("proof nonce", "proof-nonce"),
            ("proof of possession", "proof-of-possession"),
        )
        return next((category for phrase, category in categories if phrase in normalized), None)

    def error_categories(value: object) -> set[str]:
        categories: set[str] = set()
        stack = [value]
        while stack:
            current = stack.pop()
            if isinstance(current, dict):
                for key, child in current.items():
                    if key == "error_description" and isinstance(child, str):
                        category = error_category(child)
                        if category is not None:
                            categories.add(category)
                    stack.append(child)
            elif isinstance(current, list):
                stack.extend(current)
        return categories

    def safe_details(value: object) -> dict[str, object]:
        found: dict[str, object] = {}
        if isinstance(value, dict):
            for key, child in value.items():
                if key in allowed_detail_keys:
                    if key in {"http_status", "expected_status_codes"}:
                        if (
                            isinstance(child, int)
                            or isinstance(child, list)
                            and all(isinstance(item, int) for item in child)
                        ):
                            found[key] = child
                    elif isinstance(child, str) and re.fullmatch(r"[a-z0-9_]{1,80}", child):
                        found[key] = child
                found.update({name: detail for name, detail in safe_details(child).items() if name not in found})
        elif isinstance(value, list):
            for child in value:
                found.update({name: detail for name, detail in safe_details(child).items() if name not in found})
        return found

    for archive in sorted(output.glob("*.zip")):
        with zipfile.ZipFile(archive) as result_zip:
            for name in sorted(result_zip.namelist()):
                if not name.endswith(".json"):
                    continue
                raw: object = json.loads(result_zip.read(name))
                if not isinstance(raw, dict):
                    continue
                test_info = raw.get("testInfo")
                results = raw.get("results")
                if not isinstance(test_info, dict) or not isinstance(results, list):
                    continue
                module = test_info.get("testName")
                if not isinstance(module, str) or not module:
                    continue
                module_categories = error_categories(results)
                blocks: dict[str, str] = {}
                for entry in results:
                    if not isinstance(entry, dict):
                        continue
                    block_id = entry.get("blockId")
                    if entry.get("startBlock") is True and entry.get("src") == "-START-BLOCK-":
                        if isinstance(block_id, str) and isinstance(entry.get("msg"), str):
                            blocks[block_id] = entry["msg"]
                        continue
                    if (
                        entry.get("result") == "WARNING"
                        and entry.get("src") == "VP1FinalCheckForUnexpectedParametersInVpClientMetadata"
                        and SAFE_MODULE.fullmatch(module)
                    ):
                        parameters = entry.get("unknown_params")
                        diagnostics.append(
                            {
                                "module": module,
                                "condition": "VP1FinalCheckForUnexpectedParametersInVpClientMetadata",
                                "result": "WARNING",
                                "error_category": "unexpected-client-metadata",
                                "unexpected_parameters": sorted(
                                    {
                                        value
                                        for value in parameters
                                        if isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", value)
                                    }
                                )
                                if isinstance(parameters, list)
                                else [],
                            }
                        )
                        continue
                    if entry.get("result") != "FAILURE":
                        continue
                    condition = entry.get("src")
                    if not isinstance(condition, str) or not condition:
                        continue
                    diagnostic: dict[str, object] = {
                        "module": module,
                        "condition": condition,
                    }
                    if isinstance(block_id, str) and block_id in blocks:
                        diagnostic["block"] = blocks[block_id]
                    diagnostic.update(safe_details(entry))
                    entry_categories = error_categories(entry)
                    category = next(iter(entry_categories), None)
                    if category is None and len(module_categories) == 1:
                        category = next(iter(module_categories))
                    if category is not None:
                        diagnostic["error_category"] = category
                    diagnostics.append(diagnostic)

    destination = output / "failure-diagnostics.json"
    destination.write_text(json.dumps(diagnostics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("OIDF public-safe failure diagnostics:", json.dumps(diagnostics, sort_keys=True), flush=True)
    return diagnostics


BROWSER_AUTOMATION_MESSAGES = {
    "Scripted browser HTTP request": "request-started",
    "Scripted browser HTTP response": "response-received",
    "Waiting": "wait-started",
    "Updated placeholder from scripted browser": "placeholder-updated",
    "All placeholders filled by scripted browser": "all-placeholders-filled",
    "Completed processing of webpage": "task-completed",
    "Unexpected URL for non-optional task": "task-url-mismatch",
}
BROWSER_AUTOMATION_SOURCES = {"BROWSER", "WebRunner"}
SAFE_MODULE = re.compile(r"^[A-Za-z0-9_.:-]{1,180}$")
SAFE_MODULE_STATES = {"CONFIGURED", "RUNNING", "WAITING", "FINISHED", "INTERRUPTED"}
SAFE_MODULE_RESULTS = {"UNKNOWN", "PASSED", "WARNING", "REVIEW", "SKIPPED", "FAILED"}


def write_browser_automation_diagnostics(output: Path) -> list[dict[str, object]]:
    """Record only fixed BrowserControl lifecycle facts from official exports.

    The exported logs can contain request objects, credentials, URLs, and test
    instance IDs. This diagnostic copies none of those values. It reports only
    the public test name, allowlisted state/result enums, and fixed categories
    derived from exact upstream BrowserControl messages.
    """

    diagnostics: list[dict[str, object]] = []
    for archive in sorted(output.glob("*.zip")):
        with zipfile.ZipFile(archive) as result_zip:
            for name in sorted(result_zip.namelist()):
                if not name.endswith(".json"):
                    continue
                raw: object = json.loads(result_zip.read(name))
                if not isinstance(raw, dict):
                    continue
                test_info = raw.get("testInfo")
                results = raw.get("results")
                if not isinstance(test_info, dict) or not isinstance(results, list):
                    continue
                module = test_info.get("testName")
                if not isinstance(module, str) or not SAFE_MODULE.fullmatch(module):
                    continue

                browser_entries = [
                    entry
                    for entry in results
                    if isinstance(entry, dict) and entry.get("src") in BROWSER_AUTOMATION_SOURCES
                ]
                status = test_info.get("status")
                if not browser_entries and status != "WAITING":
                    continue

                categories: set[str] = set()
                for entry in browser_entries:
                    message = entry.get("msg")
                    if isinstance(message, str) and message in BROWSER_AUTOMATION_MESSAGES:
                        categories.add(BROWSER_AUTOMATION_MESSAGES[message])
                    if entry.get("result") == "FAILURE":
                        categories.add("browser-runner-failure")
                if not categories:
                    categories.add("automation-not-observed" if not browser_entries else "unclassified-browser-event")

                diagnostic: dict[str, object] = {
                    "module": module,
                    "events": sorted(categories),
                }
                if status in SAFE_MODULE_STATES:
                    diagnostic["status"] = status
                result = test_info.get("result")
                if result in SAFE_MODULE_RESULTS:
                    diagnostic["result"] = result
                diagnostics.append(diagnostic)

    destination = output / "browser-automation-diagnostics.json"
    destination.write_text(json.dumps(diagnostics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("OIDF public-safe browser diagnostics:", json.dumps(diagnostics, sort_keys=True), flush=True)
    return diagnostics


def exported_module_documents(output: Path) -> list[dict[str, Any]]:
    """Read unchanged upstream module documents through one export boundary."""
    documents = []
    for archive in sorted(output.glob("*.zip")):
        with zipfile.ZipFile(archive) as exported:
            for path in exported.namelist():
                if not path.endswith(".json"):
                    continue
                raw = json.loads(exported.read(path))
                if not isinstance(raw, dict) or not isinstance(raw.get("testInfo"), dict):
                    continue
                documents.append(raw)
    return documents


def exported_module_info(output: Path) -> list[dict[str, Any]]:
    return [document["testInfo"] for document in exported_module_documents(output)]


def strict_module_summary(output: Path, expected_skips: list[dict]) -> dict[str, object]:
    """A successful runner process cannot qualify missing or review-only results."""
    modules: dict[str, dict[str, object]] = {}
    for info in exported_module_info(output):
        name = info.get("testName")
        if not isinstance(name, str) or not SAFE_MODULE.fullmatch(name):
            raise ValueError("official export has an invalid module name")
        if name in modules:
            raise ValueError("official export has ambiguous duplicate module results")
        status = info.get("status")
        result = info.get("result")
        modules[name] = {
            "test_name": name,
            "status": status if isinstance(status, str) and status in SAFE_MODULE_STATES else "UNKNOWN",
            "result": result if isinstance(result, str) and result in SAFE_MODULE_RESULTS else "UNKNOWN",
        }
    rows = list(modules.values())
    pending_review = [row["test_name"] for row in rows if row["result"] == "REVIEW"]
    unexpected_skips = [
        row["test_name"]
        for row in rows
        if row["result"] == "SKIPPED"
        and not any(fnmatch.fnmatchcase(str(row["test_name"]), entry["test-name"]) for entry in expected_skips)
    ]
    passed = (
        any(row["result"] == "PASSED" for row in rows)
        and not unexpected_skips
        and all(row["status"] == "FINISHED" and row["result"] in {"PASSED", "SKIPPED"} for row in rows)
    )
    return {
        "schema": "elevenid.official-oidf-module-results/v1",
        "source_policy": "unmodified",
        "modules": rows,
        "counts": dict(Counter(str(row["result"]) for row in rows)),
        "pending_review": pending_review,
        "unexpected_skips": unexpected_skips,
        "passed": passed,
    }


def compare_plan_coverage(infos: list[dict[str, Any]], plan: Any, selection: str) -> dict[str, object]:
    """Bind every exported instance to the complete, live upstream plan."""
    name, _, suffix = selection.partition("[")
    pairs = re.findall(r"\[([A-Za-z0-9_]+)=([A-Za-z0-9_.:-]+)\]", "[" + suffix if suffix else "")
    if selection != name + "".join(f"[{key}={value}]" for key, value in pairs) or len(dict(pairs)) != len(pairs):
        raise ValueError("invalid official plan selection")
    variant = dict(pairs)
    if not isinstance(plan, dict) or plan.get("planName") != name or plan.get("variant") != variant:
        raise ValueError("live official plan does not match the selected profile")
    plan_id = plan.get("_id")
    if not isinstance(plan_id, str) or not re.fullmatch(r"[A-Za-z0-9]{1,180}", plan_id):
        raise ValueError("invalid official plan identity")
    expected: dict[str, tuple[str, dict[str, str]]] = {}
    module_bindings = []
    modules = plan.get("modules")
    if not isinstance(modules, list) or not modules:
        raise ValueError("official plan contains no modules")
    for module in modules:
        if not isinstance(module, dict):
            raise ValueError("invalid official plan module")
        module_name = module.get("testModule")
        instances = module.get("instances")
        extra_variant = module.get("variant")
        if (
            not isinstance(module_name, str)
            or not SAFE_MODULE.fullmatch(module_name)
            or module_name in expected
            or not isinstance(extra_variant, dict)
            or not all(
                isinstance(k, str) and re.fullmatch(r"[A-Za-z0-9_]{1,80}", k)
                and isinstance(v, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,120}", v)
                for k, v in extra_variant.items()
            )
            or not isinstance(instances, list)
            or len(instances) != 1
            or not isinstance(instances[0], str)
            or not re.fullmatch(r"[A-Za-z0-9]{1,180}", instances[0])
        ):
            raise ValueError("official plan has missing or ambiguous module instances")
        expected[module_name] = (instances[0], {**variant, **extra_variant})
        module_bindings.append({
            "test_name": module_name,
            "test_id": instances[0],
            # Match stock run-test-plan.py's callback naming exactly. The raw
            # TestInfo name stays undecorated; never strip unverified suffixes.
            "interaction_name": module_name + "".join(
                f"[{key}={extra_variant[key]}]" for key in sorted(extra_variant)
            ),
        })
    if len({identity for identity, _ in expected.values()}) != len(expected):
        raise ValueError("official plan reuses an instance identity")
    exported = set()
    for info in infos:
        module_name = info.get("testName")
        if not isinstance(module_name, str) or module_name not in expected or module_name in exported:
            raise ValueError("official export has unexpected or duplicate modules")
        identity, module_variant = expected[module_name]
        if (
            info.get("planId") != plan_id
            or info.get("testId") != identity
            or info.get("_id") != identity
            or info.get("variant") != module_variant
        ):
            raise ValueError("official export does not match its live plan instance")
        exported.add(module_name)
    missing = sorted(expected.keys() - exported)
    # Hash only the bounded binding, never the plan's private configuration.
    binding = {"plan_id": plan_id, "selection": selection, "modules": expected}
    return {
        "complete": not missing,
        "expected_modules": sorted(expected),
        "missing_modules": missing,
        "exported_module_count": len(exported),
        "module_bindings": sorted(module_bindings, key=lambda row: row["test_name"]),
        "binding_sha256": sha256(json.dumps(binding, sort_keys=True).encode()).hexdigest(),
    }


def official_plan_coverage(output: Path, selection: str) -> dict[str, object]:
    """Read the actual selected plan before teardown; unavailable evidence fails closed."""
    try:
        # Reuse the existing public OIDF transport, including scoped local DNS,
        # configured trust and the runner's explicit local TLS mode.
        from oidf_marty_verifier import request_json

        infos = exported_module_info(output)
        plan_ids = {info.get("planId") for info in infos}
        if len(plan_ids) != 1:
            raise ValueError("official exports do not identify one plan")
        plan_id = next(iter(plan_ids))
        if not isinstance(plan_id, str) or not re.fullmatch(r"[A-Za-z0-9]{1,180}", plan_id):
            raise ValueError("invalid official plan identity")
        server = os.environ.get("CONFORMANCE_SERVER", "")
        _validate_absolute_url(server, "CONFORMANCE_SERVER")
        token = os.environ.get("CONFORMANCE_TOKEN")
        status, plan = request_json(
            server.rstrip("/") + "/api/plan/" + plan_id,
            headers={"Authorization": "Bearer " + token} if token else {},
            insecure="CONFORMANCE_DEV_MODE" in os.environ or "DISABLE_SSL_VERIFY" in os.environ,
        )
        if status != 200:
            raise ValueError("official plan readback failed")
        return compare_plan_coverage(infos, plan, selection)
    except Exception as error:  # noqa: BLE001 - API errors/configuration may contain credentials
        return {"complete": False, "error_class": type(error).__name__}


def artifact_inventory(output: Path) -> list[dict[str, str]]:
    """Hash regular artifacts only; never follow a link outside owned output."""
    if output.is_symlink():
        raise ValueError("official artifact directory must not be a symlink")
    artifacts = []
    for path in sorted(output.rglob("*")):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError("official artifacts must be regular files or directories")
        if path.is_file() and path != output / "evidence.json":
            artifacts.append({"path": path.relative_to(output).as_posix(), "sha256": file_sha256(path)})
    return artifacts


def finalize_evidence_artifacts(output: Path) -> dict:
    """Append late capture/stock-image receipts without changing any verdict.

    The stock ZIP, module table and every previously hashed artifact must remain
    byte-identical. This is inventory finalization, never REVIEW approval.
    """
    path = output / "evidence.json"
    if path.is_symlink() or not path.is_file():
        raise ValueError("official evidence must be a regular file")
    evidence = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(evidence, dict) or evidence.get("schema") != "elevenid.official-interop-evidence/v1":
        raise ValueError("official evidence schema is invalid")
    original = evidence.get("artifacts")
    if not isinstance(original, list) or not original or any(
        not isinstance(row, dict) or not isinstance(row.get("path"), str)
        or not isinstance(row.get("sha256"), str) for row in original
    ):
        raise ValueError("original official artifact inventory is invalid")
    expected = {row["path"]: row["sha256"] for row in original}
    artifacts = artifact_inventory(output)
    current = {row["path"]: row["sha256"] for row in artifacts}
    if len(expected) != len(original) or any(current.get(name) != digest for name, digest in expected.items()):
        raise ValueError("an original official artifact changed or disappeared")
    evidence["artifacts"] = artifacts
    pending = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=output,
                                         prefix=".finalize-evidence-", delete=False) as target:
            pending = Path(target.name)
            json.dump(evidence, target, indent=2, sort_keys=True)
            target.write("\n")
        pending.replace(path)
    finally:
        if pending is not None:
            pending.unlink(missing_ok=True)
    return evidence


def write_evidence(
    output: Path,
    manifest: dict,
    profile_name: str,
    config: Path,
    runner: Path,
    exit_code: int,
    stack_manifest: Path | None,
    execution_mode: str,
    expected_skips: list[dict] | None = None,
) -> int:
    """Write non-secret provenance alongside an official suite export.

    Configurations can contain private signing keys, so evidence records their
    digest and path only. Result files are listed by digest after the official
    runner exits; this makes later review independent of mutable runner state.
    """
    stack: dict[str, object] | None = None
    if stack_manifest is not None:
        raw_stack = json.loads(stack_manifest.read_text(encoding="utf-8"))
        if raw_stack.get("schema") != "marty.stack/v1":
            raise ValueError("stack manifest must use marty.stack/v1")
        stack = {
            "path": str(stack_manifest),
            "sha256": file_sha256(stack_manifest),
            "release": raw_stack.get("release"),
        }
    effective_skips = expected_skips if expected_skips is not None else applicable_expected_skips(config)
    module_summary = strict_module_summary(output, effective_skips)
    coverage = official_plan_coverage(output, manifest["profiles"][profile_name]["test_plan"])
    module_summary["plan_coverage"] = coverage
    module_summary["passed"] = module_summary["passed"] and coverage["complete"]
    (output / "module-results.json").write_text(
        json.dumps(module_summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    qualified_exit = exit_code or (0 if module_summary["passed"] else 1)
    artifacts = artifact_inventory(output)
    evidence = {
        "schema": "elevenid.official-interop-evidence/v1",
        "official_runner": manifest["official_runner"],
        "profile": profile_name,
        "execution_mode": execution_mode,
        "runner": {"path": str(runner), "commit": git_revision(runner)},
        "marty": {"commit": os.environ.get("MARTY_COMMIT", "unrecorded"), "stack_manifest": stack},
        "configuration": {"path": str(config), "sha256": file_sha256(config)},
        "exclusions": {
            "expected_failures": json.loads(
                (ROOT / "conformance" / "expected-failures.json").read_text(encoding="utf-8")
            ),
            "expected_skips": effective_skips,
        },
        "result": {"exit_code": qualified_exit, "process_exit_code": exit_code, "passed": qualified_exit == 0},
        "module_results": module_summary,
        "artifacts": artifacts,
    }
    (output / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return qualified_exit


def execution_mode(profile_name: str, profile: dict, *, allow_planned: bool, stack_manifest: Path | None) -> str:
    """Allow an evidence-only run before a verifier profile is activated.

    A planned profile must be runnable to earn activation, but that execution
    must not turn into an accidental support claim. Requiring both an explicit
    switch and an attested stack manifest makes the pre-activation run
    reviewable and keeps ordinary/release invocations strict.
    """
    status = profile.get("status")
    if status == "active":
        return "active"
    if status != "planned":
        raise ValueError(f"profile {profile_name} has unsupported status {status!r}")
    if not allow_planned:
        raise ValueError(f"profile {profile_name} is not active: {profile.get('reason', 'no reason recorded')}")
    if stack_manifest is None:
        raise ValueError("--stack-manifest is required for an evidence-only planned-profile run")
    return "pre-activation"


def validate_verifier_interaction_environment(profile_name: str) -> None:
    """Reject a verifier hook that would drive the wrong official transport.

    The OIDF runner's plan is immutable, but the bridge invokes a deployment
    command through environment variables.  Checking that small boundary here
    prevents a pre-activation run from silently substituting a different
    transport and then leaving misleading evidence.
    """
    expected = {
        "oid4vp-verifier": ("standard", "request_uri_signed"),
        "oid4vp-url-query-verifier": ("standard", "url_query"),
        "oid4vp-mdoc-verifier": ("standard", "request_uri_signed"),
        "oid4vp-haip-verifier": ("haip", "request_uri_signed"),
    }.get(profile_name)
    if expected is None:
        return
    expected_profile, expected_method = expected
    actual_profile = os.environ.get("OIDF_MARTY_VERIFIER_PROFILE", "standard").strip()
    actual_method = os.environ.get("OIDF_VERIFIER_REQUEST_METHOD", "request_uri_signed").strip()
    if actual_profile != expected_profile or actual_method != expected_method:
        raise ValueError(
            f"{profile_name} requires OIDF_MARTY_VERIFIER_PROFILE={expected_profile!r} "
            f"and OIDF_VERIFIER_REQUEST_METHOD={expected_method!r}; got "
            f"{actual_profile!r} and {actual_method!r}"
        )


def cmd_validate(_args: argparse.Namespace) -> int:
    manifest = load_manifest()
    validate_expected_failures()
    print(f"OIDF runner manifest is valid: {manifest['official_runner']['release']}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    manifest = load_manifest()
    validate_expected_failures()
    profile = manifest["profiles"].get(args.profile)
    if profile is None:
        raise ValueError(f"unknown profile: {args.profile}")
    mode = execution_mode(
        args.profile,
        profile,
        allow_planned=args.allow_planned_profile,
        stack_manifest=args.stack_manifest,
    )
    runner = args.runner.resolve()
    config = args.config.resolve()
    validate_runner(runner, manifest)
    validate_config(config, args.profile)
    if args.interaction_script is not None:
        validate_verifier_interaction_environment(args.profile)
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    expected_skips = applicable_expected_skips(config)
    effective_expected_skips = output / "expected-skips-effective.json"
    effective_expected_skips.write_text(
        json.dumps(expected_skips, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    config_argument = runner_relative_path(config, runner)
    command = [
        sys.executable,
        "scripts/run-test-plan.py",
        "--no-parallel",
        "--verbose",
        "--export-dir",
        str(output),
        "--expected-failures-file",
        str((ROOT / "conformance" / "expected-failures.json").resolve()),
        "--expected-skips-file",
        str(effective_expected_skips),
        profile["test_plan"],
        config_argument,
    ]
    if args.rerun:
        command[3:3] = ["--rerun", args.rerun]
    print("Running the official OIDF plan:", profile["test_plan"])
    if args.interaction_script is None:
        result = subprocess.run(command, cwd=runner, check=False).returncode
        validate_runner(runner, manifest)
        write_failure_diagnostics(output)
        write_browser_automation_diagnostics(output)
        return write_evidence(
            output,
            manifest,
            args.profile,
            config,
            runner,
            result,
            args.stack_manifest,
            mode,
            expected_skips,
        )

    interaction_script = args.interaction_script.resolve()
    if not interaction_script.is_file():
        raise ValueError(f"OIDF interaction script is missing: {interaction_script}")
    browser_interaction_script = args.browser_interaction_script.resolve() if args.browser_interaction_script else None
    if browser_interaction_script is not None and not browser_interaction_script.is_file():
        raise ValueError(f"OIDF browser interaction script is missing: {browser_interaction_script}")

    # The official runner prints a module ID immediately after creating it and
    # then waits for the issuer interaction.  Keep the runner unmodified while
    # allowing an implementation-owned script to drive that interaction.  The
    # hook receives only public test metadata through arguments; credentials
    # remain environment variables owned by the invoking environment.
    current_module = ""
    hooks: list[subprocess.Popen[bytes]] = []
    process = subprocess.Popen(
        # ``run-test-plan.py`` is a Python program.  Its output becomes a pipe
        # here, so force unbuffered mode; otherwise a waiting official module
        # can deadlock before the interaction hook sees its ID.
        [command[0], "-u", *command[1:]],
        cwd=runner,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert process.stdout is not None
    for line in process.stdout:
        print(line, end="")
        match = re.search(r"Running test module: (.+)", line)
        if match:
            current_module = match.group(1).strip()
            continue
        match = re.search(r"Created test module, new id: ([A-Za-z0-9]+)", line)
        if match:
            if not requires_interaction_hook(current_module, expected_skips):
                print(f"Not starting a product interaction for expected-skipped module {current_module}")
                continue
            hook_command = [
                sys.executable,
                str(interaction_script),
                "--test-id",
                match.group(1),
                "--test-name",
                current_module,
                "--server",
                os.environ.get("CONFORMANCE_SERVER", ""),
            ]
            hooks.append(subprocess.Popen(hook_command, cwd=ROOT))
            if browser_interaction_script is not None:
                hooks.append(
                    subprocess.Popen(
                        [
                            sys.executable,
                            str(browser_interaction_script),
                            "--test-id",
                            match.group(1),
                            "--test-name",
                            current_module,
                            "--server",
                            os.environ.get("CONFORMANCE_SERVER", ""),
                        ],
                        cwd=ROOT,
                    )
                )

    runner_result = process.wait()
    hook_result = 0
    for hook in hooks:
        hook_result = hook.wait() or hook_result
    result = runner_result or hook_result
    validate_runner(runner, manifest)
    write_failure_diagnostics(output)
    write_browser_automation_diagnostics(output)
    return write_evidence(
        output, manifest, args.profile, config, runner, result, args.stack_manifest, mode, expected_skips
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("validate")
    run = commands.add_parser("run")
    run.add_argument("--runner", type=Path, required=True)
    run.add_argument("--profile", required=True)
    run.add_argument("--config", type=Path, required=True)
    run.add_argument("--output-dir", type=Path, required=True)
    run.add_argument(
        "--stack-manifest",
        type=Path,
        help="attested marty.stack/v1 manifest for the deployment under test",
    )
    run.add_argument(
        "--allow-planned-profile",
        action="store_true",
        help="run a planned profile only to produce pre-activation evidence; requires --stack-manifest",
    )
    run.add_argument("--rerun", help="official runner plan/module selector, for example 1:3")
    run.add_argument(
        "--interaction-script",
        type=Path,
        help="implementation-owned script invoked for each official test module",
    )
    run.add_argument(
        "--browser-interaction-script",
        type=Path,
        help="local browser adapter invoked for each official test module",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "validate":
        return cmd_validate(args)
    if args.command == "run":
        return cmd_run(args)
    raise ValueError(f"unsupported OIDF conformance command: {args.command}")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f"OIDF conformance setup error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
