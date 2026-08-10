#!/usr/bin/env python3
"""Classify OIDF SD-JWT verifier outcomes without publishing private values.

The deployment adapter records the official public module name and the Marty
flow identifier in a private directory. This audit correlates those records
with the private Compose log and the owned public-safe view of the unchanged
Official export. It emits only allowlisted Marty flow outcomes and Official
interaction-stage facts. Flow identifiers, tokens, claims, URLs, and raw
error text are never included in the report.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

FLOW_ID_PATTERN = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
FLOW_ID = re.compile(rf"^{FLOW_ID_PATTERN}$")
SAFE_MODULE = re.compile(r"^oid4vp-[A-Za-z0-9_.:\[\]=,+/-]{1,292}$")
POLICY_OUTCOME = re.compile(
    rf"Policy evaluation for (?P<flow>{FLOW_ID_PATTERN}): "
    r"result=(?P<result>passed|failed|partial) "
    r"decision=(?P<decision>allow|deny|manual_review) "
    r"reason=(?P<reason>[^\r\n]*)",
    re.IGNORECASE,
)

# Order is significant: precise causes precede their broader fallback class.
FAILURE_CATEGORIES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("issuer-signature-invalid", re.compile(r"(?i)Cannot decode jwt:.{0,160}InvalidSignature")),
    ("issuer-token-expired", re.compile(r"(?i)Cannot decode jwt:.{0,160}ExpiredSignature")),
    ("issuer-audience-invalid", re.compile(r"(?i)Cannot decode jwt:.{0,160}InvalidAudience")),
    ("issuer-required-claim-missing", re.compile(r"(?i)Cannot decode jwt:.{0,160}MissingRequiredClaim")),
    ("issuer-key-invalid", re.compile(r"(?i)(?:Invalid issuer JWK|Failed to create decoding key)")),
    ("issuer-token-invalid", re.compile(r"(?i)Cannot decode jwt")),
    (
        "disclosure-invalid",
        re.compile(
            r"(?i)(?:invalid (?:array )?disclosure|Digest .{0,120} appears multiple times|"
            r"Key .{0,120} appears multiple times|invalid path|index .{0,120} is out of bounds)"
        ),
    ),
    (
        "holder-key-missing-or-invalid",
        re.compile(
            r"(?i)(?:No holder public key in SD-JWT|SD-JWT has no cnf\.jwk|"
            r"holder_public_key_payload is malformed|Cannot parse (?:JWK|DecodingKey)|"
            r"Invalid cnf\.jwk|Key Binding JWK is unusable)"
        ),
    ),
    (
        "key-binding-required",
        re.compile(r"(?i)(?:Key Binding JWT is required|Cannot take Key Binding JWK from String)"),
    ),
    (
        "key-binding-type-invalid",
        re.compile(r"(?i)(?:Invalid header type|Key Binding JWT header parse failed)"),
    ),
    (
        "key-binding-signature-invalid",
        re.compile(r"(?i)Key Binding JWT signature validation failed"),
    ),
    (
        "key-binding-hash-invalid",
        re.compile(r"(?i)(?:Invalid digest in KB-JWT|sd_hash does not bind this SD-JWT)"),
    ),
    (
        "key-binding-audience-invalid",
        re.compile(r"(?i)(?:Invalid audience|Key Binding JWT audience does not match)"),
    ),
    (
        "key-binding-nonce-invalid",
        re.compile(r"(?i)(?:Invalid nonce|Key Binding JWT nonce does not match|Nonce mismatch)"),
    ),
    (
        "key-binding-time-invalid",
        re.compile(r"(?i)(?:Key Binding JWT is missing a numeric iat|iat is outside the five-minute)"),
    ),
    ("did-resolution-failed", re.compile(r"(?i)DID resolution failed")),
    (
        "issuer-trust-material-missing",
        re.compile(r"(?i)issuer is not a DID and has no pinned trust-profile JWK"),
    ),
    (
        "native-verifier-unavailable",
        re.compile(r"(?i)marty-rs SD-JWT verification bindings are not installed"),
    ),
    ("unsupported-format", re.compile(r"(?i)unsupported credential format")),
    ("sd-jwt-verification-unclassified", re.compile(r"(?i)SD-JWT verification failed")),
)

DIRECT_POST_CONDITION = "EnsureHttpStatusCodeIs200"
DIRECT_POST_BLOCK = "Authorization endpoint"


def classify_failure(reason: str) -> str:
    """Map one private product reason to a fixed public-safe category."""
    return next(
        (category for category, pattern in FAILURE_CATEGORIES if pattern.search(reason)),
        "verification-denied-unclassified",
    )


def _private_mappings(directory: Path) -> dict[str, str]:
    mappings: dict[str, str] = {}
    for source in sorted(directory.glob("*.json")):
        value = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or value.get("schema") != "elevenid.oidf-flow-correlation/private-v1":
            raise ValueError("invalid private OIDF flow-correlation record")
        flow = value.get("flow_instance_id")
        test_name = value.get("test_name")
        if not isinstance(flow, str) or FLOW_ID.fullmatch(flow) is None:
            raise ValueError("private OIDF flow-correlation record has an invalid flow identifier")
        if not isinstance(test_name, str) or SAFE_MODULE.fullmatch(test_name) is None:
            raise ValueError("private OIDF flow-correlation record has an unsafe module name")
        previous = mappings.get(flow)
        if previous is not None and previous != test_name:
            raise ValueError("one Marty flow is mapped to conflicting official modules")
        mappings[flow] = test_name
    if not mappings:
        raise ValueError("no private OIDF flow-correlation records were found")
    return mappings


def _runtime_outcomes(compose_log: Path) -> dict[str, dict[str, str]]:
    text = compose_log.read_text(encoding="utf-8", errors="replace")
    outcomes: dict[str, dict[str, str]] = {}
    for match in POLICY_OUTCOME.finditer(text):
        values = {
            "marty_flow_result": match.group("result").lower(),
            "marty_flow_decision": match.group("decision").lower(),
            "marty_flow_category": (
                "accepted"
                if match.group("result").lower() == "passed" and match.group("decision").lower() == "allow"
                else classify_failure(match.group("reason"))
            ),
        }
        flow = match.group("flow").lower()
        previous = outcomes.get(flow)
        if previous is not None and previous != values:
            raise ValueError("one Marty flow emitted conflicting policy outcomes")
        outcomes[flow] = values
    return outcomes


def _official_failure_outcomes(path: Path) -> dict[str, dict[str, object]]:
    """Map the owned safe Official export view to fixed interaction stages."""
    raw: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("Official failure diagnostics must be a list")

    failures: dict[str, list[dict[str, object]]] = {}
    for entry in raw:
        if not isinstance(entry, dict):
            raise ValueError("Official failure diagnostic has an invalid shape")
        module = entry.get("module")
        condition = entry.get("condition")
        if not isinstance(module, str) or SAFE_MODULE.fullmatch(module) is None:
            raise ValueError("Official failure diagnostic has an unsafe module name")
        if not isinstance(condition, str) or not condition:
            raise ValueError("Official failure diagnostic has no condition")
        failures.setdefault(module, []).append(entry)

    outcomes: dict[str, dict[str, object]] = {}
    for module, entries in failures.items():
        direct_post = [
            entry
            for entry in entries
            if entry.get("condition") == DIRECT_POST_CONDITION
            and entry.get("block") == DIRECT_POST_BLOCK
        ]
        if not direct_post:
            outcomes[module] = {
                "official_failure_stage": "other-official-failure",
                "official_http_status": None,
            }
            continue
        statuses = {entry.get("http_status") for entry in direct_post}
        if (
            len(statuses) != 1
            or any(
                isinstance(status, bool) or not isinstance(status, int)
                for status in statuses
            )
        ):
            raise ValueError(
                "Official direct-post failures have conflicting or invalid HTTP status"
            )
        status = next(iter(statuses))
        if not 100 <= status <= 599:
            raise ValueError("Official direct-post failure HTTP status is out of range")
        outcomes[module] = {
            "official_failure_stage": "direct-post-callback-response",
            "official_http_status": status,
        }
    return outcomes


def audit(
    mapping_dir: Path,
    compose_log: Path,
    official_failure_diagnostics: Path,
) -> dict[str, Any]:
    """Return a public-safe per-module verifier and Official-stage report."""
    mappings = _private_mappings(mapping_dir)
    outcomes = _runtime_outcomes(compose_log)
    official_outcomes = _official_failure_outcomes(official_failure_diagnostics)
    if set(official_outcomes).difference(mappings.values()):
        raise ValueError("Official failures contain modules with no private flow correlation")
    modules: list[dict[str, object]] = []
    for flow, test_name in sorted(mappings.items(), key=lambda item: item[1]):
        outcome = outcomes.get(flow)
        if outcome is None:
            outcome = {
                "marty_flow_result": "unavailable",
                "marty_flow_decision": "unavailable",
                "marty_flow_category": "runtime-outcome-unavailable",
            }
        official = official_outcomes.get(
            test_name,
            {
                "official_failure_stage": "no-official-failure-observed",
                "official_http_status": None,
            },
        )
        modules.append({"test_name": test_name, **outcome, **official})
    return {
        "schema": "elevenid.oidf-sd-jwt-diagnostic-audit/v2",
        "source_policy": "unmodified",
        "modules": modules,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--mapping-dir", type=Path, required=True)
    result.add_argument("--compose-log", type=Path, required=True)
    result.add_argument("--official-failure-diagnostics", type=Path, required=True)
    result.add_argument("--output", type=Path, required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    report = audit(
        args.mapping_dir,
        args.compose_log,
        args.official_failure_diagnostics,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print("--- OIDF SD-JWT verifier audit (redacted) ---")
    for module in report["modules"]:
        print(
            f"{module['test_name']}: marty_flow_result={module['marty_flow_result']} "
            f"marty_flow_decision={module['marty_flow_decision']} "
            f"marty_flow_category={module['marty_flow_category']} "
            f"official_failure_stage={module['official_failure_stage']} "
            f"official_http_status={module['official_http_status']}"
        )
    print("--- end OIDF SD-JWT verifier audit ---")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
