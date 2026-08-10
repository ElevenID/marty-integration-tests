#!/usr/bin/env python3
"""Classify OIDF SD-JWT verifier outcomes without publishing private values.

The deployment adapter records the official public module name and the Marty
flow identifier in a private directory. This audit correlates those records
with the private Compose log, then emits only allowlisted result, decision,
and error-category values. Flow identifiers, tokens, claims, URLs, and raw
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
            "result": match.group("result").lower(),
            "decision": match.group("decision").lower(),
            "category": (
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


def audit(mapping_dir: Path, compose_log: Path) -> dict[str, Any]:
    """Return a public-safe per-module verifier outcome report."""
    mappings = _private_mappings(mapping_dir)
    outcomes = _runtime_outcomes(compose_log)
    modules: list[dict[str, str]] = []
    for flow, test_name in sorted(mappings.items(), key=lambda item: item[1]):
        outcome = outcomes.get(flow)
        if outcome is None:
            outcome = {
                "result": "unavailable",
                "decision": "unavailable",
                "category": "runtime-outcome-unavailable",
            }
        modules.append({"test_name": test_name, **outcome})
    return {
        "schema": "elevenid.oidf-sd-jwt-diagnostic-audit/v1",
        "source_policy": "unmodified",
        "modules": modules,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--mapping-dir", type=Path, required=True)
    result.add_argument("--compose-log", type=Path, required=True)
    result.add_argument("--output", type=Path, required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    report = audit(args.mapping_dir, args.compose_log)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print("--- OIDF SD-JWT verifier audit (redacted) ---")
    for module in report["modules"]:
        print(
            f"{module['test_name']}: result={module['result']} "
            f"decision={module['decision']} category={module['category']}"
        )
    print("--- end OIDF SD-JWT verifier audit ---")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
