"""Tests for the private-to-public-safe OIDF SD-JWT diagnostic audit."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "oidf_sd_jwt_audit",
    ROOT / "scripts" / "oidf_sd_jwt_diagnostic_audit.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load OIDF SD-JWT diagnostic audit")
audit_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit_module)


def write_mapping(directory: Path, name: str, flow: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{name}.json").write_text(
        json.dumps(
            {
                "schema": "elevenid.oidf-flow-correlation/private-v1",
                "test_name": name,
                "flow_instance_id": flow,
            }
        ),
        encoding="utf-8",
    )


def write_official_failures(path: Path, failures: list[dict[str, object]]) -> None:
    path.write_text(json.dumps(failures), encoding="utf-8")


def test_audit_correlates_modules_and_emits_only_fixed_categories(tmp_path: Path) -> None:
    mapping = tmp_path / "mapping"
    positive_flow = "12345678-1234-1234-1234-123456789abc"
    negative_flow = "abcdefab-cdef-cdef-cdef-abcdefabcdef"
    write_mapping(mapping, "oid4vp-1final-verifier-happy-flow", positive_flow)
    write_mapping(mapping, "oid4vp-1final-verifier-invalid-kb-jwt-nonce", negative_flow)
    compose = tmp_path / "compose.log"
    compose.write_text(
        "token=must-not-leak\n"
        f"Policy evaluation for {positive_flow}: result=failed decision=deny "
        "reason=Credential verification failed: SD-JWT verification failed: "
        'DeserializationError("Cannot decode jwt: InvalidAudience")\n'
        f"Policy evaluation for {negative_flow}: result=failed decision=deny "
        "reason=Credential verification failed: Key Binding JWT nonce does not match "
        "the request secret=must-not-leak\n",
        encoding="utf-8",
    )
    official = tmp_path / "failure-diagnostics.json"
    write_official_failures(
        official,
        [
            {
                "module": "oid4vp-1final-verifier-happy-flow",
                "condition": "EnsureHttpStatusCodeIs200",
                "block": "Authorization endpoint",
                "http_status": 400,
            }
        ],
    )

    report = audit_module.audit(mapping, compose, official)

    assert report == {
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
            },
            {
                "test_name": "oid4vp-1final-verifier-invalid-kb-jwt-nonce",
                "marty_flow_result": "failed",
                "marty_flow_decision": "deny",
                "marty_flow_category": "key-binding-nonce-invalid",
                "official_failure_stage": "no-official-failure-observed",
                "official_http_status": None,
            },
        ],
    }
    serialized = json.dumps(report)
    assert positive_flow not in serialized
    assert negative_flow not in serialized
    assert "must-not-leak" not in serialized
    assert "Cannot decode jwt" not in serialized


def test_audit_reports_missing_runtime_outcome_without_private_values(tmp_path: Path) -> None:
    mapping = tmp_path / "mapping"
    flow = "12345678-1234-1234-1234-123456789abc"
    write_mapping(mapping, "oid4vp-1final-verifier-happy-flow", flow)
    compose = tmp_path / "compose.log"
    compose.write_text("token=must-not-leak\n", encoding="utf-8")
    official = tmp_path / "failure-diagnostics.json"
    write_official_failures(official, [])

    report = audit_module.audit(mapping, compose, official)

    assert report["modules"] == [
        {
            "test_name": "oid4vp-1final-verifier-happy-flow",
            "marty_flow_result": "unavailable",
            "marty_flow_decision": "unavailable",
            "marty_flow_category": "runtime-outcome-unavailable",
            "official_failure_stage": "no-official-failure-observed",
            "official_http_status": None,
        }
    ]


def test_audit_rejects_unsafe_module_names(tmp_path: Path) -> None:
    mapping = tmp_path / "mapping"
    write_mapping(
        mapping,
        "unsafe module token=must-not-leak",
        "12345678-1234-1234-1234-123456789abc",
    )
    compose = tmp_path / "compose.log"
    compose.write_text("", encoding="utf-8")
    official = tmp_path / "failure-diagnostics.json"
    write_official_failures(official, [])

    with pytest.raises(ValueError, match="unsafe module"):
        audit_module.audit(mapping, compose, official)


def test_audit_rejects_unmapped_or_conflicting_official_failure_facts(
    tmp_path: Path,
) -> None:
    mapping = tmp_path / "mapping"
    flow = "12345678-1234-1234-1234-123456789abc"
    write_mapping(mapping, "oid4vp-1final-verifier-happy-flow", flow)
    compose = tmp_path / "compose.log"
    compose.write_text("", encoding="utf-8")
    official = tmp_path / "failure-diagnostics.json"
    write_official_failures(
        official,
        [
            {
                "module": "oid4vp-1final-verifier-minimal-cnf-jwk",
                "condition": "EnsureHttpStatusCodeIs200",
                "block": "Authorization endpoint",
                "http_status": 400,
            }
        ],
    )
    with pytest.raises(ValueError, match="no private flow correlation"):
        audit_module.audit(mapping, compose, official)

    write_official_failures(
        official,
        [
            {
                "module": "oid4vp-1final-verifier-happy-flow",
                "condition": "EnsureHttpStatusCodeIs200",
                "block": "Authorization endpoint",
                "http_status": status,
            }
            for status in (400, 422)
        ],
    )
    with pytest.raises(ValueError, match="conflicting or invalid HTTP status"):
        audit_module.audit(mapping, compose, official)
