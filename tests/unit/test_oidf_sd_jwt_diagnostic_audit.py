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


RUST_FLOW = "12345678-1234-1234-1234-123456789abc"


def native_rejection(reason: str | None = None, **overrides: object) -> str:
    diagnostic = {
        "result": "failed",
        "decision": "deny",
        "decision_reason": reason,
        "error_codes": ["PRIVATE-error-must-not-leak"],
        "credential_results": [{"signature_valid": False}],
    }
    fields = {
        "message": "OID4VP presentation authentication rejected",
        "flow_instance_id": RUST_FLOW,
        "organization_id": "PRIVATE-tenant",
        "diagnostic": json.dumps(diagnostic),
        **overrides,
    }
    return "flow-1  | " + json.dumps({"target": "marty_flow::verification_submission", "fields": fields})


@pytest.mark.parametrize(
    ("reason", "category"),
    [
        ("No governed issuer public JWK is available for SD-JWT", "issuer-trust-material-missing"),
        ("SD-JWT verification rejected the credential", "sd-jwt-verification-unclassified"),
        ("Key Binding JWT nonce does not match PRIVATE-nonce", "key-binding-nonce-invalid"),
        (None, "verification-denied-unclassified"),
        ("PRIVATE-customer-data unknown reason", "verification-denied-unclassified"),
    ],
)
def test_native_json_rejection_survives_public_sanitizer(tmp_path: Path, reason: str | None, category: str) -> None:
    mapping = tmp_path / "mapping"
    write_mapping(mapping, "oid4vp-1final-verifier-happy-flow", RUST_FLOW)
    compose = tmp_path / "compose.log"
    compose.write_text(native_rejection(reason) + "\n", encoding="utf-8")
    official = tmp_path / "failure-diagnostics.json"
    write_official_failures(official, [])
    report = audit_module.audit(mapping, compose, official)
    row = report["modules"][0]
    assert row["marty_flow_result"] == "failed"
    assert row["marty_flow_decision"] == "deny"
    assert row["marty_flow_category"] == category
    spec = importlib.util.spec_from_file_location(
        "native_diagnostic_sanitizer", ROOT / "scripts" / "sanitize_official_evidence.py"
    )
    sanitizer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sanitizer)
    assert sanitizer.sd_jwt_diagnostic_report(report) == report
    serialized = json.dumps(report)
    assert "PRIVATE" not in serialized
    assert RUST_FLOW not in serialized


@pytest.mark.parametrize(
    "fields",
    [
        {"flow_instance_id": "PRIVATE-invalid-id"},
        {"diagnostic": "not-json PRIVATE"},
        {"diagnostic": "[]"},
        {"diagnostic": json.dumps({"result": "passed", "decision": "allow"})},
        {"diagnostic": json.dumps({"result": "PRIVATE-result", "decision": "deny"})},
        {"diagnostic": "x" * 262145},
    ],
)
def test_malformed_native_rejection_cannot_become_an_outcome(fields: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="native Flow") as error:
        audit_module._rust_runtime_outcome(native_rejection(**fields))
    assert "PRIVATE" not in str(error.value)


def test_native_parser_ignores_other_log_owners_and_unrecognized_messages() -> None:
    line = native_rejection()
    assert audit_module._rust_runtime_outcome(line.replace("marty_flow::verification_submission", "unrelated")) is None
    assert (
        audit_module._rust_runtime_outcome(line.replace("OID4VP presentation authentication rejected", "unrelated"))
        is None
    )
    assert audit_module._rust_runtime_outcome("unrelated {not-json") is None


def test_native_conflicting_or_legacy_accepted_outcome_is_refused(tmp_path: Path) -> None:
    compose = tmp_path / "compose.log"
    legacy = f"Policy evaluation for {RUST_FLOW}: result=passed decision=allow reason=ok\n"
    compose.write_text(legacy + native_rejection(), encoding="utf-8")
    with pytest.raises(ValueError, match="conflicting policy outcomes"):
        audit_module._runtime_outcomes(compose)


def test_repeated_native_rejection_is_consistent(tmp_path: Path) -> None:
    compose = tmp_path / "compose.log"
    compose.write_text(native_rejection() + "\n" + native_rejection(), encoding="utf-8")
    assert len(audit_module._runtime_outcomes(compose)) == 1
