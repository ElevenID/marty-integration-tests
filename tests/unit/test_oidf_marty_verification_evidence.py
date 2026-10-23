from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "oidf_marty_verification_evidence", ROOT / "scripts" / "oidf_marty_verification_evidence.py"
)
assert SPEC
assert SPEC.loader
evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evidence)
FLOW = "12345678-1234-1234-1234-123456789abc"


@pytest.mark.parametrize("mutation", ["none", "variant", "instance"])
def test_correlations_require_exact_plan_variant_and_test_instance(tmp_path: Path, mutation: str) -> None:
    from oidf_marty_start_verification import PRIVATE_FLOW_AUDIT_SCHEMA, private_flow_audit_path

    name = "oid4vp-1final-verifier-happy-flow"
    label = name + "[vp_profile=haip]"
    source = private_flow_audit_path(tmp_path, "test1", FLOW)
    source.write_text(json.dumps({"schema": PRIVATE_FLOW_AUDIT_SCHEMA, "test_name": label, "flow_instance_id": FLOW}))
    binding = {"test_name": name, "test_id": "test1", "interaction_name": label}
    modules = {"modules": [{"test_name": name}], "plan_coverage": {"complete": True, "module_bindings": [binding]}}
    if mutation == "none":
        assert evidence.bound_correlations(tmp_path, modules) == {FLOW: name}
    else:
        binding["interaction_name" if mutation == "variant" else "test_id"] = "different"
        with pytest.raises((ValueError, FileNotFoundError)):
            evidence.bound_correlations(tmp_path, modules)


def test_outcomes_require_the_exact_public_flow_binding() -> None:
    with pytest.raises(ValueError, match="different flow"):
        evidence.outcome_projection({"instance_id": "other", "result": "passed"}, FLOW)
    with pytest.raises(ValueError, match="different flow"):
        evidence.outcome_projection({"instance_id": "unsafe-selector"}, "unsafe-selector")


def test_public_projection_cannot_publish_tokens_claims_or_server_error_text() -> None:
    projected = evidence.outcome_projection(
        {
            "instance_id": FLOW,
            "result": "passed",
            "decision": "allow",
            "status": "completed",
            "verified_claims": {"secret": "do-not-export"},
            "decision_reason": "private-url",
        },
        FLOW,
    )
    assert projected == {"result": "passed", "decision": "allow", "status": "completed"}
    assert evidence.outcome_projection({"instance_id": FLOW, "status": "COMPLETED"}, FLOW)["status"] == "completed"
    assert evidence.outcome_projection(
        {
            "instance_id": FLOW,
            "result": "do-not-export",
            "status": "private-url",
        },
        FLOW,
    ) == {"result": "UNKNOWN", "decision": "UNKNOWN", "status": "UNKNOWN"}


def test_pending_negative_submission_records_instance_state_without_a_terminal_decision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []

    def request(_base: str, _session: str, path: str) -> object:
        calls.append(path)
        if path.endswith("/result"):
            raise evidence.PublicGatewayHttpError(409, "private error text")
        return {"id": FLOW, "status": "AWAITING_WALLET", "result": "passed", "decision": "allow"}

    monkeypatch.setattr(evidence, "authenticated_json_request", request)
    _, projection, source = evidence.read_flow_evidence(
        "https://marty.test", "private-session", FLOW, review_required=False
    )
    assert projection == {"status": "awaiting_wallet", "result": "UNKNOWN", "decision": "UNKNOWN"}
    assert source == "instance_result_pending"
    assert len(calls) == 2


@pytest.mark.parametrize(("status", "review_required"), [(401, False), (403, False), (409, True), (500, False)])
def test_authentication_errors_and_unfinished_positive_flows_are_not_hidden(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    review_required: bool,
) -> None:
    calls = []

    def request(*_args: object) -> object:
        calls.append(True)
        raise evidence.PublicGatewayHttpError(status, "private error text")

    monkeypatch.setattr(evidence, "authenticated_json_request", request)
    with pytest.raises(evidence.PublicGatewayHttpError):
        evidence.read_flow_evidence("https://marty.test", "private-session", FLOW, review_required=review_required)
    assert len(calls) == 1


@pytest.mark.parametrize(
    "outcome",
    [
        {"status": "failed", "result": "failed", "decision": "deny"},
        {"status": "pending", "result": "passed", "decision": "allow"},
        {"status": "completed", "result": "partial", "decision": "manual_review"},
        {"status": "completed", "result": "UNKNOWN", "decision": "allow"},
    ],
)
def test_unsuccessful_or_incomplete_results_cannot_produce_success_screenshots(
    tmp_path: Path,
    outcome: dict[str, str],
) -> None:
    destination = tmp_path / "must-not-exist.png"
    with pytest.raises(ValueError, match="completed allow"):
        evidence.capture_success_page(None, FLOW, outcome, destination)
    assert not destination.exists()
