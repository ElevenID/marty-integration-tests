from __future__ import annotations

import importlib.util
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


def test_outcomes_require_the_exact_public_flow_binding() -> None:
    with pytest.raises(ValueError, match="different flow"):
        evidence.outcome_projection({"instance_id": "other", "result": "passed"}, FLOW)
    with pytest.raises(ValueError, match="different flow"):
        evidence.outcome_projection({"instance_id": "unsafe-selector"}, "unsafe-selector")


def test_public_projection_cannot_publish_tokens_claims_or_server_error_text() -> None:
    projected = evidence.outcome_projection({
        "instance_id": FLOW, "result": "passed", "decision": "allow", "status": "completed",
        "verified_claims": {"secret": "do-not-export"}, "decision_reason": "private-url",
    }, FLOW)
    assert projected == {"result": "passed", "decision": "allow", "status": "completed"}
    assert evidence.outcome_projection({
        "instance_id": FLOW, "result": "do-not-export", "status": "private-url",
    }, FLOW) == {"result": "UNKNOWN", "decision": "UNKNOWN", "status": "UNKNOWN"}


@pytest.mark.parametrize("outcome", [
    {"status": "failed", "result": "failed", "decision": "deny"},
    {"status": "pending", "result": "passed", "decision": "allow"},
    {"status": "completed", "result": "partial", "decision": "manual_review"},
    {"status": "completed", "result": "UNKNOWN", "decision": "allow"},
])
def test_unsuccessful_or_incomplete_results_cannot_produce_success_screenshots(
    tmp_path: Path, outcome: dict[str, str],
) -> None:
    destination = tmp_path / "must-not-exist.png"
    with pytest.raises(ValueError, match="completed allow"):
        evidence.capture_success_page(None, FLOW, outcome, destination)
    assert not destination.exists()
