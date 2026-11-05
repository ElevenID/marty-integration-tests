from __future__ import annotations

import copy
import hashlib
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "oidf_marty_automated_assessment", ROOT / "scripts/oidf_marty_automated_assessment.py"
)
assert SPEC and SPEC.loader
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)
FLOW = "12345678-1234-1234-1234-123456789abc"
VARIANT = {"credential_format": "sd_jwt_vc", "request_method": "request_uri_signed"}


def unit_observations() -> dict:
    return {
        "api_outcome": {"status": "completed", "result": "passed", "decision": "allow"},
        "browser_result_match": True,
        "ui_instance_match": True,
        "ui_decision": "allow",
        "ui_verified_visible": True,
        "ui_error_absent": True,
        "flow_instance_sha256": "sha256:" + hashlib.sha256(FLOW.encode()).hexdigest(),
    }


def unit_document() -> dict:
    return {
        "testInfo": {
            "testName": policy.HAPPY,
            "testId": "test1",
            "_id": "test1",
            "planId": "plan1",
            "variant": dict(VARIANT),
            "status": "FINISHED",
            "result": "REVIEW",
        },
        "results": [
            {
                "testId": "test1",
                "src": policy.UPSTREAM_CONDITION,
                "result": "REVIEW",
                "requirements": ["OID4VP-1FINAL-8.2"],
                "upload": "UnitOnly01",
            },
            {"testId": "test1", "src": policy.HAPPY, "result": "FINISHED", "testmodule_result": "REVIEW"},
        ],
    }


def evaluate(document: dict, *, profile: str = "oid4vp-verifier", commit: str = policy.UPSTREAM_COMMIT) -> str:
    return policy.positive_review_obligation(
        document, profile=profile, expected_variant=VARIANT, runner_commit=commit
    )


def test_exact_positive_obligation_does_not_mutate_official_results() -> None:
    document = unit_document()
    before = copy.deepcopy(document)
    assert evaluate(document) == "ExpectVerifierSuccessfulVerificationPage"
    assert document == before
    assert document["testInfo"]["result"] == "REVIEW"


@pytest.mark.parametrize(
    ("profile", "allowed"),
    [
        ("oid4vp-verifier", {policy.HAPPY, policy.MINIMAL, policy.POST, policy.TWICE}),
        ("oid4vp-url-query-verifier", {policy.HAPPY, policy.MINIMAL}),
        ("oid4vp-mdoc-verifier", {policy.HAPPY, policy.POST, policy.TWICE}),
        ("oid4vp-haip-verifier", {policy.HAPPY, policy.MINIMAL, policy.POST, policy.TWICE}),
    ],
)
def test_only_source_reviewed_modules_apply_to_each_profile(profile: str, allowed: set[str]) -> None:
    modules = (policy.HAPPY, policy.MINIMAL, policy.POST, policy.TWICE, "oid4vp-1final-verifier-invalid-kb-jwt-nonce")
    for module in modules:
        document = unit_document()
        document["testInfo"]["testName"] = module
        if module in allowed:
            assert evaluate(document, profile=profile) == policy.UPSTREAM_CONDITION
        else:
            with pytest.raises(ValueError, match="allowed finished positive"):
                evaluate(document, profile=profile)


@pytest.mark.parametrize(
    "mutation",
    ["warning", "failure", "other-review", "negative-review", "missing-review", "duplicate-review", "wrong-test",
     "wrong-spec", "removed-image", "incomplete", "failed", "variant", "unknown-module", "missing-log",
     "malformed-log"],
)
def test_full_original_log_cannot_hide_unsatisfied_obligations(mutation: str) -> None:
    document = unit_document()
    row = document["results"][0]
    if mutation in {"warning", "failure", "other-review"}:
        document["results"].append(
            {"testId": "test1", "src": "AnotherCondition", "result": {"warning": "WARNING", "failure": "FAILURE",
                                                                         "other-review": "REVIEW"}[mutation]}
        )
    elif mutation == "negative-review":
        row["src"] = "ExpectVerifierRejectedPresentationPage"
    elif mutation == "missing-review":
        document["results"] = document["results"][1:]
    elif mutation == "duplicate-review":
        document["results"].append(dict(row))
    elif mutation == "wrong-test":
        document["results"][-1]["testId"] = "differentRun"
    elif mutation == "wrong-spec":
        row["requirements"] = ["unreviewed-obligation"]
    elif mutation == "removed-image":
        row["image_no_longer_required"] = True
    elif mutation == "incomplete":
        document["testInfo"]["status"] = "WAITING"
    elif mutation == "failed":
        document["testInfo"]["result"] = "FAILED"
    elif mutation == "variant":
        document["testInfo"]["variant"]["request_method"] = "url_query"
    elif mutation == "unknown-module":
        document["testInfo"]["testName"] = "oid4vp-1final-verifier-unreviewed-positive"
    elif mutation == "missing-log":
        del document["results"]
    elif mutation == "malformed-log":
        row["result"] = ["REVIEW"]
    with pytest.raises(ValueError, match="automated verification"):
        evaluate(document)


def test_policy_must_be_revisited_on_runner_upgrade() -> None:
    with pytest.raises(ValueError, match="upstream source policy"):
        evaluate(unit_document(), commit="0" * 40)


@pytest.mark.parametrize("result", ["UNKNOWN", "SKIPPED", "INTERRUPTED", "future-result", "", None, 1])
def test_unknown_incomplete_and_malformed_log_results_cannot_be_ignored(result: object) -> None:
    document = unit_document()
    document["results"].append({"testId": "test1", "src": "OtherCondition", "result": result})
    with pytest.raises(ValueError, match="automated verification"):
        evaluate(document)


def test_pinned_log_supports_unclassified_messages_and_only_known_successful_values() -> None:
    document = unit_document()
    document["results"].extend([
        {"testId": "test1", "src": "-START-BLOCK-", "msg": "unit fixture only", "startBlock": True},
        {"testId": "test1", "src": "KnownCondition", "result": "INFO"},
        {"testId": "test1", "src": "KnownCondition", "result": "SUCCESS"},
    ])
    assert evaluate(document) == policy.UPSTREAM_CONDITION


def test_flow_hashing_rejects_noncanonical_uuid_case_instead_of_normalizing_evidence() -> None:
    assert policy.flow_instance_digest(FLOW) == "sha256:" + hashlib.sha256(FLOW.encode()).hexdigest()
    with pytest.raises(ValueError, match="exact flow identity"):
        policy.flow_instance_digest(FLOW.upper())


def test_observations_are_closed_bounded_and_bound_to_the_exact_flow() -> None:
    observations = unit_observations()
    assessment = {"policy": policy.POLICY, "upstream_condition": policy.UPSTREAM_CONDITION, **observations}
    assert policy.validate_assessment(assessment, flow_id=FLOW) == assessment
    with pytest.raises(ValueError, match="matching successful"):
        policy.validate_assessment(assessment, flow_id="12345678-1234-1234-1234-123456789abd")
    for field in ("browser_result_match", "ui_instance_match", "ui_verified_visible", "ui_error_absent"):
        for wrong in (False, 1, "true", None):
            with pytest.raises(ValueError):
                policy.validate_assessment({**assessment, field: wrong})
    for value in ({**assessment, "private_claims": "must-not-publish"}, {**assessment, "api_outcome": None},
                  {**assessment, "ui_decision": "deny"}, {**assessment, "flow_instance_sha256": "sha256:" + "A" * 64},
                  {**assessment, "api_outcome": {**policy.SUCCESS, "private_key": "must-not-publish"}},
                  {key: value for key, value in assessment.items() if key != "ui_verified_visible"}):
        with pytest.raises(ValueError):
            policy.validate_assessment(value)
