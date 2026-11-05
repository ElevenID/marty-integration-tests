"""Bounded, product-owned evidence for the pinned OIDF positive REVIEW obligation.

This does not alter or approve the upstream result. At the pinned commit,
ExpectVerifierSuccessfulVerificationPage asks for evidence that the verifier
successfully verified the presented credential. Negative modules instead use
ExpectVerifierRejectedPresentationPage and are deliberately outside this policy.

Primary source: https://gitlab.com/openid/conformance-suite/-/tree/
7d420f716e49d44f8a6b04f0a3e240ad6d68ab55/src/main/java/net/openid/conformance/
vp1finalverifier (the plan, four positive modules, and abstract verifier test),
condition/common/ExpectVerifierSuccessfulVerificationPage.java, and
testmodule/AbstractTestModule.java. REVIEW can mask WARNING in that implementation,
so every original log entry is inspected, including underlying warnings/failures.
"""

from __future__ import annotations

import hashlib
import re

POLICY = "marty.official-verifier-outcome/v1"
UPSTREAM_COMMIT = "7d420f716e49d44f8a6b04f0a3e240ad6d68ab55"
UPSTREAM_CONDITION = "ExpectVerifierSuccessfulVerificationPage"
# Pinned Condition.ConditionResult permits INFO/SUCCESS/REVIEW here; WARNING
# and FAILURE are disqualifying. AbstractTestModule adds FINISHED as its sole
# successful lifecycle result. INTERRUPTED/SKIPPED cannot qualify a REVIEW.
ALLOWED_LOG_RESULTS = frozenset({"INFO", "SUCCESS", "REVIEW", "FINISHED"})
SUCCESS = {"status": "completed", "result": "passed", "decision": "allow"}
HAPPY = "oid4vp-1final-verifier-happy-flow"
MINIMAL = "oid4vp-1final-verifier-minimal-cnf-jwk"
POST = "oid4vp-1final-verifier-request-uri-method-post"
TWICE = "oid4vp-1final-verifier-request-uri-fetched-twice"
ALLOWED_MODULES = {
    "oid4vp-verifier": frozenset({HAPPY, MINIMAL, POST, TWICE}),
    "oid4vp-url-query-verifier": frozenset({HAPPY, MINIMAL}),
    "oid4vp-mdoc-verifier": frozenset({HAPPY, POST, TWICE}),
    "oid4vp-haip-verifier": frozenset({HAPPY, MINIMAL, POST, TWICE}),
}
IDENTITY = re.compile(r"[A-Za-z0-9]{1,180}\Z")
FLOW_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
OBSERVATION_KEYS = frozenset(
    {
        "api_outcome",
        "browser_result_match",
        "ui_instance_match",
        "ui_decision",
        "ui_verified_visible",
        "ui_error_absent",
        "flow_instance_sha256",
    }
)


def flow_instance_digest(flow_id: str) -> str:
    if not isinstance(flow_id, str) or not FLOW_ID.fullmatch(flow_id):
        raise ValueError("automated verification requires the exact flow identity")
    return "sha256:" + hashlib.sha256(flow_id.encode("utf-8")).hexdigest()


def validate_observations(value: object, *, flow_id: str | None = None) -> dict:
    """Accept only the closed facts actually collected from the API and real UI."""
    if not isinstance(value, dict) or set(value) != OBSERVATION_KEYS:
        raise ValueError("automated verification observations have an invalid schema")
    outcome = value["api_outcome"]
    if (
        not isinstance(outcome, dict)
        or set(outcome) != set(SUCCESS)
        or any(type(outcome[key]) is not str or outcome[key] != expected for key, expected in SUCCESS.items())
        or value["ui_decision"] != "allow"
        or type(value["ui_decision"]) is not str
        or any(
            value[key] is not True
            for key in ("browser_result_match", "ui_instance_match", "ui_verified_visible", "ui_error_absent")
        )
        or not isinstance(value["flow_instance_sha256"], str)
        or not DIGEST.fullmatch(value["flow_instance_sha256"])
        or (flow_id is not None and value["flow_instance_sha256"] != flow_instance_digest(flow_id))
    ):
        raise ValueError("automated verification lacks matching successful API and UI observations")
    return {**value, "api_outcome": dict(outcome)}


def validate_assessment(value: object, *, flow_id: str | None = None) -> dict:
    if not isinstance(value, dict) or set(value) != OBSERVATION_KEYS | {"policy", "upstream_condition"}:
        raise ValueError("automated verification assessment has an invalid schema")
    if value["policy"] != POLICY or value["upstream_condition"] != UPSTREAM_CONDITION:
        raise ValueError("automated verification assessment uses an unknown policy or obligation")
    observations = validate_observations({key: value[key] for key in OBSERVATION_KEYS}, flow_id=flow_id)
    return {"policy": POLICY, "upstream_condition": UPSTREAM_CONDITION, **observations}


def positive_review_obligation(
    document: object,
    *,
    profile: str,
    expected_variant: dict,
    runner_commit: str,
) -> str:
    """Exhaustively check the unchanged export; a matching row alone is insufficient."""
    if runner_commit != UPSTREAM_COMMIT or profile not in ALLOWED_MODULES or not isinstance(document, dict):
        raise ValueError("automated verification has no reviewed upstream source policy")
    info = document.get("testInfo")
    if (
        not isinstance(info, dict)
        or info.get("testName") not in ALLOWED_MODULES[profile]
        or info.get("status") != "FINISHED"
        or info.get("result") != "REVIEW"
        or not isinstance(info.get("variant"), dict)
        or info["variant"] != expected_variant
        or any(not isinstance(info.get(key), str) or not IDENTITY.fullmatch(info[key]) for key in ("testId", "planId"))
        or info.get("_id") != info["testId"]
    ):
        raise ValueError("automated verification is not an allowed finished positive REVIEW case")
    rows = document.get("results")
    if not isinstance(rows, list) or not rows or any(not isinstance(row, dict) for row in rows):
        raise ValueError("automated verification requires the complete original result log")
    obligations = []
    for row in rows:
        if row.get("testId") != info["testId"]:
            raise ValueError("automated verification result log belongs to another test instance")
        if "result" in row and not isinstance(row["result"], str):
            raise ValueError("automated verification has a malformed original result log")
        if row.get("result") in {"WARNING", "FAILURE", "FAILED", "ERROR"}:
            raise ValueError("automated verification cannot conceal an upstream warning or failure")
        if "result" in row and row["result"] not in ALLOWED_LOG_RESULTS:
            raise ValueError("automated verification encountered an unknown or incomplete log result")
        if row.get("result") == "REVIEW":
            if (
                row.get("src") != UPSTREAM_CONDITION
                or row.get("requirements") != ["OID4VP-1FINAL-8.2"]
                or row.get("image_no_longer_required") is True
            ):
                raise ValueError("automated verification encountered an unknown REVIEW obligation")
            obligations.append(row)
    if len(obligations) != 1:
        raise ValueError("automated verification requires exactly one successful-verification obligation")
    return UPSTREAM_CONDITION
