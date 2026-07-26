from __future__ import annotations

import pytest

from tests.integration.gateway.helpers.eudi_stage import (
    EUDIInteropStageError,
    eudi_stage,
    require_presentation_accepted,
)
from tests.integration.gateway.helpers.gateway_client import GatewayClientError


def test_stage_replaces_nested_values_with_bounded_code() -> None:
    with (
        pytest.raises(EUDIInteropStageError) as captured,
        eudi_stage("mdoc-wallet-receipt"),
    ):
        raise RuntimeError("credential=must-not-escape")

    assert str(captured.value) == "eudi-stage-mdoc-wallet-receipt"
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is not None
    assert captured.value.__suppress_context__ is True


def test_stage_preserves_only_bounded_gateway_http_status() -> None:
    with (
        pytest.raises(EUDIInteropStageError) as captured,
        eudi_stage("mdoc-trust-profile-create"),
    ):
        raise GatewayClientError(
            "POST body=must-not-escape",
            status_code=422,
        )

    assert str(captured.value) == "eudi-stage-mdoc-trust-profile-create-http-422"
    assert "must-not-escape" not in str(captured.value)


def test_stage_ignores_unbounded_status_values() -> None:
    with (
        pytest.raises(EUDIInteropStageError) as captured,
        eudi_stage("mdoc-trust-profile-create"),
    ):
        raise GatewayClientError("must-not-escape", status_code=12345)

    assert str(captured.value) == "eudi-stage-mdoc-trust-profile-create"


def test_stage_rejects_dynamic_labels() -> None:
    with (
        pytest.raises(ValueError, match="bounded slug"),
        eudi_stage("must_not_escape"),
    ):
        pass


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (
            {
                "success": False,
                "error": "credential=must-not-escape",
                "responseMode": "direct_post",
                "verifierAccepted": False,
            },
            "eudi-stage-mdoc-presentation-dispatch",
        ),
        (
            {
                "success": False,
                "error": "presentation-build-mso-mdoc-decode-mso-cbor-error",
                "responseMode": "direct_post",
                "verifierAccepted": False,
            },
            "eudi-stage-build-mso-mdoc-decode-mso-cbor-error",
        ),
        (
            {
                "success": False,
                "error": "Verifier rejected the official OID4VP response",
                "responseMode": "direct_post",
                "verifierAccepted": False,
            },
            "eudi-stage-mdoc-presentation-verifier-rejected",
        ),
        (
            {
                "success": True,
                "responseMode": "secret-mode-must-not-escape",
                "verifierAccepted": True,
            },
            "eudi-stage-mdoc-presentation-response-mode",
        ),
        (
            {
                "success": True,
                "responseMode": "direct_post",
                "verifierAccepted": False,
            },
            "eudi-stage-mdoc-presentation-verifier-accepted",
        ),
    ],
)
def test_presentation_acceptance_exposes_only_fixed_stage(
    result: dict[str, object],
    expected: str,
) -> None:
    with pytest.raises(EUDIInteropStageError) as captured:
        require_presentation_accepted(
            result,
            stage="mdoc-presentation",
            expected_mode="direct_post",
        )

    assert str(captured.value) == expected
    assert "must-not-escape" not in str(captured.value)


def test_presentation_acceptance_passes_complete_result() -> None:
    require_presentation_accepted(
        {
            "success": True,
            "responseMode": "direct_post",
            "verifierAccepted": True,
        },
        stage="mdoc-presentation",
        expected_mode="direct_post",
    )


def test_presentation_acceptance_reduces_verifier_reason_to_fixed_codes() -> None:
    with pytest.raises(EUDIInteropStageError) as captured:
        require_presentation_accepted(
            {
                "success": False,
                "error": "Verifier rejected the official OID4VP response",
                "responseMode": "direct_post",
                "verifierAccepted": False,
            },
            stage="mdoc-presentation",
            expected_mode="direct_post",
            verification_result={
                "status": "completed",
                "result": {
                    "decision_reason": (
                        "Credential verification failed: Signature verification failed "
                        "for secret-doctype: private-value; Holder device authentication "
                        "failed: private-key-material"
                    )
                },
            },
        )

    assert str(captured.value) == (
        "eudi-stage-mdoc-presentation-verifier-rejected-"
        "device-authentication-invalid-issuer-signature-invalid"
    )
    assert "secret" not in str(captured.value)
    assert "private" not in str(captured.value)


@pytest.mark.parametrize(
    ("reason", "code"),
    [
        (
            "Credential verification failed: Unsupported credential format: unknown",
            "device-response-unrecognized",
        ),
        (
            "Credential verification failed: marty-rs bindings not installed",
            "verifier-binding-unavailable",
        ),
        (
            "Required credentials not satisfied",
            "policy-requirements-unsatisfied",
        ),
        (
            "Credential verification failed: Revocation status was not checked",
            "revocation-unchecked",
        ),
        (
            "Policy service unavailable: private transport detail",
            "policy-service-unavailable",
        ),
    ],
)
def test_presentation_acceptance_classifies_preverification_failures(
    reason: str,
    code: str,
) -> None:
    with pytest.raises(EUDIInteropStageError) as captured:
        require_presentation_accepted(
            {
                "success": False,
                "error": "Verifier rejected the official OID4VP response",
                "responseMode": "direct_post",
                "verifierAccepted": False,
            },
            stage="mdoc-presentation",
            expected_mode="direct_post",
            verification_result={
                "status": "completed",
                "result": {"decision_reason": reason},
            },
        )

    assert str(captured.value) == (
        f"eudi-stage-mdoc-presentation-verifier-rejected-{code}"
    )
    assert reason not in str(captured.value)
