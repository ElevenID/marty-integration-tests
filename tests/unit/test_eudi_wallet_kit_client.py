from __future__ import annotations

import httpx
import pytest

from tests.integration.gateway.helpers.eudi_wallet_kit_client import (
    EUDIWalletHarnessError,
    _raise_for_status_safely,
)


def _response(status: int, body: dict[str, str]) -> httpx.Response:
    request = httpx.Request("POST", "https://must-not-escape.example/private")
    return httpx.Response(status, request=request, json=body)


def test_safe_harness_error_reports_only_allowlisted_metadata_field() -> None:
    response = _response(
        500,
        {
            "error": "JsonDecodingException",
            "message": (
                "Unexpected value at credential_signing_alg_values_supported https://must-not-escape.example/issuer"
            ),
            "stackTrace": "token=must-not-escape",
        },
    )

    with pytest.raises(EUDIWalletHarnessError) as captured:
        _raise_for_status_safely(response)

    assert str(captured.value) == (
        "EUDI wallet harness HTTP 500: issuer-metadata-json-invalid-credential-signing-algorithms"
    )
    assert "must-not-escape" not in str(captured.value)


def test_safe_harness_error_rejects_unrecognized_error_text() -> None:
    response = _response(
        502,
        {
            "error": "CustomerSpecificFailure",
            "message": "customer=must-not-escape",
            "stackTrace": "credential=must-not-escape",
        },
    )

    with pytest.raises(EUDIWalletHarnessError) as captured:
        _raise_for_status_safely(response)

    assert str(captured.value) == ("EUDI wallet harness HTTP 502: wallet-harness-unclassified")
    assert "must-not-escape" not in str(captured.value)


def test_safe_harness_error_preserves_only_bounded_jvm_failure_class() -> None:
    response = _response(
        500,
        {
            "error": "IllegalStateException",
            "message": "offer=https://must-not-escape.example",
            "stackTrace": "credential=must-not-escape",
        },
    )

    with pytest.raises(EUDIWalletHarnessError) as captured:
        _raise_for_status_safely(response)

    assert str(captured.value) == ("EUDI wallet harness HTTP 500: wallet-harness-illegal-state-exception")
    assert "must-not-escape" not in str(captured.value)


def test_safe_harness_error_rejects_unbounded_error_label() -> None:
    response = _response(
        500,
        {
            "error": "secret-offer-value",
            "message": "must-not-escape",
        },
    )

    with pytest.raises(EUDIWalletHarnessError) as captured:
        _raise_for_status_safely(response)

    assert str(captured.value) == ("EUDI wallet harness HTTP 500: wallet-harness-unclassified")


def test_safe_harness_error_preserves_allowlisted_holder_binding_code() -> None:
    response = _response(
        422,
        {
            "error": "missing_holder_binding_key",
            "message": "credential=must-not-escape",
            "stackTrace": "",
        },
    )

    with pytest.raises(EUDIWalletHarnessError) as captured:
        _raise_for_status_safely(response)

    assert str(captured.value) == ("EUDI wallet harness HTTP 422: wallet-harness-missing-holder-binding-key")
    assert "must-not-escape" not in str(captured.value)


def test_safe_harness_error_accepts_success_without_reading_body() -> None:
    _raise_for_status_safely(_response(200, {"secret": "ignored"}))
