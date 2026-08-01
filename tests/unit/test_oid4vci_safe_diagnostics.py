from __future__ import annotations

import httpx
import pytest

from tests.integration.gateway.helpers.oid4vc_wallet_client import (
    _raise_for_oid4vci_error,
)


def test_oid4vci_diagnostic_exposes_only_allowlisted_error_code() -> None:
    response = httpx.Response(
        400,
        json={
            "error": "invalid_proof",
            "error_description": "secret-bearing tenant and key detail",
        },
    )

    with pytest.raises(
        RuntimeError,
        match=r"^OID4VCI credential failed: status=400 error=invalid_proof$",
    ) as exc_info:
        _raise_for_oid4vci_error(response, "credential")

    assert "secret-bearing" not in str(exc_info.value)
    assert "tenant" not in str(exc_info.value)
    assert "key" not in str(exc_info.value)


def test_oid4vci_diagnostic_rejects_unrecognized_response_text() -> None:
    response = httpx.Response(
        400,
        json={"error": "attacker-controlled", "detail": "must-not-escape"},
    )

    with pytest.raises(
        RuntimeError,
        match=r"^OID4VCI token failed: status=400 error=unclassified$",
    ) as exc_info:
        _raise_for_oid4vci_error(response, "token")

    assert "attacker-controlled" not in str(exc_info.value)
    assert "must-not-escape" not in str(exc_info.value)


def test_oid4vci_diagnostic_accepts_success() -> None:
    _raise_for_oid4vci_error(httpx.Response(200, json={"ok": True}), "metadata")


@pytest.mark.parametrize(
    ("detail", "category"),
    [
        (
            "DID resolution failed for issuer did:web:tenant.example: "
            "remote signing key could not be resolved (private detail)",
            "issuer-did-resolution-failed",
        ),
        (
            "Revocation service unavailable: private transport detail",
            "revocation-service-unavailable",
        ),
        (
            "Credential has no allocated status-list entry",
            "status-list-allocation-missing",
        ),
    ],
)
def test_marty_503_detail_is_reduced_to_fixed_category(
    detail: str,
    category: str,
) -> None:
    response = httpx.Response(503, json={"detail": detail})

    with pytest.raises(
        RuntimeError,
        match=rf"^OID4VCI credential failed: status=503 error={category}$",
    ) as exc_info:
        _raise_for_oid4vci_error(response, "credential")

    assert "private" not in str(exc_info.value)
    assert "did:web" not in str(exc_info.value)


def test_mip_envelope_description_is_reduced_to_fixed_category() -> None:
    response = httpx.Response(
        503,
        json={
            "error": "service_error",
            "error_description": (
                "DID resolution failed for issuer did:web:tenant.example: "
                "remote signing key could not be resolved (private detail)"
            ),
        },
    )

    with pytest.raises(
        RuntimeError,
        match=(
            r"^OID4VCI credential failed: status=503 "
            r"error=issuer-did-resolution-failed$"
        ),
    ) as exc_info:
        _raise_for_oid4vci_error(response, "credential")

    assert "private" not in str(exc_info.value)
    assert "did:web" not in str(exc_info.value)


@pytest.mark.parametrize(
    ("response", "category"),
    [
        (
            httpx.Response(503, json={"detail": "unrecognized private detail"}),
            "service-json-unclassified",
        ),
        (httpx.Response(503, text="upstream private detail"), "upstream-non-json"),
    ],
)
def test_unrecognized_503_shape_is_classified_without_echoing_response(
    response: httpx.Response,
    category: str,
) -> None:
    with pytest.raises(
        RuntimeError,
        match=rf"^OID4VCI credential failed: status=503 error={category}$",
    ) as exc_info:
        _raise_for_oid4vci_error(response, "credential")

    assert "private" not in str(exc_info.value)
