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
