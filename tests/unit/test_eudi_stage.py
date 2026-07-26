from __future__ import annotations

import pytest

from tests.integration.gateway.helpers.eudi_stage import (
    EUDIInteropStageError,
    eudi_stage,
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
