from __future__ import annotations

import pytest

from tests.integration.gateway.helpers.eudi_stage import (
    EUDIInteropStageError,
    eudi_stage,
)


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


def test_stage_rejects_dynamic_labels() -> None:
    with (
        pytest.raises(ValueError, match="bounded slug"),
        eudi_stage("must_not_escape"),
    ):
        pass
