from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "official_fixture_bootstrap", ROOT / "scripts" / "official_fixture_bootstrap.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load official fixture bootstrap")
fixtures = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixtures)


def test_bootstrap_uses_public_template_and_policy_apis() -> None:
    calls: list[tuple[str, str, dict | None]] = []
    responses = iter(
        [
            {"id": "template-1"},
            {"id": "policy-1"},
            {"id": "policy-1"},
            {"id": "template-2"},
            {"id": "policy-2"},
            {"id": "policy-2"},
        ]
    )

    def request(
        _gateway: str,
        _session: str,
        path: str,
        *,
        method: str,
        json_body: dict | None = None,
    ) -> object:
        calls.append((path, method, json_body))
        return next(responses)

    result = fixtures.bootstrap(
        "https://marty.test",
        "real-session",
        organization_id=fixtures.DEFAULT_ORGANIZATION,
        run_id="run-1",
        mode="all",
        request=request,
    )
    assert result["oid4vp_policy_id"] == "policy-1"
    assert result["w3c_policy_id"] == "policy-2"
    assert calls[0][0] == "/v1/credential-templates"
    assert calls[1][0] == "/v1/presentation-policies"
    assert calls[2][0] == "/v1/presentation-policies/policy-1/activate"
    assert all(method == "POST" for _path, method, _body in calls)
    assert calls[3][2]["credential_payload_format"] == "w3c_vcdm_v2_jwt_vc"


def test_bootstrap_rejects_invalid_public_api_identifier() -> None:
    with pytest.raises(RuntimeError, match="invalid"):
        fixtures.bootstrap(
            "https://marty.test",
            "real-session",
            organization_id=fixtures.DEFAULT_ORGANIZATION,
            run_id="run-1",
            mode="oid4vp",
            request=lambda *_args, **_kwargs: {"id": "../../private"},
        )
