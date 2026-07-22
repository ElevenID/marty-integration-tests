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

PUBLIC_SIGNING_JWK = {
    "kty": "EC",
    "crv": "P-256",
    "x": "public-x",
    "y": "public-y",
}


def test_bootstrap_uses_public_template_and_policy_apis() -> None:
    calls: list[tuple[str, str, dict | None]] = []
    responses = iter(
        [
            {"service": {"id": "service-1", "key_reference": "issuer-es256"}},
            {"profile": {"id": "issuer-1"}},
            {"id": "compliance-1"},
            {"id": "revocation-1"},
            {"id": "revocation-1"},
            {"id": "template-1"},
            {"id": "policy-1"},
            {"id": "policy-1"},
            {"id": "trust-1"},
            {"id": "trust-1"},
            {"service": {"id": "service-2", "key_reference": "issuer-es256"}},
            {"profile": {"id": "issuer-2"}},
            {"id": "compliance-2"},
            {"id": "revocation-2"},
            {"id": "revocation-2"},
            {"id": "template-2"},
            {"id": "policy-2"},
            {"id": "policy-2"},
            {"id": "policy-3"},
            {"id": "policy-3"},
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
        oidf_signer_public_jwk=PUBLIC_SIGNING_JWK,
        request=request,
    )
    assert result["oid4vp_policy_id"] == "policy-1"
    assert result["oid4vp_issuer_profile_id"] == "issuer-1"
    assert result["oid4vp_compliance_profile_id"] == "compliance-1"
    assert result["oid4vp_revocation_profile_id"] == "revocation-1"
    assert result["oid4vp_trust_profile_id"] == "trust-1"
    assert result["w3c_compliance_profile_id"] == "compliance-2"
    assert result["w3c_revocation_profile_id"] == "revocation-2"
    assert result["w3c_issuer_profile_id"] == "issuer-2"
    assert result["w3c_credential_policy_id"] == "policy-2"
    assert result["w3c_presentation_policy_id"] == "policy-3"
    assert "w3c_policy_id" not in result
    assert calls[0][0].startswith("/v1/signing-keys/config/resolve?")
    assert calls[0][2] == {
        "credential_format": "dc+sd-jwt",
        "key_purpose": "vc_jwt_issuer",
        "algorithm": "ES256",
    }
    assert calls[1][0].startswith("/v1/signing-keys/issuer-profiles?")
    assert calls[2][0] == "/v1/compliance-profiles"
    assert calls[3][0] == "/v1/revocation-profiles"
    assert calls[4][0] == "/v1/revocation-profiles/revocation-1/activate"
    assert calls[5][0] == "/v1/credential-templates"
    assert calls[5][2]["compliance_profile_id"] == "compliance-1"
    assert calls[5][2]["issuer_profile_id"] == "issuer-1"
    assert calls[5][2]["revocation_profile_id"] == "revocation-1"
    assert "compliance_profile" not in calls[5][2]
    assert calls[6][0] == "/v1/presentation-policies"
    assert calls[7][0] == "/v1/presentation-policies/policy-1/activate"
    assert calls[8][0] == "/v1/trust-profiles"
    assert calls[9][0] == "/v1/trust-profiles/trust-1/activate"
    assert all(method == "POST" for _path, method, _body in calls)
    assert calls[15][2]["credential_payload_format"] == "w3c_vcdm_v2_jwt_vc"
    assert calls[16][2]["holder_binding"] == {"required": False}
    requirement = calls[16][2]["credential_requirements"][0]
    assert requirement["credential_payload_format"] == "w3c_vcdm_v2_jwt_vc"
    assert requirement["requested_claims"] == [
        {"claim_name": "id", "display_name": "id", "required": False}
    ]
    assert calls[18][2]["holder_binding"] == {"required": True}
    assert calls[18][2]["credential_requirements"][0]["credential_payload_format"] == (
        "w3c_vcdm_v2_di"
    )


def test_oidf_fixture_matches_the_official_runner_pid_contract() -> None:
    template = fixtures.template_payload(
        fixtures.DEFAULT_ORGANIZATION,
        "compliance-1",
        "issuer-1",
        "revocation-1",
        w3c=False,
        run_id="run-1",
    )
    assert template["credential_type"] == "PID"
    assert template["vct"] == "urn:eudi:pid:1"
    assert template["schema_uri"]["required"] == ["family_name", "given_name", "birthdate"]
    assert [claim["name"] for claim in template["claims"]] == [
        "family_name",
        "given_name",
        "birthdate",
    ]
    assert template["compliance_profile_id"] == "compliance-1"
    assert template["issuer_profile_id"] == "issuer-1"
    assert template["revocation_profile_id"] == "revocation-1"
    assert "compliance_profile" not in template

    policy = fixtures.policy_payload(
        fixtures.DEFAULT_ORGANIZATION,
        "template-1",
        w3c=False,
        run_id="run-1",
    )
    requested = policy["credential_requirements"][0]["requested_claims"]
    assert [claim["claim_name"] for claim in requested] == [
        "given_name",
        "family_name",
        "birthdate",
    ]
    assert policy["holder_binding"] == {"required": True}


def test_w3c_fixture_separates_credential_and_presentation_verification() -> None:
    credential_policy = fixtures.policy_payload(
        fixtures.DEFAULT_ORGANIZATION,
        "template-1",
        w3c=True,
        run_id="run-1",
        presentation=False,
    )
    presentation_policy = fixtures.policy_payload(
        fixtures.DEFAULT_ORGANIZATION,
        "template-1",
        w3c=True,
        run_id="run-1",
        presentation=True,
    )
    assert credential_policy["holder_binding"] == {"required": False}
    credential_requirement = credential_policy["credential_requirements"][0]
    assert credential_requirement["credential_payload_format"] == "w3c_vcdm_v2_jwt_vc"
    assert credential_requirement["requested_claims"] == [
        {"claim_name": "id", "display_name": "id", "required": False}
    ]
    assert presentation_policy["holder_binding"] == {"required": True}
    assert presentation_policy["credential_requirements"][0]["credential_payload_format"] == (
        "w3c_vcdm_v2_di"
    )


def test_runner_private_jwk_is_reduced_to_public_members_before_gateway_use(tmp_path: Path) -> None:
    config = tmp_path / "runner.json"
    config.write_text(
        '{"credential":{"signing_jwk":{"kty":"EC","crv":"P-256","x":"x","y":"y","d":"private"}}}',
        encoding="utf-8",
    )

    public_jwk = fixtures.official_signer_public_jwk(config)
    payload = fixtures.trust_profile_payload(
        fixtures.DEFAULT_ORGANIZATION,
        public_jwk,
        run_id="run-1",
    )

    assert public_jwk == {"kty": "EC", "crv": "P-256", "x": "x", "y": "y"}
    pinned = payload["system_issuer_overrides"][fixtures.OFFICIAL_OIDF_ISSUER_DOMAIN]["public_jwk"]
    assert pinned == public_jwk
    assert set(pinned) == {"kty", "crv", "x", "y"}
    assert payload["allowed_issuers"] == [fixtures.OFFICIAL_OIDF_ISSUER_DOMAIN]


def test_oidf_bootstrap_requires_the_runner_public_key() -> None:
    with pytest.raises(ValueError, match="public signing JWK"):
        fixtures.bootstrap(
            "https://marty.test",
            "real-session",
            organization_id=fixtures.DEFAULT_ORGANIZATION,
            run_id="run-1",
            mode="oid4vp",
            request=lambda *_args, **_kwargs: {"id": "not-reached"},
        )


def test_bootstrap_rejects_invalid_public_api_identifier() -> None:
    responses = iter(
        [
            {"service": {"id": "service-1", "key_reference": "issuer-es256"}},
            {"profile": {"id": "issuer-1"}},
            {"id": "compliance-1"},
            {"id": "revocation-1"},
            {"id": "revocation-1"},
            {"id": "../../private"},
        ]
    )
    with pytest.raises(RuntimeError, match="invalid"):
        fixtures.bootstrap(
            "https://marty.test",
            "real-session",
            organization_id=fixtures.DEFAULT_ORGANIZATION,
            run_id="run-1",
            mode="oid4vp",
            oidf_signer_public_jwk=PUBLIC_SIGNING_JWK,
            request=lambda *_args, **_kwargs: next(responses),
        )
