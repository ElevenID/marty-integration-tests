from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

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
MDOC_TRUST_ANCHOR_PEM = """-----BEGIN CERTIFICATE-----
Y2VydGlmaWNhdGU=
-----END CERTIFICATE-----
"""


def test_mdoc_mode_is_a_supported_public_fixture_mode() -> None:
    parsed = fixtures.parser().parse_args(
        [
            "--mode",
            "oid4vp-mdoc",
            "--gateway-url",
            "https://marty.test",
            "--run-id",
            "run-1",
            "--oidf-runner-source",
            "oidf-runner",
            "--output",
            "fixtures.json",
        ]
    )

    assert parsed.mode == "oid4vp-mdoc"


def test_oid4vci_bootstrap_creates_only_issuer_resources() -> None:
    calls: list[tuple[str, str, dict | None]] = []
    responses = iter(
        [
            {"service": {"id": "service-1", "key_reference": "issuer-es256"}},
            {"profile": {"id": "issuer-profile-1"}},
            {"id": "compliance-1"},
            {"id": "revocation-1"},
            {"id": "revocation-1"},
            {"id": "template-1", "credential_type": "PID"},
            {"id": "template-1"},
            {
                "credential_configurations_supported": {
                    "PID": {
                        "format": "jwt_vc_json",
                    },
                    "PID#sd-jwt": {
                        "format": "dc+sd-jwt",
                        "vct": "urn:eudi:pid:1",
                    },
                }
            },
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
        mode="oid4vci",
        request=request,
    )

    issuer_did = f"did:web:marty.test:orgs:{fixtures.DEFAULT_ORGANIZATION}"
    assert result == {
        "organization_id": fixtures.DEFAULT_ORGANIZATION,
        "oid4vci_template_id": "template-1",
        "oid4vci_credential_configuration_id": "PID#sd-jwt",
        "oid4vci_compliance_profile_id": "compliance-1",
        "oid4vci_issuer_did": issuer_did,
        "oid4vci_revocation_profile_id": "revocation-1",
    }
    paths = [path for path, _method, _body in calls]
    assert paths[0].startswith("/v1/signing-keys/config/resolve?")
    assert paths[1].startswith("/v1/signing-keys/issuer-profiles?")
    assert paths[2:] == [
        "/v1/compliance-profiles",
        "/v1/revocation-profiles",
        "/v1/revocation-profiles/revocation-1/activate",
        "/v1/credential-templates",
        "/v1/credential-templates/template-1/activate",
        (f"/org/{fixtures.DEFAULT_ORGANIZATION}/.well-known/openid-credential-issuer"),
    ]
    template = next(body for path, method, body in calls if path == "/v1/credential-templates" and method == "POST")
    assert template is not None
    assert template["issuer_did"] == issuer_did
    assert "issuer_profile_id" not in template
    assert not any(path.startswith("/v1/presentation-policies") for path, _method, _body in calls)
    assert not any(path.startswith("/v1/trust-profiles") for path, _method, _body in calls)


def test_bootstrap_uses_public_template_and_policy_apis() -> None:
    calls: list[tuple[str, str, dict | None]] = []
    responses = iter(
        [
            {"service": {"id": "service-1", "key_reference": "issuer-es256"}},
            {"profile": {"id": "credential-issuer-1"}},
            {"service": {"id": "request-service-1", "key_reference": "request-es256"}},
            {"profile": {"id": "request-issuer-1"}},
            {"id": "compliance-1"},
            {"id": "revocation-1"},
            {"id": "revocation-1"},
            {"id": "template-1"},
            {"id": "policy-1"},
            {"id": "policy-1"},
            {"id": "trust-1"},
            {"id": "trust-1"},
            {"service": {"id": "service-2", "key_reference": "issuer-eddsa"}},
            {"profile": {"id": "issuer-di-2"}},
            {"id": "compliance-2"},
            {"id": "revocation-2"},
            {"id": "revocation-2"},
            {"id": "template-2"},
            {"id": "template-3"},
            {"id": "policy-2"},
            {"id": "policy-2"},
            {"id": "policy-3"},
            {"id": "policy-3"},
            {
                "id": "w3c-api-key-1",
                "key": "mk_test_fixture",
                "scopes": ["credentials:issue", "credentials:read"],
            },
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
    assert "oid4vp_credential_issuer_profile_id" not in result
    assert "oid4vp_issuer_profile_id" not in result
    assert result["oid4vp_issuer_did"] == (f"did:web:marty.test:orgs:{fixtures.DEFAULT_ORGANIZATION}")
    assert result["oid4vp_compliance_profile_id"] == "compliance-1"
    assert result["oid4vp_revocation_profile_id"] == "revocation-1"
    assert result["oid4vp_trust_profile_id"] == "trust-1"
    assert result["w3c_compliance_profile_id"] == "compliance-2"
    assert result["w3c_revocation_profile_id"] == "revocation-2"
    assert "w3c_issuer_profile_id" not in result
    assert result["w3c_issuer_did"] == (f"did:web:marty.test:orgs:{fixtures.DEFAULT_ORGANIZATION}")
    assert result["w3c_template_id"] == "template-2"
    assert result["w3c_presentation_template_id"] == "template-3"
    assert result["w3c_credential_policy_id"] == "policy-2"
    assert result["w3c_presentation_policy_id"] == "policy-3"
    assert result["w3c_api_key_id"] == "w3c-api-key-1"
    assert result["w3c_api_key"] == "mk_test_fixture"
    assert "w3c_policy_id" not in result
    assert calls[0][0].startswith("/v1/signing-keys/config/resolve?")
    assert calls[0][2] == {
        "credential_format": "dc+sd-jwt",
        "key_purpose": "vc_jwt_issuer",
        "algorithm": "ES256",
    }
    assert calls[1][0].startswith("/v1/signing-keys/issuer-profiles?")
    assert calls[1][2]["key_purpose"] == "vc_jwt_issuer"
    assert calls[1][2]["algorithm"] == "ES256"
    assert calls[2][0].startswith("/v1/signing-keys/config/resolve?")
    assert calls[2][2] == {
        "key_purpose": "oid4vp_request_signing",
        "algorithm": "ES256",
    }
    assert calls[3][0].startswith("/v1/signing-keys/issuer-profiles?")
    assert calls[3][2]["key_purpose"] == "oid4vp_request_signing"
    assert calls[3][2]["algorithm"] == "ES256"
    assert calls[4][0] == "/v1/compliance-profiles"
    assert calls[5][0] == "/v1/revocation-profiles"
    assert calls[6][0] == "/v1/revocation-profiles/revocation-1/activate"
    assert calls[7][0] == "/v1/credential-templates"
    assert calls[7][2]["compliance_profile_id"] == "compliance-1"
    assert calls[7][2]["issuer_did"] == (f"did:web:marty.test:orgs:{fixtures.DEFAULT_ORGANIZATION}")
    assert "issuer_profile_id" not in calls[7][2]
    assert calls[7][2]["revocation_profile_id"] == "revocation-1"
    assert "compliance_profile" not in calls[7][2]
    assert calls[8][0] == "/v1/presentation-policies"
    assert calls[9][0] == "/v1/presentation-policies/policy-1/activate"
    assert calls[10][0] == "/v1/trust-profiles"
    assert calls[11][0] == "/v1/trust-profiles/trust-1/activate"
    assert all(method == "POST" for _path, method, _body in calls)
    assert calls[12][0].startswith("/v1/signing-keys/config/resolve?")
    assert calls[12][2] == {
        "credential_format": "ldp_vc",
        "key_purpose": "vc_jwt_issuer",
        "algorithm": "EdDSA",
    }
    assert calls[13][0].startswith("/v1/signing-keys/issuer-profiles?")
    assert calls[13][2]["signing_key_reference"] == "issuer-eddsa"
    assert calls[13][2]["algorithm"] == "EdDSA"
    assert calls[17][2]["credential_payload_format"] == "ldp_vc"
    assert calls[18][2]["credential_payload_format"] == "ldp_vc"
    assert calls[19][2]["holder_binding"] == {"required": False}
    assert calls[23][0].startswith("/v1/api-keys?organization_id=")
    assert calls[23][2] == {
        "name": "Official W3C VC API run-1",
        "description": "Disposable key for one official VCDM v2 suite run",
        "scopes": ["credentials:issue", "credentials:read"],
        "is_test": True,
    }
    requirement = calls[19][2]["credential_requirements"][0]
    assert requirement["credential_template_id"] == "template-2"
    assert requirement["credential_payload_format"] == "w3c_vcdm_v2_di"
    assert requirement["requested_claims"] == [{"claim_name": "id", "display_name": "id", "required": False}]
    assert calls[21][2]["holder_binding"] == {"required": True}
    presentation_requirement = calls[21][2]["credential_requirements"][0]
    assert presentation_requirement["credential_template_id"] == "template-3"
    assert presentation_requirement["credential_payload_format"] == ("w3c_vcdm_v2_di")


def test_oidf_fixture_matches_the_official_runner_pid_contract() -> None:
    template = fixtures.template_payload(
        fixtures.DEFAULT_ORGANIZATION,
        "compliance-1",
        "did:web:issuer.example.com",
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
    assert template["issuer_did"] == "did:web:issuer.example.com"
    assert "issuer_profile_id" not in template
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


def test_oidf_mdoc_fixture_uses_the_public_mdoc_contract() -> None:
    revocation = fixtures.revocation_profile_payload(
        fixtures.DEFAULT_ORGANIZATION,
        w3c=False,
        run_id="run-1",
        mdoc=True,
    )
    # Marty resources use the protocol enum. `mso_mdoc` is reserved for the
    # OID4VC signing/metadata/wire adapter boundary.
    assert revocation["supported_formats"] == ["MDOC"]

    compliance = fixtures.compliance_profile_payload(
        fixtures.DEFAULT_ORGANIZATION,
        w3c=False,
        run_id="run-1",
        mdoc=True,
    )
    assert compliance["credential_format"] == "MDOC"
    assert compliance["frameworks"] == ["aamva", "iso_18013_5", "oid4vp"]

    template = fixtures.template_payload(
        fixtures.DEFAULT_ORGANIZATION,
        "compliance-1",
        "did:web:issuer.example.com",
        "revocation-1",
        w3c=False,
        run_id="run-1",
        mdoc=True,
    )
    assert template["credential_type"] == "org.iso.18013.5.1.mDL"
    assert template["doctype"] == "org.iso.18013.5.1.mDL"
    assert template["supported_formats"] == ["MDOC"]
    assert template["credential_payload_format"] == "MDOC"
    assert template["issuer_did"] == "did:web:issuer.example.com"
    assert "issuer_profile_id" not in template
    assert "auto_generate_artifacts" not in template

    policy = fixtures.policy_payload(
        fixtures.DEFAULT_ORGANIZATION,
        "template-1",
        w3c=False,
        run_id="run-1",
        mdoc=True,
    )
    requirement = policy["credential_requirements"][0]
    assert requirement["credential_payload_format"] == "MDOC"
    assert [claim["claim_name"] for claim in requirement["requested_claims"]] == [
        "family_name",
        "given_name",
        "birth_date",
    ]


def test_oidf_mdoc_bootstrap_resolves_a_managed_document_signer() -> None:
    calls: list[tuple[str, str, dict | None]] = []
    responses = iter(
        [
            {"service": {"id": "mdoc-service", "key_reference": "mdoc-es256"}},
            {"profile": {"id": "mdoc-issuer"}},
            {"service": {"id": "request-service", "key_reference": "request-es256"}},
            {"profile": {"id": "request-issuer"}},
            {"id": "compliance-1"},
            {"id": "revocation-1"},
            {"id": "revocation-1"},
            {"id": "template-1"},
            {"id": "policy-1"},
            {"id": "policy-1"},
            {"id": "trust-1"},
            {"id": "trust-1"},
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
        mode="oid4vp-mdoc",
        oidf_mdoc_trust_anchor_pem=MDOC_TRUST_ANCHOR_PEM,
        request=request,
    )

    assert result["oid4vp_mdoc_policy_id"] == "policy-1"
    assert result["oid4vp_mdoc_trust_profile_id"] == "trust-1"
    assert result["oid4vp_mdoc_issuer_did"] == (f"did:web:marty.test:orgs:{fixtures.DEFAULT_ORGANIZATION}")
    assert calls[0][2] == {
        "credential_format": "mso_mdoc",
        "key_purpose": "mdoc_dsc",
        "algorithm": "ES256",
    }
    assert calls[1][2]["key_purpose"] == "mdoc_dsc"
    assert calls[1][2]["algorithm"] == "ES256"
    assert calls[7][2]["credential_payload_format"] == "MDOC"
    assert calls[7][2]["doctype"] == "org.iso.18013.5.1.mDL"
    assert calls[8][2]["credential_requirements"][0]["credential_payload_format"] == "MDOC"
    trust_profile = calls[10][2]
    assert trust_profile["supported_formats"] == ["MDOC"]
    assert trust_profile["trust_sources"] == [
        {
            "name": "Official OIDF mdoc document signer",
            "source_type": "PINNED_ISSUER",
            "certificate_pem": MDOC_TRUST_ANCHOR_PEM,
            "description": ("Public test certificate extracted from the exact commit-pinned OIDF conformance runner"),
            "enabled": True,
        }
    ]
    assert "allowed_issuers" not in trust_profile
    assert "system_issuer_overrides" not in trust_profile
    assert all("issuer_profile_id" not in (body or {}) for _path, _method, body in calls)
    assert all("auto_generate_artifacts" not in (body or {}) for _path, _method, body in calls)


def test_eudi_bootstrap_keeps_custody_binding_behind_issuer_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str, dict | None]] = []
    monkeypatch.setattr(
        fixtures,
        "create_disposable_issuer_certificate_chain",
        lambda *_args, **_kwargs: SimpleNamespace(
            leaf_pem="leaf-certificate",
            chain_pem="issuer-certificate",
        ),
    )
    responses = iter(
        [
            {"service": {"id": "managed-service", "key_reference": "managed-key"}},
            {"profile": {"id": "issuer-profile"}},
            {"public_jwk": PUBLIC_SIGNING_JWK},
            {
                "issuer_profile_id": "issuer-profile",
                "certificate_chain_length": 2,
            },
            {"service": {"id": "request-service", "key_reference": "request-key"}},
            {"profile": {"id": "request-profile"}},
            {"id": "compliance-profile"},
            {"id": "revocation-profile"},
            {"id": "revocation-profile"},
            {"id": "passport-template"},
            {"id": "mdl-template"},
            {"id": "open-badge-template"},
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
        mode="eudi",
        request=request,
    )

    assert result == {
        "organization_id": fixtures.DEFAULT_ORGANIZATION,
        "eudi_issuer_did": f"did:web:marty.test:orgs:{fixtures.DEFAULT_ORGANIZATION}",
        "eudi_request_issuer_did": f"did:web:marty.test:orgs:{fixtures.DEFAULT_ORGANIZATION}",
        "eudi_compliance_profile_id": "compliance-profile",
        "eudi_revocation_profile_id": "revocation-profile",
        "eudi_passport_template_id": "passport-template",
        "eudi_mdl_template_id": "mdl-template",
        "eudi_open_badge_template_id": "open-badge-template",
    }
    profile_body = calls[1][2]
    assert profile_body is not None
    assert profile_body["issuer_did"] == result["eudi_issuer_did"]
    assert profile_body["signing_service_id"] == "managed-service"
    assert profile_body["signing_key_reference"] == "managed-key"
    assert profile_body["algorithm"] == "ES256"
    assert calls[2][0].startswith("/v1/signing-keys/issuer-profiles/issuer-profile/public-identity?")
    assert calls[2][1] == "GET"
    assert calls[2][2] is None
    assert calls[3][0].startswith("/v1/signing-keys/issuer-profiles/issuer-profile/certificate?")
    assert calls[3][1] == "PUT"
    assert calls[3][2] == {
        "cert_pem": "leaf-certificate",
        "cert_chain_pem": "issuer-certificate",
    }
    request_profile_body = calls[5][2]
    assert request_profile_body is not None
    assert request_profile_body["issuer_did"] == result["eudi_request_issuer_did"]
    assert request_profile_body["signing_service_id"] == "request-service"
    assert request_profile_body["signing_key_reference"] == "request-key"
    assert request_profile_body["key_purpose"] == "oid4vp_request_signing"
    assert request_profile_body["algorithm"] == "ES256"
    for _path, _method, body in calls[9:]:
        assert body is not None
        assert body["issuer_did"] == result["eudi_issuer_did"]
        assert "issuer_profile_id" not in body
        assert "signing_service_id" not in body
        assert "signing_key_reference" not in body


def test_new_issuer_profile_public_identity_retries_only_transient_404(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    sleeps: list[int] = []

    def request(
        _gateway: str,
        _session: str,
        _path: str,
        *,
        method: str,
    ) -> object:
        nonlocal calls
        calls += 1
        assert method == "GET"
        if calls == 1:
            raise RuntimeError("public gateway returned HTTP 404")
        return {"public_jwk": PUBLIC_SIGNING_JWK}

    monkeypatch.setattr(fixtures.time, "sleep", sleeps.append)
    identity = fixtures.resolve_new_profile_public_identity(
        "https://marty.test",
        "real-session",
        organization_id=fixtures.DEFAULT_ORGANIZATION,
        profile_id="issuer-profile",
        request=request,
    )

    assert identity == {"public_jwk": PUBLIC_SIGNING_JWK}
    assert calls == 2
    assert sleeps == [1]


def test_new_issuer_profile_public_identity_does_not_retry_other_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        fixtures.time,
        "sleep",
        lambda _seconds: pytest.fail("non-404 failures must not be retried"),
    )

    def request(
        _gateway: str,
        _session: str,
        _path: str,
        *,
        method: str,
    ) -> object:
        assert method == "GET"
        raise RuntimeError("public gateway returned HTTP 500")

    with pytest.raises(RuntimeError, match="HTTP 500"):
        fixtures.resolve_new_profile_public_identity(
            "https://marty.test",
            "real-session",
            organization_id=fixtures.DEFAULT_ORGANIZATION,
            profile_id="issuer-profile",
            request=request,
        )


def test_w3c_fixture_separates_credential_and_presentation_verification() -> None:
    credential_template = fixtures.template_payload(
        fixtures.DEFAULT_ORGANIZATION,
        "compliance-1",
        "did:web:issuer.example.com",
        "revocation-1",
        w3c=True,
        run_id="run-1",
    )
    presentation_template = fixtures.template_payload(
        fixtures.DEFAULT_ORGANIZATION,
        "compliance-1",
        "did:web:issuer.example.com",
        "revocation-1",
        w3c=True,
        run_id="run-1",
        presentation=True,
    )
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
    assert credential_template["supported_formats"] == ["ldp_vc"]
    assert credential_template["credential_payload_format"] == "ldp_vc"
    assert presentation_template["supported_formats"] == ["ldp_vc"]
    assert presentation_template["credential_payload_format"] == "ldp_vc"
    assert credential_template["issuer_did"] == "did:web:issuer.example.com"
    assert presentation_template["issuer_did"] == "did:web:issuer.example.com"
    for template in (credential_template, presentation_template):
        assert "issuer_profile_id" not in template
        assert "signing_service_id" not in template
        assert "signing_key_reference" not in template
    assert credential_policy["holder_binding"] == {"required": False}
    credential_requirement = credential_policy["credential_requirements"][0]
    assert credential_requirement["credential_payload_format"] == "w3c_vcdm_v2_di"
    assert credential_requirement["requested_claims"] == [{"claim_name": "id", "display_name": "id", "required": False}]
    assert presentation_policy["holder_binding"] == {"required": True}
    assert presentation_policy["credential_requirements"][0]["credential_payload_format"] == ("w3c_vcdm_v2_di")


def test_w3c_data_integrity_signer_uses_managed_eddsa_capability() -> None:
    assert fixtures.signing_service_request_payload(
        w3c=True,
        data_integrity=True,
    ) == {
        "credential_format": "ldp_vc",
        "key_purpose": "vc_jwt_issuer",
        "algorithm": "EdDSA",
    }


def test_w3c_revocation_profile_declares_json_ld() -> None:
    profile = fixtures.revocation_profile_payload(
        fixtures.DEFAULT_ORGANIZATION,
        w3c=True,
        run_id="run-1",
    )

    assert profile["supported_formats"] == ["JSON_LD"]


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


def test_mdoc_trust_anchor_is_read_from_exact_runner_source(tmp_path: Path) -> None:
    source = tmp_path / "src" / "main" / "kotlin" / "org" / "multipaz" / "testapp" / "TestAppUtils.kt"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
        val documentSignerCert = X509Cert.fromPem(
            \"\"\"-----BEGIN CERTIFICATE-----
            Y2VydGlmaWNhdGU=
            -----END CERTIFICATE-----\"\"\"
        )
        """,
        encoding="utf-8",
    )

    assert fixtures.official_mdoc_trust_anchor(tmp_path) == MDOC_TRUST_ANCHOR_PEM


def test_mdoc_bootstrap_requires_the_runner_document_certificate() -> None:
    with pytest.raises(ValueError, match="document certificate"):
        fixtures.bootstrap(
            "https://marty.test",
            "real-session",
            organization_id=fixtures.DEFAULT_ORGANIZATION,
            run_id="run-1",
            mode="oid4vp-mdoc",
            request=lambda *_args, **_kwargs: {"id": "not-reached"},
        )


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
            {"service": {"id": "request-service", "key_reference": "request-es256"}},
            {"profile": {"id": "request-profile"}},
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
