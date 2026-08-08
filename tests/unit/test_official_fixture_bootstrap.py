from __future__ import annotations

import importlib.util
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

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


def issuer_identity_response(
    *, key_purpose: str = "vc_jwt_issuer", credential_format: str = "SD_JWT_VC", algorithm: str = "ES256"
) -> dict[str, object]:
    return {
        "identity": {
            "issuer_did": f"did:web:marty.test:orgs:{fixtures.DEFAULT_ORGANIZATION}",
            "key_purpose": key_purpose,
            "credential_format": credential_format,
            "algorithm": algorithm,
            "status": "active",
        },
        "created": True,
    }


def mdoc_trust_anchor_pem(*, not_before: datetime, not_after: datetime) -> str:
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OIDF mdoc fixture")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(private_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


MDOC_TRUST_ANCHOR_PEM = mdoc_trust_anchor_pem(
    not_before=datetime(2025, 1, 1, tzinfo=UTC),
    not_after=datetime(2035, 1, 1, tzinfo=UTC),
)


def write_mdoc_runner_certificate(root: Path, certificate_pem: str) -> None:
    source = root / "src" / "main" / "kotlin" / "org" / "multipaz" / "testapp" / "TestAppUtils.kt"
    source.parent.mkdir(parents=True)
    source.write_text(
        f"""
        val documentSignerCert = X509Cert.fromPem(
            \"\"\"{certificate_pem.rstrip()}\"\"\"
        )
        """,
        encoding="utf-8",
    )


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
            issuer_identity_response(),
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
        oidf_key_attestation_trust_anchor_pem="-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n",
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
    assert paths[0] == "/v1/signing-keys/issuer-identities"
    issuer_identity = calls[0][2]
    assert issuer_identity is not None
    assert issuer_identity["credential_format"] == "SD_JWT_VC"
    assert issuer_identity["key_attestation_policy"] == {
        "mode": "required",
        "trusted_root_certificates_pem": ["-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n"],
        "allowed_algorithms": ["ES256"],
        "required_key_storage": [],
        "required_user_authentication": [],
        "max_age_seconds": 300,
        "require_nonce": True,
        "status_validation": "disabled",
    }
    assert paths[1:] == [
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
            issuer_identity_response(),
            issuer_identity_response(key_purpose="oid4vp_request_signing"),
            {
                "identity": issuer_identity_response(key_purpose="oid4vp_request_signing")["identity"],
                "public_jwk": PUBLIC_SIGNING_JWK,
            },
            {"id": "compliance-1"},
            {"id": "revocation-1"},
            {"id": "revocation-1"},
            {"id": "template-1"},
            {"id": "policy-1"},
            {"id": "policy-1"},
            {"id": "trust-1"},
            {"id": "trust-1"},
            issuer_identity_response(credential_format="JSON_LD", algorithm="EdDSA"),
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
    assert result["oid4vp_request_issuer_public_jwk"] == PUBLIC_SIGNING_JWK
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
    assert calls[0][0] == "/v1/signing-keys/issuer-identities"
    assert calls[0][2] == {
        "organization_id": fixtures.DEFAULT_ORGANIZATION,
        "issuer_did": f"did:web:marty.test:orgs:{fixtures.DEFAULT_ORGANIZATION}",
        "key_purpose": "vc_jwt_issuer",
        "credential_format": "SD_JWT_VC",
        "algorithm": "ES256",
    }
    assert calls[1][0] == "/v1/signing-keys/issuer-identities"
    assert calls[1][2]["key_purpose"] == "oid4vp_request_signing"
    assert calls[2][0] == "/v1/signing-keys/issuer-identities/resolve"
    assert calls[3][0] == "/v1/compliance-profiles"
    assert calls[4][0] == "/v1/revocation-profiles"
    assert calls[5][0] == "/v1/revocation-profiles/revocation-1/activate"
    assert calls[6][0] == "/v1/credential-templates"
    assert calls[6][2]["compliance_profile_id"] == "compliance-1"
    assert calls[6][2]["issuer_did"] == (f"did:web:marty.test:orgs:{fixtures.DEFAULT_ORGANIZATION}")
    assert "issuer_profile_id" not in calls[6][2]
    assert calls[6][2]["revocation_profile_id"] == "revocation-1"
    assert "compliance_profile" not in calls[6][2]
    assert calls[7][0] == "/v1/presentation-policies"
    assert calls[8][0] == "/v1/presentation-policies/policy-1/activate"
    assert calls[9][0] == "/v1/trust-profiles"
    assert calls[10][0] == "/v1/trust-profiles/trust-1/activate"
    assert all(method == "POST" for _path, method, _body in calls)
    assert calls[11][0] == "/v1/signing-keys/issuer-identities"
    assert calls[11][2] == {
        "organization_id": fixtures.DEFAULT_ORGANIZATION,
        "issuer_did": f"did:web:marty.test:orgs:{fixtures.DEFAULT_ORGANIZATION}",
        "key_purpose": "vc_jwt_issuer",
        "credential_format": "JSON_LD",
        "algorithm": "EdDSA",
    }
    assert calls[15][2]["credential_payload_format"] == "ldp_vc"
    assert calls[16][2]["credential_payload_format"] == "ldp_vc"
    assert calls[17][2]["holder_binding"] == {"required": False}
    assert calls[21][0].startswith("/v1/api-keys?organization_id=")
    assert calls[21][2] == {
        "name": "Official W3C VC API run-1",
        "description": "Disposable key for one official VCDM v2 suite run",
        "scopes": ["credentials:issue", "credentials:read"],
        "is_test": True,
    }
    requirement = calls[17][2]["credential_requirements"][0]
    assert requirement["credential_template_id"] == "template-2"
    assert requirement["credential_payload_format"] == "w3c_vcdm_v2_di"
    assert requirement["requested_claims"] == [{"claim_name": "id", "display_name": "id", "required": False}]
    assert calls[19][2]["holder_binding"] == {
        "required": True,
        "binding_methods": ["DEVICE_KEY"],
        "proof_profiles": ["OID4VP_VERIFIABLE_PRESENTATION"],
        "proof_freshness": {
            "challenge_required": True,
            "audience_binding_required": True,
            "replay_detection_required": True,
        },
    }
    presentation_requirement = calls[19][2]["credential_requirements"][0]
    assert presentation_requirement["credential_template_id"] == "template-3"
    assert presentation_requirement["credential_payload_format"] == ("w3c_vcdm_v2_di")


def test_oid4vp_bootstrap_adds_separate_disposable_browser_issuance_resources() -> None:
    calls: list[tuple[str, str, dict | None]] = []
    responses = iter(
        [
            issuer_identity_response(),
            issuer_identity_response(key_purpose="oid4vp_request_signing"),
            {
                "identity": issuer_identity_response(key_purpose="oid4vp_request_signing")["identity"],
                "public_jwk": PUBLIC_SIGNING_JWK,
            },
            {"id": "compliance-1"},
            {"id": "revocation-1"},
            {"id": "revocation-1"},
            {"id": "template-1"},
            {"id": "policy-1"},
            {"id": "policy-1"},
            {"id": "trust-1"},
            {"id": "trust-1"},
            {"id": "browser-compliance-1"},
            {"id": "browser-credential-1"},
            {"id": "browser-credential-1"},
            {"id": "browser-application-1"},
            {"id": "browser-application-1"},
            {"id": "browser-flow-1"},
            {"id": "browser-flow-1"},
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
        mode="oid4vp",
        oidf_signer_public_jwk=PUBLIC_SIGNING_JWK,
        request=request,
    )

    assert result["browser_credential_template_id"] == "browser-credential-1"
    assert result["browser_application_template_id"] == "browser-application-1"
    assert result["browser_flow_id"] == "browser-flow-1"
    assert result["oid4vp_request_issuer_public_jwk"] == PUBLIC_SIGNING_JWK
    browser_calls = calls[11:]
    assert [path for path, _method, _body in browser_calls] == [
        "/v1/compliance-profiles",
        "/v1/credential-templates",
        "/v1/credential-templates/browser-credential-1/activate",
        "/v1/application-templates",
        "/v1/application-templates/browser-application-1/activate",
        "/v1/flows/definitions",
        "/v1/flows/definitions/browser-flow-1/activate",
    ]
    credential_body = browser_calls[1][2]
    assert credential_body is not None
    assert credential_body["issuer_did"] == (f"did:web:marty.test:orgs:{fixtures.DEFAULT_ORGANIZATION}")
    assert "issuer_profile_id" not in credential_body
    assert "signing_service_id" not in credential_body
    assert "signing_key_reference" not in credential_body
    application_body = browser_calls[3][2]
    assert application_body is not None
    assert application_body["credential_template_id"] == "browser-credential-1"
    flow_body = browser_calls[5][2]
    assert flow_body is not None
    assert flow_body["credential_template_id"] == "browser-credential-1"
    assert flow_body["trigger"]["config"]["event_type"] == "APPLICATION_APPROVED"
    assert flow_body["extension"]["extends_flow_type"] == "oid4vci_pre_authorized"


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
    assert policy["holder_binding"] == {
        "required": True,
        "binding_methods": ["DEVICE_KEY"],
        "proof_profiles": ["OID4VP_VERIFIABLE_PRESENTATION"],
        "proof_freshness": {
            "challenge_required": True,
            "audience_binding_required": True,
            "replay_detection_required": True,
        },
    }


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
    assert [
        (
            claim["name"],
            claim["namespace"],
            claim["name"],
        )
        for claim in template["claims"]
    ] == [
        ("family_name", "org.iso.18013.5.1", "family_name"),
        ("given_name", "org.iso.18013.5.1", "given_name"),
        ("birth_date", "org.iso.18013.5.1", "birth_date"),
    ]

    policy = fixtures.policy_payload(
        fixtures.DEFAULT_ORGANIZATION,
        "template-1",
        w3c=False,
        run_id="run-1",
        mdoc=True,
    )
    requirement = policy["credential_requirements"][0]
    assert policy["holder_binding"] == {
        "required": True,
        "binding_methods": ["DEVICE_KEY"],
        "proof_profiles": ["MDOC_DEVICE_AUTHENTICATION"],
        "proof_freshness": {
            "challenge_required": True,
            "audience_binding_required": True,
            "replay_detection_required": True,
        },
    }
    assert requirement["credential_payload_format"] == "MDOC"
    assert [claim["claim_name"] for claim in requirement["requested_claims"]] == [
        "family_name",
        "given_name",
        "birth_date",
    ]
    template_claims = {claim["name"] for claim in template["claims"]}
    assert {claim["claim_name"] for claim in requirement["requested_claims"]} <= template_claims


def test_oidf_mdoc_bootstrap_resolves_a_managed_document_signer() -> None:
    calls: list[tuple[str, str, dict | None]] = []
    responses = iter(
        [
            issuer_identity_response(key_purpose="mdoc_dsc", credential_format="MDOC"),
            issuer_identity_response(key_purpose="oid4vp_request_signing", credential_format="MDOC"),
            {
                "identity": issuer_identity_response(key_purpose="oid4vp_request_signing", credential_format="MDOC")[
                    "identity"
                ],
                "public_jwk": PUBLIC_SIGNING_JWK,
            },
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
    assert result["oid4vp_mdoc_request_issuer_public_jwk"] == PUBLIC_SIGNING_JWK
    assert calls[0][2] == {
        "organization_id": fixtures.DEFAULT_ORGANIZATION,
        "issuer_did": f"did:web:marty.test:orgs:{fixtures.DEFAULT_ORGANIZATION}",
        "key_purpose": "mdoc_dsc",
        "credential_format": "MDOC",
        "algorithm": "ES256",
    }
    assert calls[1][2]["key_purpose"] == "oid4vp_request_signing"
    assert calls[2][0] == "/v1/signing-keys/issuer-identities/resolve"
    assert calls[6][2]["credential_payload_format"] == "MDOC"
    assert calls[6][2]["doctype"] == "org.iso.18013.5.1.mDL"
    assert calls[7][2]["credential_requirements"][0]["credential_payload_format"] == "MDOC"
    trust_profile = calls[9][2]
    assert trust_profile["supported_formats"] == ["MDOC"]
    assert trust_profile["trust_sources"] == [
        {
            "source_type": "PINNED_ISSUER",
            "certificate_pem": MDOC_TRUST_ANCHOR_PEM,
            "description": (
                "Public test certificate extracted from the exact commit-pinned OIDF conformance runner; "
                "pinning does not bypass ISO document-signer certificate validation"
            ),
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
            issuer_identity_response(),
            {
                "identity": issuer_identity_response()["identity"],
                "public_jwk": PUBLIC_SIGNING_JWK,
            },
            issuer_identity_response()["identity"],
            issuer_identity_response(key_purpose="oid4vp_request_signing"),
            {
                "identity": issuer_identity_response(key_purpose="oid4vp_request_signing")["identity"],
                "public_jwk": PUBLIC_SIGNING_JWK,
            },
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
        oidf_key_attestation_trust_anchor_pem="wallet-attester-root",
        request=request,
    )

    assert result == {
        "organization_id": fixtures.DEFAULT_ORGANIZATION,
        "eudi_issuer_did": f"did:web:marty.test:orgs:{fixtures.DEFAULT_ORGANIZATION}",
        "eudi_request_issuer_did": f"did:web:marty.test:orgs:{fixtures.DEFAULT_ORGANIZATION}",
        "eudi_request_issuer_public_jwk": PUBLIC_SIGNING_JWK,
        "eudi_compliance_profile_id": "compliance-profile",
        "eudi_revocation_profile_id": "revocation-profile",
        "eudi_passport_template_id": "passport-template",
        "eudi_mdl_template_id": "mdl-template",
        "eudi_open_badge_template_id": "open-badge-template",
    }
    identity_body = calls[0][2]
    assert identity_body is not None
    assert identity_body["issuer_did"] == result["eudi_issuer_did"]
    assert identity_body["credential_format"] == "SD_JWT_VC"
    assert identity_body["algorithm"] == "ES256"
    assert identity_body["key_attestation_policy"]["trusted_root_certificates_pem"] == ["wallet-attester-root"]
    assert calls[1][0] == "/v1/signing-keys/issuer-identities/resolve"
    assert calls[1][1] == "POST"
    assert calls[1][2] == {
        "organization_id": fixtures.DEFAULT_ORGANIZATION,
        "issuer_did": result["eudi_issuer_did"],
        "key_purpose": "vc_jwt_issuer",
        "credential_format": "SD_JWT_VC",
        "algorithm": "ES256",
    }
    assert calls[2][0] == "/v1/signing-keys/issuer-identities/certificate"
    assert calls[2][1] == "PUT"
    assert calls[2][2] == {
        "organization_id": fixtures.DEFAULT_ORGANIZATION,
        "issuer_did": result["eudi_issuer_did"],
        "key_purpose": "vc_jwt_issuer",
        "credential_format": "SD_JWT_VC",
        "algorithm": "ES256",
        "cert_pem": "leaf-certificate",
        "cert_chain_pem": "issuer-certificate",
    }
    request_identity_body = calls[3][2]
    assert request_identity_body is not None
    assert request_identity_body["issuer_did"] == result["eudi_request_issuer_did"]
    assert request_identity_body["key_purpose"] == "oid4vp_request_signing"
    assert request_identity_body["algorithm"] == "ES256"
    assert calls[4][0] == "/v1/signing-keys/issuer-identities/resolve"
    assert calls[4][1] == "POST"
    assert calls[4][2] == {
        "organization_id": fixtures.DEFAULT_ORGANIZATION,
        "issuer_did": result["eudi_request_issuer_did"],
        "key_purpose": "oid4vp_request_signing",
        "credential_format": "SD_JWT_VC",
        "algorithm": "ES256",
    }
    for _path, _method, body in calls[8:]:
        assert body is not None
        assert body["issuer_did"] == result["eudi_issuer_did"]
        assert "issuer_profile_id" not in body
        assert "signing_service_id" not in body
        assert "signing_key_reference" not in body


def test_new_issuer_did_resolution_retries_only_transient_404(
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
        json_body: dict | None = None,
    ) -> object:
        nonlocal calls
        calls += 1
        assert method == "POST"
        assert json_body is not None
        assert json_body["issuer_did"].startswith("did:web:")
        if calls == 1:
            raise RuntimeError("public gateway returned HTTP 404")
        return {
            "identity": issuer_identity_response()["identity"],
            "public_jwk": PUBLIC_SIGNING_JWK,
        }

    monkeypatch.setattr(fixtures.time, "sleep", sleeps.append)
    identity = fixtures.resolve_issuer_identity_public_jwk(
        "https://marty.test",
        "real-session",
        organization_id=fixtures.DEFAULT_ORGANIZATION,
        issuer_did=f"did:web:marty.test:orgs:{fixtures.DEFAULT_ORGANIZATION}",
        key_purpose="vc_jwt_issuer",
        credential_format="SD_JWT_VC",
        algorithm="ES256",
        request=request,
    )

    assert identity == PUBLIC_SIGNING_JWK
    assert calls == 2
    assert sleeps == [1]


def test_new_issuer_did_resolution_does_not_retry_other_errors(
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
        json_body: dict | None = None,
    ) -> object:
        assert method == "POST"
        assert json_body is not None
        raise RuntimeError("public gateway returned HTTP 500")

    with pytest.raises(RuntimeError, match="HTTP 500"):
        fixtures.resolve_issuer_identity_public_jwk(
            "https://marty.test",
            "real-session",
            organization_id=fixtures.DEFAULT_ORGANIZATION,
            issuer_did=f"did:web:marty.test:orgs:{fixtures.DEFAULT_ORGANIZATION}",
            key_purpose="vc_jwt_issuer",
            credential_format="SD_JWT_VC",
            algorithm="ES256",
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
    assert presentation_policy["holder_binding"] == {
        "required": True,
        "binding_methods": ["DEVICE_KEY"],
        "proof_profiles": ["OID4VP_VERIFIABLE_PRESENTATION"],
        "proof_freshness": {
            "challenge_required": True,
            "audience_binding_required": True,
            "replay_detection_required": True,
        },
    }
    assert presentation_policy["credential_requirements"][0]["credential_payload_format"] == ("w3c_vcdm_v2_di")


def test_w3c_data_integrity_identity_requests_eddsa_without_custody_selectors() -> None:
    payload = fixtures.issuer_identity_payload(
        fixtures.DEFAULT_ORGANIZATION,
        gateway_url="https://marty.test",
        w3c=True,
        algorithm="EdDSA",
    )
    assert payload == {
        "organization_id": fixtures.DEFAULT_ORGANIZATION,
        "issuer_did": f"did:web:marty.test:orgs:{fixtures.DEFAULT_ORGANIZATION}",
        "key_purpose": "vc_jwt_issuer",
        "credential_format": "JSON_LD",
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
    certificate_pem = mdoc_trust_anchor_pem(
        not_before=datetime(2025, 1, 1, tzinfo=UTC),
        not_after=datetime(2030, 1, 1, tzinfo=UTC),
    )
    write_mdoc_runner_certificate(tmp_path, certificate_pem)

    assert (
        fixtures.official_mdoc_trust_anchor(
            tmp_path,
            now=datetime(2026, 1, 1, tzinfo=UTC),
        )
        == certificate_pem
    )


def test_mdoc_trust_anchor_rejects_expired_official_fixture(tmp_path: Path) -> None:
    certificate_pem = mdoc_trust_anchor_pem(
        not_before=datetime(2025, 1, 1, tzinfo=UTC),
        not_after=datetime(2026, 1, 1, tzinfo=UTC),
    )
    write_mdoc_runner_certificate(tmp_path, certificate_pem)

    with pytest.raises(
        ValueError,
        match=r"official OIDF mdoc documentSignerCert has expired: .*do not bypass",
    ):
        fixtures.official_mdoc_trust_anchor(
            tmp_path,
            now=datetime(2026, 1, 2, tzinfo=UTC),
        )


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
