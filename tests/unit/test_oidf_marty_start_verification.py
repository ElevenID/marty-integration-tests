"""Unit tests for the authenticated OIDF verifier-flow deployment adapter."""

from __future__ import annotations

import importlib.util
import io
import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("oidf_start", ROOT / "scripts" / "oidf_marty_start_verification.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load OIDF verifier-flow adapter")
oidf_start = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(oidf_start)

ISSUER_ENTITY_ID = "11111111-1111-4111-8111-111111111111"
RELATIONSHIP_ID = "22222222-2222-4222-8222-222222222222"


@pytest.fixture(autouse=True)
def issuer_profile_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OIDF_MARTY_ORGANIZATION_ID", "org-1")
    monkeypatch.setenv("OIDF_MARTY_ISSUER_DID", "did:web:verifier.example")


def test_flow_body_selects_post_only_for_the_official_signed_post_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OIDF_MARTY_PRESENTATION_POLICY_ID", "policy-1")
    monkeypatch.setenv("OIDF_MARTY_TRUST_PROFILE_ID", "trust-1")
    monkeypatch.setenv("OIDF_MARTY_VERIFIER_PROFILE", "haip")
    payload = {
        "test_id": "module-1",
        "test_name": "oid4vp-1final-verifier-request-uri-method-post",
        "request_method": "request_uri_signed",
    }
    assert oidf_start.flow_body(payload) == {
        "organization_id": "org-1",
        "presentation_policy_id": "policy-1",
        "trust_profile_id": "trust-1",
        "issuer_did": "did:web:verifier.example",
        "expiry_minutes": 15,
        "oid4vp_profile": "haip",
        "request_transport": "request_uri",
        "request_uri_method": "post",
    }


def test_flow_body_selects_post_for_the_haip_module_with_official_variant_suffix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OIDF_MARTY_PRESENTATION_POLICY_ID", "policy-1")
    monkeypatch.setenv("OIDF_MARTY_VERIFIER_PROFILE", "haip")
    payload = {
        "test_id": "module-1",
        "test_name": (
            "oid4vp-1final-verifier-request-uri-method-post"
            "[client_id_prefix=x509_hash][request_method=request_uri_signed][vp_profile=haip]"
        ),
        "request_method": "request_uri_signed",
    }

    assert oidf_start.flow_body(payload)["request_uri_method"] == "post"


@pytest.mark.parametrize(
    "test_name",
    [
        "oid4vp-1final-verifier-request-uri-method-post-suffix",
        "oid4vp-1final-verifier-happy-flow",
    ],
)
def test_flow_body_does_not_force_other_transports_to_post(
    monkeypatch: pytest.MonkeyPatch,
    test_name: str,
) -> None:
    monkeypatch.setenv("OIDF_MARTY_PRESENTATION_POLICY_ID", "policy-1")
    monkeypatch.setenv("OIDF_MARTY_VERIFIER_PROFILE", "haip")

    body = oidf_start.flow_body(
        {
            "test_id": "module-1",
            "test_name": test_name,
            "request_method": "request_uri_signed",
        }
    )

    assert body["request_uri_method"] == "get"


def test_flow_body_selects_native_direct_url_query_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OIDF_MARTY_PRESENTATION_POLICY_ID", "policy-1")

    body = oidf_start.flow_body(
        {
            "test_id": "module-1",
            "test_name": "oid4vp-1final-verifier-happy-flow",
            "request_method": "url_query",
        }
    )

    assert body["request_transport"] == "url_query"
    assert body["request_uri_method"] == "get"


def test_flow_body_rejects_unknown_request_method(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OIDF_MARTY_PRESENTATION_POLICY_ID", "policy-1")

    with pytest.raises(ValueError, match="url_query"):
        oidf_start.flow_body(
            {
                "test_id": "module-1",
                "test_name": "oid4vp-1final-verifier-happy-flow",
                "request_method": "url_query_signed",
            }
        )


def test_flow_body_requires_the_official_module_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OIDF_MARTY_PRESENTATION_POLICY_ID", "policy-1")
    with pytest.raises(ValueError, match="test_name"):
        oidf_start.flow_body({"test_id": "module-1", "request_method": "request_uri_signed"})


def test_start_flow_sends_authenticated_gateway_request(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_request(origin: str, session_id: str, path: str, **kwargs: object) -> dict[str, str]:
        captured.update({"origin": origin, "session_id": session_id, "path": path, **kwargs})
        return {"authorization_request": "openid4vp://authorize?request_uri=https://marty.test/request"}

    monkeypatch.setattr(oidf_start, "authenticated_json_request", fake_request)
    result = oidf_start.start_flow("https://marty.test", "session-1", {"presentation_policy_id": "policy-1"})
    assert result["authorization_request"].startswith("openid4vp://")
    assert captured == {
        "origin": "https://marty.test",
        "session_id": "session-1",
        "path": "/v1/flows/verify",
        "method": "POST",
        "json_body": {"presentation_policy_id": "policy-1"},
    }


def test_official_credential_issuer_is_the_exact_test_instance_base() -> None:
    assert oidf_start.official_credential_issuer(
        {
            "authorization_endpoint": (
                "https://localhost.emobix.co.uk:8443/test/a/module-alias/authorize"
            )
        },
        "https://localhost.emobix.co.uk:8443/",
    ) == "https://localhost.emobix.co.uk:8443/test/a/module-alias"
    assert oidf_start.official_credential_issuer(
        {
            "authorization_endpoint": (
                "https://localhost.emobix.co.uk:8443/test/0123456789abcdef/authorize"
            )
        },
        "https://localhost.emobix.co.uk:8443/",
    ) == "https://localhost.emobix.co.uk:8443/test/0123456789abcdef"


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://other.example/test/a/module/authorize",
        "https://localhost.emobix.co.uk:8443/not-the-official-route/authorize",
        "https://localhost.emobix.co.uk:8443/test/a/module/authorize?issuer=other",
        "https://user@localhost.emobix.co.uk:8443/test/a/module/authorize",
    ],
)
def test_official_credential_issuer_rejects_untrusted_routes(endpoint: str) -> None:
    with pytest.raises(ValueError, match="Official test route|CONFORMANCE_SERVER"):
        oidf_start.official_credential_issuer(
            {"authorization_endpoint": endpoint},
            "https://localhost.emobix.co.uk:8443/",
        )


def test_govern_official_module_issuer_creates_exact_entity_then_relationship(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OIDF_MARTY_DYNAMIC_ISSUER_GOVERNANCE", "1")
    monkeypatch.setenv("CONFORMANCE_SERVER", "https://localhost.emobix.co.uk:8443/")
    monkeypatch.setenv("OIDF_MARTY_TRUST_PROFILE_ID", "trust-1")
    monkeypatch.setenv(
        "OIDF_MARTY_OFFICIAL_SIGNER_PUBLIC_JWK",
        json.dumps(
            {
                "kty": "EC",
                "crv": "P-256",
                "x": "public-x",
                "y": "public-y",
            }
        ),
    )
    calls: list[tuple[str, str, object | None]] = []

    def fake_request(
        _origin: str,
        _session_id: str,
        path: str,
        *,
        method: str = "GET",
        json_body: object | None = None,
    ) -> object:
        calls.append((path, method, json_body))
        if method == "GET":
            return []
        return {
            "id": ISSUER_ENTITY_ID
            if path == "/v1/issuer-entities"
            else RELATIONSHIP_ID
        }

    monkeypatch.setattr(oidf_start, "authenticated_json_request", fake_request)
    oidf_start.govern_official_module_issuer(
        "https://marty.test",
        "session-1",
        {
            "authorization_endpoint": (
                "https://localhost.emobix.co.uk:8443/test/a/module-alias/authorize"
            )
        },
    )

    assert calls[0] == (
        "/v1/issuer-entities?organization_id=org-1",
        "GET",
        None,
    )
    assert calls[1] == (
        "/v1/issuer-entities",
        "POST",
        {
            "organization_id": "org-1",
            "issuer_id": "https://localhost.emobix.co.uk:8443/test/a/module-alias",
            "issuer_type": "ORGANIZATION",
            "display_name": "Official OIDF test-instance issuer",
            "description": (
                "Disposable exact issuer for one module in the commit-pinned "
                "unmodified OIDF runner"
            ),
            "compliance_status": "COMPLIANT",
            "metadata": {
                "source": "official-oidf-commit-pinned-test-instance",
                "verification_keys": [
                    {
                        "kty": "EC",
                        "crv": "P-256",
                        "x": "public-x",
                        "y": "public-y",
                    }
                ],
            },
        },
    )
    assert calls[2] == (
        "/v1/trust-profiles/trust-1/issuers",
        "GET",
        None,
    )
    assert calls[3] == (
        "/v1/trust-profiles/trust-1/issuers",
        "POST",
        {
            "issuer_id": ISSUER_ENTITY_ID,
            "trust_level": 100,
            "relationship_status": "TRUSTED",
            "cascade_revocation_policy": "AUTO_CASCADE",
            "metadata": {
                "source": "official-oidf-commit-pinned-test-instance",
            },
        },
    )


def test_govern_official_module_issuer_reuses_only_exact_governance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signer = {
        "kty": "EC",
        "crv": "P-256",
        "x": "public-x",
        "y": "public-y",
    }
    monkeypatch.setenv("OIDF_MARTY_DYNAMIC_ISSUER_GOVERNANCE", "1")
    monkeypatch.setenv("CONFORMANCE_SERVER", "https://localhost.emobix.co.uk:8443/")
    monkeypatch.setenv("OIDF_MARTY_TRUST_PROFILE_ID", "trust-1")
    monkeypatch.setenv("OIDF_MARTY_OFFICIAL_SIGNER_PUBLIC_JWK", json.dumps(signer))
    calls: list[str] = []

    def fake_request(
        _origin: str,
        _session_id: str,
        path: str,
        **_kwargs: object,
    ) -> object:
        calls.append(path)
        if path.startswith("/v1/issuer-entities?"):
            return [
                {
                    "id": ISSUER_ENTITY_ID,
                    "organization_id": "org-1",
                    "issuer_id": "https://localhost.emobix.co.uk:8443/test/a/module-alias",
                    "issuer_type": "ORGANIZATION",
                    "display_name": "Official OIDF test-instance issuer",
                    "description": (
                        "Disposable exact issuer for one module in the commit-pinned "
                        "unmodified OIDF runner"
                    ),
                    "is_system_issuer": False,
                    "compliance_status": "COMPLIANT",
                    "revoked_at": None,
                    "metadata": {
                        "source": "official-oidf-commit-pinned-test-instance",
                        "verification_keys": [signer],
                    },
                }
            ]
        return [
            {
                "id": RELATIONSHIP_ID,
                "issuer_id": ISSUER_ENTITY_ID,
                "trust_level": 100,
                "relationship_status": "TRUSTED",
                "cascade_revocation_policy": "AUTO_CASCADE",
                "metadata": {
                    "source": "official-oidf-commit-pinned-test-instance",
                },
            }
        ]

    monkeypatch.setattr(oidf_start, "authenticated_json_request", fake_request)
    oidf_start.govern_official_module_issuer(
        "https://marty.test",
        "session-1",
        {
            "authorization_endpoint": (
                "https://localhost.emobix.co.uk:8443/test/a/module-alias/authorize"
            )
        },
    )

    assert calls == [
        "/v1/issuer-entities?organization_id=org-1",
        "/v1/trust-profiles/trust-1/issuers",
    ]


def test_official_signer_jwk_rejects_private_or_extra_members(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "OIDF_MARTY_OFFICIAL_SIGNER_PUBLIC_JWK",
        json.dumps(
            {
                "kty": "EC",
                "crv": "P-256",
                "x": "public-x",
                "y": "public-y",
                "d": "must-not-cross-custody-boundary",
            }
        ),
    )
    with pytest.raises(ValueError, match="public-only"):
        oidf_start.official_signer_public_jwk()


def test_main_governs_the_module_issuer_before_starting_the_flow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = {
        "test_id": "module-1",
        "test_name": "oid4vp-1final-verifier-happy-flow",
        "authorization_endpoint": (
            "https://localhost.emobix.co.uk:8443/test/a/module-alias/authorize"
        ),
        "request_method": "request_uri_signed",
    }
    events: list[str] = []
    monkeypatch.setenv("OIDF_MARTY_GATEWAY_URL", "https://marty.test")
    monkeypatch.setenv("OIDF_MARTY_PRESENTATION_POLICY_ID", "policy-1")
    monkeypatch.setattr(oidf_start.sys, "stdin", io.StringIO(json.dumps(payload)))
    monkeypatch.setattr(oidf_start, "gateway_session_id", lambda: "session-1")
    monkeypatch.setattr(
        oidf_start,
        "govern_official_module_issuer",
        lambda gateway, session, actual: events.append(
            f"govern:{gateway}:{session}:{actual['test_id']}"
        ),
    )
    monkeypatch.setattr(
        oidf_start,
        "start_flow",
        lambda gateway, session, _body: (
            events.append(f"start:{gateway}:{session}")
            or {
                "instance_id": "flow-1",
                "authorization_request": "openid4vp://authorize?request_uri=https://marty.test/request",
            }
        ),
    )
    monkeypatch.setattr(oidf_start, "write_private_flow_audit", lambda *_args: None)

    assert oidf_start.main() == 0
    assert events == [
        "govern:https://marty.test:session-1:module-1",
        "start:https://marty.test:session-1",
    ]


def test_private_flow_audit_records_only_module_to_flow_correlation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "private-audit"
    monkeypatch.setenv("OIDF_MARTY_FLOW_AUDIT_DIR", str(destination))
    payload = {
        "test_id": "private-runner-id",
        "test_name": "oid4vp-1final-verifier-happy-flow",
        "credential": "must-not-leak",
    }
    result = {
        "instance_id": "12345678-1234-1234-1234-123456789abc",
        "authorization_request": "openid4vp://must-not-leak",
    }

    oidf_start.write_private_flow_audit(payload, result)

    records = list(destination.glob("*.json"))
    assert len(records) == 1
    assert json.loads(records[0].read_text(encoding="utf-8")) == {
        "schema": "elevenid.oidf-flow-correlation/private-v1",
        "test_name": "oid4vp-1final-verifier-happy-flow",
        "flow_instance_id": "12345678-1234-1234-1234-123456789abc",
    }
    serialized = records[0].read_text(encoding="utf-8")
    assert "private-runner-id" not in serialized
    assert "must-not-leak" not in serialized


def test_gateway_must_be_https() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        oidf_start.https_url("http://localhost:8000", "OIDF_MARTY_GATEWAY_URL")


def test_gateway_session_uses_public_login_only_when_not_preconfigured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OIDF_MARTY_SESSION_ID", raising=False)
    monkeypatch.setattr(
        oidf_start.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "public-session\n", ""),
    )

    assert oidf_start.gateway_session_id() == "public-session"

    monkeypatch.setenv("OIDF_MARTY_SESSION_ID", "operator-supplied-session")
    assert oidf_start.gateway_session_id() == "operator-supplied-session"
