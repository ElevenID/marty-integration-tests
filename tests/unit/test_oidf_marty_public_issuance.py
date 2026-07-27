from __future__ import annotations

import json

import pytest

from scripts import oidf_marty_public_issuance as issuance

PUBLIC_JWKS = {
    "keys": [
        {
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "use": "sig",
            "kid": "wallet-key-1",
            "x": "A" * 43,
            "y": "B" * 43,
        }
    ]
}


def test_issuance_body_uses_fixed_did_first_public_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OIDF_MARTY_ORGANIZATION_ID", "org-1")
    monkeypatch.setenv("OIDF_MARTY_CREDENTIAL_TEMPLATE_ID", "template-1")
    monkeypatch.setenv("OIDF_MARTY_ISSUER_DID", "did:web:issuer.example")

    body = issuance.issuance_body(
        {
            "organization_id": "attacker-org",
            "credential_template_id": "attacker-template",
            "issuer_profile_id": "attacker-profile",
            "signing_service_id": "attacker-service",
            "authorized_client": {
                "client_id": "official-wallet",
                "jwks": PUBLIC_JWKS,
            },
            "claims": {"given_name": "Official"},
        }
    )

    assert body == {
        "organization_id": "org-1",
        "credential_template_id": "template-1",
        "issuer_did": "did:web:issuer.example",
        "authorized_client": {
            "client_id": "official-wallet",
            "jwks": PUBLIC_JWKS,
        },
        "claims": {"given_name": "Official"},
    }


def test_issuance_body_rejects_wallet_private_key_material(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OIDF_MARTY_ORGANIZATION_ID", "org-1")
    monkeypatch.setenv("OIDF_MARTY_CREDENTIAL_TEMPLATE_ID", "template-1")
    monkeypatch.setenv("OIDF_MARTY_ISSUER_DID", "did:web:issuer.example")
    private_jwks = json.loads(json.dumps(PUBLIC_JWKS))
    private_jwks["keys"][0]["d"] = "private"

    with pytest.raises(ValueError, match="public keys only"):
        issuance.issuance_body(
            {
                "authorized_client": {
                    "client_id": "official-wallet",
                    "jwks": private_jwks,
                },
                "claims": {},
            }
        )


@pytest.mark.parametrize(
    "patch",
    [
        {"kty": "RSA"},
        {"crv": "P-384"},
        {"alg": "none"},
        {"x": "short"},
        {"unexpected": "contract-drift"},
    ],
)
def test_issuance_body_rejects_keys_outside_marty_protocol(
    patch: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OIDF_MARTY_ORGANIZATION_ID", "org-1")
    monkeypatch.setenv("OIDF_MARTY_CREDENTIAL_TEMPLATE_ID", "template-1")
    monkeypatch.setenv("OIDF_MARTY_ISSUER_DID", "did:web:issuer.example")
    jwks = json.loads(json.dumps(PUBLIC_JWKS))
    jwks["keys"][0].update(patch)

    with pytest.raises(ValueError, match="authorized_client"):
        issuance.issuance_body(
            {
                "authorized_client": {
                    "client_id": "official-wallet",
                    "jwks": jwks,
                },
                "claims": {},
            }
        )


def test_create_offer_uses_normal_gateway_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def request(
        origin: str,
        session_id: str,
        path: str,
        *,
        method: str,
        json_body: object,
    ) -> object:
        captured.update(
            origin=origin,
            session_id=session_id,
            path=path,
            method=method,
            json_body=json_body,
        )
        return {"credential_offer_uri": "openid-credential-offer://?credential_offer=%7B%7D"}

    monkeypatch.setattr(issuance, "authenticated_json_request", request)
    body = {"organization_id": "org-1", "issuer_did": "did:web:issuer.example"}
    result = issuance.create_offer("https://gateway.example", "session-1", body)

    assert result["credential_offer_uri"].startswith("openid-credential-offer://")
    assert captured == {
        "origin": "https://gateway.example",
        "session_id": "session-1",
        "path": "/v1/issuance",
        "method": "POST",
        "json_body": body,
    }


def test_main_writes_only_the_gateway_response(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("OIDF_MARTY_GATEWAY_URL", "https://gateway.example")
    monkeypatch.setenv("OIDF_MARTY_ORGANIZATION_ID", "org-1")
    monkeypatch.setenv("OIDF_MARTY_CREDENTIAL_TEMPLATE_ID", "template-1")
    monkeypatch.setenv("OIDF_MARTY_ISSUER_DID", "did:web:issuer.example")
    monkeypatch.setattr(issuance, "gateway_session_id", lambda: "session-1")
    monkeypatch.setattr(
        issuance,
        "create_offer",
        lambda *_args: {"credential_offer_uri": "openid-credential-offer://offer"},
    )
    monkeypatch.setattr(
        issuance.sys,
        "stdin",
        type(
            "_Input",
            (),
            {
                "read": lambda _self: json.dumps(
                    {
                        "authorized_client": {
                            "client_id": "official-wallet",
                            "jwks": PUBLIC_JWKS,
                        },
                        "claims": {},
                    }
                )
            },
        )(),
    )

    assert issuance.main() == 0
    assert json.loads(capsys.readouterr().out) == {"credential_offer_uri": "openid-credential-offer://offer"}
