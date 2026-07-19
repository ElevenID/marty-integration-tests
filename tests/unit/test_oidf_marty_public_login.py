"""Unit tests for the public-only OIDC session bootstrap."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("oidf_public_login", ROOT / "scripts" / "oidf_marty_public_login.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load public OIDC login adapter")
public_login = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(public_login)


def test_public_origin_rejects_non_origin_and_non_https_urls() -> None:
    assert public_login.public_origin("https://marty.test:28443") == "https://marty.test:28443"
    for invalid in ("http://marty.test", "https://marty.test/path", "not-a-url"):
        with pytest.raises(ValueError, match="HTTPS origin"):
            public_login.public_origin(invalid)


def test_operator_credential_prefers_role_neutral_environment_variable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OIDF_MARTY_OPERATOR_EMAIL", "operator@example.test")
    monkeypatch.setenv("OIDF_MARTY_REVIEWER_EMAIL", "reviewer@example.test")
    assert (
        public_login.operator_credential("OIDF_MARTY_OPERATOR_EMAIL", "OIDF_MARTY_REVIEWER_EMAIL")
        == "operator@example.test"
    )


def test_parse_response_uses_the_last_header_block() -> None:
    raw = (
        "HTTP/1.1 100 Continue\r\n\r\n"
        "HTTP/2 302 Found\r\nLocation: /callback\r\nSet-Cookie: sessionId=abc; Secure\r\n\r\nbody"
    )
    status, headers, body = public_login.parse_response(raw)

    assert status == 302
    assert headers["location"] == ["/callback"]
    assert public_login.session_from_headers(headers) == "abc"
    assert body == "body"


def test_login_uses_only_the_configured_public_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    origin = "https://marty-oidf.test:28443"
    observed: list[tuple[str, str, dict[str, str] | None]] = []
    responses = iter(
        [
            (302, {"location": ["/realms/11id/protocol/openid-connect/auth?state=one"]}, ""),
            (200, {}, '<html><form action="/realms/11id/login-actions/authenticate?code=one"></form></html>'),
            (302, {"location": ["/v1/auth/callback?code=issued&state=one"]}, ""),
            (302, {"set-cookie": ["sessionId=real-gateway-session; Path=/; Secure; HttpOnly"]}, ""),
        ]
    )

    def fake_request(
        url: str,
        *,
        cookie_jar: Path,
        origin: str,
        method: str = "GET",
        form: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, list[str]], str]:
        assert cookie_jar.name == "cookies.txt"
        assert origin == "https://marty-oidf.test:28443"
        observed.append((url, method, form))
        return next(responses)

    monkeypatch.setattr(public_login, "curl_request", fake_request)
    assert public_login.login(origin, "conformance.reviewer@elevenid.dev", "not-logged") == "real-gateway-session"
    assert observed == [
        (f"{origin}/v1/auth/login?redirect_uri=%2Fconsole%2Foperate", "GET", None),
        (f"{origin}/realms/11id/protocol/openid-connect/auth?state=one", "GET", None),
        (
            f"{origin}/realms/11id/login-actions/authenticate?code=one",
            "POST",
            {"username": "conformance.reviewer@elevenid.dev", "password": "not-logged"},
        ),
        (f"{origin}/v1/auth/callback?code=issued&state=one", "GET", None),
    ]


def test_login_rejects_a_redirect_to_an_untrusted_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        public_login,
        "curl_request",
        lambda *_args, **_kwargs: (302, {"location": ["https://outside.example/steal"]}, ""),
    )
    with pytest.raises(RuntimeError, match="outside"):
        public_login.login("https://marty-oidf.test", "reviewer@example.test", "password")


def test_authenticated_json_request_is_origin_scoped_and_uses_gateway_cookie(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_request(url: str, **kwargs: object) -> tuple[int, dict[str, list[str]], str]:
        captured["url"] = url
        captured.update(kwargs)
        return 200, {}, '{"ok":true}'

    monkeypatch.setattr(public_login, "curl_request", fake_request)
    result = public_login.authenticated_json_request(
        "https://marty-oidf.test",
        "public-session",
        "/v1/presentation-policies",
        method="POST",
        json_body={"name": "Official OID4VP policy"},
    )

    assert result == {"ok": True}
    assert captured["url"] == "https://marty-oidf.test/v1/presentation-policies"
    assert captured["headers"] == {"Accept": "application/json", "Cookie": "sessionId=public-session"}
    assert captured["json_body"] == {"name": "Official OID4VP policy"}


def test_authenticated_json_request_rejects_non_origin_relative_paths() -> None:
    with pytest.raises(ValueError, match="origin-relative"):
        public_login.authenticated_json_request("https://marty-oidf.test", "session", "https://outside.test")
