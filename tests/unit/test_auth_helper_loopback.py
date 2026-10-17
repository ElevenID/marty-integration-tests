"""Direct-loopback PKCE cookie behavior for the disposable self-host install."""

import httpx

from tests.integration.gateway.helpers.auth_helper import AuthHelper


def _client_with_secure_realm_cookie(host: str) -> httpx.AsyncClient:
    client = httpx.AsyncClient(cookies=httpx.Cookies())
    client.cookies.set("AUTH_SESSION_ID", "synthetic", domain=host, path="/realms/11id/")
    for cookie in client.cookies.jar:
        cookie.secure = True
    return client


def test_secure_keycloak_cookie_reaches_only_the_direct_loopback_realm() -> None:
    client = _client_with_secure_realm_cookie("127.0.0.1")
    helper = AuthHelper(keycloak_local_url="http://127.0.0.1:38180")
    action = "http://127.0.0.1:38180/realms/11id/login-actions/authenticate"

    assert "cookie" not in client.build_request("POST", action).headers
    helper._allow_loopback_keycloak_session(client, action)
    assert "AUTH_SESSION_ID=synthetic" in client.build_request("POST", action).headers["cookie"]
    assert "cookie" not in client.build_request("POST", "http://127.0.0.1:38180/v1/auth/callback").headers
    assert "cookie" not in client.build_request("POST", "http://example.org/realms/11id/login-actions/authenticate").headers


def test_remote_and_mismatched_keycloak_urls_retain_secure_cookies() -> None:
    for local, action in (
        ("http://keycloak.example.org:38180", "http://keycloak.example.org:38180/realms/11id/login-actions/authenticate"),
        ("http://127.0.0.1:38180", "http://127.0.0.1:38181/realms/11id/login-actions/authenticate"),
        ("http://127.0.0.1:38180", "http://127.0.0.1:38180/not-a-realm"),
    ):
        host = httpx.URL(local).host
        client = _client_with_secure_realm_cookie(host)
        AuthHelper(keycloak_local_url=local)._allow_loopback_keycloak_session(client, action)
        assert all(cookie.secure for cookie in client.cookies.jar)
