"""
Programmatic PKCE Authentication Helper for Integration Tests

Implements the full OIDC PKCE flow to get a Marty gateway session cookie
without requiring a browser. Works against local and remote environments.

Flow:
  1. GET /v1/auth/login → 302 to Keycloak
  2. GET Keycloak login page → extract form action
  3. POST credentials → 302 to callback
  4. GET /v1/auth/callback → auth service creates session → sets sessionId cookie
"""

from __future__ import annotations

import logging
import os
import re
from typing import Optional
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode, urljoin

import httpx

logger = logging.getLogger(__name__)


class AuthError(Exception):
    """Authentication flow failure."""


class AuthHelper:
    """
    Programmatic PKCE authentication helper.

    Drives the Keycloak PKCE flow on behalf of the test suite,
    returning a ``sessionId`` cookie value that the gateway accepts.

    URL rewriting is used to route Keycloak & auth callbacks through
    localhost instead of going through Cloudflare/external DNS.

    Environment variables
    ---------------------
    AUTH_SERVICE_URL     Internal auth service URL   (default: http://localhost:8001)
    KEYCLOAK_LOCAL_URL   Local Keycloak base URL     (default: http://localhost:8180)
    GATEWAY_EXTERNAL     Public gateway hostname     (default: beta.elevenidllc.com)
    TEST_USERNAME        Keycloak user email         (default: admin@marty.demo)
    TEST_PASSWORD        Keycloak user password      (default: Admin123!)
    """

    #: Redirect-target during login that we want to intercept
    CALLBACK_PATH = "/v1/auth/callback"

    def __init__(
        self,
        auth_service_url: Optional[str] = None,
        keycloak_local_url: Optional[str] = None,
        gateway_external_host: Optional[str] = None,
    ):
        self.auth_service_url = (
            auth_service_url
            or os.getenv("AUTH_SERVICE_URL", "http://localhost:8001")
        ).rstrip("/")
        self.keycloak_local_url = (
            keycloak_local_url
            or os.getenv("KEYCLOAK_LOCAL_URL", "http://localhost:8180")
        ).rstrip("/")
        self.gateway_external_host = (
            gateway_external_host
            or os.getenv("GATEWAY_EXTERNAL", "beta.elevenidllc.com")
        )

    # ------------------------------------------------------------------
    # URL rewriting helpers
    # ------------------------------------------------------------------

    def _to_keycloak_local(self, url: str) -> str:
        """Rewrite an external Keycloak URL to the local host:port."""
        # Pattern 1: https://beta.elevenidllc.com/realms/...
        # Pattern 2: http://beta.elevenidllc.com:8180/realms/...
        # Pattern 3: http://keycloak:8080/realms/...  (Docker-internal DNS)
        parsed = urlparse(url)
        host = parsed.netloc  # e.g. "beta.elevenidllc.com" or "keycloak:8080"

        is_external_host = self.gateway_external_host in host
        is_docker_keycloak = host in ("keycloak:8080", "keycloak")

        if not (is_external_host or is_docker_keycloak):
            return url  # Already local or unknown host – leave as-is

        # Only rewrite paths that go to Keycloak
        if not parsed.path.startswith("/realms"):
            return url

        local_parsed = urlparse(self.keycloak_local_url)
        rewritten = parsed._replace(
            scheme=local_parsed.scheme,
            netloc=local_parsed.netloc,
        )
        return urlunparse(rewritten)

    def _to_auth_callback_local(self, url: str) -> str:
        """Rewrite the auth callback URL to the local auth service.

        The Keycloak ``redirect_uri`` registered for the client can point at the
        frontend (e.g. ``localhost:3000``), a Docker-internal gateway hostname
        (e.g. ``gateway:8000``), or the production domain.  In every case we
        want to call the *auth service* directly so the integration tests don't
        need a running frontend.
        """
        if self.CALLBACK_PATH not in url:
            return url
        parsed = urlparse(url)
        # Always rewrite: the callback is always handled by the auth service
        # regardless of what host Keycloak has in the redirect_uri.
        local_parsed = urlparse(self.auth_service_url)
        rewritten = parsed._replace(
            scheme=local_parsed.scheme,
            netloc=local_parsed.netloc,
        )
        return urlunparse(rewritten)

    # ------------------------------------------------------------------
    # Core PKCE flow
    # ------------------------------------------------------------------

    async def get_session_id(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> str:
        """
        Perform the full PKCE flow and return a ``sessionId`` cookie.

        Parameters
        ----------
        username:
            Keycloak username / email.  Falls back to ``TEST_USERNAME`` env var
            then ``admin@marty.demo``.
        password:
            Keycloak password.  Falls back to ``TEST_PASSWORD`` env var
            then ``Admin123!``.

        Returns
        -------
        str
            The value of the ``sessionId`` cookie set by the auth service.
        """
        username = username or os.getenv("TEST_USERNAME", "admin@marty.demo")
        password = password or os.getenv("TEST_PASSWORD", "Admin123!")

        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=30.0,
            # Collect cookies across redirects we manually follow
            cookies=httpx.Cookies(),
        ) as client:
            return await self._run_pkce_flow(client, username, password)

    async def _run_pkce_flow(
        self,
        client: httpx.AsyncClient,
        username: str,
        password: str,
    ) -> str:
        # ----------------------------------------------------------------
        # Step 1: Initiate login – auth service stores PKCE state in Redis,
        #         redirects us to Keycloak
        # ----------------------------------------------------------------
        login_url = f"{self.auth_service_url}/v1/auth/login"
        logger.debug("[pkce] GET %s", login_url)
        r1 = await client.get(login_url)
        _assert_redirect(r1, step=1, url=login_url)

        keycloak_auth_url = self._to_keycloak_local(r1.headers["location"])
        logger.debug("[pkce] → Keycloak: %s", keycloak_auth_url[:120])

        # ----------------------------------------------------------------
        # Step 2: GET Keycloak login page
        # ----------------------------------------------------------------
        r2 = await client.get(keycloak_auth_url)
        if r2.status_code == 302:
            # Keycloak may immediately redirect (e.g. already authenticated)
            keycloak_auth_url = self._to_keycloak_local(r2.headers["location"])
            r2 = await client.get(keycloak_auth_url)

        if r2.status_code != 200:
            raise AuthError(
                f"[pkce] step 2: Keycloak login page returned {r2.status_code}\n"
                f"URL: {keycloak_auth_url}\nBody: {r2.text[:400]}"
            )

        # ----------------------------------------------------------------
        # Step 3: Extract form action from Keycloak HTML
        # ----------------------------------------------------------------
        action_match = re.search(r'action="([^"]+)"', r2.text)
        if not action_match:
            raise AuthError(
                f"[pkce] step 3: No form action found in Keycloak login page.\n"
                f"Body snippet: {r2.text[:600]}"
            )
        raw_action = action_match.group(1).replace("&amp;", "&")
        action_url = self._to_keycloak_local(raw_action)
        logger.debug("[pkce] Form action: %s", action_url[:120])

        # ----------------------------------------------------------------
        # Step 4: POST credentials to Keycloak
        # ----------------------------------------------------------------
        logger.debug("[pkce] Posting credentials for %s", username)
        r3 = await client.post(
            action_url,
            data={"username": username, "password": password},
        )

        # Keycloak may return 200 (error page) or 302 (success)
        if r3.status_code == 200:
            # Probably a login error – try to extract the message
            err_match = re.search(
                r'id="kc-feedback-wrapper"[^>]*>(.*?)</div',
                r3.text,
                re.DOTALL,
            )
            err_text = err_match.group(1).strip() if err_match else r3.text[:300]
            raise AuthError(
                f"[pkce] step 4: Keycloak credential rejection.\n{err_text}"
            )
        _assert_redirect(r3, step=4, url=action_url)

        # ----------------------------------------------------------------
        # Step 5: Follow intermediate Keycloak redirects until we reach
        #         the auth callback URL
        # ----------------------------------------------------------------
        next_url = r3.headers["location"]
        for hop in range(8):
            if self.CALLBACK_PATH in next_url:
                break
            next_url = self._to_keycloak_local(next_url)
            logger.debug("[pkce] intermediate redirect → %s", next_url[:120])
            rx = await client.get(next_url)
            if rx.status_code not in (301, 302, 303, 307, 308):
                raise AuthError(
                    f"[pkce] step 5 (hop {hop}): Expected redirect, got "
                    f"{rx.status_code}\nURL: {next_url}\nBody: {rx.text[:300]}"
                )
            next_url = rx.headers.get("location", "")
        else:
            raise AuthError(
                f"[pkce] step 5: Did not reach {self.CALLBACK_PATH} after 8 hops."
            )

        # ----------------------------------------------------------------
        # Step 6: Rewrite callback to local auth service and GET it
        # ----------------------------------------------------------------
        callback_url = self._to_auth_callback_local(next_url)
        logger.debug("[pkce] Callback: %s", callback_url[:120])

        r4 = await client.get(callback_url)
        # The auth service either redirects (302) to the UI with sessionId cookie,
        # or returns 200/4xx if something went wrong.

        # Walk any post-callback redirects but harvest the sessionId as soon as
        # we see it (the UI redirect may go somewhere we can't reach).
        session_id = _extract_session_cookie(r4)
        if session_id:
            logger.debug("[pkce] Got sessionId on callback response")
            return session_id

        # Follow the auth-service redirect a bit further to find the cookie
        for hop in range(3):
            loc = r4.headers.get("location", "")
            if not loc:
                break
            # Rewrite any external gateway URL to avoid going off-network
            if self.gateway_external_host in loc:
                loc_parsed = urlparse(loc)
                # If it's a UI redirect (e.g. /dashboard), we already have the cookie
                break
            r4 = await client.get(loc)
            session_id = _extract_session_cookie(r4)
            if session_id:
                return session_id

        # Check cookies accumulated in the client (httpx tracks them)
        session_id = client.cookies.get("sessionId")
        if session_id:
            return session_id

        raise AuthError(
            f"[pkce] step 6: No sessionId cookie found after callback.\n"
            f"Final status: {r4.status_code}\n"
            f"Headers: {dict(r4.headers)}\n"
            f"Client cookies: {dict(client.cookies)}"
        )


# ------------------------------------------------------------------
# Module-level convenience factory
# ------------------------------------------------------------------

_default_helper: Optional[AuthHelper] = None


def get_auth_helper() -> AuthHelper:
    """Return a module-level singleton AuthHelper."""
    global _default_helper
    if _default_helper is None:
        _default_helper = AuthHelper()
    return _default_helper


async def get_test_session_id(
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> str:
    """
    Convenience wrapper: run PKCE flow and return sessionId.

    Uses the default ``AuthHelper`` singleton.
    """
    return await get_auth_helper().get_session_id(username, password)


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------

def _assert_redirect(response: httpx.Response, step: int, url: str) -> None:
    """Raise ``AuthError`` if the response is not a redirect."""
    if response.status_code not in (301, 302, 303, 307, 308):
        raise AuthError(
            f"[pkce] step {step}: Expected redirect at {url!r}, "
            f"got {response.status_code}.\nBody: {response.text[:300]}"
        )


def _extract_session_cookie(response: httpx.Response) -> Optional[str]:
    """Extract ``sessionId`` from Set-Cookie header or response.cookies."""
    # httpx populates response.cookies from Set-Cookie headers
    val = response.cookies.get("sessionId")
    if val:
        return val
    # Fallback: parse Set-Cookie headers manually
    for hdr_val in response.headers.get_list("set-cookie"):
        if "sessionId=" in hdr_val:
            match = re.search(r"sessionId=([^;]+)", hdr_val)
            if match:
                return match.group(1)
    return None
