#!/usr/bin/env python3
"""Create a disposable Marty gateway session through the public OIDC path.

This helper is intentionally limited to the production-shaped OIDF Compose
topology: Keycloak and the gateway share one externally reachable HTTPS
origin. It follows ``/v1/auth/login`` through Keycloak and returns only the
``sessionId`` cookie set by ``/v1/auth/callback``. It never contacts a Docker
service name, an internal auth port, or a database.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlparse

REDIRECT_CODES = {301, 302, 303, 307, 308}


def required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"{name} is required")
    return value


def operator_credential(primary: str, legacy: str) -> str:
    """Prefer a role-neutral operator name while retaining local compatibility."""
    value = os.environ.get(primary, "").strip() or os.environ.get(legacy, "").strip()
    if not value:
        raise ValueError(f"{primary} is required")
    return value


def public_origin(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.path not in {"", "/"}:
        raise ValueError("OIDF_MARTY_GATEWAY_URL must be an HTTPS origin without a path")
    return value.rstrip("/")


def same_origin(url: str, origin: str) -> bool:
    candidate = urlparse(url)
    expected = urlparse(origin)
    return (candidate.scheme, candidate.netloc) == (expected.scheme, expected.netloc)


def resolve_option(origin: str) -> list[str]:
    """Optionally map a disposable TLS hostname to a local test address."""
    address = os.environ.get("OIDF_MARTY_RESOLVE_IP", "").strip()
    if not address:
        return []
    parsed = urlparse(origin)
    host = parsed.hostname
    if not host:
        raise ValueError("OIDF_MARTY_GATEWAY_URL has no hostname")
    port = parsed.port or 443
    return ["--resolve", f"{host}:{port}:{address}"]


def parse_response(raw: str) -> tuple[int, dict[str, list[str]], str]:
    """Extract the final HTTP header block emitted by curl without redirects."""
    matches = list(re.finditer(r"HTTP/\d(?:\.\d)?\s+(\d{3})[^\r\n]*\r?\n", raw))
    if not matches:
        raise RuntimeError("public OIDC request returned no HTTP status line")
    match = matches[-1]
    header_end = re.search(r"\r?\n\r?\n", raw[match.start() :])
    if header_end is None:
        raise RuntimeError("public OIDC response has incomplete headers")
    split_at = match.start() + header_end.end()
    header_text = raw[match.start() : split_at]
    headers: dict[str, list[str]] = {}
    for line in header_text.splitlines()[1:]:
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers.setdefault(key.lower(), []).append(value.strip())
    return int(match.group(1)), headers, raw[split_at:]


def curl_request(
    url: str,
    *,
    cookie_jar: Path,
    origin: str,
    method: str = "GET",
    form: dict[str, str] | None = None,
    headers: Mapping[str, str] | None = None,
    json_body: object | None = None,
) -> tuple[int, dict[str, list[str]], str]:
    if form is not None and json_body is not None:
        raise ValueError("a public request cannot include both form and JSON data")
    command = [
        "curl",
        "--silent",
        "--show-error",
        "--dump-header",
        "-",
        "--output",
        "-",
        "--request",
        method,
        "--connect-timeout",
        "10",
        "--max-time",
        "30",
        "--cookie",
        str(cookie_jar),
        "--cookie-jar",
        str(cookie_jar),
        *resolve_option(origin),
    ]
    for name, value in (headers or {}).items():
        command.extend(["--header", f"{name}: {value}"])
    if os.environ.get("OIDF_INSECURE_TLS") == "1":
        command.append("--insecure")
    input_data: bytes | None = None
    if form is not None:
        command.extend(["--header", "Content-Type: application/x-www-form-urlencoded", "--data-binary", "@-"])
        input_data = urlencode(form).encode("utf-8")
    elif json_body is not None:
        import json

        command.extend(["--header", "Content-Type: application/json", "--data-binary", "@-"])
        input_data = json.dumps(json_body, separators=(",", ":")).encode("utf-8")
    command.append(url)
    result = subprocess.run(command, input=input_data, capture_output=True, check=False)
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"public OIDC curl request failed with exit code {result.returncode}: {detail[:300]}")
    return parse_response(result.stdout.decode("utf-8", errors="replace"))


def authenticated_json_request(
    origin: str,
    session_id: str,
    path: str,
    *,
    method: str = "GET",
    json_body: object | None = None,
) -> object:
    """Call a Marty HTTPS gateway endpoint with a normal gateway session.

    This is deliberately limited to an origin-relative path. It keeps the
    conformance setup on the published gateway boundary even on a local stack
    whose disposable TLS hostname is resolved with curl's ``--resolve``.
    """
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError("public gateway path must be origin-relative")
    with tempfile.TemporaryDirectory(prefix="marty-oidf-api-cookie-") as temp_dir:
        status, _, body = curl_request(
            f"{origin}{path}",
            cookie_jar=Path(temp_dir) / "cookies.txt",
            origin=origin,
            method=method,
            headers={"Accept": "application/json", "Cookie": f"sessionId={session_id}"},
            json_body=json_body,
        )
    if not 200 <= status < 300:
        raise RuntimeError(f"public gateway {method} {path} returned HTTP {status}: {body[:300]}")
    import json

    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"public gateway {method} {path} returned non-JSON content") from exc


def redirect_location(headers: dict[str, list[str]], *, step: str) -> str:
    locations = headers.get("location", [])
    if not locations:
        raise RuntimeError(f"public OIDC {step} redirect has no Location header")
    return locations[-1]


def session_from_headers(headers: dict[str, list[str]]) -> str | None:
    for value in headers.get("set-cookie", []):
        match = re.match(r"sessionId=([^;]+)", value, flags=re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def login(origin: str, email: str, password: str) -> str:
    """Complete the normal public authorization-code flow and return its cookie."""
    with tempfile.TemporaryDirectory(prefix="marty-oidf-cookie-") as temp_dir:
        cookies = Path(temp_dir) / "cookies.txt"
        status, headers, _ = curl_request(
            f"{origin}/v1/auth/login?redirect_uri=%2Fconsole%2Foperate",
            cookie_jar=cookies,
            origin=origin,
        )
        if status not in REDIRECT_CODES:
            raise RuntimeError(f"public OIDC login returned HTTP {status}, expected a redirect")
        current = urljoin(origin + "/", redirect_location(headers, step="login"))
        if not same_origin(current, origin):
            raise RuntimeError("public OIDC login redirected outside the configured gateway origin")

        status, headers, body = curl_request(current, cookie_jar=cookies, origin=origin)
        if status != 200:
            raise RuntimeError(f"public OIDC Keycloak page returned HTTP {status}")
        action = re.search(r'<form[^>]+action="([^"]+)"', body, flags=re.IGNORECASE)
        if action is None:
            raise RuntimeError("public OIDC Keycloak page has no login form action")
        current = urljoin(current, action.group(1).replace("&amp;", "&"))
        if not same_origin(current, origin):
            raise RuntimeError("public OIDC login form action is outside the configured gateway origin")

        status, headers, _ = curl_request(
            current,
            cookie_jar=cookies,
            origin=origin,
            method="POST",
            form={"username": email, "password": password},
        )
        if status not in REDIRECT_CODES:
            raise RuntimeError(f"public OIDC credential submission returned HTTP {status}")
        current = urljoin(origin + "/", redirect_location(headers, step="credential submission"))

        for _ in range(8):
            if not same_origin(current, origin):
                raise RuntimeError("public OIDC redirect is outside the configured gateway origin")
            status, headers, _ = curl_request(current, cookie_jar=cookies, origin=origin)
            session_id = session_from_headers(headers)
            if session_id:
                return session_id
            if status not in REDIRECT_CODES:
                raise RuntimeError(f"public OIDC callback returned HTTP {status} without a session cookie")
            current = urljoin(current, redirect_location(headers, step="callback"))
        raise RuntimeError("public OIDC flow did not return a sessionId cookie after eight redirects")


def main() -> int:
    origin = public_origin(required_env("OIDF_MARTY_GATEWAY_URL"))
    email = operator_credential("OIDF_MARTY_OPERATOR_EMAIL", "OIDF_MARTY_REVIEWER_EMAIL")
    password = operator_credential("OIDF_MARTY_OPERATOR_PASSWORD", "OIDF_MARTY_REVIEWER_PASSWORD")
    print(login(origin, email, password))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"OIDF public login failed: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
