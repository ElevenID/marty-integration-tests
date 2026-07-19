#!/usr/bin/env python3
"""Drive a real Marty verification flow through an OIDF mock wallet.

The OpenID Foundation conformance suite owns every protocol assertion.  This
adapter only bridges its per-module mock-wallet endpoint to a deployment-owned
command which creates a normal Marty gateway verification flow.  It never
creates a session directly, fabricates a VP, or treats an expected failure as
a pass.

``OIDF_VERIFIER_COMMAND`` receives a JSON object on stdin and must write a
JSON object containing the normal Marty ``openid4vp://...request_uri=...``
authorization request (or the HTTPS request URI itself) to stdout.  Keeping
authentication, organization membership, and policy selection in that command
makes the same adapter usable against a clean Docker stack and a future
certification deployment without checking credentials into this repository.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import ssl
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urljoin, urlparse
from urllib.request import Request, urlopen


def local_marty_resolve(url: str) -> list[str]:
    """Return a narrow curl resolver override for a disposable public URL.

    The official runner and its mock wallet remain on their own Compose
    network.  A local operator may run this interaction bridge on the host,
    however, where the disposable Marty hostname only exists on the runner
    bridge.  Resolve *only* the configured public Marty origin to its local
    address while preserving the hostname for HTTPS and Host-header checks.
    No service name or private Marty network is exposed.
    """
    address = os.environ.get("OIDF_MARTY_RESOLVE_IP", "").strip()
    origin = os.environ.get("OIDF_MARTY_GATEWAY_URL", "").strip()
    if not address or not origin:
        return []
    target = urlparse(url)
    public = urlparse(origin)
    if target.scheme != "https" or (target.hostname, target.port or 443) != (public.hostname, public.port or 443):
        return []
    if not target.hostname:
        return []
    return ["--resolve", f"{target.hostname}:{target.port or 443}:{address}"]


def curl_executable() -> str:
    """Find curl on Windows hosts and Linux runner images alike."""
    value = shutil.which("curl.exe") or shutil.which("curl")
    if not value:
        raise RuntimeError("curl is required for a local OIDF_MARTY_RESOLVE_IP bridge")
    return value


def request_json(url: str, *, method: str = "GET", body: bytes | None = None,
                 headers: dict[str, str] | None = None, insecure: bool = False) -> tuple[int, Any]:
    resolver = local_marty_resolve(url)
    if resolver:
        command = [
            curl_executable(), "--silent", "--show-error", "--request", method,
            "--connect-timeout", "10", "--max-time", "30", *resolver,
        ]
        if insecure:
            command.append("--insecure")
        for name, value in (headers or {}).items():
            command.extend(["--header", f"{name}: {value}"])
        if body is not None:
            command.extend(["--data-binary", "@-"])
        command.extend(["--write-out", "\\n%{http_code}", url])
        completed = subprocess.run(command, input=body, capture_output=True, check=False)
        if completed.returncode:
            detail = completed.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"request to public Marty URL failed: {detail[:300]}")
        raw, separator, status_text = completed.stdout.decode("utf-8", errors="replace").rpartition("\n")
        if not separator or not status_text.isdigit():
            raise RuntimeError("public Marty URL returned no HTTP status")
        status = int(status_text)
        try:
            return status, json.loads(raw) if raw else None
        except json.JSONDecodeError:
            return status, raw

    request = Request(url, data=body, headers=headers or {}, method=method)
    context = ssl._create_unverified_context() if insecure else None  # nosec B323: explicit local-only option
    try:
        with urlopen(request, timeout=30, context=context) as response:  # nosec B310: configured test endpoints
            raw = response.read().decode("utf-8")
            try:
                return response.status, json.loads(raw) if raw else None
            except json.JSONDecodeError:
                return response.status, raw
    except HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(raw) if raw else None
        except json.JSONDecodeError:
            return exc.code, raw
    except URLError as exc:
        raise RuntimeError(f"request to {url} failed: {exc.reason}") from exc


def wait_for_exposed_authorization_endpoint(server: str, test_id: str, *, insecure: bool, timeout: int) -> str | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status, info = request_json(urljoin(server, f"api/runner/{test_id}"), insecure=insecure)
        if status == 200 and isinstance(info, dict):
            endpoint = info.get("exposed", {}).get("authorization_endpoint")
            if isinstance(endpoint, str) and endpoint:
                return endpoint
            # Negative modules can complete before they expose an interaction.
            if info.get("status") in {"FINISHED", "INTERRUPTED"}:
                return None
        time.sleep(1)
    raise RuntimeError(f"OIDF module {test_id} did not expose an authorization endpoint within {timeout} seconds")


def invoke_flow_command(command: Path, payload: dict[str, Any]) -> str:
    if not command.is_file():
        raise ValueError(f"OIDF verifier command is missing: {command}")
    completed = subprocess.run(
        [sys.executable, str(command.resolve())],
        input=json.dumps(payload).encode("utf-8"),
        capture_output=True,
        check=False,
    )
    if completed.returncode:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"OIDF verifier command failed with exit code {completed.returncode}: {detail[:400]}")
    try:
        response = json.loads(completed.stdout.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError("OIDF verifier command did not return JSON") from exc
    value = response.get("authorization_request") or response.get("request_uri")
    if not isinstance(value, str) or not value:
        raise RuntimeError("OIDF verifier command response needs authorization_request or request_uri")
    return value


def request_uri_from_authorization_request(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme in {"http", "https"}:
        request_uri = value
    else:
        request_uri = (parse_qs(parsed.query).get("request_uri") or [""])[0]
    parsed_request_uri = urlparse(request_uri)
    if parsed_request_uri.scheme != "https" or not parsed_request_uri.netloc:
        raise ValueError("Marty must return an externally reachable HTTPS request_uri")
    return request_uri


def decode_request_object(request_uri: str, *, insecure: bool) -> dict[str, Any]:
    status, raw = request_json(
        request_uri,
        headers={"Accept": "application/oauth-authz-req+jwt"},
        insecure=insecure,
    )
    if status != 200 or not isinstance(raw, str):
        raise RuntimeError(f"Marty request_uri returned HTTP {status}, not a signed request object")
    parts = raw.split(".")
    if len(parts) != 3:
        raise RuntimeError("Marty request object is not a compact signed JWT")
    try:
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Marty request object has invalid JSON claims") from exc
    if not isinstance(claims, dict):
        raise RuntimeError("Marty request object claims must be an object")
    return claims


def query_parameters(claims: dict[str, Any]) -> dict[str, str]:
    """Encode request claims for the official URL-query profile.

    The profile itself intentionally assesses query transport; the Marty
    request object is still fetched above to prove the deployed flow emitted a
    signed object before these values are passed to the mock wallet.
    """
    params: dict[str, str] = {}
    for key, value in claims.items():
        if value is None:
            continue
        params[key] = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))
    return params


def call_mock_wallet(endpoint: str, request_uri: str, *, request_method: str, insecure: bool) -> None:
    claims = decode_request_object(request_uri, insecure=insecure)
    if request_method == "url_query":
        url = endpoint + ("&" if "?" in endpoint else "?") + urlencode(query_parameters(claims))
        status, _ = request_json(url, insecure=insecure)
    elif request_method == "request_uri_signed":
        client_id = claims.get("client_id")
        if not isinstance(client_id, str) or not client_id:
            raise RuntimeError("signed request object has no client_id")
        url = endpoint + ("&" if "?" in endpoint else "?") + urlencode({
            "client_id": client_id,
            "request_uri": request_uri,
        })
        status, _ = request_json(url, insecure=insecure)
    else:
        raise ValueError("OIDF_VERIFIER_REQUEST_METHOD must be url_query or request_uri_signed")
    if status not in {200, 302, 303}:
        raise RuntimeError(f"OIDF mock wallet authorization endpoint returned HTTP {status}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test-id", required=True)
    parser.add_argument("--test-name", required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("--flow-command", type=Path, default=os.environ.get("OIDF_VERIFIER_COMMAND"))
    parser.add_argument("--request-method", default=os.environ.get("OIDF_VERIFIER_REQUEST_METHOD", "url_query"))
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--insecure", action="store_true", default=os.environ.get("OIDF_INSECURE_TLS") == "1")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.server:
        raise ValueError("CONFORMANCE_SERVER must be set")
    if args.flow_command is None:
        raise ValueError("OIDF_VERIFIER_COMMAND is required")
    endpoint = wait_for_exposed_authorization_endpoint(
        args.server, args.test_id, insecure=args.insecure, timeout=args.timeout
    )
    if endpoint is None:
        print(f"OIDF module {args.test_id} ({args.test_name}) finished without verifier interaction")
        return 0
    authorization_request = invoke_flow_command(args.flow_command, {
        "test_id": args.test_id,
        "test_name": args.test_name,
        "authorization_endpoint": endpoint,
        "request_method": args.request_method,
    })
    request_uri = request_uri_from_authorization_request(authorization_request)
    call_mock_wallet(endpoint, request_uri, request_method=args.request_method, insecure=args.insecure)
    print(f"Submitted real Marty request URI to OIDF module {args.test_id} ({args.test_name})")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"OIDF verifier interaction failed: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
