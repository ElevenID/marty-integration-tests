#!/usr/bin/env python3
"""Start one normal Marty verifier flow for an OIDF verifier module.

This deployment adapter uses the public, authenticated gateway endpoint and
returns the ordinary ``openid4vp`` request created by the flow service. The
OIDF runner adapter then gives that request to its own mock wallet. It does
not create a test-only flow, a bypass, or a synthetic VP.
"""

from __future__ import annotations

import json
import os
import ssl
import sys
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen


def required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"{name} is required")
    return value


def https_url(value: str, field: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError(f"{field} must be an externally reachable HTTPS URL")
    return value.rstrip("/")


def flow_body(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload.get("test_id"), str) or not payload["test_id"]:
        raise ValueError("OIDF module test_id is required")
    request_method = payload.get("request_method", "url_query")
    if request_method not in {"url_query", "request_uri_signed"}:
        raise ValueError("OIDF request method is unsupported")
    profile = os.environ.get("OIDF_MARTY_VERIFIER_PROFILE", "standard")
    if profile not in {"standard", "haip"}:
        raise ValueError("OIDF_MARTY_VERIFIER_PROFILE must be standard or haip")
    return {
        "presentation_policy_id": required_env("OIDF_MARTY_PRESENTATION_POLICY_ID"),
        "trust_profile_id": os.environ.get("OIDF_MARTY_TRUST_PROFILE_ID") or None,
        "expiry_minutes": int(os.environ.get("OIDF_MARTY_FLOW_EXPIRY_MINUTES", "15")),
        "oid4vp_profile": profile,
        "request_uri_method": "post" if request_method == "request_uri_signed" else "get",
    }


def start_flow(gateway_url: str, session_id: str, body: dict[str, Any], *, insecure: bool) -> dict[str, Any]:
    request = Request(
        f"{gateway_url}/v1/flows/verify",
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={"Accept": "application/json", "Content-Type": "application/json", "Cookie": f"sessionId={session_id}"},
    )
    context = ssl._create_unverified_context() if insecure else None  # nosec B323: disposable local TLS only
    with urlopen(request, timeout=30, context=context) as response:  # nosec B310: configured disposable gateway
        if response.status != 200:
            raise RuntimeError(f"Marty verifier flow returned HTTP {response.status}")
        data = json.loads(response.read().decode("utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError("Marty verifier flow response is not a JSON object")
    return data


def main() -> int:
    payload = json.load(sys.stdin)
    if not isinstance(payload, dict):
        raise ValueError("OIDF flow input must be a JSON object")
    gateway = https_url(required_env("OIDF_MARTY_GATEWAY_URL"), "OIDF_MARTY_GATEWAY_URL")
    result = start_flow(gateway, required_env("OIDF_MARTY_SESSION_ID"), flow_body(payload), insecure=os.environ.get("OIDF_INSECURE_TLS") == "1")
    value = result.get("authorization_request") or result.get("request_uri")
    if not isinstance(value, str) or not value:
        raise RuntimeError("Marty flow response has no authorization_request or request_uri")
    print(json.dumps({"authorization_request": value}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, OSError, json.JSONDecodeError) as exc:
        print(f"OIDF Marty flow start failed: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
