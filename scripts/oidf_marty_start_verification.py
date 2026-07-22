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
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# The deployment helpers are deliberately standalone scripts rather than an
# installed package. Make their directory importable too when this module is
# loaded by the unit suite through ``importlib``.
_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))
from oidf_marty_public_login import authenticated_json_request  # noqa: E402 -- import follows standalone path setup

REQUEST_URI_METHOD_POST_TEST = "oid4vp-1final-verifier-request-uri-method-post"


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
    if not isinstance(payload.get("test_name"), str) or not payload["test_name"]:
        raise ValueError("OIDF module test_name is required")
    request_method = payload.get("request_method", "url_query")
    if request_method not in {"url_query", "request_uri_signed"}:
        raise ValueError("OIDF request method is unsupported")
    profile = os.environ.get("OIDF_MARTY_VERIFIER_PROFILE", "standard")
    if profile not in {"standard", "haip"}:
        raise ValueError("OIDF_MARTY_VERIFIER_PROFILE must be standard or haip")
    module_name = payload["test_name"].partition("[")[0]
    return {
        "presentation_policy_id": required_env("OIDF_MARTY_PRESENTATION_POLICY_ID"),
        "trust_profile_id": os.environ.get("OIDF_MARTY_TRUST_PROFILE_ID") or None,
        # The verifier selects its profile and asserts that profile's DID. The
        # flow API intentionally accepts no KMS service or provider key fields.
        "issuer_profile_id": required_env("OIDF_MARTY_ISSUER_PROFILE_ID"),
        "issuer_did": required_env("OIDF_MARTY_ISSUER_DID"),
        "expiry_minutes": int(os.environ.get("OIDF_MARTY_FLOW_EXPIRY_MINUTES", "15")),
        "oid4vp_profile": profile,
        # Select POST retrieval only for the official module that verifies
        # the OID4VP 5.10 wallet_nonce round trip.  The ordinary signed-JAR
        # modules remain GET, and the standard url_query plan remains a
        # transport adaptation rather than being silently forced to POST.
        "request_uri_method": (
            "post" if request_method == "request_uri_signed" and module_name == REQUEST_URI_METHOD_POST_TEST else "get"
        ),
    }


def start_flow(gateway_url: str, session_id: str, body: dict[str, Any]) -> dict[str, Any]:
    """Start through the same public gateway helper used for OIDC login.

    The shared helper honors ``OIDF_MARTY_RESOLVE_IP`` for a disposable local
    TLS hostname without replacing the published URL with a Docker service
    address. Remote and certification deployments simply use DNS.
    """
    data = authenticated_json_request(
        gateway_url,
        session_id,
        "/v1/flows/verify",
        method="POST",
        json_body=body,
    )
    if not isinstance(data, dict):
        raise RuntimeError("Marty verifier flow response is not a JSON object")
    return data


def gateway_session_id() -> str:
    """Use an existing session only when an operator deliberately supplies one.

    Disposable official runs normally leave ``OIDF_MARTY_SESSION_ID`` unset.
    In that case complete the public Keycloak redirect flow and keep the
    resulting cookie in this process only. This prevents an internal service
    login or a synthetic session from becoming part of verifier evidence.
    """
    existing = os.environ.get("OIDF_MARTY_SESSION_ID", "").strip()
    if existing:
        return existing
    command = Path(
        os.environ.get("OIDF_MARTY_PUBLIC_LOGIN_COMMAND", "") or Path(__file__).with_name("oidf_marty_public_login.py")
    )
    completed = subprocess.run([sys.executable, str(command)], capture_output=True, text=True, check=False)
    if completed.returncode:
        detail = completed.stderr.strip()
        raise RuntimeError(f"OIDF public login command failed: {detail[:400]}")
    session_id = completed.stdout.strip()
    if not session_id or "\n" in session_id:
        raise RuntimeError("OIDF public login command did not return one session ID")
    return session_id


def main() -> int:
    payload = json.load(sys.stdin)
    if not isinstance(payload, dict):
        raise ValueError("OIDF flow input must be a JSON object")
    gateway = https_url(required_env("OIDF_MARTY_GATEWAY_URL"), "OIDF_MARTY_GATEWAY_URL")
    result = start_flow(
        gateway,
        gateway_session_id(),
        flow_body(payload),
    )
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
