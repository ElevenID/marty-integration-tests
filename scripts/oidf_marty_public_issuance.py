#!/usr/bin/env python3
"""Create one OIDF issuer-plan offer through Marty's public production API."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from oidf_marty_public_login import authenticated_json_request  # noqa: E402
from oidf_marty_start_verification import gateway_session_id, https_url  # noqa: E402


def required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"{name} is required")
    return value


def validated_authorized_client(value: object) -> dict[str, Any]:
    """Validate the exact marty-protocol OID4VCI authorized-client shape."""

    if not isinstance(value, dict) or set(value) != {"client_id", "jwks"}:
        raise ValueError("authorized_client must contain only client_id and jwks")
    client_id = value.get("client_id")
    jwks = value.get("jwks")
    if (
        not isinstance(client_id, str)
        or not 1 <= len(client_id) <= 512
        or not isinstance(jwks, dict)
        or set(jwks) != {"keys"}
    ):
        raise ValueError("authorized_client must contain a client_id and public JWKS")
    keys = jwks.get("keys")
    if not isinstance(keys, list) or not keys:
        raise ValueError("authorized_client must contain a client_id and public JWKS")

    allowed_fields = {"alg", "crv", "key_ops", "kid", "kty", "use", "x", "y"}
    required_fields = {"crv", "kid", "kty", "x", "y"}
    key_ids: set[str] = set()
    for key in keys:
        if (
            not isinstance(key, dict)
            or not required_fields <= set(key)
            or set(key) - allowed_fields
        ):
            raise ValueError("authorized_client JWKS must contain public keys only")
        if (
            key.get("kty") != "EC"
            or key.get("crv") != "P-256"
            or key.get("alg") not in (None, "ES256")
            or key.get("use") not in (None, "sig")
            or key.get("key_ops") not in (None, ["verify"])
        ):
            raise ValueError("authorized_client JWKS must use public ES256 P-256 keys")
        kid = key.get("kid")
        if (
            not isinstance(kid, str)
            or not 1 <= len(kid) <= 256
            or kid in key_ids
            or not isinstance(key.get("x"), str)
            or not isinstance(key.get("y"), str)
            or re.fullmatch(r"[A-Za-z0-9_-]{43}", key["x"]) is None
            or re.fullmatch(r"[A-Za-z0-9_-]{43}", key["y"]) is None
        ):
            raise ValueError("authorized_client JWKS is not a valid public key set")
        key_ids.add(kid)
    return value


def issuance_body(payload: dict[str, Any]) -> dict[str, Any]:
    claims = payload.get("claims")
    if claims is None:
        claims = {
            "given_name": "Conformance",
            "family_name": "Test",
            "email": "conformance@example.test",
        }
    if not isinstance(claims, dict):
        raise ValueError("OIDF issuance claims must be an object")
    authorized_client = validated_authorized_client(payload.get("authorized_client"))
    return {
        "organization_id": required_env("OIDF_MARTY_ORGANIZATION_ID"),
        "credential_template_id": required_env("OIDF_MARTY_CREDENTIAL_TEMPLATE_ID"),
        "issuer_did": required_env("OIDF_MARTY_ISSUER_DID"),
        "authorized_client": authorized_client,
        "claims": claims,
    }


def create_offer(
    gateway_url: str,
    session_id: str,
    body: dict[str, Any],
) -> dict[str, Any]:
    result = authenticated_json_request(
        gateway_url,
        session_id,
        "/v1/issuance",
        method="POST",
        json_body=body,
    )
    if not isinstance(result, dict):
        raise RuntimeError("Marty issuance response is not a JSON object")
    offer_uri = result.get("credential_offer_uri")
    if not isinstance(offer_uri, str) or not offer_uri:
        raise RuntimeError("Marty issuance response has no credential_offer_uri")
    return result


def main() -> int:
    payload = json.load(sys.stdin)
    if not isinstance(payload, dict):
        raise ValueError("OIDF issuance input must be a JSON object")
    gateway_url = https_url(
        required_env("OIDF_MARTY_GATEWAY_URL"),
        "OIDF_MARTY_GATEWAY_URL",
    )
    result = create_offer(
        gateway_url,
        gateway_session_id(),
        issuance_body(payload),
    )
    json.dump(result, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"OIDF public issuance failed: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
