#!/usr/bin/env python3
"""Start one normal Marty verifier flow for an OIDF verifier module.

This deployment adapter uses the public, authenticated gateway endpoint and
returns the ordinary ``openid4vp`` request created by the flow service. The
OIDF runner adapter then gives that request to its own mock wallet. It does
not create a test-only flow, a bypass, or a synthetic VP.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlparse

# The deployment helpers are deliberately standalone scripts rather than an
# installed package. Make their directory importable too when this module is
# loaded by the unit suite through ``importlib``.
_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))
from oidf_marty_public_login import authenticated_json_request  # noqa: E402 -- import follows standalone path setup

REQUEST_URI_METHOD_POST_TEST = "oid4vp-1final-verifier-request-uri-method-post"
PRIVATE_FLOW_AUDIT_SCHEMA = "elevenid.oidf-flow-correlation/private-v1"
OFFICIAL_AUTHORIZATION_PATH = re.compile(
    r"^/test/(?:a/)?[A-Za-z0-9._~-]{1,200}/authorize$"
)
RESOURCE_ID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


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


def official_credential_issuer(payload: dict[str, Any], conformance_server: str) -> str:
    """Derive the exact issuer URL used by the unchanged Official module.

    The runner configures its credential ``iss`` from the test-instance base
    URL and exposes ``<base>/authorize`` to the interaction adapter. Accept
    only that fixed public route on the configured runner origin; arbitrary
    endpoints must never become governed issuers.
    """
    endpoint_value = payload.get("authorization_endpoint")
    if not isinstance(endpoint_value, str) or not endpoint_value:
        raise ValueError("OIDF module authorization_endpoint is required")
    endpoint = urlparse(endpoint_value)
    server = urlparse(conformance_server)
    if (
        endpoint.scheme.lower() != "https"
        or not endpoint.hostname
        or endpoint.username is not None
        or endpoint.password is not None
        or endpoint.params
        or endpoint.query
        or endpoint.fragment
        or OFFICIAL_AUTHORIZATION_PATH.fullmatch(endpoint.path) is None
    ):
        raise ValueError("OIDF module authorization_endpoint is not an exact Official test route")
    if (
        server.scheme.lower() != "https"
        or not server.hostname
        or server.username is not None
        or server.password is not None
        or server.params
        or server.query
        or server.fragment
        or server.path not in {"", "/"}
    ):
        raise ValueError("CONFORMANCE_SERVER must be an HTTPS origin")
    endpoint_origin = (
        endpoint.hostname.lower(),
        endpoint.port or 443,
    )
    server_origin = (
        server.hostname.lower(),
        server.port or 443,
    )
    if endpoint_origin != server_origin:
        raise ValueError("OIDF module authorization_endpoint is not on CONFORMANCE_SERVER")
    issuer_path = endpoint.path[: -len("/authorize")]
    return endpoint._replace(path=issuer_path, params="", query="", fragment="").geturl()


def official_signer_public_jwk() -> dict[str, str]:
    """Load the public-only signer copied from the commit-pinned runner config."""
    raw = required_env("OIDF_MARTY_OFFICIAL_SIGNER_PUBLIC_JWK")
    try:
        value: object = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("OIDF official signer public JWK is invalid JSON") from exc
    if (
        not isinstance(value, dict)
        or set(value) != {"kty", "crv", "x", "y"}
        or value.get("kty") != "EC"
        or value.get("crv") != "P-256"
        or not isinstance(value.get("x"), str)
        or not value["x"]
        or not isinstance(value.get("y"), str)
        or not value["y"]
    ):
        raise ValueError("OIDF official signer JWK must be a public-only P-256 key")
    return {name: value[name] for name in ("kty", "crv", "x", "y")}


def _resource_id(value: object, resource: str) -> str:
    if not isinstance(value, dict):
        raise RuntimeError(f"public API returned a non-object for {resource}")
    identifier = value.get("id")
    if not isinstance(identifier, str) or RESOURCE_ID.fullmatch(identifier) is None:
        raise RuntimeError(f"public API returned no {resource} id")
    return identifier


def _existing_module_issuer_entity(
    gateway_url: str,
    session_id: str,
    *,
    organization_id: str,
    issuer_id: str,
    signer_jwk: dict[str, str],
) -> str | None:
    value = authenticated_json_request(
        gateway_url,
        session_id,
        f"/v1/issuer-entities?{urlencode({'organization_id': organization_id})}",
    )
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise RuntimeError("public API returned an invalid issuer entity list")
    matches = [item for item in value if item.get("issuer_id") == issuer_id]
    if len(matches) > 1:
        raise RuntimeError("public API returned ambiguous Official module issuer entities")
    if not matches:
        return None
    entity = matches[0]
    if (
        entity.get("organization_id") != organization_id
        or entity.get("issuer_type") != "ORGANIZATION"
        or entity.get("display_name") != "Official OIDF test-instance issuer"
        or entity.get("description")
        != (
            "Disposable exact issuer for one module in the commit-pinned "
            "unmodified OIDF runner"
        )
        or entity.get("is_system_issuer") is not False
        or entity.get("compliance_status") != "COMPLIANT"
        or entity.get("revoked_at") is not None
        or entity.get("metadata")
        != {
            "source": "official-oidf-commit-pinned-test-instance",
            "verification_keys": [signer_jwk],
        }
    ):
        raise RuntimeError("existing Official module issuer entity is not exact")
    return _resource_id(entity, "Official module issuer entity")


def _has_exact_module_issuer_relationship(
    gateway_url: str,
    session_id: str,
    *,
    trust_profile_id: str,
    issuer_entity_id: str,
) -> bool:
    value = authenticated_json_request(
        gateway_url,
        session_id,
        f"/v1/trust-profiles/{trust_profile_id}/issuers",
    )
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise RuntimeError("public API returned an invalid issuer relationship list")
    matches = [item for item in value if item.get("issuer_id") == issuer_entity_id]
    if len(matches) > 1:
        raise RuntimeError("public API returned ambiguous Official module issuer relationships")
    if not matches:
        return False
    relationship = matches[0]
    if (
        relationship.get("trust_level") != 100
        or relationship.get("relationship_status") != "TRUSTED"
        or relationship.get("cascade_revocation_policy") != "AUTO_CASCADE"
        or relationship.get("metadata")
        != {"source": "official-oidf-commit-pinned-test-instance"}
    ):
        raise RuntimeError("existing Official module issuer relationship is not exact")
    _resource_id(relationship, "Official module issuer relationship")
    return True


def govern_official_module_issuer(
    gateway_url: str,
    session_id: str,
    payload: dict[str, Any],
) -> None:
    """Create one exact issuer entity and relationship before starting a flow."""
    mode = os.environ.get("OIDF_MARTY_DYNAMIC_ISSUER_GOVERNANCE", "").strip()
    if not mode:
        return
    if mode != "1":
        raise ValueError("OIDF_MARTY_DYNAMIC_ISSUER_GOVERNANCE must be 1 when enabled")
    issuer_id = official_credential_issuer(
        payload,
        required_env("CONFORMANCE_SERVER"),
    )
    organization_id = required_env("OIDF_MARTY_ORGANIZATION_ID")
    signer_jwk = official_signer_public_jwk()
    issuer_entity_id = _existing_module_issuer_entity(
        gateway_url,
        session_id,
        organization_id=organization_id,
        issuer_id=issuer_id,
        signer_jwk=signer_jwk,
    )
    if issuer_entity_id is None:
        created = authenticated_json_request(
            gateway_url,
            session_id,
            "/v1/issuer-entities",
            method="POST",
            json_body={
                "organization_id": organization_id,
                "issuer_id": issuer_id,
                "issuer_type": "ORGANIZATION",
                "display_name": "Official OIDF test-instance issuer",
                "description": (
                    "Disposable exact issuer for one module in the commit-pinned "
                    "unmodified OIDF runner"
                ),
                "compliance_status": "COMPLIANT",
                "metadata": {
                    "source": "official-oidf-commit-pinned-test-instance",
                    "verification_keys": [signer_jwk],
                },
            },
        )
        issuer_entity_id = _resource_id(created, "Official module issuer entity")
    trust_profile_id = required_env("OIDF_MARTY_TRUST_PROFILE_ID")
    if _has_exact_module_issuer_relationship(
        gateway_url,
        session_id,
        trust_profile_id=trust_profile_id,
        issuer_entity_id=issuer_entity_id,
    ):
        return
    relationship = authenticated_json_request(
        gateway_url,
        session_id,
        f"/v1/trust-profiles/{trust_profile_id}/issuers",
        method="POST",
        json_body={
            "issuer_id": issuer_entity_id,
            "trust_level": 100,
            "relationship_status": "TRUSTED",
            "cascade_revocation_policy": "AUTO_CASCADE",
            "metadata": {
                "source": "official-oidf-commit-pinned-test-instance",
            },
        },
    )
    _resource_id(relationship, "Official module issuer relationship")


def flow_body(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload.get("test_id"), str) or not payload["test_id"]:
        raise ValueError("OIDF module test_id is required")
    if not isinstance(payload.get("test_name"), str) or not payload["test_name"]:
        raise ValueError("OIDF module test_name is required")
    request_method = payload.get("request_method", "request_uri_signed")
    if request_method not in {"request_uri_signed", "url_query"}:
        raise ValueError(
            "OIDF request_method must be request_uri_signed or url_query"
        )
    profile = os.environ.get("OIDF_MARTY_VERIFIER_PROFILE", "standard")
    if profile not in {"standard", "haip"}:
        raise ValueError("OIDF_MARTY_VERIFIER_PROFILE must be standard or haip")
    module_name = payload["test_name"].partition("[")[0]
    return {
        # Organization is an explicit public authorization boundary. Do not
        # infer it from an operator session or omit it for conformance runs.
        "organization_id": required_env("OIDF_MARTY_ORGANIZATION_ID"),
        "presentation_policy_id": required_env("OIDF_MARTY_PRESENTATION_POLICY_ID"),
        "trust_profile_id": os.environ.get("OIDF_MARTY_TRUST_PROFILE_ID") or None,
        # The public DID is the sole signing-identity input. The organization
        # registry resolves the internal profile and KMS binding.
        "issuer_did": required_env("OIDF_MARTY_ISSUER_DID"),
        "expiry_minutes": int(os.environ.get("OIDF_MARTY_FLOW_EXPIRY_MINUTES", "15")),
        "oid4vp_profile": profile,
        # Match the unchanged OIDF variant literally. request_uri_signed uses
        # a profile-signed JAR by reference; url_query carries the product's
        # direct unsigned OID4VP authorization parameters.
        "request_transport": (
            "url_query" if request_method == "url_query" else "request_uri"
        ),
        # Select POST retrieval only for the official module that verifies
        # the OID4VP 5.10 wallet_nonce round trip.  The ordinary signed-JAR
        # modules remain GET.
        "request_uri_method": (
            "post"
            if request_method == "request_uri_signed"
            and module_name == REQUEST_URI_METHOD_POST_TEST
            else "get"
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


def write_private_flow_audit(payload: dict[str, Any], result: dict[str, Any]) -> None:
    """Record only the private correlation needed for safe failure diagnosis."""
    configured = os.environ.get("OIDF_MARTY_FLOW_AUDIT_DIR", "").strip()
    if not configured:
        return
    test_id = payload.get("test_id")
    test_name = payload.get("test_name")
    flow_instance_id = result.get("instance_id")
    if not all(isinstance(value, str) and value for value in (test_id, test_name, flow_instance_id)):
        raise RuntimeError("OIDF flow audit requires module and flow identifiers")
    record = {
        "schema": PRIVATE_FLOW_AUDIT_SCHEMA,
        "test_name": test_name,
        "flow_instance_id": flow_instance_id,
    }
    serialized = json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n"
    digest = hashlib.sha256(f"{test_id}\0{flow_instance_id}".encode()).hexdigest()
    directory = Path(configured)
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / f"{digest}.json"
    try:
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        if destination.read_text(encoding="utf-8") != serialized:
            raise RuntimeError("OIDF flow audit correlation conflicts with an existing record") from exc
        return
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
        output.write(serialized)


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
    session_id = gateway_session_id()
    govern_official_module_issuer(gateway, session_id, payload)
    result = start_flow(gateway, session_id, flow_body(payload))
    write_private_flow_audit(payload, result)
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
