#!/usr/bin/env python3
"""Create disposable official-suite fixtures through Marty's public API."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from collections.abc import Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from oidf_marty_public_login import authenticated_json_request
from oidf_marty_start_verification import gateway_session_id, https_url

DEFAULT_ORGANIZATION = "00000000-0000-0000-0000-000000000001"
RUN_ID = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


def template_payload(organization_id: str, *, w3c: bool, run_id: str) -> dict[str, object]:
    if w3c:
        return {
            "organization_id": organization_id,
            "name": f"Official W3C VC v2 {run_id}",
            "credential_type": "VerifiableId",
            "vct": "https://credentials.marty.dev/VerifiableId",
            "supported_formats": ["jwt_vc"],
            "credential_payload_format": "w3c_vcdm_v2_jwt_vc",
            "compliance_profile": {
                "name": "W3C VC Data Model v2",
                "compliance_code": "W3C_VC",
                "credential_format": "jwt_vc",
                "frameworks": ["w3c_vc"],
            },
            "schema_uri": {
                "type": "object",
                "properties": {
                    "givenName": {"type": "string"},
                    "familyName": {"type": "string"},
                    "birthDate": {"type": "string", "format": "full-date"},
                    "documentNumber": {"type": "string"},
                },
                "required": ["givenName", "familyName", "birthDate", "documentNumber"],
            },
            "claims": [
                {"name": "givenName", "display_name": "Given Name", "required": True},
                {"name": "familyName", "display_name": "Family Name", "required": True},
                {"name": "birthDate", "display_name": "Birth Date", "required": True},
                {"name": "documentNumber", "display_name": "Document Number", "required": True},
            ],
            "auto_generate_artifacts": True,
        }
    return {
        "organization_id": organization_id,
        "name": f"Official OID4VP SD-JWT {run_id}",
        "credential_type": "DriversLicense",
        "vct": "https://credentials.marty.dev/DriversLicense",
        "supported_formats": ["sd_jwt_vc"],
        "credential_payload_format": "w3c_vcdm_v2_sd_jwt",
        "compliance_profile": {
            "name": "Official OID4VP SD-JWT",
            "compliance_code": "OID4VP_FINAL",
            "credential_format": "sd_jwt_vc",
            "frameworks": ["openid4vp"],
        },
        "schema_uri": {
            "type": "object",
            "properties": {
                "family_name": {"type": "string"},
                "given_name": {"type": "string"},
                "birth_date": {"type": "string", "format": "full-date"},
            },
            "required": ["family_name", "given_name", "birth_date"],
        },
        "claims": [
            {"name": "family_name", "display_name": "Family Name", "required": True},
            {"name": "given_name", "display_name": "Given Name", "required": True},
            {"name": "birth_date", "display_name": "Birth Date", "required": True},
        ],
        "auto_generate_artifacts": True,
    }


def policy_payload(
    organization_id: str,
    template_id: str,
    *,
    w3c: bool,
    run_id: str,
) -> dict[str, object]:
    claims = ("givenName", "familyName", "birthDate") if w3c else ("given_name", "family_name", "birth_date")
    label = "W3C VC v2" if w3c else "OID4VP SD-JWT"
    return {
        "organization_id": organization_id,
        "name": f"Official {label} {run_id}",
        "purpose": f"Disposable {label} official-suite verification",
        "credential_requirements": [
            {
                "credential_template_id": template_id,
                "display_name": label,
                "requested_claims": [
                    {
                        "claim_name": claim,
                        "display_name": claim,
                        "required": True,
                    }
                    for claim in claims
                ],
            }
        ],
    }


def response_id(value: object, resource: str) -> str:
    if not isinstance(value, dict):
        raise RuntimeError(f"public API returned a non-object for {resource}")
    identifier = value.get("id")
    if not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier):
        raise RuntimeError(f"public API returned an invalid {resource} id")
    return identifier


def bootstrap(
    gateway_url: str,
    session_id: str,
    *,
    organization_id: str,
    run_id: str,
    mode: str,
    request: Callable[..., object] = authenticated_json_request,
) -> dict[str, str]:
    if not RUN_ID.fullmatch(run_id):
        raise ValueError("run id must use lowercase letters, digits, and internal hyphens")
    if not IDENTIFIER.fullmatch(organization_id):
        raise ValueError("organization id contains unsupported characters")
    result = {"organization_id": organization_id}
    targets = (False, True) if mode == "all" else (mode == "w3c",)
    for w3c in targets:
        prefix = "w3c" if w3c else "oid4vp"
        created_template = request(
            gateway_url,
            session_id,
            "/v1/credential-templates",
            method="POST",
            json_body=template_payload(organization_id, w3c=w3c, run_id=run_id),
        )
        template_id = response_id(created_template, f"{prefix} credential template")
        created_policy = request(
            gateway_url,
            session_id,
            "/v1/presentation-policies",
            method="POST",
            json_body=policy_payload(organization_id, template_id, w3c=w3c, run_id=run_id),
        )
        policy_id = response_id(created_policy, f"{prefix} presentation policy")
        activated = request(
            gateway_url,
            session_id,
            f"/v1/presentation-policies/{policy_id}/activate",
            method="POST",
        )
        activated_id = response_id(activated, f"activated {prefix} presentation policy")
        if activated_id != policy_id:
            raise RuntimeError(f"activated {prefix} policy id changed unexpectedly")
        result[f"{prefix}_template_id"] = template_id
        result[f"{prefix}_policy_id"] = policy_id
    return result


def write_private_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--mode", choices=("oid4vp", "w3c", "all"), required=True)
    result.add_argument("--gateway-url", default=os.environ.get("OIDF_MARTY_GATEWAY_URL"))
    result.add_argument(
        "--organization-id", default=os.environ.get("MARTY_CONFORMANCE_ORGANIZATION_ID", DEFAULT_ORGANIZATION)
    )
    result.add_argument("--run-id", default=os.environ.get("OFFICIAL_SUITE_RUN_ID"), required=False)
    result.add_argument("--output", type=Path, required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if not args.gateway_url:
        raise ValueError("--gateway-url or OIDF_MARTY_GATEWAY_URL is required")
    if not args.run_id:
        raise ValueError("--run-id or OFFICIAL_SUITE_RUN_ID is required")
    gateway = https_url(args.gateway_url, "gateway URL")
    fixtures = bootstrap(
        gateway,
        gateway_session_id(),
        organization_id=args.organization_id,
        run_id=args.run_id,
        mode=args.mode,
    )
    write_private_json(args.output.resolve(), fixtures)
    # The file contains identifiers only, but keep stdout free of values so it
    # remains safe if future fixture metadata grows.
    print(f"Created {args.mode} official-suite fixtures through the public gateway.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"Official fixture bootstrap error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
