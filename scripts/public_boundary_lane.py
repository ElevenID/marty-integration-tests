#!/usr/bin/env python3
"""Run ElevenID-owned tenant-boundary tests against an immutable stack release.

This lane is deliberately separate from imported official compliance suites.
It may evolve with Marty's product model and must never be represented as an
upstream standards assertion.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

from official_interoperability_lane import (
    compose_command,
    file_sha256,
    load_material_environment,
    load_stack_environment,
    load_stack_metadata,
    run,
    validate_stack_binding,
    wait_for_public_stack,
)

ROOT = Path(__file__).resolve().parents[1]
RUN_ID = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
TEST_PATH = (
    "tests/integration/gateway/test_two_organization_isolation.py"
)
PUBLIC_LOGIN = ROOT / "scripts" / "oidf_marty_public_login.py"


def environment(args: argparse.Namespace) -> tuple[dict[str, str], dict[str, object]]:
    if not RUN_ID.fullmatch(args.run_id):
        raise ValueError("run id must use lowercase letters, digits, and internal hyphens")
    launcher = args.marty_ui / "scripts" / "conformance_stack.py"
    if not launcher.is_file():
        raise ValueError(
            "released marty-ui checkout has no conformance stack launcher"
        )

    metadata = load_stack_metadata(args.stack_metadata)
    stack_environment = load_stack_environment(args.stack_env)
    validate_stack_binding(args.stack_manifest, metadata, stack_environment)

    result = os.environ.copy()
    result.update(stack_environment)
    result.update(load_material_environment(args.material))
    gateway_url = result.get(
        "OIDF_PUBLIC_BASE_URL",
        "https://marty-oidf.test:18443",
    ).rstrip("/")
    gateway = urlsplit(gateway_url)
    if gateway.scheme != "https" or not gateway.hostname or gateway.path:
        raise ValueError("generated public base URL must be an HTTPS origin")

    for name in (
        "MARTY_CONFORMANCE_ADMIN_PASSWORD",
        "MARTY_CONFORMANCE_REVIEWER_PASSWORD",
    ):
        if not result.get(name, "").strip():
            raise ValueError(
                f"{name} is required and must be generated for this disposable run"
            )

    result.update(
        {
            "OFFICIAL_SUITE_RUN_ID": args.run_id,
            "MARTY_COMMIT": str(metadata["marty_commit"]),
            "MARTY_CONFORMANCE_ORGANIZATION_ID": result.get(
                "MARTY_CONFORMANCE_ORGANIZATION_ID",
                "00000000-0000-0000-0000-000000000001",
            ),
            "MARTY_CONFORMANCE_ADMIN_EMAIL": result.get(
                "MARTY_CONFORMANCE_ADMIN_EMAIL",
                "conformance@elevenid.dev",
            ),
            "MARTY_CONFORMANCE_REVIEWER_EMAIL": result.get(
                "MARTY_CONFORMANCE_REVIEWER_EMAIL",
                "conformance.reviewer@elevenid.dev",
            ),
            "OIDF_PUBLIC_BASE_URL": gateway_url,
            "OIDF_TLS_HOST_PORT": result.get(
                "OIDF_TLS_HOST_PORT",
                str(gateway.port or 443),
            ),
            "OIDF_CONFORMANCE_BRIDGE_ALIAS": result.get(
                "OIDF_CONFORMANCE_BRIDGE_ALIAS",
                gateway.hostname,
            ),
            "OIDF_MARTY_GATEWAY_URL": gateway_url,
            "OIDF_MARTY_RESOLVE_IP": result.get(
                "OIDF_MARTY_RESOLVE_IP",
                "127.0.0.1",
            ),
            "GATEWAY_URL": gateway_url,
            "PUBLIC_DOMAIN": gateway.hostname,
            "GATEWAY_EXTERNAL": gateway.hostname,
            "TEST_USERNAME": result.get(
                "MARTY_CONFORMANCE_ADMIN_EMAIL",
                "conformance@elevenid.dev",
            ),
            "TEST_PASSWORD": result["MARTY_CONFORMANCE_ADMIN_PASSWORD"],
            "SSL_CERT_FILE": str((args.material / "root-ca.pem").resolve()),
            "REQUESTS_CA_BUNDLE": str((args.material / "root-ca.pem").resolve()),
            "CURL_CA_BUNDLE": str((args.material / "root-ca.pem").resolve()),
        }
    )
    return result, metadata


def public_session(
    lane_environment: dict[str, str],
    *,
    email: str,
    password: str,
) -> str:
    """Obtain a browser-equivalent session through the public OIDC boundary."""
    login_environment = lane_environment.copy()
    login_environment.update(
        {
            "OIDF_MARTY_OPERATOR_EMAIL": email,
            "OIDF_MARTY_OPERATOR_PASSWORD": password,
        }
    )
    completed = subprocess.run(
        [sys.executable, str(PUBLIC_LOGIN)],
        cwd=ROOT,
        env=login_environment,
        capture_output=True,
        text=True,
        check=False,
    )
    session_id = completed.stdout.strip()
    if completed.returncode or not session_id:
        detail = completed.stderr.strip()
        raise RuntimeError(
            "public OIDC login failed for a disposable boundary-test principal"
            + (f": {detail[:300]}" if detail else "")
        )
    if any(character.isspace() for character in session_id):
        raise RuntimeError("public OIDC login returned a malformed session cookie")
    return session_id


def write_summary(
    args: argparse.Namespace,
    metadata: dict[str, object],
    exit_code: int,
) -> None:
    stack = json.loads(args.stack_manifest.read_text(encoding="utf-8"))
    summary = {
        "schema": "elevenid.product-security-evidence/v1",
        "evidence_class": "elevenid-owned-product-security",
        "lane": "two-organization-public-boundary",
        "result": {
            "exit_code": exit_code,
            "passed": exit_code == 0,
        },
        "stack": {
            "release": stack.get("release"),
            "manifest_sha256": file_sha256(args.stack_manifest),
            "marty_commit": metadata.get("marty_commit"),
        },
        "test_source": {
            "repository": "ElevenID/marty-integration-tests",
            "commit": os.environ.get("GITHUB_SHA", "local"),
            "path": TEST_PATH,
            "owner": "ElevenID",
        },
        "official_suite_boundary": {
            "official_suite_invoked": False,
            "official_suite_source_modified": False,
            "claim": "This lane is not an official standards-compliance result.",
        },
        "coverage": [
            "two authenticated principals",
            "organization membership and RBAC",
            "resource-ID substitution",
            "API-key organization binding",
            "SCIM resource isolation",
            "flow definition, instance, and result isolation",
            "issuance transaction and revocation-status isolation",
            "issued-credential lifecycle and revocation isolation",
            "trust-profile ownership and mutation isolation",
            "applicant form-data and vetting isolation",
            "deployment-profile, lane, and device-assignment isolation",
            "webhook ownership and secret leakage prevention",
            "audit-event isolation",
            "DID-first issuance and verification",
            "public custody-selector rejection",
            "unknown, inactive, and purpose-incompatible DID rejection",
            "idempotent issuer-profile uniqueness",
            "public response custody-metadata minimization",
        ],
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def execute(args: argparse.Namespace) -> int:
    lane_environment, metadata = environment(args)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    started = run(
        compose_command(args, "up", marty_only=True),
        lane_environment,
    ) == 0
    exit_code = 1
    try:
        if started:
            wait_for_public_stack(lane_environment)
            lane_environment["MARTY_TEST_SESSION_ID"] = public_session(
                lane_environment,
                email=lane_environment["MARTY_CONFORMANCE_ADMIN_EMAIL"],
                password=lane_environment["MARTY_CONFORMANCE_ADMIN_PASSWORD"],
            )
            lane_environment["MARTY_REVIEWER_TEST_SESSION_ID"] = public_session(
                lane_environment,
                email=lane_environment["MARTY_CONFORMANCE_REVIEWER_EMAIL"],
                password=lane_environment["MARTY_CONFORMANCE_REVIEWER_PASSWORD"],
            )
            exit_code = run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-q",
                    TEST_PATH,
                ],
                lane_environment,
            )
    finally:
        write_summary(args, metadata, exit_code)
        private = args.output_dir / "private"
        private.mkdir(parents=True, exist_ok=True)
        run(
            compose_command(args, "logs", marty_only=True),
            lane_environment,
            capture=private / "compose.log",
        )
        run(
            compose_command(args, "down", marty_only=True),
            lane_environment,
        )
    return exit_code


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--run-id", required=True)
    result.add_argument("--marty-ui", type=Path, required=True)
    result.add_argument("--stack-manifest", type=Path, required=True)
    result.add_argument("--stack-metadata", type=Path, required=True)
    result.add_argument("--stack-env", type=Path, required=True)
    result.add_argument("--material", type=Path, required=True)
    result.add_argument("--output-dir", type=Path, required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    for name in (
        "marty_ui",
        "stack_manifest",
        "stack_metadata",
        "stack_env",
        "material",
        "output_dir",
    ):
        setattr(args, name, getattr(args, name).resolve())
    return execute(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"Public-boundary lane error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
