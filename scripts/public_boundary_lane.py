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
    redact_initializer_log,
    run,
    validate_stack_binding,
    wait_for_public_stack,
)

ROOT = Path(__file__).resolve().parents[1]
RUN_ID = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
TEST_PATH = "tests/integration/gateway/test_two_organization_isolation.py"
DIDCOMM_TEST_PATH = (
    "tests/integration/gateway/test_didcomm_v2_delivery.py::"
    "TestDidcommDeliveryWithMockAgent::test_deliver_to_mock_agent"
)
PUBLIC_LOGIN = ROOT / "scripts" / "oidf_marty_public_login.py"
DIDCOMM_INTEROP_MANIFEST = ROOT / "conformance" / "didcomm-interoperability.json"


def independent_didcomm_record(
    environment: dict[str, str] | None = None,
) -> dict[str, object]:
    """Validate and describe the separately maintained DIDComm verifier."""
    data: object = json.loads(DIDCOMM_INTEROP_MANIFEST.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema") != "elevenid.didcomm-interoperability/v1":
        raise ValueError("independent DIDComm manifest has an unsupported schema")
    implementation = data.get("independent_implementation")
    profile = data.get("tested_profile")
    if not isinstance(implementation, dict) or not isinstance(profile, dict):
        raise ValueError("independent DIDComm manifest is incomplete")
    repository = implementation.get("repository")
    release = implementation.get("release")
    commit = implementation.get("commit")
    if repository != "https://github.com/notabene-id/go-didcomm.git":
        raise ValueError("independent DIDComm repository is not the reviewed implementation")
    if not isinstance(release, str) or not release.startswith("v"):
        raise ValueError("independent DIDComm release is invalid")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("independent DIDComm commit is not immutable")

    values = environment or os.environ
    required = values.get("DIDCOMM_INDEPENDENT_VERIFIER_REQUIRED", "").lower() in {
        "1",
        "true",
        "yes",
    }
    expected_identity = f"notabene-id/go-didcomm@{release}#{commit}"
    if required:
        if values.get("DIDCOMM_INTEROP_IMPLEMENTATION") != expected_identity:
            raise ValueError("independent DIDComm implementation does not match the reviewed pin")
        cli = Path(values.get("DIDCOMM_INTEROP_CLI", ""))
        if not cli.is_file():
            raise ValueError("independent DIDComm verifier executable is unavailable")
    return {
        "implementation": {
            "repository": repository,
            "release": release,
            "commit": commit,
        },
        "tested_profile": profile,
        "required": required,
        "claim": data.get("claim"),
    }


def local_source_commit(marty_ui: Path) -> str:
    """Return the exact checked-out source commit for a local-build preflight."""
    completed = subprocess.run(
        ["git", "-C", str(marty_ui), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    commit = completed.stdout.strip().lower()
    if completed.returncode or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("local marty-ui checkout must resolve to an exact Git commit")
    return commit


def boundary_compose_command(
    args: argparse.Namespace,
    action: str,
) -> list[str]:
    """Select released images by default and source builds only when explicit."""
    command = compose_command(args, action, marty_only=True)
    if getattr(args, "local_build", False):
        command.append("--local-build")
    return command


def environment(args: argparse.Namespace) -> tuple[dict[str, str], dict[str, object]]:
    if not RUN_ID.fullmatch(args.run_id):
        raise ValueError("run id must use lowercase letters, digits, and internal hyphens")
    launcher = args.marty_ui / "scripts" / "conformance_stack.py"
    if not launcher.is_file():
        raise ValueError("released marty-ui checkout has no conformance stack launcher")

    metadata = load_stack_metadata(args.stack_metadata)
    stack_environment = load_stack_environment(args.stack_env)
    validate_stack_binding(args.stack_manifest, metadata, stack_environment)
    if getattr(args, "local_build", False):
        metadata = dict(metadata)
        metadata["bootstrap_marty_commit"] = metadata.get("marty_commit")
        metadata["marty_commit"] = local_source_commit(args.marty_ui)

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
            raise ValueError(f"{name} is required and must be generated for this disposable run")

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


def emit_pytest_diagnostic(
    path: Path,
    environment: dict[str, str],
) -> None:
    """Print a bounded, redacted test failure without publishing raw evidence."""
    print("--- public-boundary pytest diagnostic (redacted) ---", file=sys.stderr)
    if not path.is_file():
        print("No pytest diagnostic was captured.", file=sys.stderr)
        print("--- end public-boundary pytest diagnostic ---", file=sys.stderr)
        return

    diagnostic = redact_initializer_log(path.read_text(encoding="utf-8"))
    for name in (
        "MARTY_CONFORMANCE_ADMIN_PASSWORD",
        "MARTY_CONFORMANCE_REVIEWER_PASSWORD",
        "MARTY_TEST_SESSION_ID",
        "MARTY_REVIEWER_TEST_SESSION_ID",
    ):
        secret = environment.get(name, "")
        if secret:
            diagnostic = diagnostic.replace(secret, "<redacted>")

    for line in diagnostic.splitlines()[-160:]:
        print(line[:500], file=sys.stderr)
    print("--- end public-boundary pytest diagnostic ---", file=sys.stderr)


def write_summary(
    args: argparse.Namespace,
    metadata: dict[str, object],
    exit_code: int,
) -> None:
    stack = json.loads(args.stack_manifest.read_text(encoding="utf-8"))
    didcomm_interop = metadata.get("didcomm_interoperability")
    if not isinstance(didcomm_interop, dict):
        didcomm_interop = independent_didcomm_record()
    didcomm_passed = bool(didcomm_interop.get("required")) and exit_code == 0
    didcomm_interop = dict(didcomm_interop)
    didcomm_interop["cross_implementation_decryption_passed"] = didcomm_passed
    coverage = [
        "two authenticated principals",
        "organization membership and RBAC",
        "resource-ID substitution",
        "API-key organization binding",
        "SCIM resource isolation",
        "flow definition, instance, and result isolation",
        "issuance transaction and revocation-status isolation",
        "issued-credential lifecycle and revocation isolation",
        "trust-profile ownership and mutation isolation",
        "issuer-entity and trust-profile relationship isolation",
        "applicant form-data and vetting isolation",
        "application evidence collection, deletion, revocation, and tenant isolation",
        "deployment-profile, lane, and device-assignment isolation",
        "webhook ownership and secret leakage prevention",
        "wallet catalogue and organization-override isolation",
        "browser-driven issuance and verification through the shipped UI",
        "notification SSE delivery and subscription isolation",
        "audit-event isolation",
        "DID-first issuance and verification",
        "public custody-selector rejection",
        "unknown, inactive, and purpose-incompatible DID rejection",
        "idempotent issuer-profile uniqueness",
        "ambiguous compatible issuer-profile rejection and recovery",
        "encrypted DIDComm v2 delivery with holder-key decryption",
        "public response custody-metadata minimization",
    ]
    if didcomm_passed:
        coverage.append("independent go-didcomm decryption of Marty's released anoncrypt envelope")
    summary = {
        "schema": "elevenid.product-security-evidence/v1",
        "evidence_class": "elevenid-owned-product-security",
        "lane": "two-organization-public-boundary",
        "execution": {
            "mode": ("local-source-preflight" if getattr(args, "local_build", False) else "immutable-release"),
            "release_grade": not getattr(args, "local_build", False),
        },
        "result": {
            "exit_code": exit_code,
            "passed": exit_code == 0,
        },
        "stack": {
            "release": stack.get("release"),
            "manifest_sha256": file_sha256(args.stack_manifest),
            "marty_commit": metadata.get("marty_commit"),
            "bootstrap_marty_commit": metadata.get("bootstrap_marty_commit"),
        },
        "test_source": {
            "repository": "ElevenID/marty-integration-tests",
            "commit": os.environ.get("GITHUB_SHA", "local"),
            "path": TEST_PATH,
            "additional_paths": [DIDCOMM_TEST_PATH],
            "owner": "ElevenID",
        },
        "official_suite_boundary": {
            "official_suite_invoked": False,
            "official_suite_source_modified": False,
            "claim": "This lane is not an official standards-compliance result.",
        },
        "didcomm_interoperability": didcomm_interop,
        "coverage": coverage,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def execute(args: argparse.Namespace) -> int:
    lane_environment, metadata = environment(args)
    metadata = dict(metadata)
    metadata["didcomm_interoperability"] = independent_didcomm_record(lane_environment)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    private = args.output_dir / "private"
    private.mkdir(parents=True, exist_ok=True)
    lane_environment["MARTY_BROWSER_EVIDENCE_DIR"] = str((private / "browser").resolve())
    lane_environment["DIDCOMM_PRIVATE_AGENT_TESTS"] = "true"
    started = (
        run(
            boundary_compose_command(args, "up"),
            lane_environment,
        )
        == 0
    )
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
                    DIDCOMM_TEST_PATH,
                ],
                lane_environment,
                capture=private / "pytest.log",
            )
            if exit_code:
                emit_pytest_diagnostic(private / "pytest.log", lane_environment)
    finally:
        write_summary(args, metadata, exit_code)
        run(
            boundary_compose_command(args, "logs"),
            lane_environment,
            capture=private / "compose.log",
        )
        run(
            boundary_compose_command(args, "down"),
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
    result.add_argument(
        "--local-build",
        action="store_true",
        help="build the checked-out Marty source as a non-release-grade preflight",
    )
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
