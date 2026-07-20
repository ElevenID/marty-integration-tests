#!/usr/bin/env python3
"""Validate immutable inputs for EUDI reference-wallet interoperability."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ElementTree
from hashlib import sha256
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from eudi_test_material import merged_material_environment, validate_environment

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "conformance" / "eudi-reference-interop.json"
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST_IMAGE = re.compile(r"^ghcr\.io/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$")


def load_manifest(path: Path = MANIFEST) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("EUDI interop manifest must be a JSON object")
    if data.get("schema") != "elevenid.eudi-reference-interop/v1":
        raise ValueError("unsupported EUDI interop manifest schema")
    components = data.get("components", {})
    for name in ("wallet_tester", "verifier_endpoint", "wallet_kit"):
        component = components.get(name, {})
        if not component.get("repository", "").startswith("https://github.com/eu-digital-identity-wallet/"):
            raise ValueError(f"{name} must point to an official EUDI repository")
        if not SHA.fullmatch(component.get("commit", "")):
            raise ValueError(f"{name} must pin a full commit SHA")
        image = component.get("image")
        if image is not None and not DIGEST_IMAGE.fullmatch(image):
            raise ValueError(f"{name} image must be pinned by sha256 digest")
    coverage = data.get("coverage", {})
    if not {"sd_jwt_vc", "mso_mdoc"} <= set(coverage.get("issuance", [])):
        raise ValueError("EUDI issuance coverage must include SD-JWT VC and mdoc")
    if not {"sd_jwt_vc", "mso_mdoc"} <= set(coverage.get("presentation", [])):
        raise ValueError("EUDI presentation coverage must include SD-JWT VC and mdoc")
    if "replayed_response" not in coverage.get("negative", []):
        raise ValueError("EUDI coverage must include replay rejection")
    return data


def absolute_url(value: str, field: str) -> str:
    if not re.match(r"^https?://[^/]+", value):
        raise ValueError(f"{field} must be an absolute http(s) URL")
    return value.rstrip("/")


def file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def junit_skip_count(path: Path) -> int:
    if not path.is_file():
        raise ValueError("EUDI runner did not produce JUnit output")
    root = ElementTree.parse(path).getroot()
    return sum(int(node.attrib.get("skipped", "0")) for node in root.iter() if node.tag == "testsuite")


def stack_manifest_metadata(path: Path) -> dict:
    """Return immutable Marty deployment provenance for a conformance run."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("schema") != "marty.stack/v1":
        raise ValueError("stack manifest must use marty.stack/v1")
    images: list[dict[str, str]] = []
    for component in raw.get("components", []):
        if not isinstance(component, dict):
            continue
        for artifact in component.get("artifacts", []):
            if not isinstance(artifact, dict) or artifact.get("type") != "oci":
                continue
            uri, digest = artifact.get("uri"), artifact.get("digest")
            if (
                not isinstance(uri, str)
                or not isinstance(digest, str)
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
            ):
                raise ValueError("every OCI artifact in the stack manifest must have a sha256 digest")
            images.append({"component": str(component.get("name", "unknown")), "uri": uri, "digest": digest})
    if not images:
        raise ValueError("stack manifest contains no immutable OCI artifacts")
    return {"path": str(path), "sha256": file_sha256(path), "release": raw.get("release"), "images": images}


def write_evidence(
    output: Path,
    manifest: dict,
    endpoints: dict[str, str],
    result: int,
    skipped: int = 0,
    stack_manifest: Path | None = None,
) -> None:
    artifacts = [
        {"path": str(path.relative_to(output)).replace("\\", "/"), "sha256": file_sha256(path)}
        for path in sorted(output.rglob("*"))
        if path.is_file() and path.name != "evidence.json"
    ]
    evidence = {
        "schema": "elevenid.official-interop-evidence/v1",
        "components": manifest["components"],
        "coverage": manifest["coverage"],
        "marty": {
            "commit": os.environ.get("MARTY_COMMIT", "unrecorded"),
            "stack_manifest": stack_manifest_metadata(stack_manifest) if stack_manifest else None,
        },
        "endpoints": endpoints,
        "result": {"exit_code": result, "passed": result == 0, "skipped": skipped},
        "artifacts": artifacts,
    }
    (output / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def public_gateway_session(environment: dict[str, str]) -> str:
    """Obtain a normal public OIDC session for the disposable EUDI run.

    The EUDI runner must not authenticate through a private Docker address or
    invent a session cookie.  Reuse the production-shaped OIDF helper, which
    follows the gateway's published Keycloak redirects and returns only the
    gateway-issued session ID.
    """
    existing = environment.get("MARTY_TEST_SESSION_ID", "").strip()
    if existing:
        return existing
    command = Path(
        environment.get("EUDI_MARTY_PUBLIC_LOGIN_COMMAND", "") or ROOT / "scripts" / "oidf_marty_public_login.py"
    )
    if not command.is_file():
        raise ValueError("EUDI public login helper is missing")
    completed = subprocess.run(
        [sys.executable, str(command)],
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    session = completed.stdout.strip()
    if completed.returncode or not session or "\n" in session:
        detail = completed.stderr.strip()
        raise ValueError(f"EUDI public OIDC login failed: {detail[:300]}")
    return session


def run_environment(args: argparse.Namespace) -> tuple[dict[str, str], dict[str, str]]:
    """Load the same generated trust and endpoint contract used by Compose."""
    environment = os.environ.copy()
    material_values: dict[str, str] = {}
    if args.eudi_material is not None:
        _mode, environment = merged_material_environment(args.eudi_material.resolve(), environment)
        validate_environment(environment, validate_java=False)
        material_values = {
            "gateway": environment["OIDF_PUBLIC_BASE_URL"],
            "wallet_tester": environment["EUDI_WALLET_TESTER_PUBLIC_URL"],
            "verifier": environment["EUDI_VERIFIER_PUBLIC_URL"],
            "wallet_kit": environment.get("EUDI_WALLET_KIT_URL", ""),
        }
    if environment.get("OIDF_INSECURE_TLS", "").strip().lower() in {"1", "true", "yes"}:
        raise ValueError("OIDF_INSECURE_TLS is prohibited for EUDI interoperability evidence")
    explicit = {
        "gateway": args.gateway_url,
        "wallet_tester": args.wallet_tester_url,
        "verifier": args.verifier_url,
        "wallet_kit": args.wallet_kit_url,
    }
    endpoints: dict[str, str] = {}
    for name, value in explicit.items():
        selected = value or material_values.get(name, "")
        if not selected:
            raise ValueError(f"{name.replace('_', ' ')} URL is required without --eudi-material")
        endpoint = absolute_url(selected, f"{name.replace('_', ' ')} URL")
        material_endpoint = material_values.get(name, "")
        if value and material_endpoint and endpoint != absolute_url(material_endpoint, f"material {name} URL"):
            raise ValueError(f"{name.replace('_', ' ')} URL must match --eudi-material")
        endpoints[name] = endpoint
    environment.update(
        {
            "RUN_EUDI_TESTS": "true",
            "GATEWAY_URL": endpoints["gateway"],
            "OIDF_MARTY_GATEWAY_URL": endpoints["gateway"],
            "EUDI_WALLET_TESTER_URL": endpoints["wallet_tester"],
            "EUDI_VERIFIER_URL": endpoints["verifier"],
            "EUDI_WALLET_KIT_URL": endpoints["wallet_kit"],
        }
    )
    return environment, endpoints


def run(args: argparse.Namespace) -> int:
    manifest = load_manifest()
    environment, endpoints = run_environment(args)
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    stack_manifest = args.stack_manifest.resolve()
    # Validate before any external calls so an evidence run cannot silently use
    # mutable image tags or an unrelated deployment.
    stack_manifest_metadata(stack_manifest)
    environment["MARTY_TEST_SESSION_ID"] = public_gateway_session(environment)
    command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "--junitxml",
        str(output / "junit.xml"),
        "tests/integration/gateway/test_eudi_interop.py",
        "tests/integration/gateway/test_eudi_wallet_kit.py",
        "tests/integration/gateway/test_eudi_wallet_kit_vp.py",
        "tests/integration/gateway/test_eudi_wallet_kit_dtc.py",
    ]
    completed = subprocess.run(command, cwd=ROOT, env=environment, text=True, capture_output=True, check=False)
    result = completed.returncode
    skipped = 0
    detail = completed.stdout + completed.stderr
    if result == 0:
        try:
            skipped = junit_skip_count(output / "junit.xml")
        except (ElementTree.ParseError, ValueError) as exc:
            result = 1
            detail += f"\nEUDI evidence failure: {exc}\n"
        if skipped:
            result = 1
            detail += f"\nEUDI evidence failure: {skipped} test(s) were skipped.\n"
    (output / "runner.log").write_text(detail, encoding="utf-8")
    write_evidence(output, manifest, endpoints, result, skipped, stack_manifest)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate")
    run_parser = sub.add_parser("run")
    run_parser.add_argument("--eudi-material", type=Path, help="generated trust and endpoint environment")
    run_parser.add_argument("--gateway-url")
    run_parser.add_argument("--wallet-tester-url")
    run_parser.add_argument("--verifier-url")
    run_parser.add_argument("--wallet-kit-url")
    run_parser.add_argument("--output-dir", type=Path, required=True)
    run_parser.add_argument(
        "--stack-manifest",
        type=Path,
        required=True,
        help="attested marty.stack/v1 manifest for the deployment under test",
    )
    args = parser.parse_args()
    if args.command == "validate":
        manifest = load_manifest()
        print("EUDI reference interop manifest is valid:", manifest["components"]["wallet_tester"]["commit"])
        return 0
    return run(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError, subprocess.CalledProcessError) as exc:
        print(f"EUDI reference interop setup error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
