#!/usr/bin/env python3
"""Validate immutable inputs for EUDI reference-wallet interoperability."""

from __future__ import annotations

import json
import argparse
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ElementTree
from hashlib import sha256
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "conformance" / "eudi-reference-interop.json"
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST_IMAGE = re.compile(r"^ghcr\.io/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$")


def load_manifest(path: Path = MANIFEST) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
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


def write_evidence(output: Path, manifest: dict, endpoints: dict[str, str], result: int, skipped: int = 0) -> None:
    artifacts = [
        {"path": str(path.relative_to(output)).replace("\\", "/"), "sha256": file_sha256(path)}
        for path in sorted(output.rglob("*"))
        if path.is_file() and path.name != "evidence.json"
    ]
    evidence = {
        "schema": "elevenid.official-interop-evidence/v1",
        "components": manifest["components"],
        "coverage": manifest["coverage"],
        "marty": {"commit": os.environ.get("MARTY_COMMIT", "unrecorded")},
        "endpoints": endpoints,
        "result": {"exit_code": result, "passed": result == 0, "skipped": skipped},
        "artifacts": artifacts,
    }
    (output / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run(args: argparse.Namespace) -> int:
    manifest = load_manifest()
    endpoints = {
        "gateway": absolute_url(args.gateway_url, "gateway URL"),
        "wallet_tester": absolute_url(args.wallet_tester_url, "wallet tester URL"),
        "verifier": absolute_url(args.verifier_url, "verifier URL"),
        "wallet_kit": absolute_url(args.wallet_kit_url, "wallet kit URL"),
    }
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment.update({
        "RUN_EUDI_TESTS": "true",
        "GATEWAY_URL": endpoints["gateway"],
        "EUDI_WALLET_TESTER_URL": endpoints["wallet_tester"],
        "EUDI_VERIFIER_URL": endpoints["verifier"],
        "EUDI_WALLET_KIT_URL": endpoints["wallet_kit"],
    })
    command = [
        sys.executable, "-m", "pytest", "-q", "--junitxml", str(output / "junit.xml"),
        "tests/integration/gateway/test_eudi_interop.py",
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
    write_evidence(output, manifest, endpoints, result, skipped)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate")
    run_parser = sub.add_parser("run")
    run_parser.add_argument("--gateway-url", required=True)
    run_parser.add_argument("--wallet-tester-url", required=True)
    run_parser.add_argument("--verifier-url", required=True)
    run_parser.add_argument("--wallet-kit-url", required=True)
    run_parser.add_argument("--output-dir", type=Path, required=True)
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
