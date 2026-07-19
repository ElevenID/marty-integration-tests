#!/usr/bin/env python3
"""Validate and execute the pinned W3C VC Data Model v2 suite boundary."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "conformance" / "w3c-vc-data-model-v2.json"
SHA = re.compile(r"^[0-9a-f]{40}$")


def load_manifest(path: Path = MANIFEST) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != "elevenid.official-vc-suite/v1":
        raise ValueError("unsupported W3C VC suite manifest schema")
    suite = data.get("official_suite", {})
    if suite.get("repository") != "https://github.com/w3c/vc-data-model-2.0-test-suite.git":
        raise ValueError("W3C VC suite must use the official repository")
    if not SHA.fullmatch(suite.get("commit", "")):
        raise ValueError("W3C VC suite commit must be a full lowercase SHA")
    for exclusion in data.get("exclusions", []):
        if not {"capability", "reason", "owner", "review_date"} <= exclusion.keys():
            raise ValueError("every W3C exclusion needs capability, reason, owner, and review_date")
    return data


def revision(path: Path) -> str:
    return subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()


def validate_checkout(path: Path, manifest: dict) -> None:
    if not (path / "package.json").is_file():
        raise ValueError("W3C VC suite package.json is missing")
    actual = revision(path)
    expected = manifest["official_suite"]["commit"]
    if actual != expected:
        raise ValueError(f"W3C VC suite is {actual}; expected pinned {expected}")


def write_local_config(path: Path, adapter_base_url: str) -> None:
    base = adapter_base_url.rstrip("/")
    if not base.startswith(("http://", "https://")):
        raise ValueError("adapter URL must be absolute http(s)")
    path.write_text(
        "module.exports = {\n"
        "  settings: { enableInteropTests: false, testAllImplementations: false },\n"
        "  implementations: [{\n"
        "    name: 'ElevenID', implementation: 'Marty VC API test adapter',\n"
        f"    verifiers: [{{ id: 'marty-vc-verifier', endpoint: '{base}/credentials/verify', tags: ['vc2.0'] }}],\n"
        f"    vpVerifiers: [{{ id: 'marty-vp-verifier', endpoint: '{base}/presentations/verify', tags: ['vc2.0'] }}]\n"
        "  }]\n};\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate")
    run = sub.add_parser("write-local-config")
    run.add_argument("--adapter-url", required=True)
    run.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = load_manifest()
    if args.command == "validate":
        print(f"W3C VC v2 suite manifest is valid: {manifest['official_suite']['commit']}")
        return 0
    write_local_config(args.output, args.adapter_url)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f"W3C VC conformance setup error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
