#!/usr/bin/env python3
"""Run a pinned OpenID Foundation conformance plan against Marty.

The helper owns only the reproducibility boundary. The OpenID Foundation's
``run-test-plan.py`` remains the test runner and determines pass/fail.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "conformance" / "oidf-runner.json"
SHA = re.compile(r"^[0-9a-f]{40}$")


def load_manifest(path: Path = MANIFEST) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != "elevenid.oidf-conformance-runner/v1":
        raise ValueError("unsupported OIDF runner manifest schema")
    runner = data.get("official_runner", {})
    if runner.get("repository") != "https://gitlab.com/openid/conformance-suite.git":
        raise ValueError("official runner repository must be the OIDF conformance suite")
    if not SHA.fullmatch(runner.get("commit", "")):
        raise ValueError("official runner commit must be a full lowercase SHA")
    if not runner.get("release", "").startswith("release-v"):
        raise ValueError("official runner release must be an immutable release tag")
    return data


def validate_expected_failures() -> None:
    entries = json.loads((ROOT / "conformance" / "expected-failures.json").read_text(encoding="utf-8"))
    if not isinstance(entries, list):
        raise ValueError("expected failures must be a JSON list")
    for entry in entries:
        required = {"test-id", "issue", "owner", "expires"}
        if not isinstance(entry, dict) or required - entry.keys():
            raise ValueError("each expected failure requires test-id, issue, owner, and expires")


def git_revision(path: Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(path), "rev-parse", "HEAD"], text=True
    ).strip()


def validate_runner(path: Path, manifest: dict) -> None:
    runner_script = path / "scripts" / "run-test-plan.py"
    if not runner_script.is_file():
        raise ValueError(f"OIDF runner script is missing: {runner_script}")
    actual = git_revision(path)
    expected = manifest["official_runner"]["commit"]
    if actual != expected:
        raise ValueError(f"OIDF runner is {actual}; expected pinned {expected}")


def validate_config(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    vci = data.get("vci", {})
    issuer = vci.get("credential_issuer_url", "")
    parsed = urlparse(issuer)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("vci.credential_issuer_url must be an absolute http(s) gateway URL")
    if "example.invalid" in parsed.netloc or "REPLACE_" in issuer:
        raise ValueError("OIDF configuration still contains example values")
    for field in ("authorization_server", "credential_configuration_id"):
        if not vci.get(field):
            raise ValueError(f"vci.{field} is required by the official issuer plan")


def runner_relative_path(path: Path, runner: Path) -> str:
    """Return a runner-relative path safe for the suite's positional parser.

    The upstream runner uses ``:`` in its test-plan grammar.  On Windows an
    absolute drive path therefore looks like a malformed test-plan argument.
    A relative path works on every platform and keeps the config outside the
    runner checkout when desired.
    """
    resolved_path = path.resolve()
    resolved_runner = runner.resolve()
    if resolved_path.is_relative_to(resolved_runner):
        return str(resolved_path.relative_to(resolved_runner))
    return os.path.relpath(resolved_path, resolved_runner)


def cmd_validate(_args: argparse.Namespace) -> int:
    manifest = load_manifest()
    validate_expected_failures()
    print(f"OIDF runner manifest is valid: {manifest['official_runner']['release']}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    manifest = load_manifest()
    validate_expected_failures()
    profile = manifest["profiles"].get(args.profile)
    if profile is None:
        raise ValueError(f"unknown profile: {args.profile}")
    if profile["status"] != "active":
        raise ValueError(f"profile {args.profile} is not active: {profile.get('reason', 'no reason recorded')}")
    runner = args.runner.resolve()
    config = args.config.resolve()
    validate_runner(runner, manifest)
    validate_config(config)
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    config_argument = runner_relative_path(config, runner)
    command = [
        sys.executable,
        "scripts/run-test-plan.py",
        "--no-parallel",
        "--export-dir",
        str(output),
        "--expected-failures-file",
        str((ROOT / "conformance" / "expected-failures.json").resolve()),
        profile["test_plan"],
        config_argument,
    ]
    print("Running the official OIDF plan:", profile["test_plan"])
    return subprocess.run(command, cwd=runner, check=False).returncode


def cmd_check_update(_args: argparse.Namespace) -> int:
    manifest = load_manifest()
    request = urllib.request.Request(
        "https://gitlab.com/api/v4/projects/openid%2Fconformance-suite/releases/permalink/latest",
        headers={"Accept": "application/json", "User-Agent": "ElevenID-OIDF-Conformance"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:  # nosec B310: fixed HTTPS URL
        latest = json.load(response)
    latest_tag = latest.get("tag_name", "")
    if not latest_tag.startswith("release-v"):
        raise ValueError("OIDF latest release response has no release tag")
    pinned = manifest["official_runner"]["release"]
    print(f"Pinned OIDF runner: {pinned}; latest official release: {latest_tag}")
    return 0 if latest_tag == pinned else 3


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("validate")
    run = commands.add_parser("run")
    run.add_argument("--runner", type=Path, required=True)
    run.add_argument("--profile", required=True)
    run.add_argument("--config", type=Path, required=True)
    run.add_argument("--output-dir", type=Path, required=True)
    commands.add_parser("check-update")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "validate":
        return cmd_validate(args)
    if args.command == "run":
        return cmd_run(args)
    return cmd_check_update(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f"OIDF conformance setup error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
