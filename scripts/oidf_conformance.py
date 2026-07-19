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
from hashlib import sha256
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

    skips = json.loads((ROOT / "conformance" / "expected-skips.json").read_text(encoding="utf-8"))
    if not isinstance(skips, list):
        raise ValueError("expected skips must be a JSON list")
    for entry in skips:
        required = {"test-name", "configuration-filename", "variant", "reason", "owner", "expires"}
        if not isinstance(entry, dict) or required - entry.keys():
            raise ValueError(
                "each expected skip requires test-name, configuration-filename, variant, reason, owner, and expires"
            )


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


def _validate_absolute_url(value: object, field: str) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an absolute http(s) URL")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"{field} must be an absolute http(s) URL")
    if "example.invalid" in parsed.netloc or "REPLACE_" in value:
        raise ValueError("OIDF configuration still contains example values")


def validate_config(path: Path, profile_name: str = "oid4vci-issuer") -> None:
    """Validate only the profile-specific, non-secret runner configuration.

    OIDF verifier tests create their own wallet response.  Marty is started by
    the deployment-owned interaction command, so this file deliberately
    contains neither gateway credentials nor a test bypass.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("OIDF configuration must be a JSON object")
    if profile_name == "oid4vci-issuer":
        vci = data.get("vci", {})
        issuer = vci.get("credential_issuer_url", "")
        _validate_absolute_url(issuer, "vci.credential_issuer_url")
        for field in ("authorization_server", "credential_configuration_id"):
            if not vci.get(field):
                raise ValueError(f"vci.{field} is required by the official issuer plan")
        return

    if profile_name not in {"oid4vp-verifier", "oid4vp-haip-verifier"}:
        raise ValueError(f"unknown OIDF configuration profile: {profile_name}")
    signing_jwk = data.get("credential", {}).get("signing_jwk")
    if not isinstance(signing_jwk, dict) or not signing_jwk.get("kty"):
        raise ValueError("credential.signing_jwk is required by the official verifier plans")
    verifier = data.get("verifier", {})
    _validate_absolute_url(verifier.get("gateway_url"), "verifier.gateway_url")
    if not verifier.get("profile"):
        raise ValueError("verifier.profile is required by the official verifier plans")
    if profile_name == "oid4vp-haip-verifier":
        anchor = data.get("client", {}).get("request_object_trust_anchor_pem")
        if not isinstance(anchor, str) or not anchor.strip() or "REPLACE_" in anchor:
            raise ValueError("client.request_object_trust_anchor_pem is required by the HAIP verifier plan")


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
    # The upstream plan grammar treats backslashes as separators outside the
    # configuration-file token.  Normalize the relative path for Windows as
    # well as POSIX hosts before passing it as a positional argument.
    return Path(os.path.relpath(resolved_path, resolved_runner)).as_posix()


def file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def write_evidence(
    output: Path,
    manifest: dict,
    profile_name: str,
    config: Path,
    runner: Path,
    exit_code: int,
    stack_manifest: Path | None,
) -> None:
    """Write non-secret provenance alongside an official suite export.

    Configurations can contain private signing keys, so evidence records their
    digest and path only. Result files are listed by digest after the official
    runner exits; this makes later review independent of mutable runner state.
    """
    stack: dict[str, object] | None = None
    if stack_manifest is not None:
        raw_stack = json.loads(stack_manifest.read_text(encoding="utf-8"))
        if raw_stack.get("schema") != "marty.stack/v1":
            raise ValueError("stack manifest must use marty.stack/v1")
        stack = {"path": str(stack_manifest), "sha256": file_sha256(stack_manifest), "release": raw_stack.get("release")}
    artifacts = [
        {"path": str(path.relative_to(output)).replace("\\", "/"), "sha256": file_sha256(path)}
        for path in sorted(output.rglob("*"))
        if path.is_file() and path.name != "evidence.json"
    ]
    evidence = {
        "schema": "elevenid.official-interop-evidence/v1",
        "official_runner": manifest["official_runner"],
        "profile": profile_name,
        "runner": {"path": str(runner), "commit": git_revision(runner)},
        "marty": {"commit": os.environ.get("MARTY_COMMIT", "unrecorded"), "stack_manifest": stack},
        "configuration": {"path": str(config), "sha256": file_sha256(config)},
        "exclusions": {
            "expected_failures": json.loads((ROOT / "conformance" / "expected-failures.json").read_text(encoding="utf-8")),
            "expected_skips": json.loads((ROOT / "conformance" / "expected-skips.json").read_text(encoding="utf-8")),
        },
        "result": {"exit_code": exit_code, "passed": exit_code == 0},
        "artifacts": artifacts,
    }
    (output / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")


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
    validate_config(config, args.profile)
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
        "--expected-skips-file",
        str((ROOT / "conformance" / "expected-skips.json").resolve()),
        profile["test_plan"],
        config_argument,
    ]
    if args.rerun:
        command[3:3] = ["--rerun", args.rerun]
    print("Running the official OIDF plan:", profile["test_plan"])
    if args.interaction_script is None:
        result = subprocess.run(command, cwd=runner, check=False).returncode
        write_evidence(output, manifest, args.profile, config, runner, result, args.stack_manifest)
        return result

    interaction_script = args.interaction_script.resolve()
    if not interaction_script.is_file():
        raise ValueError(f"OIDF interaction script is missing: {interaction_script}")
    browser_interaction_script = args.browser_interaction_script.resolve() if args.browser_interaction_script else None
    if browser_interaction_script is not None and not browser_interaction_script.is_file():
        raise ValueError(f"OIDF browser interaction script is missing: {browser_interaction_script}")

    # The official runner prints a module ID immediately after creating it and
    # then waits for the issuer interaction.  Keep the runner unmodified while
    # allowing an implementation-owned script to drive that interaction.  The
    # hook receives only public test metadata through arguments; credentials
    # remain environment variables owned by the invoking environment.
    current_module = ""
    hooks: list[subprocess.Popen[str]] = []
    process = subprocess.Popen(
        # ``run-test-plan.py`` is a Python program.  Its output becomes a pipe
        # here, so force unbuffered mode; otherwise a waiting official module
        # can deadlock before the interaction hook sees its ID.
        [command[0], "-u", *command[1:]],
        cwd=runner,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert process.stdout is not None
    for line in process.stdout:
        print(line, end="")
        match = re.search(r"Running test module: (.+)", line)
        if match:
            current_module = match.group(1).strip()
            continue
        match = re.search(r"Created test module, new id: ([A-Za-z0-9]+)", line)
        if match:
            hook_command = [
                sys.executable,
                str(interaction_script),
                "--test-id",
                match.group(1),
                "--test-name",
                current_module,
                "--server",
                os.environ.get("CONFORMANCE_SERVER", ""),
            ]
            hooks.append(subprocess.Popen(hook_command, cwd=ROOT))
            if browser_interaction_script is not None:
                hooks.append(subprocess.Popen(
                    [
                        sys.executable, str(browser_interaction_script), "--test-id", match.group(1),
                        "--test-name", current_module, "--server", os.environ.get("CONFORMANCE_SERVER", ""),
                    ],
                    cwd=ROOT,
                ))

    runner_result = process.wait()
    hook_result = 0
    for hook in hooks:
        hook_result = hook.wait() or hook_result
    result = runner_result or hook_result
    write_evidence(output, manifest, args.profile, config, runner, result, args.stack_manifest)
    return result


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
    run.add_argument("--stack-manifest", type=Path, help="attested marty.stack/v1 manifest for the deployment under test")
    run.add_argument("--rerun", help="official runner plan/module selector, for example 1:3")
    run.add_argument(
        "--interaction-script",
        type=Path,
        help="implementation-owned script invoked for each official test module",
    )
    run.add_argument(
        "--browser-interaction-script",
        type=Path,
        help="local browser adapter invoked for each official test module",
    )
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
