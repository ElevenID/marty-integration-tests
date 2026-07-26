#!/usr/bin/env python3
"""Materialize an exact reviewed official-suite revision without a moving branch."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import TypedDict

ROOT = Path(__file__).resolve().parents[1]


class SuiteDefinition(TypedDict):
    manifest: Path
    section: str
    repository: str


SUITES: dict[str, SuiteDefinition] = {
    "oidf": {
        "manifest": ROOT / "conformance" / "oidf-runner.json",
        "section": "official_runner",
        "repository": "https://gitlab.com/openid/conformance-suite.git",
    },
    "w3c": {
        "manifest": ROOT / "conformance" / "w3c-vc-data-model-v2.json",
        "section": "official_suite",
        "repository": "https://github.com/w3c/vc-data-model-2.0-test-suite.git",
    },
}
COMMIT = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
W3C_PR = re.compile(
    r"^https://github\.com/w3c/vc-data-model-2\.0-test-suite/pull/([1-9][0-9]*)$"
)
W3C_PR_REF = re.compile(r"^refs/pull/([1-9][0-9]*)/head$")


def pinned_source(name: str) -> tuple[str, str]:
    definition = SUITES[name]
    data = json.loads(definition["manifest"].read_text(encoding="utf-8"))
    section = data.get(definition["section"], {})
    repository = section.get("repository")
    commit = section.get("commit")
    if repository != definition["repository"]:
        raise ValueError(f"{name} manifest does not use the reviewed official repository")
    if not isinstance(commit, str) or not COMMIT.fullmatch(commit):
        raise ValueError(f"{name} manifest does not pin a full lowercase commit")
    return repository, commit


def pinned_compatibility_patch(name: str) -> dict[str, object] | None:
    """Return a narrowly reviewed upstream-pending test-harness patch.

    A compatibility patch is never treated as part of the official source
    revision. It may repair the runner itself, but cannot modify Marty's
    adapter or suppress/skip a normative test.
    """
    definition = SUITES[name]
    data = json.loads(definition["manifest"].read_text(encoding="utf-8"))
    patch = data.get("compatibility_patch")
    if patch is None:
        return None
    if name != "w3c" or not isinstance(patch, dict):
        raise ValueError(f"{name} manifest has an unsupported compatibility patch")
    required_strings = (
        "status",
        "reason",
        "upstream_pull_request",
        "pull_request_ref",
        "base_commit",
        "commit",
        "diff_sha256",
        "owner",
        "review_date",
        "removal_condition",
    )
    if any(not isinstance(patch.get(field), str) or not patch[field] for field in required_strings):
        raise ValueError("W3C compatibility patch metadata is incomplete")
    official_commit = data.get(definition["section"], {}).get("commit")
    if patch["status"] != "upstream-pending" or patch["base_commit"] != official_commit:
        raise ValueError("W3C compatibility patch must target the pinned official commit")
    if not COMMIT.fullmatch(str(patch["commit"])) or not DIGEST.fullmatch(str(patch["diff_sha256"])):
        raise ValueError("W3C compatibility patch must pin a full commit and SHA-256")
    pr_match = W3C_PR.fullmatch(str(patch["upstream_pull_request"]))
    ref_match = W3C_PR_REF.fullmatch(str(patch["pull_request_ref"]))
    if not pr_match or not ref_match or pr_match.group(1) != ref_match.group(1):
        raise ValueError("W3C compatibility patch PR URL and ref do not match")
    paths = patch.get("paths")
    if (
        not isinstance(paths, list)
        or not paths
        or not all(
            isinstance(path, str)
            and path.startswith("tests/")
            and ".." not in Path(path).parts
            for path in paths
        )
    ):
        raise ValueError("W3C compatibility patch paths must stay under tests/")
    return patch


def run_git(*arguments: str, cwd: Path | None = None) -> None:
    subprocess.run(["git", *arguments], cwd=cwd, check=True)


def apply_compatibility_patch(name: str, output: Path, official_commit: str) -> None:
    patch = pinned_compatibility_patch(name)
    if patch is None:
        return
    patch_commit = str(patch["commit"])
    patch_ref = str(patch["pull_request_ref"])
    paths = [str(path) for path in patch["paths"]]
    run_git("fetch", "--depth", "1", "origin", patch_ref, cwd=output)
    actual_patch_commit = subprocess.check_output(
        ["git", "rev-parse", "FETCH_HEAD"], cwd=output, text=True
    ).strip()
    if actual_patch_commit != patch_commit:
        raise ValueError(
            f"{name} compatibility PR moved to {actual_patch_commit}; expected {patch_commit}"
        )
    patch_file = output / ".elevenid-reviewed-compatibility.patch"
    try:
        run_git(
            "diff",
            "--binary",
            f"--output={patch_file}",
            official_commit,
            patch_commit,
            "--",
            *paths,
            cwd=output,
        )
        actual_digest = f"sha256:{hashlib.sha256(patch_file.read_bytes()).hexdigest()}"
        if actual_digest != patch["diff_sha256"]:
            raise ValueError(
                f"{name} compatibility patch is {actual_digest}; expected {patch['diff_sha256']}"
            )
        run_git("apply", "--index", "--whitespace=error-all", str(patch_file), cwd=output)
    finally:
        patch_file.unlink(missing_ok=True)
    changed = subprocess.check_output(
        ["git", "diff", "--cached", "--name-only", "--format=", official_commit],
        cwd=output,
        text=True,
    ).splitlines()
    if changed != paths:
        raise ValueError(f"{name} compatibility patch changed unexpected paths: {changed}")
    run_git("diff", "--cached", "--check", official_commit, cwd=output)


def checkout(name: str, output: Path) -> str:
    repository, commit = pinned_source(name)
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"refusing to reuse a non-empty official-suite checkout: {output}")
    output.mkdir(parents=True, exist_ok=True)
    run_git("init", cwd=output)
    run_git("config", "core.autocrlf", "false", cwd=output)
    run_git("remote", "add", "origin", repository, cwd=output)
    run_git("fetch", "--depth", "1", "origin", commit, cwd=output)
    run_git("-c", "advice.detachedHead=false", "checkout", "--detach", "FETCH_HEAD", cwd=output)
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=output, text=True).strip()
    if actual != commit:
        raise ValueError(f"{name} checkout resolved {actual}; expected {commit}")
    apply_compatibility_patch(name, output, commit)
    return commit


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--suite", choices=sorted(SUITES), required=True)
    result.add_argument("--output", type=Path, required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    commit = checkout(args.suite, args.output.resolve())
    patch = pinned_compatibility_patch(args.suite)
    if patch:
        print(
            f"Checked out {args.suite} official suite at {commit} with reviewed "
            f"upstream-pending patch {patch['commit']} ({patch['upstream_pull_request']})."
        )
    else:
        print(f"Checked out {args.suite} official suite at {commit}.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError, subprocess.CalledProcessError) as exc:
        print(f"Official suite checkout error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
