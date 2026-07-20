#!/usr/bin/env python3
"""Materialize an exact reviewed official-suite revision without a moving branch."""

from __future__ import annotations

import argparse
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


def run_git(*arguments: str, cwd: Path | None = None) -> None:
    subprocess.run(["git", *arguments], cwd=cwd, check=True)


def checkout(name: str, output: Path) -> str:
    repository, commit = pinned_source(name)
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"refusing to reuse a non-empty official-suite checkout: {output}")
    output.mkdir(parents=True, exist_ok=True)
    run_git("init", cwd=output)
    run_git("remote", "add", "origin", repository, cwd=output)
    run_git("fetch", "--depth", "1", "origin", commit, cwd=output)
    run_git("-c", "advice.detachedHead=false", "checkout", "--detach", "FETCH_HEAD", cwd=output)
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=output, text=True).strip()
    if actual != commit:
        raise ValueError(f"{name} checkout resolved {actual}; expected {commit}")
    return commit


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--suite", choices=sorted(SUITES), required=True)
    result.add_argument("--output", type=Path, required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    commit = checkout(args.suite, args.output.resolve())
    print(f"Checked out {args.suite} official suite at {commit}.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError, subprocess.CalledProcessError) as exc:
        print(f"Official suite checkout error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
