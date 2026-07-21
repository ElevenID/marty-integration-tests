#!/usr/bin/env python3
"""Record public-safe provenance for the locally built EUDI wallet harness."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from docker_context import docker_command

ROOT = Path(__file__).resolve().parents[1]
PROJECT = re.compile(r"^eudi-reference(?:-[a-z0-9][a-z0-9-]{0,62})?$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
RECIPE_FILES = (
    ROOT / "services" / "eudi-wallet-harness" / "Dockerfile",
    ROOT / "services" / "eudi-wallet-harness" / "gradle.lockfile",
    ROOT / "services" / "eudi-wallet-harness" / "gradle" / "verification-metadata.xml",
)


def file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def inspect_digest(project: str) -> str:
    if not PROJECT.fullmatch(project):
        raise ValueError("EUDI project name is invalid")
    image = f"{project}-eudi-wallet-kit"
    completed = subprocess.run(
        docker_command(["image", "inspect", "--format", "{{.Id}}", image]),
        capture_output=True,
        text=True,
        check=False,
    )
    digest = completed.stdout.strip()
    if completed.returncode or not DIGEST.fullmatch(digest):
        detail = completed.stderr.strip()
        raise ValueError(f"could not inspect the locally built EUDI harness image: {detail[:200]}")
    return digest


def build_report(project: str) -> dict[str, object]:
    missing = [path for path in RECIPE_FILES if not path.is_file()]
    if missing:
        raise ValueError("EUDI harness build recipe is incomplete: " + ", ".join(path.name for path in missing))
    return {
        "schema": "elevenid.eudi-harness-build/v1",
        "component": "eudi-wallet-harness",
        "image_digest": inspect_digest(project),
        "recipe": {path.relative_to(ROOT).as_posix(): file_sha256(path) for path in RECIPE_FILES},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    report = build_report(args.project)
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"EUDI harness provenance error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
