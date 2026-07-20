#!/usr/bin/env python3
"""Invoke the pinned EUDI reference services as a separate Compose project.

Only the official wallet-facing services join Marty's project-scoped TLS
bridge. This helper validates that the bridge already exists instead of using
``docker network connect`` or silently creating a network with the same name.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "conformance" / "eudi-reference.compose.yml"
PROJECT = re.compile(r"^eudi-reference(?:-[a-z0-9][a-z0-9-]{0,46})?$")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--project", default=os.environ.get("EUDI_CONFORMANCE_PROJECT", "eudi-reference"))
    result.add_argument(
        "--marty-project",
        default=os.environ.get("MARTY_CONFORMANCE_PROJECT"),
        help="Marty OIDF Compose project; defaults to MARTY_CONFORMANCE_PROJECT",
    )
    result.add_argument("arguments", nargs=argparse.REMAINDER, help="arguments passed to docker compose")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if not args.marty_project:
        raise SystemExit("--marty-project or MARTY_CONFORMANCE_PROJECT is required")
    if not PROJECT.fullmatch(args.project):
        raise SystemExit("--project must be eudi-reference or eudi-reference-<run-id>")
    if args.arguments and args.arguments[0] == "--":
        args.arguments = args.arguments[1:]
    if not args.arguments:
        raise SystemExit("pass a docker compose command, for example: -- up --detach")
    if not COMPOSE.is_file():
        raise SystemExit(f"EUDI reference Compose file is missing: {COMPOSE}")

    bridge = f"{args.marty_project}_oidf-runner"
    if subprocess.run(["docker", "network", "inspect", bridge], check=False).returncode:
        raise SystemExit(f"Marty TLS bridge does not exist: {bridge}")
    environment = os.environ.copy()
    environment["OIDF_MARTY_BRIDGE_NETWORK"] = bridge
    command = [
        "docker", "compose", "--project-name", args.project,
        "--file", str(COMPOSE), *args.arguments,
    ]
    return subprocess.run(command, check=False, env=environment).returncode


if __name__ == "__main__":
    sys.exit(main())
