#!/usr/bin/env python3
"""Safely invoke the official OIDF runner Compose project with Marty's bridge.

The runner is intentionally a separate Compose project.  This helper adds the
versioned overlay which attaches *only* the official runner's ``server``
service to the project-scoped Marty TLS bridge.  It never adds the runner to
Marty's private network and it never uses ``docker network connect``.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / "conformance" / "oidf-runner-bridge.compose.yml"
PREBUILT_OVERLAY = ROOT / "conformance" / "oidf-runner-prebuilt.compose.yml"


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--runner", type=Path, required=True, help="pinned official runner checkout")
    result.add_argument(
        "--prebuilt",
        action="store_true",
        help="use the upstream prebuilt Compose file with ElevenID's immutable image overrides",
    )
    result.add_argument("--project", default=os.environ.get("OIDF_CONFORMANCE_PROJECT", "oidf-runner"))
    result.add_argument(
        "--marty-project",
        default=os.environ.get("MARTY_CONFORMANCE_PROJECT"),
        help="Marty Compose project; defaults to MARTY_CONFORMANCE_PROJECT",
    )
    result.add_argument("arguments", nargs=argparse.REMAINDER, help="arguments passed to docker compose")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if not args.marty_project:
        raise SystemExit("--marty-project or MARTY_CONFORMANCE_PROJECT is required")
    if args.arguments and args.arguments[0] == "--":
        args.arguments = args.arguments[1:]
    if not args.arguments:
        raise SystemExit("pass a docker compose command, for example: -- up --detach")
    compose_name = "docker-compose-prebuilt.yml" if args.prebuilt else "docker-compose.yml"
    compose = args.runner.resolve() / compose_name
    if not compose.is_file():
        raise SystemExit(f"official runner Compose file is missing: {compose}")

    environment = os.environ.copy()
    environment["OIDF_MARTY_BRIDGE_NETWORK"] = f"{args.marty_project}_oidf-runner"
    overlays = ["--file", str(OVERLAY)]
    if args.prebuilt:
        overlays = ["--file", str(PREBUILT_OVERLAY), *overlays]
    command = [
        "docker", "compose", "--project-name", args.project,
        "--file", str(compose), *overlays, *args.arguments,
    ]
    return subprocess.run(command, check=False, env=environment).returncode


if __name__ == "__main__":
    sys.exit(main())
