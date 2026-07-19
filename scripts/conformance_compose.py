#!/usr/bin/env python3
"""Run Compose for an official conformance deployment in a scoped project."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from docker_context import docker_command, project_name


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run Docker Compose only through MARTY_CONFORMANCE_PROJECT"
    )
    parser.add_argument("arguments", nargs=argparse.REMAINDER, help="arguments passed to docker compose")
    args = parser.parse_args()
    if not args.arguments:
        parser.error("provide Docker Compose arguments after --")
    return subprocess.run(
        docker_command(["compose", "--project-name", project_name(), *args.arguments]),
        check=False,
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
