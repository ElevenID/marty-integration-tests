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
import re
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath

sys.path.insert(0, str(Path(__file__).parent))
from docker_context import docker_command, docker_endpoint_is_local

ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / "conformance" / "oidf-runner-bridge.compose.yml"
PREBUILT_OVERLAY = ROOT / "conformance" / "oidf-runner-prebuilt.compose.yml"
OIDF_PROJECT = re.compile(r"^oidf-runner(?:-[a-z0-9][a-z0-9-]{0,46})?$")
MARTY_PROJECT = re.compile(r"^marty-conformance-[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$")
RUNNER_TLS_PATHS = (
    "OIDF_RUNNER_TLS_CERT_FILE",
    "OIDF_RUNNER_TLS_KEY_FILE",
    "OIDF_RUNNER_TRUSTSTORE_FILE",
)


def _daemon_absolute(value: str, field: str) -> str:
    normalized = value.strip()
    if not normalized or not (PurePosixPath(normalized).is_absolute() or PureWindowsPath(normalized).is_absolute()):
        raise SystemExit(f"{field} must be an absolute path on the Docker daemon host")
    return normalized


def _validate_runner_tls_environment(environment: dict[str, str]) -> None:
    required = (*RUNNER_TLS_PATHS, "OIDF_RUNNER_TRUSTSTORE_PASSWORD", "OIDF_RUNNER_TLS_MODE")
    missing = [name for name in required if not environment.get(name, "").strip()]
    if missing:
        raise SystemExit("missing OIDF runner TLS environment: " + ", ".join(missing))
    mode = environment["OIDF_RUNNER_TLS_MODE"].strip()
    if mode not in {"generated", "external"}:
        raise SystemExit("OIDF_RUNNER_TLS_MODE must be generated or external")
    if not docker_endpoint_is_local(environment):
        if mode == "generated":
            raise SystemExit(
                "generated OIDF runner TLS material is local to this host and cannot be bind-mounted "
                "through a remote Docker context"
            )
        for name in RUNNER_TLS_PATHS:
            _daemon_absolute(environment[name], name)
        return
    for name in RUNNER_TLS_PATHS:
        path = Path(environment[name])
        if not path.is_absolute():
            raise SystemExit(f"{name} must be an absolute path")
        if not path.is_file():
            raise SystemExit(f"{name} does not identify a readable file: {path}")
    if os.name != "nt":
        key_mode = os.stat(environment["OIDF_RUNNER_TLS_KEY_FILE"]).st_mode
        if key_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise SystemExit("OIDF_RUNNER_TLS_KEY_FILE must not be accessible by group or other users")


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
    if not MARTY_PROJECT.fullmatch(args.marty_project):
        raise SystemExit("--marty-project must be an isolated marty-conformance-<run-id> project")
    if not OIDF_PROJECT.fullmatch(args.project):
        raise SystemExit("--project must be oidf-runner or oidf-runner-<run-id>")
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
    _validate_runner_tls_environment(environment)
    overlays = ["--file", str(OVERLAY)]
    if args.prebuilt:
        overlays = ["--file", str(PREBUILT_OVERLAY), *overlays]
    command = docker_command(
        [
            "compose",
            "--project-name",
            args.project,
            "--file",
            str(compose),
            *overlays,
            *args.arguments,
        ]
    )
    return subprocess.run(command, check=False, env=environment).returncode


if __name__ == "__main__":
    sys.exit(main())
