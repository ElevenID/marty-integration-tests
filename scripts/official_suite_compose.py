#!/usr/bin/env python3
"""Own the isolated Compose lifecycle for Marty and official test suites.

Marty, the OIDF runner, and the EUDI reference services remain independent
Compose projects. They share only Marty's project-scoped TLS bridge. Every
child command uses the same Docker context, and teardown always runs in the
reverse order in which projects were started.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from docker_context import CONTEXT_ENV, docker_command

ROOT = Path(__file__).resolve().parents[1]
RUN_ID = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("command", choices=("up", "down", "ps", "logs"))
    result.add_argument("--run-id", default=os.environ.get("OFFICIAL_SUITE_RUN_ID") or os.environ.get("GITHUB_RUN_ID"))
    result.add_argument("--marty-ui", type=Path, required=True, help="pinned marty-ui checkout")
    result.add_argument("--oidf-runner", type=Path, help="pinned official OIDF runner checkout")
    result.add_argument("--oidf", action="store_true", help="include the official OIDF runner project")
    result.add_argument("--eudi", action="store_true", help="include the EUDI reference project")
    result.add_argument("--w3c", action="store_true", help="enable Marty's test-only W3C VC adapter")
    result.add_argument("--haip", action="store_true", help="enable Marty's HAIP verifier profile")
    result.add_argument("--local-build", action="store_true", help="build Marty locally; never release-grade")
    return result


def project_names(run_id: str) -> dict[str, str]:
    if not RUN_ID.fullmatch(run_id):
        raise ValueError("run id must use lowercase letters, digits, and internal hyphens")
    return {
        "marty": f"marty-conformance-{run_id}",
        "oidf": f"oidf-runner-{run_id}",
        "eudi": f"eudi-reference-{run_id}",
    }


def child_environment() -> dict[str, str]:
    environment = os.environ.copy()
    context = environment.get(CONTEXT_ENV, "").strip()
    if context:
        # docker_command validates the named context before any project starts.
        docker_command(["info"])
        environment["DOCKER_CONTEXT"] = context
    return environment


def run(command: list[str], environment: dict[str, str]) -> int:
    print("+", subprocess.list2cmdline(command), flush=True)
    return subprocess.run(command, check=False, env=environment).returncode


def marty_command(args: argparse.Namespace, projects: dict[str, str], action: str) -> list[str]:
    script = args.marty_ui.resolve() / "scripts" / "conformance_stack.py"
    if not script.is_file():
        raise ValueError(f"Marty conformance launcher is missing: {script}")
    command = [sys.executable, str(script), "--project", projects["marty"]]
    if args.w3c:
        command.append("--include-w3c")
    if args.haip:
        command.append("--haip")
    if args.local_build:
        command.append("--local-build")
    command.append(action)
    return command


def oidf_command(args: argparse.Namespace, projects: dict[str, str], action: str) -> list[str]:
    if args.oidf_runner is None:
        raise ValueError("--oidf requires --oidf-runner")
    compose_args = {
        "up": ["up", "--detach", "--wait"],
        "down": ["down", "--volumes", "--remove-orphans"],
        "ps": ["ps"],
        "logs": ["logs", "--no-color"],
    }[action]
    return [
        sys.executable,
        str(ROOT / "scripts" / "oidf_runner_compose.py"),
        "--runner",
        str(args.oidf_runner.resolve()),
        "--prebuilt",
        "--project",
        projects["oidf"],
        "--marty-project",
        projects["marty"],
        "--",
        *compose_args,
    ]


def eudi_command(projects: dict[str, str], action: str) -> list[str]:
    compose_args = {
        "up": ["up", "--detach", "--wait"],
        "down": ["down", "--volumes", "--remove-orphans"],
        "ps": ["ps"],
        "logs": ["logs", "--no-color"],
    }[action]
    return [
        sys.executable,
        str(ROOT / "scripts" / "eudi_reference_compose.py"),
        "--project",
        projects["eudi"],
        "--marty-project",
        projects["marty"],
        "--",
        *compose_args,
    ]


def components(
    args: argparse.Namespace, projects: dict[str, str], action: str
) -> list[tuple[str, Callable[[], list[str]]]]:
    entries: list[tuple[str, Callable[[], list[str]]]] = [("marty", lambda: marty_command(args, projects, action))]
    if args.oidf:
        entries.append(("oidf", lambda: oidf_command(args, projects, action)))
    if args.eudi:
        entries.append(("eudi", lambda: eudi_command(projects, action)))
    if action != "up":
        entries.reverse()
    return entries


def stop_started(
    names: list[str],
    args: argparse.Namespace,
    projects: dict[str, str],
    environment: dict[str, str],
) -> None:
    down = dict(components(args, projects, "down"))
    for name in reversed(names):
        try:
            run(down[name](), environment)
        except (OSError, ValueError) as exc:
            print(f"cleanup for {name} failed: {exc}", file=sys.stderr)


def execute(args: argparse.Namespace) -> int:
    if not args.run_id:
        raise ValueError("--run-id, OFFICIAL_SUITE_RUN_ID, or GITHUB_RUN_ID is required")
    if args.haip and not args.oidf:
        raise ValueError("--haip requires --oidf")
    if not any((args.oidf, args.eudi, args.w3c)):
        raise ValueError("select at least one of --oidf, --eudi, or --w3c")

    projects = project_names(args.run_id)
    environment = child_environment()
    selected = components(args, projects, args.command)
    if args.command != "up":
        first_failure = 0
        for _name, command in selected:
            result = run(command(), environment)
            if result and not first_failure:
                first_failure = result
        return first_failure

    started: list[str] = []
    for name, command in selected:
        # Include a partially created project in cleanup if its up command fails.
        started.append(name)
        result = run(command(), environment)
        if result:
            stop_started(started, args, projects, environment)
            return result
    return 0


def main(argv: list[str] | None = None) -> int:
    return execute(parser().parse_args(argv))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        print(f"Official suite Compose error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
