#!/usr/bin/env python3
"""Scope Docker interoperability helpers to explicit Compose projects.

A Docker context is only a connection endpoint; it does not provide isolation.
The safety boundary used here is the Compose project label on every container.
This works on a shared local engine and on a remote engine without letting an
adapter exec into a similarly named container owned by another stack.
"""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Sequence

CONTEXT_ENV = "MARTY_CONFORMANCE_DOCKER_CONTEXT"
PROJECT_ENV = "MARTY_CONFORMANCE_PROJECT"
OIDF_PROJECT_ENV = "OIDF_CONFORMANCE_PROJECT"
PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]{1,62}$")


def docker_command(arguments: Sequence[str]) -> list[str]:
    """Build a Docker command for the selected context, or the current one."""
    command = ["docker"]
    context = os.environ.get(CONTEXT_ENV, "").strip()
    if context:
        inspected = subprocess.run(
            ["docker", "context", "inspect", context],
            capture_output=True,
            text=True,
            check=False,
        )
        if inspected.returncode:
            raise ValueError(f"Docker context {context!r} cannot be inspected")
        command.extend(["--context", context])
    return [*command, *arguments]


def project_name(environment: str = PROJECT_ENV) -> str:
    project = os.environ.get(environment, "").strip()
    if not project:
        raise ValueError(f"{environment} is required")
    if not PROJECT.fullmatch(project):
        raise ValueError(f"{environment} contains an invalid Compose project name")
    if environment == PROJECT_ENV and not project.startswith("marty-conformance-"):
        raise ValueError(f"{PROJECT_ENV} must start with marty-conformance-")
    return project


def require_project_container(container: str, environment: str = PROJECT_ENV) -> None:
    """Prove a Docker exec target belongs to the expected Compose project."""
    expected = project_name(environment)
    inspected = subprocess.run(
        docker_command(
            [
                "inspect",
                "--format",
                '{{ index .Config.Labels "com.docker.compose.project" }}',
                container,
            ]
        ),
        capture_output=True,
        text=True,
        check=False,
    )
    if inspected.returncode:
        raise ValueError(f"container {container!r} cannot be inspected")
    actual = inspected.stdout.strip()
    if actual != expected:
        raise ValueError(
            f"container {container!r} belongs to Compose project {actual!r}, expected {expected!r}"
        )
