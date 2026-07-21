#!/usr/bin/env python3
"""Scope Docker interoperability helpers to explicit Compose projects.

A Docker context is only a connection endpoint; it does not provide isolation.
The safety boundary used here is the Compose project label on every container.
This works on a shared local engine and on a remote engine without letting an
adapter exec into a similarly named container owned by another stack.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import urlparse

CONTEXT_ENV = "MARTY_CONFORMANCE_DOCKER_CONTEXT"
PROJECT_ENV = "MARTY_CONFORMANCE_PROJECT"
OIDF_PROJECT_ENV = "OIDF_CONFORMANCE_PROJECT"
NETWORK_BIND_OVERRIDE_ENV = "MARTY_CONFORMANCE_ALLOW_NETWORK_BINDS"
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


def selected_docker_endpoint(environment: Mapping[str, str] | None = None) -> str:
    """Return the endpoint Docker CLI will actually use.

    The ElevenID context override has CLI precedence. Otherwise Docker honors
    DOCKER_CONTEXT, then DOCKER_HOST, then the active context. Inspecting only
    our custom variable is insufficient and can send client-side bind paths to
    a remote daemon.
    """
    values = environment if environment is not None else os.environ
    elevenid_context = values.get(CONTEXT_ENV, "").strip()
    standard_context = values.get("DOCKER_CONTEXT", "").strip()
    docker_host = values.get("DOCKER_HOST", "").strip()
    context = elevenid_context or standard_context
    if docker_host and not context:
        return docker_host
    command = ["docker", "context", "inspect"]
    if context:
        command.append(context)
    completed = subprocess.run(command, capture_output=True, text=True, check=False, env=dict(values))
    if completed.returncode:
        selected = f" {context!r}" if context else ""
        raise ValueError(f"Docker context{selected} cannot be inspected")
    try:
        documents: Any = json.loads(completed.stdout)
        endpoint = documents[0]["Endpoints"]["docker"]["Host"]
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("Docker context inspection did not return a Docker endpoint") from exc
    if not isinstance(endpoint, str) or not endpoint.strip():
        raise ValueError("Docker context has no Docker endpoint")
    return endpoint.strip()


def docker_endpoint_is_local(environment: Mapping[str, str] | None = None) -> bool:
    """Return whether bind sources live on the current client host."""
    values = environment if environment is not None else os.environ
    endpoint = selected_docker_endpoint(values)
    parsed = urlparse(endpoint)
    if parsed.scheme in {"unix", "npipe", "fd"}:
        return True
    if parsed.scheme in {"tcp", "http", "https", "ssh"}:
        # Even a loopback endpoint may be a tunnel to another filesystem.
        # Accept network transports only through an explicit, reviewed claim
        # that every bind source is shared with the daemon host.
        return values.get(NETWORK_BIND_OVERRIDE_ENV, "").strip() == "1"
    return False


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
        raise ValueError(f"container {container!r} belongs to Compose project {actual!r}, expected {expected!r}")
