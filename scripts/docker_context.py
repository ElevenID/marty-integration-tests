#!/usr/bin/env python3
"""Guard Docker commands used by disposable interoperability runs.

Docker contexts are names, not isolation boundaries: two local contexts can
point at the same Docker Desktop daemon.  Official conformance execution must
therefore use an explicitly selected remote daemon, normally a short-lived VM
or an isolated CI runner.  This module rejects local named pipes so adapters
cannot accidentally inspect or modify a developer or production-like stack.
"""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Sequence

CONTEXT_ENV = "MARTY_CONFORMANCE_DOCKER_CONTEXT"


def isolated_context_name() -> str:
    """Return the explicitly selected, non-local Docker context."""
    context = os.environ.get(CONTEXT_ENV, "").strip()
    if not context:
        raise ValueError(
            f"{CONTEXT_ENV} is required; use an isolated remote Docker daemon, not Docker Desktop"
        )
    if context in {"default", "desktop-linux"}:
        raise ValueError(f"{CONTEXT_ENV}={context!r} is a local Docker Desktop context and is not isolated")

    result = subprocess.run(
        ["docker", "context", "inspect", context, "--format", "{{json .Endpoints.docker.Host}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise ValueError(f"Docker context {context!r} cannot be inspected")
    try:
        host = json.loads(result.stdout.strip())
    except json.JSONDecodeError as error:
        raise ValueError(f"Docker context {context!r} returned an invalid endpoint") from error
    if not isinstance(host, str) or host.startswith(("npipe://", "unix://")):
        raise ValueError(f"Docker context {context!r} points to a local daemon and is not isolated")
    return context


def docker_command(arguments: Sequence[str]) -> list[str]:
    """Build a Docker command pinned to the verified isolated context."""
    return ["docker", "--context", isolated_context_name(), *arguments]
