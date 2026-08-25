"""Stable Docker Compose command construction for artifact-stack probes."""

from __future__ import annotations

import os


def stack_compose_command() -> tuple[str, ...]:
    """Address the Rust candidate stack without ambient Compose file state."""
    command = [
        "docker",
        "compose",
        "--env-file",
        ".env.stack",
        "--file",
        "docker-compose.yml",
        "--file",
        "docker-compose.rust-revocation.yml",
    ]
    project = os.environ.get("MARTY_OSS_STACK_PROJECT", "").strip()
    if project:
        command.extend(("--project-name", project))
    return tuple(command)
