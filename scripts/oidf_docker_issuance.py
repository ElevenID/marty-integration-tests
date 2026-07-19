#!/usr/bin/env python3
"""Local-only issuance transport for the disposable Docker integration stack.

It reads an issuance request on stdin and writes the issuance response on
stdout. The API key stays inside the target container; use the HTTP transport
in oidf_marty_offer.py for staging or certification deployments.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from docker_context import docker_command


def main() -> int:
    container = os.environ.get("OIDF_ISSUANCE_CONTAINER", "m-integration-tests-issuance-service-1")
    api_key = os.environ.get("OIDF_ISSUANCE_API_KEY")
    payload = sys.stdin.buffer.read()
    if not payload:
        print("missing issuance request", file=sys.stderr)
        return 2
    if not api_key:
        print("OIDF_ISSUANCE_API_KEY is required for the local Docker transport", file=sys.stderr)
        return 2
    command = docker_command([
        "exec", "-i", container, "curl", "-fsS",
        "-H", f"X-API-Key: {api_key}",
        "-H", "Content-Type: application/json",
        "-d", "@-", "http://localhost:8005/v1/issuance/initiate",
    ])
    result = subprocess.run(command, input=payload, capture_output=True, check=False)
    if result.returncode:
        print("Docker issuance transport failed", file=sys.stderr)
        return result.returncode
    sys.stdout.buffer.write(result.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
