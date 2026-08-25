"""Language-neutral Applicant-to-Flow event probes.

The probe implements the wire contract with Python's standard library instead
of importing either service implementation. Network calls run from the stack's
Python migration artifact, keeping private ports private without adding an
interpreter to a production service image.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import textwrap
import time
import uuid
from collections.abc import Mapping
from typing import Any, cast

from tests.oss_stack.compose import stack_compose_command

_DEFAULT_KEY = "oss-ci-application-event-hmac-key-32-bytes"
_PRODUCER = "marty-applicant-service"
_AUDIENCE = "marty-flow-application-approved"
_VERSION = "v1"


def sign_application_event(
    event: Mapping[str, Any],
    *,
    event_id: str | None = None,
    now: int | None = None,
) -> dict[str, str]:
    """Sign the transport contract independently of either service language."""
    event_id = event_id or str(uuid.uuid4())
    uuid.UUID(event_id)
    timestamp = str(int(time.time() if now is None else now))
    canonical = json.dumps(
        dict(event),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()
    payload_sha256 = hashlib.sha256(canonical).hexdigest()
    signature_input = "\n".join((_VERSION, _PRODUCER, _AUDIENCE, event_id, timestamp, payload_sha256)).encode()
    key = os.environ.get("FLOW_APPLICATION_EVENT_HMAC_KEY", _DEFAULT_KEY).encode()
    signature = hmac.new(key, signature_input, hashlib.sha256).hexdigest()
    return {
        "x-marty-event-producer": _PRODUCER,
        "x-marty-event-audience": _AUDIENCE,
        "x-marty-event-id": event_id,
        "x-marty-event-timestamp": timestamp,
        "x-marty-event-signature-version": _VERSION,
        "x-marty-event-signature": signature,
    }


def _run_python(probe: str, *, timeout: int = 45) -> str:
    completed = subprocess.run(
        [
            *stack_compose_command(),
            "run",
            "--rm",
            "--no-deps",
            "-T",
            "migrations",
            "python",
            "-c",
            probe,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"network probe failed with exit {completed.returncode}: {completed.stderr.strip()}")
    return completed.stdout.strip().splitlines()[-1]


def post_json(
    url: str,
    event: Mapping[str, Any],
    headers: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """POST JSON over the private Compose network using only Python stdlib."""
    body = json.dumps(dict(event), separators=(",", ":"), ensure_ascii=False)
    request_headers = {"Content-Type": "application/json", **dict(headers or {})}
    probe = textwrap.dedent(
        f"""
        import json
        import urllib.error
        import urllib.request

        request = urllib.request.Request(
            {url!r},
            data={body!r}.encode(),
            headers={request_headers!r},
            method="POST",
        )
        try:
            response = urllib.request.urlopen(request, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        payload = response.read().decode()
        print(json.dumps({{
            "status": response.status,
            "body": json.loads(payload) if payload else None,
        }}, sort_keys=True))
        """
    )
    return cast(dict[str, Any], json.loads(_run_python(probe)))


def send_without_reading_response(event: Mapping[str, Any], headers: Mapping[str, str]) -> None:
    """Send a complete request, observe response readiness, then close unread."""
    body = json.dumps(dict(event), separators=(",", ":"), ensure_ascii=False)
    probe = textwrap.dedent(
        f"""
        import socket

        body = {body!r}.encode()
        headers = {dict(headers)!r}
        lines = [
            b"POST /v1/flows/webhooks/application-approved HTTP/1.1",
            b"Host: flow-service:8011",
            b"Content-Type: application/json",
            f"Content-Length: {{len(body)}}".encode(),
            b"Connection: close",
            *[f"{{name}}: {{value}}".encode() for name, value in headers.items()],
            b"",
            b"",
        ]
        with socket.create_connection(("flow-service", 8011), timeout=10) as connection:
            connection.sendall(b"\\r\\n".join(lines) + body)
            connection.settimeout(30)
            if not connection.recv(1, socket.MSG_PEEK):
                raise RuntimeError("connection closed before a response")
        print("response-ready")
        """
    )
    if _run_python(probe) != "response-ready":
        raise RuntimeError("network probe did not observe response readiness")


def internal_url_is_healthy(url: str) -> bool:
    probe = textwrap.dedent(
        f"""
        import urllib.request

        with urllib.request.urlopen({url!r}, timeout=2) as response:
            if response.status != 200:
                raise RuntimeError(f"unhealthy status: {{response.status}}")
        print("healthy")
        """
    )
    try:
        return _run_python(probe, timeout=10) == "healthy"
    except (RuntimeError, subprocess.TimeoutExpired):
        return False
