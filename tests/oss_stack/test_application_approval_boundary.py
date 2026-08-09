"""Artifact-only checks for the Applicant -> Flow issuance-authority boundary."""

from __future__ import annotations

import json
import subprocess
import textwrap

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.oss_stack]


def test_application_approval_authentication_and_replay_inside_private_network() -> None:
    """Use released workload code without disclosing its dedicated key."""
    probe = textwrap.dedent(
        """
        import json
        import uuid
        from datetime import UTC, datetime

        import httpx

        from common.application_event_auth import sign_application_event

        event = {
            "event_type": "application.approved",
            "aggregate_id": f"artifact-probe-{uuid.uuid4()}",
            "aggregate_type": "application",
            "organization_id": str(uuid.uuid4()),
            "data": {"applicant_id": f"artifact-probe-{uuid.uuid4()}"},
            "timestamp": datetime.now(UTC).isoformat(),
        }
        endpoint = "http://flow-service:8011/v1/flows/webhooks/application-approved"
        unsigned = httpx.post(endpoint, json=event, timeout=10.0)
        headers = sign_application_event(event)
        accepted = httpx.post(endpoint, json=event, headers=headers, timeout=10.0)
        replayed = httpx.post(endpoint, json=event, headers=headers, timeout=10.0)
        print(json.dumps({
            "unsigned": unsigned.status_code,
            "accepted": accepted.status_code,
            "accepted_body": accepted.json(),
            "replayed": replayed.status_code,
        }, sort_keys=True))
        """
    )
    completed = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            ".env.stack",
            "exec",
            "-T",
            "applicant-service",
            "python",
            "-c",
            probe,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=45,
    )
    result = json.loads(completed.stdout.strip().splitlines()[-1])

    assert result["unsigned"] == 401
    assert result["accepted"] == 200
    assert result["replayed"] == 409
    assert result["accepted_body"]["success"] is True
    assert result["accepted_body"]["flows_triggered"] == 0
