"""Artifact-only checks for the Applicant -> Flow issuance-authority boundary."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from tests.oss_stack.application_event_probe import post_json, sign_application_event

pytestmark = [pytest.mark.integration, pytest.mark.oss_stack]


def test_application_approval_authentication_and_replay_inside_private_network() -> None:
    """Authenticate the wire protocol without importing either implementation."""
    event = {
        "event_type": "application.approved",
        "aggregate_id": f"artifact-probe-{uuid.uuid4()}",
        "aggregate_type": "application",
        "organization_id": str(uuid.uuid4()),
        "data": {"applicant_id": f"artifact-probe-{uuid.uuid4()}"},
        "timestamp": datetime.now(UTC).isoformat(),
    }
    endpoint = "http://flow-service:8011/v1/flows/webhooks/application-approved"
    unsigned = post_json(endpoint, event)
    headers = sign_application_event(event)
    accepted = post_json(endpoint, event, headers)
    replayed = post_json(endpoint, event, headers)

    assert unsigned["status"] == 401
    assert accepted["status"] == 200
    assert replayed["status"] == 409
    assert accepted["body"]["success"] is True
    assert accepted["body"]["flows_triggered"] == 0
