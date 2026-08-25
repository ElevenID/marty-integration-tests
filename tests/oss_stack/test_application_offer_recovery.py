"""Released-stack recovery checks for application-approved credential offers."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import textwrap
import time
import uuid
from datetime import UTC, datetime
from typing import Any, cast

import pytest

from tests.oss_stack.application_event_probe import (
    internal_url_is_healthy,
    post_json,
    send_without_reading_response,
    sign_application_event,
)
from tests.oss_stack.compose import stack_compose_command

pytestmark = [pytest.mark.integration, pytest.mark.oss_stack]

_ORGANIZATION_ID = "00000000-0000-0000-0000-000000000001"
_CREDENTIAL_TEMPLATE_ID = "50000000-0000-0000-0000-000000000040"
_DISPOSABLE_EXTENSION_URI = "urn:elevenid:test:released-stack-offer-recovery"


def _compose(
    *args: str,
    timeout: int = 45,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [*stack_compose_command(), *args],
        check=True,
        capture_output=True,
        input=input_text,
        text=True,
        timeout=timeout,
    )


def _psql(sql: str, *, variables: dict[str, str] | None = None) -> str:
    arguments = [
        "exec",
        "-T",
        "postgres",
        "psql",
        "-U",
        "marty",
        "-d",
        "marty_credentials",
        "-v",
        "ON_ERROR_STOP=1",
        "-At",
    ]
    for name, value in (variables or {}).items():
        arguments.extend(("--set", f"{name}={value}"))
    # psql performs variable interpolation while reading input, but ``-c``
    # sends its argument directly to the server and leaves :'name' literals.
    arguments.extend(("-f", "-"))
    completed = _compose(*arguments, input_text=sql)
    return completed.stdout.strip()


def _install_disposable_application_flow(flow_id: str) -> None:
    extension = json.dumps(
        {
            "extension_uri": _DISPOSABLE_EXTENSION_URI,
            "extension_version": "1.0.0",
            "extends_flow_type": "oid4vci_pre_authorized",
            "entry_step_id": "create_offer",
            "steps": [{"step_id": "create_offer", "action": "create_offer", "config": {}}],
            "transitions": [],
            "config": {},
        },
        separators=(",", ":"),
    )
    trigger = json.dumps(
        {
            "trigger_type": "WEBHOOK",
            "config": {"event_type": "APPLICATION_APPROVED"},
        },
        separators=(",", ":"),
    )
    _psql(
        textwrap.dedent(
            """
            INSERT INTO flow_service.flow_definitions (
                id, organization_id, name, description, status, flow_type,
                steps, transitions, start_step_id, credential_template_id,
                application_template_id, presentation_policy_id,
                delivery_destination_profile_id, deployment_profile_id,
                deployment_profile_ids, trust_profile_id, approval_strategy,
                hooks, trigger, extension, preconditions,
                default_timeout_seconds, max_retries, enable_resume, version,
                created_at, updated_at
            ) VALUES (
                :'flow_id', :'organization_id',
                'Released-stack application offer recovery',
                'Disposable integration-test flow', 'ACTIVE', 'custom',
                '[]'::json, '[]'::json, NULL, :'credential_template_id',
                NULL, NULL, NULL, NULL, '[]'::json, NULL, 'MANUAL',
                '{}'::json, :'trigger'::json, :'extension'::json, '[]'::json,
                3600, 3, TRUE, 1, NOW(), NOW()
            );
            """
        ),
        variables={
            "flow_id": flow_id,
            "organization_id": _ORGANIZATION_ID,
            "credential_template_id": _CREDENTIAL_TEMPLATE_ID,
            "trigger": trigger,
            "extension": extension,
        },
    )


def _deactivate_disposable_application_flows() -> None:
    _psql(
        textwrap.dedent(
            """
            UPDATE flow_service.flow_definitions
               SET status = 'ARCHIVED', updated_at = NOW()
             WHERE extension->>'extension_uri' = :'extension_uri'
               AND status <> 'ARCHIVED';
            """
        ),
        variables={"extension_uri": _DISPOSABLE_EXTENSION_URI},
    )


def _send_without_reading_response(
    application_id: str,
) -> tuple[dict[str, object], dict[str, str]]:
    """Send one signed request and return the exact language-neutral envelope."""
    event: dict[str, object] = {
        "event_type": "application.approved",
        "aggregate_id": application_id,
        "aggregate_type": "application",
        "organization_id": _ORGANIZATION_ID,
        "data": {
            "applicant_id": f"applicant-{application_id}",
            "credential_template_id": _CREDENTIAL_TEMPLATE_ID,
            "claims": {"email": "offer-recovery@example.invalid"},
        },
        "timestamp": datetime.now(UTC).isoformat(),
    }
    headers = sign_application_event(event)
    send_without_reading_response(event, headers)
    return event, headers


def _durable_state(application_id: str) -> dict[str, object] | None:
    result = _psql(
        textwrap.dedent(
            """
            SELECT json_build_object(
                'receipt_count', COUNT(DISTINCT receipt.event_id_sha256),
                'planned_flows', COALESCE(MAX(json_array_length(receipt.flow_plan)), 0),
                'flows', COALESCE(
                    json_agg(
                        json_build_object(
                            'flow_definition_id', plan.entry->>'flow_definition_id',
                            'instance_id', instance.id,
                            'artifact_id', artifact.id,
                            'transaction_id', issuance_tx.id,
                            'offer_sha256', encode(sha256(convert_to(
                                artifact.credential_offer_uri, 'UTF8')), 'hex'),
                            'pre_auth_sha256', encode(sha256(convert_to(
                                issuance_tx.pre_auth_code, 'UTF8')), 'hex')
                        ) ORDER BY plan.position
                    ) FILTER (WHERE plan.entry IS NOT NULL),
                    '[]'::json
                )
            )
            FROM flow_service.flow_application_event_receipts AS receipt
            LEFT JOIN LATERAL json_array_elements(receipt.flow_plan)
              WITH ORDINALITY AS plan(entry, position) ON TRUE
            LEFT JOIN flow_service.flow_instances AS instance
              ON instance.id = plan.entry->>'instance_id'
             AND instance.flow_definition_id = plan.entry->>'flow_definition_id'
             AND instance.organization_id = receipt.organization_id
             AND instance.context->>'application_id' = receipt.application_id
            LEFT JOIN flow_service.flow_instance_artifacts AS artifact
              ON artifact.flow_instance_id = instance.id
            LEFT JOIN issuance_service.issuance_transactions AS issuance_tx
              ON issuance_tx.id = artifact.issuance_transaction_id
            WHERE receipt.application_id = :'application_id'
              AND receipt.organization_id = :'organization_id';
            """
        ),
        variables={
            "application_id": application_id,
            "organization_id": _ORGANIZATION_ID,
        },
    )
    if not result:
        return None
    state = cast(dict[str, object], json.loads(result))
    planned_flows = state.get("planned_flows")
    flows = state.get("flows")
    if state.get("receipt_count") != 1 or not isinstance(planned_flows, int):
        return None
    if planned_flows < 1 or not isinstance(flows, list) or len(flows) != planned_flows:
        return None

    required_fields = (
        "flow_definition_id",
        "instance_id",
        "artifact_id",
        "transaction_id",
        "offer_sha256",
        "pre_auth_sha256",
    )
    if any(not all(flow.get(field) for field in required_fields) for flow in flows):
        return None
    for identity_field in (
        "flow_definition_id",
        "instance_id",
        "artifact_id",
        "transaction_id",
    ):
        if len({flow[identity_field] for flow in flows}) != planned_flows:
            return None
    return state


def _wait_for_durable_state(application_id: str, timeout: float = 60.0) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    last_state: dict[str, object] | None = None
    while time.monotonic() < deadline:
        last_state = _durable_state(application_id)
        if last_state is not None:
            return last_state
        time.sleep(0.5)
    pytest.fail(f"application offer did not become durable: {last_state}")


def _wait_for_flow_service(timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if internal_url_is_healthy("http://flow-service:8011/health"):
            return
        time.sleep(1)
    pytest.fail("flow service did not recover after restart")


def _retry_event(event: dict[str, object], headers: dict[str, str]) -> dict[str, Any]:
    result = post_json(
        "http://flow-service:8011/v1/flows/webhooks/application-approved",
        event,
        headers,
    )
    if result["status"] != 200:
        return {
            "status": result["status"],
            "body": {
                "error": result["body"].get("error"),
                "detail": result["body"].get("detail"),
            },
        }
    body = result["body"]
    return {
        "status": 200,
        "body": {
            "flows_triggered": body["flows_triggered"],
            "flows": [
                {
                    "flow_definition_id": offer["flow_definition_id"],
                    "instance_id": offer["flow_instance_id"],
                    "artifact_id": offer["artifact_id"],
                    "transaction_id": offer["credential_offer_transaction_id"],
                    "offer_sha256": hashlib.sha256(offer["credential_offer_uri"].encode()).hexdigest(),
                    "pre_auth_sha256": hashlib.sha256(offer["pre_authorized_code"].encode()).hexdigest(),
                }
                for offer in body["offers"]
            ],
        },
    }


def test_uncertain_application_offer_response_recovers_after_flow_restart() -> None:
    flow_id = str(uuid.uuid4())
    application_id = f"artifact-recovery-{uuid.uuid4()}"
    _deactivate_disposable_application_flows()
    _install_disposable_application_flow(flow_id)
    try:
        event, headers = _send_without_reading_response(application_id)
        before_restart = _wait_for_durable_state(application_id)

        _compose("restart", "flow-service", timeout=60)
        _wait_for_flow_service()

        recovered = _retry_event(event, headers)
        assert recovered["status"] == 200, recovered
        assert recovered["body"] == {
            "flows_triggered": before_restart["planned_flows"],
            "flows": before_restart["flows"],
        }
        assert _wait_for_durable_state(application_id) == before_restart

        changed_event = copy.deepcopy(event)
        changed_data = changed_event["data"]
        assert isinstance(changed_data, dict)
        changed_claims = changed_data["claims"]
        assert isinstance(changed_claims, dict)
        changed_claims["email"] = "changed@example.invalid"
        changed = _retry_event(changed_event, sign_application_event(changed_event))
        assert changed["status"] == 409, changed
        assert changed["body"]["error"] == "APPLICATION_OFFER_CONFLICT"
        assert _wait_for_durable_state(application_id) == before_restart
    finally:
        _deactivate_disposable_application_flows()
