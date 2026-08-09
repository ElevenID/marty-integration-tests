"""Released-stack recovery checks for application-approved credential offers."""

from __future__ import annotations

import json
import subprocess
import textwrap
import time
import uuid

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.oss_stack]

_COMPOSE = ("docker", "compose", "--env-file", ".env.stack")
_ORGANIZATION_ID = "00000000-0000-0000-0000-000000000001"
_CREDENTIAL_TEMPLATE_ID = "50000000-0000-0000-0000-000000000040"


def _compose(
    *args: str,
    timeout: int = 45,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [*_COMPOSE, *args],
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
            "extension_uri": "urn:elevenid:test:released-stack-offer-recovery",
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


def _send_without_reading_response(application_id: str) -> None:
    """Send one complete signed request, then close before reading its response."""
    probe = textwrap.dedent(
        f"""
        import json
        import socket
        from datetime import UTC, datetime
        from pathlib import Path

        from common.application_event_auth import sign_application_event

        event = {{
            "event_type": "application.approved",
            "aggregate_id": "{application_id}",
            "aggregate_type": "application",
            "organization_id": "{_ORGANIZATION_ID}",
            "data": {{
                "applicant_id": "applicant-{application_id}",
                "credential_template_id": "{_CREDENTIAL_TEMPLATE_ID}",
                "claims": {{"email": "offer-recovery@example.invalid"}},
            }},
            "timestamp": datetime.now(UTC).isoformat(),
        }}
        headers = sign_application_event(event)
        Path("/tmp/application-offer-recovery.json").write_text(
            json.dumps({{"event": event, "headers": headers}}), encoding="utf-8"
        )
        body = json.dumps(event, separators=(",", ":")).encode()
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
        """
    )
    _compose(
        "exec",
        "-T",
        "applicant-service",
        "python",
        "-c",
        probe,
    )


def _durable_state(application_id: str) -> dict[str, object] | None:
    result = _psql(
        textwrap.dedent(
            """
            SELECT json_build_object(
                'receipt_count', COUNT(DISTINCT receipt.event_id_sha256),
                'instance_count', COUNT(DISTINCT instance.id),
                'artifact_count', COUNT(DISTINCT artifact.id),
                'transaction_count', COUNT(DISTINCT issuance_tx.id),
                'instance_id', MIN(instance.id),
                'artifact_id', MIN(artifact.id),
                'transaction_id', MIN(issuance_tx.id),
                'offer_sha256', MIN(encode(sha256(convert_to(
                    artifact.credential_offer_uri, 'UTF8')), 'hex')),
                'pre_auth_sha256', MIN(encode(sha256(convert_to(
                    issuance_tx.pre_auth_code, 'UTF8')), 'hex')),
                'planned_flows', MAX(json_array_length(receipt.flow_plan))
            )
            FROM flow_service.flow_application_event_receipts AS receipt
            LEFT JOIN flow_service.flow_instances AS instance
              ON instance.organization_id = receipt.organization_id
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
    state = json.loads(result)
    required_counts = ("receipt_count", "instance_count", "artifact_count", "transaction_count")
    if all(state.get(name) == 1 for name in required_counts) and state.get("planned_flows") == 1:
        return state
    return None


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
    probe = (
        "import httpx; "
        "response=httpx.get('http://flow-service:8011/health', timeout=2); "
        "response.raise_for_status()"
    )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            _compose(
                "exec",
                "-T",
                "applicant-service",
                "python",
                "-c",
                probe,
                timeout=10,
            )
            return
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            time.sleep(1)
    pytest.fail("flow service did not recover after restart")


def _retry_saved_event(*, mutate_claims: bool = False) -> dict[str, object]:
    probe = textwrap.dedent(
        f"""
        import hashlib
        import json
        from pathlib import Path

        import httpx
        from common.application_event_auth import sign_application_event

        saved = json.loads(Path("/tmp/application-offer-recovery.json").read_text(encoding="utf-8"))
        event = saved["event"]
        headers = saved["headers"]
        if {mutate_claims!r}:
            event["data"]["claims"]["email"] = "changed@example.invalid"
            headers = sign_application_event(event)
        response = httpx.post(
            "http://flow-service:8011/v1/flows/webhooks/application-approved",
            json=event,
            headers=headers,
            timeout=30,
        )
        body = response.json()
        if response.status_code == 200:
            offer = body["offers"][0]
            body = {{
                "flows_triggered": body["flows_triggered"],
                "instance_id": body["instance_ids"][0],
                "artifact_id": offer["artifact_id"],
                "transaction_id": offer["credential_offer_transaction_id"],
                "offer_sha256": hashlib.sha256(
                    offer["credential_offer_uri"].encode()
                ).hexdigest(),
                "pre_auth_sha256": hashlib.sha256(
                    offer["pre_authorized_code"].encode()
                ).hexdigest(),
            }}
        else:
            body = {{"detail": body.get("detail")}}
        print(json.dumps({{"status": response.status_code, "body": body}}, sort_keys=True))
        """
    )
    completed = _compose(
        "exec",
        "-T",
        "applicant-service",
        "python",
        "-c",
        probe,
    )
    return json.loads(completed.stdout.strip().splitlines()[-1])


def test_uncertain_application_offer_response_recovers_after_flow_restart() -> None:
    flow_id = str(uuid.uuid4())
    application_id = f"artifact-recovery-{uuid.uuid4()}"
    _install_disposable_application_flow(flow_id)

    _send_without_reading_response(application_id)
    before_restart = _wait_for_durable_state(application_id)

    _compose("restart", "flow-service", timeout=60)
    _wait_for_flow_service()

    recovered = _retry_saved_event()
    assert recovered["status"] == 200, recovered
    assert recovered["body"] == {
        "flows_triggered": 1,
        "instance_id": before_restart["instance_id"],
        "artifact_id": before_restart["artifact_id"],
        "transaction_id": before_restart["transaction_id"],
        "offer_sha256": before_restart["offer_sha256"],
        "pre_auth_sha256": before_restart["pre_auth_sha256"],
    }
    assert _wait_for_durable_state(application_id) == before_restart

    changed = _retry_saved_event(mutate_claims=True)
    assert changed["status"] == 409, changed
    assert changed["body"]["detail"]["error"] == "APPLICATION_OFFER_CONFLICT"
    assert _wait_for_durable_state(application_id) == before_restart
