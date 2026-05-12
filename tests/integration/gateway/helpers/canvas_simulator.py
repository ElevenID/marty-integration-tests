"""Helpers for simulating signed Canvas credential events in gateway tests."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from typing import Any

import httpx


class CanvasSimulator:
    """Small helper that behaves like a signed Canvas event sender."""

    def __init__(
        self,
        *,
        base_url: str | None = None,
        shared_secret: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        self.base_url = base_url or os.getenv("GATEWAY_URL", "http://localhost:8000")
        self.shared_secret = shared_secret or os.getenv("CANVAS_CREDENTIALS_SHARED_SECRET", "")
        self.client = httpx.AsyncClient(base_url=self.base_url, timeout=timeout)

    async def close(self) -> None:
        await self.client.aclose()

    def build_completion_event(
        self,
        *,
        event_id: str,
        canvas_account_id: str,
        organization_id: str | None = None,
        credential_template_id: str | None = None,
        overrides: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "canvas_event_id": event_id,
            "canvas_account_id": canvas_account_id,
            "canvas_course_id": "course-101",
            "canvas_course_name": "Foundations of Portable Credentials",
            "canvas_enrollment_id": "enrollment-202",
            "canvas_user_id": "user-303",
            "learner_email": "student@example.edu",
            "learner_given_name": "Student",
            "learner_family_name": "Example",
            "achievement_name": "Canvas Course Completion",
            "achievement_description": "Completed the portable trust module.",
            "completion_at": "2026-05-07T14:00:00Z",
        }
        if organization_id:
            payload["organization_id"] = organization_id
        if credential_template_id:
            payload["credential_template_id"] = credential_template_id
        if overrides:
            payload.update(overrides)
        return payload

    def sign_payload(self, raw_body: bytes, *, timestamp: str) -> str:
        digest = hmac.new(
            self.shared_secret.encode("utf-8"),
            f"{timestamp}.".encode("utf-8") + raw_body,
            hashlib.sha256,
        ).hexdigest()
        return f"sha256={digest}"

    def signed_request_parts(
        self,
        payload: dict[str, Any],
        *,
        timestamp: str | None = None,
        signature_override: str | None = None,
    ) -> tuple[bytes, dict[str, str]]:
        raw_body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        header_timestamp = timestamp or str(int(time.time()))
        signature = signature_override or self.sign_payload(raw_body, timestamp=header_timestamp)
        headers = {
            "Content-Type": "application/json",
            "X-Canvas-Timestamp": header_timestamp,
            "X-Canvas-Signature-256": signature,
        }
        return raw_body, headers

    async def post_credential_event(
        self,
        payload: dict[str, Any],
        *,
        timestamp: str | None = None,
        signature_override: str | None = None,
    ) -> httpx.Response:
        raw_body, headers = self.signed_request_parts(
            payload,
            timestamp=timestamp,
            signature_override=signature_override,
        )
        return await self.client.post(
            "/v1/integrations/canvas/credential-events",
            content=raw_body,
            headers=headers,
        )
