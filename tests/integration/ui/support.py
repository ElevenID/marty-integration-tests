from __future__ import annotations

import json
import shutil
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml
from playwright.sync_api import Page, Request, Route, sync_playwright

ORG_ID = "org-console-001"
ORG_NAME = "Acme Transit"

TEAM_MEMBERS = [
    {
        "id": "member_1",
        "name": "Alex Admin",
        "email": "alex@example.com",
        "role": "admin",
        "joined_at": "2026-04-01T00:00:00Z",
    }
]

PENDING_INVITES = [
    {
        "id": "invite_1",
        "email": "pending@example.com",
        "role": "developer",
        "created_at": "2026-04-01T00:00:00Z",
        "expires_at": "2026-04-08T00:00:00Z",
    }
]

AVAILABLE_ROLES = {
    "roles": [
        {
            "id": "role_admin",
            "name": "admin",
            "display_name": "Admin",
            "description": "Admin access",
            "is_system": True,
        },
        {
            "id": "role_operator",
            "name": "operator",
            "display_name": "Operator",
            "description": "Operational access",
            "is_system": True,
        },
    ]
}

NOTIFICATIONS_PAYLOAD = {
    "notifications": [
        {
            "id": "notif_1",
            "title": "Credential issued",
            "message": "A new credential was issued.",
            "severity": "info",
            "read": False,
            "created_at": "2026-04-11T08:00:00Z",
        },
        {
            "id": "notif_2",
            "title": "Team invite accepted",
            "message": "A teammate joined the organization.",
            "severity": "success",
            "read": True,
            "created_at": "2026-04-11T07:00:00Z",
        },
    ],
    "total": 2,
}

SIGNING_KEYS_PAYLOAD = {
    "keys": [
        {
            "id": "key_1",
            "name": "Issuer Key",
            "algorithm": "ES256",
            "status": "active",
            "expiry_date": "2030-01-01T00:00:00Z",
            "created_at": "2026-01-01T00:00:00Z",
        }
    ]
}

KEY_MANAGEMENT_CONFIG = {
    "hsm_enabled": False,
    "hsm_settings": {},
    "vault_enabled": False,
    "vault_settings": {},
}


def load_contract(contract_path: Path) -> dict[str, Any]:
    return yaml.safe_load(contract_path.read_text(encoding="utf-8"))


def get_scenario(contract: dict[str, Any], name: str) -> dict[str, Any]:
    for scenario in contract.get("scenarios", []):
        if scenario.get("name") == name:
            return scenario
    raise KeyError(f"Unknown UI contract scenario: {name}")


def slugify(value: str) -> str:
    slug = "".join(ch.lower() if ch.isalnum() else "-" for ch in value)
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-") or "scenario"


def install_browser_test_doubles(page: Page) -> None:
    page.add_init_script(
        """
        class FakeEventSource {
          constructor(url) {
            this.url = url;
            this.readyState = 1;
            setTimeout(() => {
              if (typeof this.onopen === 'function') {
                this.onopen({ type: 'open', url });
              }
            }, 0);
          }
          addEventListener() {}
          close() {
            this.readyState = 2;
          }
        }
        window.EventSource = FakeEventSource;
        """
    )


def maybe_generate_gif(video_path: Path, gif_path: Path) -> bool:
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg or not video_path.exists():
        return False

    import subprocess

    command = [
        ffmpeg,
        "-y",
        "-i",
        str(video_path),
        "-vf",
        "fps=10,scale=1280:-1:flags=lanczos",
        str(gif_path),
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    return completed.returncode == 0 and gif_path.exists()


@contextmanager
def managed_ui_page(artifact_dir: Path):
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(
            ignore_https_errors=True,
            viewport={"width": 1440, "height": 900},
            record_video_dir=str(artifact_dir),
        )
        page = context.new_page()
        install_browser_test_doubles(page)

        try:
            yield page
        finally:
            video = page.video

            if not page.is_closed():
                try:
                    page.screenshot(path=str(artifact_dir / "final.png"), full_page=True)
                except Exception:
                    pass

            context.close()

            if video:
                try:
                    video_path = Path(video.path())
                    stable_video_path = artifact_dir / "session.webm"
                    if video_path.exists() and video_path.resolve() != stable_video_path.resolve():
                        stable_video_path.write_bytes(video_path.read_bytes())
                    elif video_path.exists():
                        stable_video_path = video_path
                    maybe_generate_gif(stable_video_path, artifact_dir / "session.gif")
                except Exception:
                    pass

            browser.close()


def _recent_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _build_persona(persona_name: str) -> dict[str, Any]:
    if persona_name == "anonymous":
        return {
            "authenticated": False,
            "user": None,
            "permissions": [],
            "roles": [],
        }

    if persona_name == "org_admin":
        return {
            "authenticated": True,
            "user": {
                "user_id": "user_admin",
                "name": "Alice Admin",
                "email": "alice.admin@example.com",
                "given_name": "Alice",
                "family_name": "Admin",
                "roles": ["vendor"],
                "organization_id": ORG_ID,
                "organization_name": ORG_NAME,
                "capabilities": ["org:view", "org:manage", "org:issue"],
            },
            "permissions": [
                "team:view",
                "team:invite",
                "team:manage",
                "notification:view",
                "notification:send",
                "audit:view",
                "audit:export",
                "signing-key:create",
                "signing-key:delete",
            ],
            "roles": [
                {
                    "id": "role_admin",
                    "name": "admin",
                    "display_name": "Admin",
                }
            ],
        }

    if persona_name == "org_operator":
        return {
            "authenticated": True,
            "user": {
                "user_id": "user_operator",
                "name": "Owen Operator",
                "email": "owen.operator@example.com",
                "given_name": "Owen",
                "family_name": "Operator",
                "roles": ["operator"],
                "organization_id": ORG_ID,
                "organization_name": ORG_NAME,
                "capabilities": ["org:view"],
            },
            "permissions": [
                "team:view",
                "notification:view",
                "audit:view",
            ],
            "roles": [
                {
                    "id": "role_operator",
                    "name": "operator",
                    "display_name": "Operator",
                }
            ],
        }

    raise KeyError(f"Unsupported UI contract persona: {persona_name}")


def _fulfill_json(route: Route, payload: Any, status: int = 200) -> None:
    route.fulfill(
        status=status,
        content_type="application/json",
        body=json.dumps(payload),
    )


def install_console_backend_mock(page: Page, persona_name: str) -> None:
    persona = _build_persona(persona_name)
    recent_timestamp = _recent_timestamp()

    audit_events = {
        "events": [
            {
                "id": "evt_1",
                "timestamp": recent_timestamp,
                "category": "team",
                "action": "member.invited",
                "actor": "alex@example.com",
                "resource": "Team workspace",
                "severity": "warning",
                "details": "Invite invite_1 pending",
                "ipAddress": "127.0.0.1",
            }
        ],
        "total": 1,
    }

    def handle_route(route: Route, request: Request) -> None:
        path = urlparse(request.url).path

        if path in {"/v1/auth/login", "/v1/auth/register"}:
            route.fulfill(
                status=200,
                content_type="text/html",
                body=(
                    "<!doctype html>"
                    "<html><body>"
                    '<main data-testid="mock.auth.redirect">Mock auth redirect</main>'
                    "</body></html>"
                ),
            )
            return

        if path == "/v1/auth/me":
            _fulfill_json(
                route,
                {
                    "authenticated": persona["authenticated"],
                    "user": persona["user"],
                },
            )
            return

        if path == "/v1/organizations/mine":
            organizations = []
            if persona["authenticated"]:
                organizations = [{"id": ORG_ID, "name": ORG_NAME}]
            _fulfill_json(route, organizations)
            return

        if path == "/v1/me/preferences":
            if request.method.upper() == "GET":
                _fulfill_json(
                    route,
                    {
                        "last_view_mode": "org" if persona["authenticated"] else "applicant",
                        "last_active_org_id": ORG_ID if persona["authenticated"] else None,
                    },
                )
                return

            if request.method.upper() == "PUT":
                _fulfill_json(route, json.loads(request.post_data or "{}"))
                return

        if path == f"/v1/organizations/{ORG_ID}/members/me/permissions":
            _fulfill_json(
                route,
                {
                    "permissions": persona["permissions"],
                    "roles": persona["roles"],
                },
            )
            return

        if path == "/v1/notifications/unread/count":
            _fulfill_json(route, {"unread_count": 1})
            return

        if path == "/v1/notifications":
            _fulfill_json(route, NOTIFICATIONS_PAYLOAD)
            return

        if path == "/v1/notifications/rules":
            _fulfill_json(
                route,
                {
                    "rules": [
                        {
                            "id": "rule_1",
                            "name": "Failed sign-ins",
                            "event_type": "authentication.failed",
                            "severity": "error",
                            "enabled": True,
                        }
                    ]
                },
            )
            return

        if path == "/v1/notifications/preferences":
            _fulfill_json(
                route,
                {
                    "email_notifications": True,
                    "push_notifications": False,
                    "digest_enabled": False,
                    "digest_frequency": "daily",
                },
            )
            return

        if path == f"/v1/organizations/{ORG_ID}/members":
            _fulfill_json(route, TEAM_MEMBERS)
            return

        if path == f"/v1/organizations/{ORG_ID}/invites":
            _fulfill_json(route, PENDING_INVITES)
            return

        if path == f"/v1/organizations/{ORG_ID}/roles":
            _fulfill_json(route, AVAILABLE_ROLES)
            return

        if path == "/v1/trust-profiles":
            _fulfill_json(route, [])
            return

        if path == "/v1/credential-templates":
            _fulfill_json(route, [])
            return

        if path == "/v1/presentation-policies":
            _fulfill_json(route, [])
            return

        if path == "/v1/deployment-profiles":
            _fulfill_json(route, [])
            return

        if path == "/v1/flows":
            _fulfill_json(route, [])
            return

        if path == f"/v1/organizations/{ORG_ID}/api-keys":
            _fulfill_json(route, {"keys": []})
            return

        if path == "/health":
            _fulfill_json(
                route,
                {
                    "gateway": "healthy",
                    "issuer": "healthy",
                    "verifier": "healthy",
                },
            )
            return

        if path == f"/v1/organizations/{ORG_ID}/team/snapshot":
            _fulfill_json(
                route,
                {
                    "members": TEAM_MEMBERS,
                    "pending_invites": PENDING_INVITES,
                    "role_distribution": {"admin": 1, "developer": 0, "operator": 1},
                },
            )
            return

        if path == f"/v1/organizations/{ORG_ID}/runtime/status":
            _fulfill_json(
                route,
                {
                    "can_issue": False,
                    "can_verify": False,
                    "issuer_keys_valid": True,
                    "issuer_active": False,
                    "deployment_active": False,
                    "policy_reachable": False,
                    "last_issuance_timestamp": None,
                    "last_verification_timestamp": None,
                },
            )
            return

        if path == f"/v1/organizations/{ORG_ID}/audit-events":
            _fulfill_json(route, audit_events)
            return

        if path == f"/v1/organizations/{ORG_ID}/environment":
            _fulfill_json(route, {"environment": "development"})
            return

        if path == f"/v1/organizations/{ORG_ID}/lifecycle":
            _fulfill_json(
                route,
                {
                    "created_at": "2026-01-01T00:00:00Z",
                    "compliance_profiles": [],
                    "plan_tier": "free",
                    "plan_expires_at": None,
                    "commercial_offer": "Developer Sandbox",
                    "data_retention_mode": "standard",
                    "audit_retention_days": 90,
                    "pilot_retention": None,
                },
            )
            return

        if path == f"/v1/organizations/{ORG_ID}/lifecycle/purge":
            _fulfill_json(
                route,
                {
                    "organization_id": ORG_ID,
                    "retention_days": 30,
                    "cutoff_at": "2026-01-01T00:00:00Z",
                    "purged_at": "2026-01-01T00:00:00Z",
                    "next_expiry_at": None,
                    "oldest_retained_record_at": None,
                    "tracked_scope": [
                        "applications",
                        "submitted_evidence",
                        "issuance_transactions",
                        "issued_credentials",
                        "authorization_sessions",
                        "issuance_events",
                    ],
                    "purged_records": {
                        "issuance_transactions": 0,
                        "applications": 0,
                        "authorization_sessions": 0,
                        "issuance_events": 0,
                        "issued_credentials": 0,
                        "total": 0,
                    },
                },
            )
            return

        if path == f"/v1/organizations/{ORG_ID}/dashboard/applicant-stats":
            _fulfill_json(route, {"pending": 0, "approved": 0, "issuable": 0, "total": 0})
            return

        if path == f"/v1/organizations/{ORG_ID}/integration-info":
            _fulfill_json(
                route,
                {
                    "org_id": ORG_ID,
                    "base_url": "http://127.0.0.1:8000",
                    "example_request": f'curl -X GET "http://127.0.0.1:8000/v1/organizations/{ORG_ID}"',
                },
            )
            return

        if path == "/api/issuance/analytics/summary":
            _fulfill_json(route, {"active_offers": 0, "total_scans": 0, "success_rate": 100, "total_offers": 0})
            return

        if path == "/v1/signing-keys":
            _fulfill_json(route, SIGNING_KEYS_PAYLOAD)
            return

        if path == "/v1/signing-keys/config":
            _fulfill_json(route, KEY_MANAGEMENT_CONFIG)
            return

        if path.startswith("/v1/") or path.startswith("/api/") or path == "/health":
            _fulfill_json(route, {"detail": f"Unhandled UI contract mock for {request.method} {path}"}, status=404)
            return

        route.continue_()

    page.route("**/*", handle_route)