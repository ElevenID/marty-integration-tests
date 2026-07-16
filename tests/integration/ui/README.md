# UI Contract Tests

These tests drive the released Marty UI image selected by an attested stack manifest.

## Scope

- Post-login organization-console entry and redirect behavior
- Sidebar navigation across the key release pages
- Read-only versus admin affordances for team, audit, and signing-key surfaces
- Screenshots, videos, and optional GIFs captured from the same browser runs

## Prerequisites

- Install Python extras: `pip install -e ".[dev,e2e]"`
- Install Chromium once: `python -m playwright install chromium`
- Start the immutable stack with `make start`, or set `MARTY_UI_URL` to a running released UI (default: `http://127.0.0.1:23000`).

## Run

```bash
pytest tests/integration/ui/test_post_login_console_contract.py -v
```

Artifacts are written to `reports/ui-contracts/`. When `ffmpeg` is available on `PATH`, the recorded Playwright videos are also converted to GIFs.
