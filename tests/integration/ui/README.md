# UI Contract Tests

These tests keep post-login console coverage in `marty-integration-tests` while still driving the real Marty UI in a browser.

## Scope

- Post-login organization-console entry and redirect behavior
- Sidebar navigation across the key release pages
- Read-only versus admin affordances for team, audit, and signing-key surfaces
- Screenshots, videos, and optional GIFs captured from the same browser runs

## Prerequisites

- Install Python extras: `pip install -e ".[dev,e2e]"`
- Install Chromium once: `python -m playwright install chromium`
- Have a local Marty UI checkout available.

The harness looks for the UI in this order:

1. `MARTY_UI_URL` if you already have a dev server running
2. `MARTY_UI_DIR` if you want the harness to start one for you
3. a sibling checkout at `../marty-ui/ui`

## Run

```bash
pytest tests/integration/ui/test_post_login_console_contract.py -v
```

Artifacts are written to `reports/ui-contracts/`. When `ffmpeg` is available on `PATH`, the recorded Playwright videos are also converted to GIFs.