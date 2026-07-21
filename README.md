# Marty OSS Integration Tests

This repository verifies the public Marty credential stack using only released, immutable artifacts. It does not check out component source, access private repositories, or require commerce services.

## What it tests

- Gateway and service health
- Organization and credential-template operations
- OpenID4VCI issuance and OpenID4VP presentation
- Trust, policy, flow, deployment, and revocation behavior
- Headless-wallet and interoperability flows
- Browser contracts against the released Marty UI
- Upgrade and rollback manifest compatibility

Billing, Square, subscription plans, and product-catalog tests live in the private commerce overlay and are intentionally excluded.

## Prerequisites

- Docker with Compose v2
- Python 3.11+
- An attested `marty.stack/v1` manifest from a `marty-ui` release
- Optional: the published `@elevenid/marty-cli` package for CLI scenarios

## Run the public stack

Download `stack-manifest.json` and its signature/attestation from a Marty UI release, verify it, then run:

```bash
pip install -e ".[dev]"
make start STACK_MANIFEST=/path/to/stack-manifest.json
pytest tests/integration/ -v
make stop
```

`scripts/render_stack_env.py` rejects commerce markers, mutable image tags, missing digests, duplicate image roles, and unsupported manifest schemas. The generated `.env.stack` contains digest-pinned GHCR and base-image references and is never committed.

To validate upgrade and rollback inputs before running the suite:

```bash
python scripts/render_stack_env.py \
  --manifest candidate-stack-manifest.json \
  --previous-manifest previous-stack-manifest.json
```

## UI contracts

The default Compose stack exposes the released UI at `http://127.0.0.1:23000`. To use another running release artifact, set `MARTY_UI_URL`.

```bash
pip install -e ".[dev,e2e]"
python -m playwright install chromium
pytest tests/integration/ui/test_post_login_console_contract.py -v
```

Screenshots, videos, and optional GIFs are written to `reports/ui-contracts/`.

## CLI tests

Install the released CLI package globally, or point to an equivalent installed executable:

```bash
npm install --global @elevenid/marty-cli
export MARTY_CLI_BIN=marty  # optional when already on PATH
pytest tests/integration/gateway/test_cli_wallet_flows.py -v
```

The harness creates an isolated temporary config directory and never reads the developer's Marty credentials.

## Conformance

Protocol conformance tests in this repository exercise the running public stack. Crate-level cryptographic and mDoc conformance remains in `marty-core`, where it is tested by that component's own CI.

```bash
make conformance-local
```

The fast regression suite is strict: a failure fails the command. The actual
OpenID Foundation runner is pinned separately and runs against the same
gateway-facing production-path deployment. See
[conformance/README.md](conformance/README.md) for the official issuer plan,
evidence handling, certification switch, and the single monthly draft-PR
review of every official suite pin.

## Configuration

- `docker-compose.yml` defines the public service topology.
- `config/base-images.json` pins PostgreSQL and Redis by digest.
- `.env.stack` is generated from the signed stack manifest.
- Environment-specific non-secret overrides may be supplied by the caller.

Public CI must use standard GitHub-hosted runners and must not receive repository secrets for pull requests from forks.

## Contributing

Add tests under `tests/integration/`, reuse existing fixtures, and mark optional wallet or interoperability suites with their existing pytest markers. New public tests must remain runnable without private checkouts, commerce services, customer data, or organization credentials.

See `CONTRIBUTING.md`, `SECURITY.md`, and `SUPPORT.md` for project policies.

## License

MIT
