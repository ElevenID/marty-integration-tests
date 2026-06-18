# Marty Integration Tests

Comprehensive integration test suite for the Marty credential ecosystem. This repository contains end-to-end tests that verify the interaction between all Marty services.

## Architecture

This repository consolidates integration testing for:
- **Gateway API** - Main entry point for all credential operations
- **Organization Service** - Organization and user management
- **Credential Template Service** - Credential schema management  
- **Issuance Service** - OpenID4VCI credential issuance
- **Presentation Policy Service** - Credential verification policies
- **Flow Service** - OpenID4VP verification flows
- **Trust Profile Service** - Trust framework configuration

## Prerequisites

- **Docker Desktop** (for running services)
- **Python 3.11+** (for running tests)
- **Walt.ID Community Stack** (for wallet integration tests)

## Quick Start

### 1. Start Services

```bash
# Start all services and dependencies
docker compose up -d

# Wait for services to be healthy
docker compose ps
```

### 2. Run Tests

```bash
# Install test dependencies
pip install -e ".[dev]"

# Run all integration tests
pytest tests/integration/

# Run specific test suite
pytest tests/integration/gateway/test_wallet_verification_flow.py -v

# Run with Walt.ID wallet tests
pytest -m wallet
```

## Test Structure

```
tests/
├── integration/
│   ├── gateway/              # Gateway API integration tests
│   │   ├── test_credential_issuance.py
│   │   ├── test_wallet_verification_flow.py
│   │   ├── test_credential_templates.py
│   │   └── helpers/          # Test helpers and clients
│   │       ├── gateway_client.py
│   │       ├── waltid_wallet_client.py
│   │       └── test_data.py
│   └── fixtures/             # Shared test fixtures
│       ├── conftest.py
│       └── wallet_fixtures.py
```

## Service Architecture

All services run in Docker containers with the following setup:

- **Database**: PostgreSQL 15 with automatic migrations
- **Gateway**: Port 8000 (main API entry point)
- **Walt.ID Wallet**: Port 7001 (for wallet integration tests)
- **Walt.ID Verifier**: Port 7003 (for verification tests)
- **Service Network**: `marty-test-network` (Docker bridge network)

## Configuration

Service configuration is managed through:
- `docker-compose.yml` - Service definitions and networking
- `config/` - Service-specific configuration files
- Environment variables (see `.env.example`)

## Running Specific Test Suites

### Credential Issuance Tests
```bash
pytest tests/integration/gateway/test_credential_issuance.py -v
```

### Wallet Integration Tests
```bash
# Requires Walt.ID services running
pytest -m wallet -v
```

### Verification Flow Tests
```bash
pytest tests/integration/gateway/test_wallet_verification_flow.py -v
```

### UI Contract Tests
```bash
# Install browser-test extras once
pip install -e ".[dev,e2e]"
python -m playwright install chromium

# Point at a sibling Marty UI checkout if it is not under ../marty-ui/ui
set MARTY_UI_DIR=..\marty-ui\ui

# Run the post-login org-console browser contracts
pytest tests/integration/ui/test_post_login_console_contract.py -v
```

These browser tests live in this repo but drive the real Marty UI from a local checkout. By default the harness looks for a sibling UI tree at `../marty-ui/ui`, starts a Vite dev server if one is not already running, and writes screenshots, videos, and optional GIFs to `reports/ui-contracts/`. GIF generation is automatic when `ffmpeg` is available on `PATH`.

## Development

### Adding New Tests

1. Create test file in appropriate directory
2. Use existing fixtures from `conftest.py`
3. Add test markers (`@pytest.mark.integration`, `@pytest.mark.wallet`)
4. Follow naming convention: `test_*.py`

### Test Fixtures

Common fixtures available:
- `gateway_client` - HTTP client for gateway API
- `test_organization` - Pre-configured test organization
- `test_wallet` - Walt.ID wallet instance
- `mdl_template` - mDL credential template
- `age_verification_policy` - Age verification policy

### Debugging Tests

```bash
# Run with verbose output and stop on first failure
pytest -xvs tests/integration/gateway/test_name.py

# Run specific test method
pytest tests/integration/gateway/test_file.py::TestClass::test_method -v

# Show logs from services
docker compose logs -f gateway
```

## CI/CD Integration

This repository is designed for CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run Integration Tests
  run: |
    docker compose up -d
    docker compose exec -T integration-tests pytest tests/integration/
    docker compose down -v
```

## Walt.ID Integration

Walt.ID wallet integration tests verify:
- OpenID4VCI credential issuance flows
- OpenID4VP credential presentation flows  
- DID creation and management
- Credential storage and retrieval

### Walt.ID Setup

Walt.ID services are automatically started with `docker compose up`. Configuration:
- Wallet API: http://localhost:7001
- Verifier API: http://localhost:7003

See `tests/integration/gateway/helpers/waltid_wallet_client.py` for wallet API client.

## Test Coverage

Run tests with coverage:
```bash
pytest --cov=tests --cov-report=html tests/integration/
open htmlcov/index.html
```

## Troubleshooting

### Services won't start
```bash
# Check service logs
docker compose logs

# Restart services
docker compose down -v
docker compose up -d
```

### Tests fail to connect
```bash
# Verify services are running
docker compose ps

# Check network connectivity
docker network inspect marty-test-network
```

### Database migration issues
```bash
# Run migrations manually
docker compose exec gateway python services/run_all_migrations.py
```

## Contributing

1. Write integration tests for new features
2. Ensure tests pass: `pytest tests/integration/`
3. Add documentation for new test suites
4. Follow existing test patterns and fixtures

### UI Contract Harness

The browser contract suite under `tests/integration/ui/` is intended for post-login console coverage that is too cross-cutting for component tests alone.

- Contracts are defined in YAML and executed with Playwright.
- The harness mocks auth, organization, RBAC, and page data at the browser boundary so flows stay deterministic.
- Demo artifacts are captured from the same runs used for verification.
- The suite currently assumes a local Marty UI checkout is available; it is not wired into this repo's GitHub Actions workflow because that workflow does not automatically have the sibling UI repository.

## License

MIT
