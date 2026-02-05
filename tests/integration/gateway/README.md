# Gateway Integration Tests

Integration tests that exclusively use the Gateway API to test end-to-end flows used by the UI for credential issuance, verification, and lifecycle management.

## Overview

These tests validate complete workflows through the gateway API:
- Organization setup and configuration
- Application-based credential issuance
- Direct credential issuance
- Stateless and async verification flows
- Complete credential lifecycle

## Prerequisites

### For Docker-based tests (recommended):
- Docker and Docker Compose installed
- Gateway and all backend services available (defined in `docker-compose.integration.yml`)

### For local tests:
- Gateway running at `http://localhost:8000` (or set `GATEWAY_URL` env var)
- All backend services running:
  - Auth Service (8001)
  - Organization Service (8002)
  - Credential Template Service (8003)
  - Trust Profile Service (8004)
  - Issuance Service (8005)
  - Presentation Policy Service (8009)
  - Flow Service (8011)
- PostgreSQL and Redis running

## Running Tests

### Run in Docker (Recommended)

```bash
# Build and run all services + tests
make integration-test

# Or using docker-compose directly
docker-compose -f docker-compose.integration.yml up --build --abort-on-container-exit
```

This will:
1. Start PostgreSQL and Redis
2. Start all backend microservices
3. Start the gateway
4. Wait for gateway to be healthy
5. Run the integration tests
6. Exit with test results

### Run Locally

```bash
# Make sure gateway is running at http://localhost:8000
make integration-test-local

# Or directly with pytest
pytest tests/integration/gateway/ -v -m integration
```

### Run Specific Tests

```bash
# Run only organization flow tests
pytest tests/integration/gateway/test_organization_flow.py -v

# Run specific test class
pytest tests/integration/gateway/test_application_flow.py::TestApplicationApprovalFlow -v

# Run specific test
pytest tests/integration/gateway/test_complete_lifecycle.py::TestCompleteCredentialLifecycle::test_full_mdl_lifecycle -v
```

## Test Structure

```
tests/integration/gateway/
├── __init__.py                          # Package init with overview
├── conftest.py                          # Shared fixtures
├── helpers/
│   ├── __init__.py
│   ├── gateway_client.py                # HTTP client for gateway API
│   ├── test_data.py                     # Test data builders
│   └── waltid_wallet_client.py          # Walt.id wallet client
├── test_organization_flow.py            # Organization setup tests
├── test_application_flow.py             # Application workflow tests
├── test_credential_issuance_flow.py     # Direct issuance tests
├── test_verification_flow.py            # Verification tests
├── test_complete_lifecycle.py           # End-to-end lifecycle tests
├── test_wallet_issuance_flow.py         # Wallet issuance tests (OpenID4VCI)
├── test_wallet_verification_flow.py     # Wallet verification tests (OpenID4VP)
└── wait-for-gateway.sh                  # Docker health check script
```

## Test Coverage

### Organization Setup (`test_organization_flow.py`)
- Create organizations
- Configure trust profiles
- Create credential templates (mDL, employee badge)
- Create presentation policies

### Application Flow (`test_application_flow.py`)
- Create application templates
- Submit applications
- Upload evidence
- Admin approval/rejection
- Verify credential issuance on approval

### Direct Issuance (`test_credential_issuance_flow.py`)
- Issue credentials directly (bypass application process)
- Multiple credential formats
- Bulk issuance
- Validation and error handling

### Verification Flow (`test_verification_flow.py`)
- Stateless presentation evaluation
- Async verification flows (wallet QR code)
- Multiple verification policies
- Concurrent verifications

### Complete Lifecycle (`test_complete_lifecycle.py`)
- End-to-end flow: setup → application → issuance → verification
- Multiple applicants
- Cross-organization isolation

### Wallet Integration Tests (`test_wallet_issuance_flow.py`, `test_wallet_verification_flow.py`)
- **Real wallet testing using Walt.id Wallet Kit**
- Complete OpenID4VCI credential issuance flows
- Complete OpenID4VP credential presentation flows
- Wallet DID management
- Credential storage and retrieval
- Multi-credential scenarios
- End-to-end lifecycle with real wallet

## Wallet Testing with Walt.id

The test suite includes integration with **Walt.id Wallet Kit**, a production-grade wallet implementation with REST API support. This enables automated testing of real OpenID4VCI and OpenID4VP flows.

### What is Walt.id Wallet Kit?

Walt.id Wallet Kit is an open-source, standards-compliant digital wallet that supports:
- **OpenID4VCI** (OpenID for Verifiable Credential Issuance)
- **OpenID4VP** (OpenID for Verifiable Presentation)
- W3C Verifiable Credentials
- SD-JWT (Selective Disclosure JWT)
- ISO mDL (Mobile Driver's License)
- DID management (did:key, did:web, did:jwk)
- REST API for headless/automated operation

### Why Use a Real Wallet for Testing?

Testing with a real wallet (vs. mocked wallet behavior) provides:
1. **Protocol Compliance**: Validates that our issuer/verifier correctly implements OpenID4VCI/VP
2. **Interoperability**: Ensures credentials work with real wallet implementations
3. **Realistic Flows**: Tests the actual user experience including offer acceptance, credential storage, and presentation
4. **Edge Cases**: Discovers issues that only appear with real wallet behavior
5. **CI/CD Ready**: Walt.id's REST API enables fully automated testing in pipelines

### Wallet Test Coverage

#### Issuance Tests (`test_wallet_issuance_flow.py`):
- Wallet creation and DID management
- Accepting credential offers via OpenID4VCI
- Storing multiple credentials in wallet
- Retrieving and inspecting credentials
- Credential deletion and cleanup
- Multi-credential scenarios

#### Verification Tests (`test_wallet_verification_flow.py`):
- Resolving presentation requests
- Presenting credentials via OpenID4VP
- Selective disclosure (only sharing required fields)
- Age verification flows
- Identity verification flows
- Multi-wallet concurrent verification

### Running Wallet Tests

Wallet tests require Walt.id services to be running. They are included in the Docker Compose configuration.

```bash
# Run all tests including wallet tests (Docker)
make integration-test

# Run only wallet tests
pytest tests/integration/gateway/test_wallet_issuance_flow.py -v
pytest tests/integration/gateway/test_wallet_verification_flow.py -v

# Run specific wallet test
pytest tests/integration/gateway/test_wallet_issuance_flow.py::TestCredentialIssuanceToWallet::test_issue_mdl_to_wallet -v
```

### Wallet Environment Variables

- `WALTID_WALLET_URL`: Walt.id Wallet Kit API URL (default: `http://localhost:7001`)

### Wallet Fixtures

Additional fixtures for wallet testing (in `conftest.py`):
- `waltid_wallet_client`: Configured Walt.id wallet client
- `test_wallet`: Pre-created wallet with DID for each test

Example usage:
```python
@pytest.mark.asyncio
@pytest.mark.integration
async def test_with_wallet(test_wallet, gateway_client, mdl_template):
    # Get wallet details
    wallet_id = test_wallet["wallet_id"]
    did = test_wallet["did"]
    wallet_client = test_wallet["client"]
    
    # Issue credential to wallet
    result = await gateway_client.issue_credential(
        organization_id=org_id,
        template_id=mdl_template["id"],
        holder_identifier=did,
        claims={"given_name": "Alice", ...}
    )
    
    # Wallet accepts the offer
    await wallet_client.accept_credential_offer(
        offer_url=result["offer_url"],
        did=did
    )
    
    # Verify credential is in wallet
    credentials = await wallet_client.list_credentials()
    assert len(credentials) > 0
```

### Walt.id Architecture in Tests

The Docker Compose setup includes:
- **waltid-core**: Core services (issuer/verifier capabilities)
- **waltid-wallet**: Wallet Kit REST API
- Persistent data volumes for wallet storage
- Health checks to ensure services are ready

These services automatically start with the integration test environment.

## Configuration

### Environment Variables

- `GATEWAY_URL`: Gateway base URL (default: `http://localhost:8000`)
- `WALTID_WALLET_URL`: Walt.id Wallet Kit API URL (default: `http://localhost:7001`)
- `PYTHONUNBUFFERED`: Set to `1` for real-time test output

### Fixtures

Key fixtures available in `conftest.py`:
- `gateway_client`: Configured HTTP client for gateway
- `test_organization`: Unique organization per test
- `test_trust_profile`: Trust profile for test org
- `mdl_template`: mDL credential template
- `employee_badge_template`: Employee badge template
- `age_verification_policy`: Age verification presentation policy
- `identity_verification_policy`: Identity verification policy
- `mdl_application_template`: Application template for mDL
- `waltid_wallet_client`: Walt.id wallet client instance
- `test_wallet`: Pre-created wallet with DID

## Test Data Builders

Located in `helpers/test_data.py`:

```python
# Organization
TestDataBuilder.organization(name="acme-corp")

# Credential Templates
TestDataBuilder.mdl_template(organization_id)
TestDataBuilder.employee_badge_template(organization_id)

# Claims
TestDataBuilder.mdl_claims(given_name="Alice", family_name="Smith")
TestDataBuilder.employee_badge_claims(given_name="Bob")

# Application Data
TestDataBuilder.mdl_application_data(given_name="Charlie")

# Policies
TestDataBuilder.presentation_policy_age_verification(organization_id, min_age=21)
TestDataBuilder.presentation_policy_identity_verification(organization_id)
TestDataBuilder.presentation_policy_employee_access(organization_id)

# Evidence
TestDataBuilder.portrait_evidence()
TestDataBuilder.identity_document_evidence()
```

## Cleanup

```bash
# Stop and remove all containers, networks, and volumes
make integration-test-clean

# Or manually
docker-compose -f docker-compose.integration.yml down -v
```

## CI/CD Integration

These tests are designed to run in CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run Integration Tests
  run: make integration-test
  
- name: Upload Test Results
  uses: actions/upload-artifact@v3
  with:
    name: test-results
    path: test-results/
```

## Troubleshooting

### Gateway not available
```bash
# Check if gateway is running
curl http://localhost:8000/health

# Check service health via gateway
curl http://localhost:8000/health/services

# View Docker logs
docker-compose -f docker-compose.integration.yml logs gateway
```

### Tests timeout
- Increase timeout in `wait-for-gateway.sh`
- Check Docker resource limits
- Verify all services are healthy

### Database errors
```bash
# Reset database
docker-compose -f docker-compose.integration.yml down -v
docker-compose -f docker-compose.integration.yml up -d postgres
```

## Development

### Adding New Tests

1. Create test file in `tests/integration/gateway/`
2. Import fixtures from `conftest.py`
3. Use `@pytest.mark.integration` decorator
4. Use `GatewayClient` for API calls
5. Use `TestDataBuilder` for test data

Example:
```python
@pytest.mark.asyncio
@pytest.mark.integration
async def test_my_flow(gateway_client, test_organization):
    # Your test here
    org_id = test_organization["id"]
    result = await gateway_client.create_something(org_id)
    assert result["status"] == "success"
```

### Running Individual Tests During Development

```bash
# Run with verbose output and show print statements
pytest tests/integration/gateway/test_organization_flow.py -v -s

# Stop on first failure
pytest tests/integration/gateway/ -x

# Run only failed tests from last run
pytest tests/integration/gateway/ --lf
```
