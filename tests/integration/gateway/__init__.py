"""Gateway API Integration Tests

Integration tests that exclusively use the Gateway API to test end-to-end
flows that the UI uses for credential issuance, verification, and lifecycle management.

These tests require:
- Gateway running (http://localhost:8000 or GATEWAY_URL env var)
- All backend services running (auth, organization, issuance, etc.)
- Redis for rate limiting
- PostgreSQL for data persistence

Run with: pytest tests/integration/gateway/ -v -m integration
Run in Docker: make integration-test
"""
