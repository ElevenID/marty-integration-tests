# Wallet Integration Tests

## Overview

Wallet integration tests verify the complete OpenID4VCI credential issuance and OpenID4VP presentation flows using a real Walt.id wallet instance.

## Requirements

### Services Required

1. **Gateway API** - `http://localhost:8000`
2. **Walt.id Wallet** - `http://localhost:7001`
3. **Proper Network Configuration** - Credential offer URIs must be resolvable by the wallet

### Configuration Issues

⚠️ **Known Issue**: Wallet tests currently fail due to network configuration:

- Gateway generates credential offer URIs like: `openid-credential-offer://?credential_offer_uri=https://api.marty.dev/v1/issuance/offers/...`
- Walt.id wallet (on localhost:7001) cannot resolve `api.marty.dev` URLs
- This causes HTTP 400 errors when the wallet tries to fetch the offer JSON

## Running Wallet Tests

### Skip Wallet Tests (Default)

By default, wallet tests are skipped:

```bash
pytest tests/integration/gateway/
# Wallet tests will be skipped automatically
```

### Enable Wallet Tests

To run wallet tests, you must:

1. **Set environment variable**:
   ```bash
   export RUN_WALLET_TESTS=true
   ```

2. **Configure Gateway to use localhost URLs** (required fix):
   ```bash
   # Set in Gateway service environment
   export ISSUER_BASE_URL=http://localhost:8000
   export STATUS_LIST_BASE_URL=http://localhost:8000
   ```

3. **Start Walt.id wallet**:
   ```bash
   # Using Docker
   docker run -p 7001:7001 waltid/wallet-api:latest
   
   # Or using docker-compose (if available)
   docker-compose up wallet
   ```

4. **Run tests**:
   ```bash
   RUN_WALLET_TESTS=true pytest tests/integration/gateway/test_wallet_*.py -v
   ```

## Test Files

- `test_wallet_issuance_flow.py` - Credential issuance to wallet
- `test_wallet_verification_flow.py` - Credential presentation from wallet

## Wallet Test Markers

Wallet tests are marked with `@pytest.mark.wallet`:

```python
@pytest.mark.integration
@pytest.mark.wallet
@pytest.mark.asyncio
class TestCredentialIssuanceToWallet:
    ...
```

## Troubleshooting

### Error: `Client error '400 Bad Request' for url 'http://localhost:7001/wallet-api/wallet/.../exchange/useOfferRequest'`

**Cause**: Walt.id wallet cannot fetch the credential offer from the Gateway's configured URL.

**Solutions**:

1. **Short-term**: Configure Gateway to use `http://localhost:8000` for `ISSUER_BASE_URL`
2. **Medium-term**: Set up local DNS to resolve `api.marty.dev` to localhost
3. **Long-term**: Use inline credential offers instead of offer-by-reference in tests

### Error: `Gateway not available at http://localhost:8000`

**Solution**: Start the Gateway service:
```bash
cd marty-ui/services/gateway
python main.py
```

### Error: Walt.id wallet not responding

**Solution**: Verify Walt.id wallet is running:
```bash
curl http://localhost:7001/wallet-api
```

## Alternative: Mock Wallet Responses

If you cannot configure proper networking, consider mocking the wallet responses for testing:

```python
@pytest.fixture
def mock_wallet_client(monkeypatch):
    """Mock wallet client for testing without network dependencies"""
    # Mock implementation here
    pass
```

## Related Documentation

- [OpenID4VCI Specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [Walt.id Documentation](https://docs.walt.id/)
- [Gateway API Documentation](../../README.md)
