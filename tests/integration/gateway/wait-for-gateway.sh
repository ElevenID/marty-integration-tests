#!/bin/bash
# Wait for gateway to be healthy before running tests

set -e

GATEWAY_URL="${GATEWAY_URL:-http://gateway:8000}"
MAX_TRIES=60
WAIT_SECONDS=2

echo "Waiting for gateway at $GATEWAY_URL to be ready..."

for i in $(seq 1 $MAX_TRIES); do
    if curl -sf "$GATEWAY_URL/health" > /dev/null 2>&1; then
        echo "✓ Gateway is ready!"
        exit 0
    fi
    echo "  Attempt $i/$MAX_TRIES: Gateway not ready yet, waiting ${WAIT_SECONDS}s..."
    sleep $WAIT_SECONDS
done

echo "✗ Gateway failed to become ready after $MAX_TRIES attempts"
exit 1
