"""Regression tests for the owned DIDComm test-agent fixture."""

import base64
import json

from tests.integration.gateway.test_didcomm_v2_delivery import (
    _make_did_peer_2_with_service,
)


def test_peer_did_uses_x25519_and_full_didcomm_service() -> None:
    endpoint = "https://holder.example/didcomm"

    holder_did, private_key = _make_did_peer_2_with_service(endpoint)

    assert len(private_key) == 32
    assert holder_did.startswith("did:peer:2.Ez6LS")

    service_segment = holder_did.split(".S", maxsplit=1)[1]
    padding = "=" * (-len(service_segment) % 4)
    service = json.loads(base64.urlsafe_b64decode(service_segment + padding))
    assert service == {
        "id": "#didcomm-1",
        "type": "DIDCommMessaging",
        "serviceEndpoint": endpoint,
    }
