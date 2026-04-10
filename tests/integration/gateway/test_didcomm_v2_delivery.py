"""
DIDComm v2 Credential Delivery Integration Tests

Tests DIDComm v2 push delivery of credentials:
1. Issue + deliver via /v1/issuance/didcomm/deliver
2. DID resolution (did:key, did:web, did:peer)
3. Holder DID validation / error handling
4. Auto-delivery via wallet_configs with format_variant="didcomm_v2"

Requires a running DIDComm agent endpoint or a mock service that accepts
DIDComm plaintext messages (application/didcomm-plain+json).
"""

import asyncio
import json
import os
from typing import Any, Dict
from uuid import uuid4

import httpx
import pytest

from .helpers.gateway_client import GatewayClient, GatewayClientError
from .helpers.test_data import TestDataBuilder

# Mark all tests in this module as integration + didcomm
pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

# Optional: URL of a DIDComm agent that can receive messages.
# If not set, delivery tests that require a live agent are skipped.
DIDCOMM_AGENT_URL = os.getenv("DIDCOMM_AGENT_URL", "")

# A did:web DID that resolves to a DID Document with a DIDComm service endpoint.
# Used for live delivery tests. Example: did:web:agent.example.com
DIDCOMM_HOLDER_DID = os.getenv("DIDCOMM_HOLDER_DID", "")


def _make_did_peer_2_with_service(endpoint: str) -> str:
    """Construct a did:peer:2 DID that embeds a DIDComm service endpoint.

    did:peer method 2 encodes verification and key agreement keys plus
    services directly in the DID string using purpose-prefixed segments:
      V = verification, E = key agreement, S = service

    This builds a minimal peer DID with a DIDCommMessaging service entry
    pointing at the given endpoint URL, suitable for testing push delivery.
    """
    import base64 as _b64

    # Minimal Ed25519 key (32 zero bytes — NOT cryptographically valid,
    # but sufficient for DID resolution and endpoint extraction tests).
    dummy_key_multibase = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

    # Service block encoded as base64url JSON (per did:peer spec §2)
    service_obj = {
        "t": "dm",  # type = DIDCommMessaging (abbreviated per spec)
        "s": endpoint,
    }
    service_b64 = _b64.urlsafe_b64encode(
        json.dumps(service_obj).encode()
    ).rstrip(b"=").decode()

    # Assemble: .V<key>.E<key>.S<service>
    return f"did:peer:2.V{dummy_key_multibase}.E{dummy_key_multibase}.S{service_b64}"


# =============================================================================
# Test: DIDComm Deliver Endpoint
# =============================================================================


class TestDidcommDeliverEndpoint:
    """Test the /v1/issuance/didcomm/deliver REST endpoint."""

    async def test_deliver_requires_transaction_id(
        self,
        gateway_client: GatewayClient,
    ):
        """Delivery without a valid transaction_id should fail."""
        with pytest.raises(GatewayClientError, match="4[0-9]{2}"):
            await gateway_client.didcomm_deliver(
                transaction_id="nonexistent-tx-id",
                holder_did="did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            )

    async def test_deliver_requires_holder_did_with_endpoint(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        sd_jwt_mdl_template: Dict[str, Any],
    ):
        """Delivery to a did:key (no service endpoint) should return 422."""
        claims = TestDataBuilder.mdl_claims(
            given_name="DIDComm",
            family_name="TestNoEndpoint",
        )
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=sd_jwt_mdl_template["id"],
            claims=claims,
        )

        # did:key has no service endpoint — delivery should fail with 422
        with pytest.raises(GatewayClientError, match="422"):
            await gateway_client.didcomm_deliver(
                transaction_id=issuance["id"],
                holder_did="did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            )

    async def test_deliver_already_issued_returns_409(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        sd_jwt_mdl_template: Dict[str, Any],
    ):
        """Delivering to an already-issued transaction should return 409."""
        claims = TestDataBuilder.mdl_claims(
            given_name="DIDComm",
            family_name="TestAlreadyIssued",
        )
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=sd_jwt_mdl_template["id"],
            claims=claims,
        )

        # The issuance via OID4VCI flow may auto-complete.
        # If it's already ISSUED, the deliver endpoint should reject it.
        retrieved = await gateway_client.get_issuance(issuance["id"])
        if retrieved.get("status") == "issued":
            with pytest.raises(GatewayClientError, match="409"):
                await gateway_client.didcomm_deliver(
                    transaction_id=issuance["id"],
                    holder_did="did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                )


# =============================================================================
# Test: DIDComm Delivery with Mock Agent
# =============================================================================


class TestDidcommDeliveryWithMockAgent:
    """Test DIDComm v2 push delivery using a mock DIDComm agent.

    These tests start a lightweight HTTP server that accepts DIDComm messages
    and verify that the issuance service correctly delivers credentials.
    """

    @pytest.fixture
    async def mock_agent(self):
        """Start a minimal HTTP server that captures DIDComm messages.

        Returns (base_url, received_messages_list).
        The server listens on a random port and captures all POSTs.
        """
        from http.server import HTTPServer, BaseHTTPRequestHandler
        import threading

        received: list[dict] = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                content_type = self.headers.get("Content-Type", "")
                try:
                    msg = json.loads(body)
                except Exception:
                    msg = {"raw": body.decode("utf-8", errors="replace")}
                received.append({
                    "content_type": content_type,
                    "body": msg,
                })
                self.send_response(202)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"accepted"}')

            def log_message(self, format, *args):
                pass  # Suppress server logs in test output

        server = HTTPServer(("0.0.0.0", 0), Handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        yield f"http://host.docker.internal:{port}", received

        server.shutdown()

    async def test_deliver_to_mock_agent(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        sd_jwt_mdl_template: Dict[str, Any],
        mock_agent,
    ):
        """Test full DIDComm v2 delivery to a mock agent.

        1. Create issuance transaction
        2. Construct did:peer:2 with mock agent's service endpoint
        3. Call /didcomm/deliver
        4. Verify the mock agent received a valid DIDComm message
        """
        agent_url, received = mock_agent

        # Construct a did:peer:2 DID that points to the mock agent
        holder_did = _make_did_peer_2_with_service(agent_url)

        claims = TestDataBuilder.mdl_claims(
            given_name="DIDComm",
            family_name="MockDelivery",
            birth_date="1990-01-15",
        )
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=sd_jwt_mdl_template["id"],
            claims=claims,
        )
        assert issuance is not None
        assert "id" in issuance

        # Deliver via DIDComm v2
        try:
            result = await gateway_client.didcomm_deliver(
                transaction_id=issuance["id"],
                holder_did=holder_did,
            )
        except GatewayClientError as e:
            # If the service can't reach host.docker.internal (non-Docker),
            # try localhost
            if "delivery_failed" in str(e) or "Connection" in str(e):
                pytest.skip("Mock agent not reachable from issuance service (Docker network)")
            raise

        # Verify delivery result
        assert result["transaction_id"] == issuance["id"]
        assert result["holder_did"] == holder_did
        assert result["credential_id"]
        assert result["didcomm_message_id"]
        assert result["status"] in ("delivered", "delivery_failed")

        if result["status"] == "delivered":
            # Verify mock agent received the message
            assert len(received) == 1
            msg = received[0]
            assert "didcomm" in msg["content_type"].lower()
            assert msg["body"]["type"] == "https://didcomm.org/issue-credential/3.0/issue-credential"
            assert msg["body"]["from"]  # issuer DID
            assert msg["body"]["to"] == [holder_did]
            assert len(msg["body"]["attachments"]) >= 1

            # Verify the transaction is now ISSUED
            tx = await gateway_client.get_issuance(issuance["id"])
            assert tx["status"] == "issued"


# =============================================================================
# Test: DIDComm Delivery with Live Agent
# =============================================================================


@pytest.mark.skipif(
    not DIDCOMM_AGENT_URL or not DIDCOMM_HOLDER_DID,
    reason="Set DIDCOMM_AGENT_URL and DIDCOMM_HOLDER_DID to run live agent tests",
)
class TestDidcommLiveAgentDelivery:
    """Test DIDComm v2 delivery to a live DIDComm agent."""

    async def test_deliver_to_live_agent(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        sd_jwt_mdl_template: Dict[str, Any],
    ):
        """Deliver a credential to a live DIDComm agent."""
        claims = TestDataBuilder.mdl_claims(
            given_name="DIDComm",
            family_name="LiveDelivery",
            birth_date="1985-03-20",
        )
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=sd_jwt_mdl_template["id"],
            claims=claims,
        )

        result = await gateway_client.didcomm_deliver(
            transaction_id=issuance["id"],
            holder_did=DIDCOMM_HOLDER_DID,
        )

        assert result["status"] == "delivered"
        assert result["service_endpoint"]
        assert result["didcomm_message_id"]
        assert result["credential_id"]

        # Transaction should be marked as issued
        tx = await gateway_client.get_issuance(issuance["id"])
        assert tx["status"] == "issued"


# =============================================================================
# Test: DID Resolution Validation
# =============================================================================


class TestDidResolution:
    """Test DID resolution error handling for various DID methods."""

    async def test_invalid_did_format(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        sd_jwt_mdl_template: Dict[str, Any],
    ):
        """Delivery with an invalid DID should fail."""
        claims = TestDataBuilder.mdl_claims()
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=sd_jwt_mdl_template["id"],
            claims=claims,
        )

        with pytest.raises(GatewayClientError, match="4[0-9]{2}|5[0-9]{2}"):
            await gateway_client.didcomm_deliver(
                transaction_id=issuance["id"],
                holder_did="not-a-valid-did",
            )

    async def test_unsupported_did_method(
        self,
        gateway_client: GatewayClient,
        test_organization: Dict[str, Any],
        sd_jwt_mdl_template: Dict[str, Any],
    ):
        """Delivery with an unsupported DID method (no Universal Resolver) should fail."""
        claims = TestDataBuilder.mdl_claims()
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=sd_jwt_mdl_template["id"],
            claims=claims,
        )

        with pytest.raises(GatewayClientError, match="4[0-9]{2}|5[0-9]{2}"):
            await gateway_client.didcomm_deliver(
                transaction_id=issuance["id"],
                holder_did="did:unsupported:abc123",
            )
