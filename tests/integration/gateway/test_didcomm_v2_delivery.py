"""
DIDComm v2 Credential Delivery Integration Tests

Tests DIDComm v2 push delivery of credentials:
1. Issue + deliver via /v1/issuance/didcomm/deliver
2. DID resolution (did:key, did:web, did:peer)
3. Holder DID validation / error handling
4. Auto-delivery via wallet_configs with format_variant="didcomm_v2"

Requires a running DIDComm agent endpoint or an explicitly enabled private
test agent that receives encrypted DIDComm messages.
"""

import base64
import copy
import hashlib
import json
import os
import ssl
import subprocess
import tempfile
import threading
from collections.abc import AsyncGenerator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from .helpers.didcomm import make_did_peer_2_with_service
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
DIDCOMM_PRIVATE_AGENT_TESTS = os.getenv("DIDCOMM_PRIVATE_AGENT_TESTS", "").lower() in {
    "1",
    "true",
    "yes",
}
INDEPENDENT_IMPLEMENTATION = "notabene-id/go-didcomm@v0.4.0#5ffd085c2b5088a639c1c0d3910d668887298ce5"
OPTIONAL_ABSENT_OR_NULL_PLAINTEXT_MEMBERS = frozenset({"expires_time", "pthid"})
AUTHCRYPT_POLICY_FILE_ENV = "MARTY_DIDCOMM_TEST_POLICY_FILE"


def _base64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _assert_selected_anoncrypt_profile(encrypted: dict[str, Any]) -> dict[str, Any]:
    """Enforce the normative headers for Marty's selected DIDComm 2.1 profile."""
    recipients = encrypted.get("recipients")
    assert isinstance(recipients, list)
    assert len(recipients) == 1
    recipient_header = recipients[0].get("header")
    assert isinstance(recipient_header, dict)
    recipient_kid = recipient_header.get("kid")
    assert isinstance(recipient_kid, str)
    assert recipient_kid
    assert "epk" not in recipient_header, "DIDComm requires epk to be integrity protected"

    protected_value = encrypted.get("protected")
    assert isinstance(protected_value, str)
    protected: object = json.loads(_base64url_decode(protected_value))
    assert isinstance(protected, dict)
    assert protected.get("typ") == "application/didcomm-encrypted+json"
    assert protected.get("alg") == "ECDH-ES+A256KW"
    assert protected.get("enc") == "A256CBC-HS512"
    assert protected.get("apu") is None
    assert protected.get("skid") is None
    ephemeral_key = protected.get("epk")
    assert isinstance(ephemeral_key, dict)
    assert ephemeral_key.get("kty") == "OKP"
    assert ephemeral_key.get("crv") == "X25519"
    ephemeral_x = ephemeral_key.get("x")
    assert isinstance(ephemeral_x, str)
    assert len(_base64url_decode(ephemeral_x)) == 32

    expected_apv = base64.urlsafe_b64encode(hashlib.sha256(recipient_kid.encode()).digest()).rstrip(b"=").decode()
    assert protected.get("apv") == expected_apv
    return protected


def _assert_selected_authcrypt_profile(
    encrypted: dict[str, Any],
    *,
    expected_sender_kid: str,
) -> tuple[dict[str, Any], str]:
    """Enforce the sender-authenticated DIDComm profile and bound key IDs."""

    recipients = encrypted.get("recipients")
    assert isinstance(recipients, list)
    assert len(recipients) == 1
    recipient_header = recipients[0].get("header")
    assert isinstance(recipient_header, dict)
    recipient_kid = recipient_header.get("kid")
    assert isinstance(recipient_kid, str)
    assert recipient_kid
    assert "epk" not in recipient_header, "DIDComm requires epk to be integrity protected"

    protected_value = encrypted.get("protected")
    assert isinstance(protected_value, str)
    protected: object = json.loads(_base64url_decode(protected_value))
    assert isinstance(protected, dict)
    assert protected.get("typ") == "application/didcomm-encrypted+json"
    assert protected.get("alg") == "ECDH-1PU+A256KW"
    assert protected.get("enc") == "A256CBC-HS512"
    assert protected.get("skid") == expected_sender_kid
    assert protected.get("apu") == _base64url_encode(expected_sender_kid.encode())
    ephemeral_key = protected.get("epk")
    assert isinstance(ephemeral_key, dict)
    assert ephemeral_key.get("kty") == "OKP"
    assert ephemeral_key.get("crv") == "X25519"
    ephemeral_x = ephemeral_key.get("x")
    assert isinstance(ephemeral_x, str)
    assert len(_base64url_decode(ephemeral_x)) == 32

    expected_apv = _base64url_encode(hashlib.sha256(recipient_kid.encode()).digest())
    assert protected.get("apv") == expected_apv
    return protected, recipient_kid


def _independent_didcomm_decrypt(
    encrypted: dict[str, Any],
    holder_did: str,
    holder_private_key: bytes,
) -> dict[str, Any] | None:
    """Decrypt Marty's envelope with the separately maintained Go implementation."""
    completed = _run_independent_didcomm_verifier(
        encrypted,
        holder_did,
        holder_private_key,
    )
    if completed is None:
        return None
    assert completed.returncode == 0, (
        "independent DIDComm verifier rejected Marty's selected profile: "
        f"{completed.stderr.strip()[:300]}"
    )
    output: object = json.loads(completed.stdout)
    assert isinstance(output, dict)
    assert output.get("encrypted") is True
    assert output.get("anonymous") is True, "anoncrypt must remain anonymous"
    assert output.get("signed") is False, "anoncrypt must not authenticate plaintext from"
    message = output.get("message")
    assert isinstance(message, dict)
    return message


def _independent_didcomm_decrypt_authcrypt(
    encrypted: dict[str, Any],
    holder_did: str,
    holder_private_key: bytes,
    *,
    sender_did_document: dict[str, Any],
    recipient_did_document: dict[str, Any],
) -> dict[str, Any] | None:
    """Authenticate and decrypt Marty authcrypt with the pinned Go implementation."""

    completed = _run_independent_didcomm_verifier(
        encrypted,
        holder_did,
        holder_private_key,
        did_documents=(sender_did_document, recipient_did_document),
    )
    if completed is None:
        return None
    assert completed.returncode == 0, (
        "independent DIDComm verifier rejected Marty's authcrypt profile: "
        f"{completed.stderr.strip()[:300]}"
    )
    output: object = json.loads(completed.stdout)
    assert isinstance(output, dict)
    assert output.get("encrypted") is True
    assert output.get("anonymous") is False, "authcrypt must authenticate its sender"
    assert output.get("signed") is True, "authcrypt must report sender authentication"
    message = output.get("message")
    assert isinstance(message, dict)
    return message


def _run_independent_didcomm_verifier(
    encrypted: dict[str, Any],
    holder_did: str,
    holder_private_key: bytes,
    *,
    did_documents: tuple[dict[str, Any], ...] = (),
) -> subprocess.CompletedProcess[str] | None:
    """Run the pinned independent verifier without interpreting its result."""
    required = os.getenv("DIDCOMM_INDEPENDENT_VERIFIER_REQUIRED", "").lower() in {
        "1",
        "true",
        "yes",
    }
    cli_value = os.getenv("DIDCOMM_INTEROP_CLI", "").strip()
    implementation = os.getenv("DIDCOMM_INTEROP_IMPLEMENTATION", "").strip()
    if not required and not cli_value:
        return None
    assert required, "an independent DIDComm verifier must be explicitly required"
    assert implementation == INDEPENDENT_IMPLEMENTATION

    cli = Path(cli_value)
    assert cli.is_file(), "the pinned independent DIDComm verifier is unavailable"
    recipients = encrypted.get("recipients")
    assert isinstance(recipients, list)
    assert len(recipients) == 1
    recipient_kid = recipients[0].get("header", {}).get("kid")
    assert isinstance(recipient_kid, str)
    assert recipient_kid.startswith(f"{holder_did}#")

    holder_public_key = (
        x25519.X25519PrivateKey.from_private_bytes(holder_private_key)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )

    # The upstream CLI accepts a standard private JWK Set. This disposable
    # holder key is generated solely for the test and is never a Marty custody
    # or issuer key.
    key_material = {
        "keys": [
            {
                "kty": "OKP",
                "crv": "X25519",
                "kid": recipient_kid,
                "alg": "ECDH-ES+A256KW",
                "x": _base64url_encode(holder_public_key),
                "d": _base64url_encode(holder_private_key),
            }
        ]
    }
    with tempfile.TemporaryDirectory(prefix="didcomm-independent-") as temporary:
        keys = Path(temporary) / "keys.json"
        keys.write_text(json.dumps(key_material), encoding="utf-8")
        command = [
            str(cli),
            "unpack",
            "--key-file",
            str(keys),
        ]
        if did_documents:
            document_paths: list[str] = []
            for index, document in enumerate(did_documents):
                document_path = Path(temporary) / f"did-document-{index}.json"
                document_path.write_text(json.dumps(document), encoding="utf-8")
                document_paths.append(str(document_path))
            command.extend(["--did-doc", ",".join(document_paths)])
        return subprocess.run(
            command,
            input=json.dumps(encrypted),
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )


def _assert_independent_didcomm_rejects(
    encrypted: dict[str, Any],
    holder_did: str,
    holder_private_key: bytes,
    case: str,
    *,
    did_documents: tuple[dict[str, Any], ...] = (),
) -> bool | None:
    """Require the independent implementation to reject a tampered envelope."""
    completed = _run_independent_didcomm_verifier(
        encrypted,
        holder_did,
        holder_private_key,
        did_documents=did_documents,
    )
    if completed is None:
        return None
    assert completed.returncode != 0, (
        "independent DIDComm verifier accepted a tampered envelope "
        f"({case})"
    )
    return True


def _configure_didcomm_issuer_policy(
    issuer_did: str,
    *,
    mode: str,
    sender_private_key: bytes | None = None,
) -> bool:
    """Atomically configure the disposable deployment's exhaustive issuer policy."""

    configured_file = os.getenv(AUTHCRYPT_POLICY_FILE_ENV, "").strip()
    if not configured_file:
        assert mode == "anoncrypt", "authcrypt evidence requires a mounted policy file"
        return False

    configured_dir = os.getenv("DIDCOMM_ENCRYPTION_POLICY_DIR", "").strip()
    assert configured_dir, "the disposable policy directory must be explicit"
    policy_dir = Path(configured_dir).resolve()
    policy_file = Path(configured_file).resolve()
    assert policy_dir.is_dir()
    assert policy_file.parent == policy_dir
    assert policy_file.name == "didcomm-encryption-policy.json"
    assert not policy_file.is_symlink()
    assert mode in {"anoncrypt", "authcrypt"}

    issuer_policy: dict[str, Any] = {"mode": mode}
    if mode == "authcrypt":
        assert sender_private_key is not None
        assert len(sender_private_key) == 32
        issuer_policy["sender_x25519_private_key"] = _base64url_encode(
            sender_private_key
        )
    else:
        assert sender_private_key is None

    payload = {"version": 1, "issuers": {issuer_did: issuer_policy}}
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".didcomm-encryption-policy-",
        suffix=".json",
        dir=policy_dir,
        text=True,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as policy_stream:
            json.dump(payload, policy_stream, separators=(",", ":"), sort_keys=True)
            policy_stream.write("\n")
            policy_stream.flush()
            os.fsync(policy_stream.fileno())
        os.replace(temporary_name, policy_file)
    finally:
        temporary_path = Path(temporary_name)
        if temporary_path.exists():
            temporary_path.unlink()
    return True


def _deployed_authcrypt_preflight_diagnostic(
    issuer_did: str,
    holder_did: str,
) -> str:
    """Classify a released-stack preflight failure without exposing key material."""

    project = os.getenv("MARTY_CONFORMANCE_PROJECT", "").strip()
    if not project:
        return "deployment probe unavailable: no Compose project"
    selection = subprocess.run(
        [
            "docker",
            "ps",
            "--quiet",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--filter",
            "label=com.docker.compose.service=issuance",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    containers = [line.strip() for line in selection.stdout.splitlines() if line.strip()]
    if selection.returncode != 0 or len(containers) != 1:
        return (
            "deployment probe unavailable: issuance container selection "
            f"returned rc={selection.returncode} count={len(containers)}"
        )
    probe = """
import json
import sys
from issuance.application.rust_integration import (
    didcomm_resolve_did,
    prepare_didcomm_delivery_encryption,
)

try:
    recipient = didcomm_resolve_did(sys.argv[2])
    context = prepare_didcomm_delivery_encryption(sys.argv[1], recipient)
except Exception as error:
    chain = []
    current = error
    while current is not None and len(chain) < 6:
        chain.append({"type": type(current).__name__, "message": str(current)})
        current = current.__cause__
    print(json.dumps({"ok": False, "chain": chain}, separators=(",", ":"), sort_keys=True))
    raise SystemExit(1)
else:
    print(json.dumps({"ok": True, "mode": context.mode}, separators=(",", ":"), sort_keys=True))
"""
    completed = subprocess.run(
        [
            "docker",
            "exec",
            containers[0],
            "python",
            "-c",
            probe,
            issuer_did,
            holder_did,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    output = (completed.stdout.strip() or completed.stderr.strip()).replace("\n", " ")
    return f"deployment preflight rc={completed.returncode}: {output[:2000]}"


def _flip_base64url_byte(value: str) -> str:
    decoded = bytearray(_base64url_decode(value))
    assert decoded, "DIDComm encoded value must not be empty"
    decoded[-1] ^= 0x01
    return base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")


def _tampered_envelopes(encrypted: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Produce integrity-breaking mutations without exposing plaintext data."""
    cases: dict[str, dict[str, Any]] = {}
    for name, path in {
        "ciphertext": ("ciphertext",),
        "authentication-tag": ("tag",),
        "protected-header": ("protected",),
        "wrapped-content-key": ("recipients", 0, "encrypted_key"),
    }.items():
        mutated = copy.deepcopy(encrypted)
        if len(path) == 1:
            member = path[0]
            value = mutated[member]
            assert isinstance(value, str)
            mutated[member] = _flip_base64url_byte(value)
        else:
            value = mutated["recipients"][0]["encrypted_key"]
            assert isinstance(value, str)
            mutated["recipients"][0]["encrypted_key"] = _flip_base64url_byte(value)
        cases[name] = mutated
    return cases


def _assert_same_didcomm_plaintext(
    independent: dict[str, Any],
    released_marty: dict[str, Any],
) -> None:
    """Compare decoded messages without weakening optional-member semantics.

    The released Python binding materializes two absent optional DIDComm fields
    as ``None`` while the independent Go decoder preserves their absence. Only
    that representation difference is equivalent; every other key, nested
    value, attachment, and non-null optional value must match exactly.

    Report only differing top-level member names so a failed public workflow
    does not copy credential contents into its diagnostic log.
    """
    differing_members: list[str] = []
    for member in sorted(independent.keys() | released_marty.keys()):
        independent_present = member in independent
        released_present = member in released_marty
        independent_value = independent.get(member)
        released_value = released_marty.get(member)
        if member in OPTIONAL_ABSENT_OR_NULL_PLAINTEXT_MEMBERS and independent_value is None and released_value is None:
            continue
        if not independent_present or not released_present or independent_value != released_value:
            differing_members.append(member)

    assert not differing_members, (
        "independent DIDComm plaintext differs from the released Marty decoder "
        f"at members: {', '.join(differing_members)}"
    )


# =============================================================================
# Test: DIDComm Deliver Endpoint
# =============================================================================


class TestDidcommDeliverEndpoint:
    """Test the /v1/issuance/didcomm/deliver REST endpoint."""

    async def test_deliver_requires_transaction_id(
        self,
        gateway_client: GatewayClient,
        test_organization: dict[str, Any],
    ) -> None:
        """Delivery without a valid transaction_id should fail."""
        with pytest.raises(GatewayClientError, match="4[0-9]{2}"):
            await gateway_client.didcomm_deliver(
                organization_id=test_organization["id"],
                transaction_id="nonexistent-tx-id",
                holder_did="did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            )

    async def test_deliver_requires_holder_did_with_endpoint(
        self,
        gateway_client: GatewayClient,
        test_organization: dict[str, Any],
        sd_jwt_mdl_template: dict[str, Any],
    ) -> None:
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
                organization_id=test_organization["id"],
                transaction_id=issuance["id"],
                holder_did="did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            )

    async def test_deliver_already_issued_returns_409(
        self,
        gateway_client: GatewayClient,
        test_organization: dict[str, Any],
        sd_jwt_mdl_template: dict[str, Any],
    ) -> None:
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
                    organization_id=test_organization["id"],
                    transaction_id=issuance["id"],
                    holder_did="did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                )


# =============================================================================
# Test: DIDComm Delivery with Mock Agent
# =============================================================================


@pytest.mark.skipif(
    not DIDCOMM_PRIVATE_AGENT_TESTS,
    reason=(
        "Set DIDCOMM_PRIVATE_AGENT_TESTS=true and enable private DIDComm endpoints "
        "only in the disposable test deployment"
    ),
)
class TestDidcommDeliveryWithMockAgent:
    """Test DIDComm v2 push delivery using a mock DIDComm agent.

    These tests start a lightweight HTTP server that accepts DIDComm messages
    and verify that the issuance service correctly delivers credentials.
    """

    @pytest.fixture
    async def mock_agent(
        self,
    ) -> AsyncGenerator[tuple[str, list[dict[str, Any]]], None]:
        """Start a minimal HTTP server that captures DIDComm messages.

        Returns (base_url, received_messages_list).
        The server listens on a random port and captures all POSTs.
        """
        received: list[dict[str, Any]] = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                content_type = self.headers.get("Content-Type", "")
                try:
                    msg = json.loads(body)
                except Exception:
                    msg = {"raw": body.decode("utf-8", errors="replace")}
                received.append(
                    {
                        "content_type": content_type,
                        "body": msg,
                    }
                )
                self.send_response(202)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"accepted"}')

            def log_message(self, format_string: str, *args: Any) -> None:
                pass  # Suppress server logs in test output

        # Docker reaches this host-side callback via host.docker.internal.
        server = HTTPServer(("0.0.0.0", 0), Handler)  # nosec B104
        certificate_dir = Path(os.environ["OIDF_TLS_CERT_DIR"])
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
        tls_context.load_cert_chain(
            certfile=certificate_dir / "tls.crt",
            keyfile=certificate_dir / "tls.key",
        )
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        yield f"https://host.docker.internal:{port}", received

        server.shutdown()

    async def test_deliver_to_mock_agent(
        self,
        gateway_client: GatewayClient,
        test_organization: dict[str, Any],
        vc_jwt_issuer_did: str,
        sd_jwt_mdl_template: dict[str, Any],
        mock_agent: tuple[str, list[dict[str, Any]]],
    ) -> None:
        """Test full DIDComm v2 delivery to a mock agent.

        1. Create issuance transaction
        2. Construct did:peer:2 with mock agent's service endpoint
        3. Call /didcomm/deliver
        4. Verify the mock agent received a valid DIDComm message
        """
        agent_url, received = mock_agent

        # Construct a did:peer:2 DID that points to the mock agent
        holder_did, holder_private_key = make_did_peer_2_with_service(agent_url)
        _configure_didcomm_issuer_policy(
            vc_jwt_issuer_did,
            mode="anoncrypt",
        )

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

        result = await gateway_client.didcomm_deliver(
            organization_id=test_organization["id"],
            transaction_id=issuance["id"],
            holder_did=holder_did,
        )

        # Verify delivery result
        assert result["transaction_id"] == issuance["id"]
        assert result["holder_did"] == holder_did
        assert result["credential_id"]
        assert result["didcomm_message_id"]
        assert result["status"] == "delivered"

        assert len(received) == 1
        encrypted = received[0]
        assert encrypted["content_type"] == "application/didcomm-encrypted+json"
        assert {
            "protected",
            "recipients",
            "iv",
            "ciphertext",
            "tag",
        } <= encrypted["body"].keys()
        _assert_selected_anoncrypt_profile(encrypted["body"])

        try:
            from marty_rs import _marty_rs
        except ImportError:
            import _marty_rs  # type: ignore[no-redef]

        plaintext = json.loads(
            _marty_rs.didcomm_decrypt(
                json.dumps(encrypted["body"]),
                holder_private_key,
            )
        )
        assert plaintext["type"] == ("https://didcomm.org/issue-credential/3.0/issue-credential")
        assert plaintext["from"]
        assert plaintext["to"] == [holder_did]
        assert plaintext["thid"] == issuance["id"]
        assert len(plaintext["attachments"]) >= 1

        independent_plaintext = _independent_didcomm_decrypt(
            encrypted["body"],
            holder_did,
            holder_private_key,
        )
        if independent_plaintext is not None:
            _assert_same_didcomm_plaintext(independent_plaintext, plaintext)

        for case, tampered in _tampered_envelopes(encrypted["body"]).items():
            with pytest.raises(Exception, match=r"(?i)(decrypt|unpack|crypto|jwe|tag)"):
                _marty_rs.didcomm_decrypt(
                    json.dumps(tampered),
                    holder_private_key,
                )
            independent_rejected = _assert_independent_didcomm_rejects(
                tampered,
                holder_did,
                holder_private_key,
                case,
            )
            if independent_plaintext is not None:
                assert independent_rejected is True

        tx = await gateway_client.get_issuance(issuance["id"])
        assert tx["status"] == "issued"

    @pytest.mark.skipif(
        not os.getenv(AUTHCRYPT_POLICY_FILE_ENV, "").strip(),
        reason="authcrypt evidence requires the disposable deployment policy mount",
    )
    async def test_deliver_authcrypt_with_managed_issuer(
        self,
        gateway_client: GatewayClient,
        test_organization: dict[str, Any],
        vc_jwt_issuer_did: str,
        sd_jwt_mdl_template: dict[str, Any],
        mock_agent: tuple[str, list[dict[str, Any]]],
    ) -> None:
        """Prove released authcrypt, sender binding, and wrong-key fail-closed behavior."""

        agent_url, received = mock_agent
        holder_did, holder_private_key = make_did_peer_2_with_service(agent_url)

        sender_key = x25519.X25519PrivateKey.generate()
        sender_private_key = sender_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        sender_public_x = _base64url_encode(
            sender_key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        )
        publication = await gateway_client.publish_issuer_didcomm_key_agreement(
            organization_id=str(test_organization["id"]),
            issuer_did=vc_jwt_issuer_did,
            public_x=sender_public_x,
        )
        expected_sender_kid = (
            f"{vc_jwt_issuer_did}#didcomm-authcrypt-x25519"
        )
        assert publication == {
            "issuer_did": vc_jwt_issuer_did,
            "key_agreement_method_id": expected_sender_kid,
        }

        sender_document = await gateway_client.get_public_did_document(
            issuer_did=vc_jwt_issuer_did
        )
        methods = sender_document.get("verificationMethod")
        assert isinstance(methods, list)
        sender_methods = [
            method
            for method in methods
            if isinstance(method, dict) and method.get("id") == expected_sender_kid
        ]
        assert sender_methods == [
            {
                "id": expected_sender_kid,
                "type": "JsonWebKey2020",
                "controller": vc_jwt_issuer_did,
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": sender_public_x,
                },
            }
        ]
        assert expected_sender_kid in sender_document.get("keyAgreement", [])
        assert all(
            "d" not in method.get("publicKeyJwk", {})
            for method in methods
            if isinstance(method, dict)
            and isinstance(method.get("publicKeyJwk"), dict)
        )

        wrong_sender_key = x25519.X25519PrivateKey.generate().private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        _configure_didcomm_issuer_policy(
            vc_jwt_issuer_did,
            mode="authcrypt",
            sender_private_key=wrong_sender_key,
        )

        issuance = await gateway_client.issue_credential(
            organization_id=str(test_organization["id"]),
            credential_template_id=str(sd_jwt_mdl_template["id"]),
            claims=TestDataBuilder.mdl_claims(
                given_name="DIDComm",
                family_name="Authcrypt",
                birth_date="1990-01-15",
            ),
        )
        transaction_before_failure = await gateway_client.get_issuance(issuance["id"])
        with pytest.raises(GatewayClientError) as wrong_key_failure:
            await gateway_client.didcomm_deliver(
                organization_id=str(test_organization["id"]),
                transaction_id=str(issuance["id"]),
                holder_did=holder_did,
            )
        assert wrong_key_failure.value.status_code == 503
        assert received == [], "wrong sender custody must fail before transport"
        transaction_after_failure = await gateway_client.get_issuance(issuance["id"])
        assert transaction_after_failure.get("status") == transaction_before_failure.get(
            "status"
        )
        assert transaction_after_failure.get("status") != "issued"

        _configure_didcomm_issuer_policy(
            vc_jwt_issuer_did,
            mode="authcrypt",
            sender_private_key=sender_private_key,
        )
        try:
            result = await gateway_client.didcomm_deliver(
                organization_id=str(test_organization["id"]),
                transaction_id=str(issuance["id"]),
                holder_did=holder_did,
            )
        except GatewayClientError as error:
            pytest.fail(
                "Released authcrypt delivery failed after correct-key recovery; "
                f"public_status={error.status_code}; "
                + _deployed_authcrypt_preflight_diagnostic(
                    vc_jwt_issuer_did,
                    holder_did,
                )
            )

        assert result["transaction_id"] == issuance["id"]
        assert result["holder_did"] == holder_did
        assert result["status"] == "delivered"
        assert len(received) == 1
        encrypted = received[0]
        assert encrypted["content_type"] == "application/didcomm-encrypted+json"
        protected, recipient_kid = _assert_selected_authcrypt_profile(
            encrypted["body"],
            expected_sender_kid=expected_sender_kid,
        )
        assert protected.get("skid") != recipient_kid

        try:
            from marty_rs import _marty_rs
        except ImportError:
            import _marty_rs  # type: ignore[no-redef]

        recipient_document_json = _marty_rs.didcomm_resolve_did(holder_did)
        recipient_document: object = json.loads(recipient_document_json)
        assert isinstance(recipient_document, dict)
        assert recipient_document.get("id") == holder_did
        authenticated: object = json.loads(
            _marty_rs.didcomm_decrypt_authcrypt(
                json.dumps(encrypted["body"]),
                holder_private_key,
                recipient_document_json,
                json.dumps(sender_document),
            )
        )
        assert isinstance(authenticated, dict)
        assert authenticated.get("sender_kid") == expected_sender_kid
        assert authenticated.get("recipient_kid") == recipient_kid
        plaintext_value = authenticated.get("plaintext")
        assert isinstance(plaintext_value, str)
        plaintext: object = json.loads(plaintext_value)
        assert isinstance(plaintext, dict)
        assert plaintext.get("from") == vc_jwt_issuer_did
        assert plaintext.get("to") == [holder_did]
        assert plaintext.get("thid") == issuance["id"]

        independent_plaintext = _independent_didcomm_decrypt_authcrypt(
            encrypted["body"],
            holder_did,
            holder_private_key,
            sender_did_document=sender_document,
            recipient_did_document=recipient_document,
        )
        if independent_plaintext is not None:
            _assert_same_didcomm_plaintext(independent_plaintext, plaintext)

        did_documents = (sender_document, recipient_document)
        for case, tampered in _tampered_envelopes(encrypted["body"]).items():
            with pytest.raises(
                Exception,
                match=r"(?i)(decrypt|unpack|crypto|jwe|tag|header)",
            ):
                _marty_rs.didcomm_decrypt_authcrypt(
                    json.dumps(tampered),
                    holder_private_key,
                    recipient_document_json,
                    json.dumps(sender_document),
                )
            independent_rejected = _assert_independent_didcomm_rejects(
                tampered,
                holder_did,
                holder_private_key,
                case,
                did_documents=did_documents,
            )
            if independent_plaintext is not None:
                assert independent_rejected is True

        transaction = await gateway_client.get_issuance(issuance["id"])
        assert transaction["status"] == "issued"


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
        test_organization: dict[str, Any],
        sd_jwt_mdl_template: dict[str, Any],
    ) -> None:
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
            organization_id=test_organization["id"],
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
        test_organization: dict[str, Any],
        sd_jwt_mdl_template: dict[str, Any],
    ) -> None:
        """Delivery with an invalid DID should fail."""
        claims = TestDataBuilder.mdl_claims()
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=sd_jwt_mdl_template["id"],
            claims=claims,
        )

        with pytest.raises(GatewayClientError, match="4[0-9]{2}|5[0-9]{2}"):
            await gateway_client.didcomm_deliver(
                organization_id=test_organization["id"],
                transaction_id=issuance["id"],
                holder_did="not-a-valid-did",
            )

    async def test_unsupported_did_method(
        self,
        gateway_client: GatewayClient,
        test_organization: dict[str, Any],
        sd_jwt_mdl_template: dict[str, Any],
    ) -> None:
        """Delivery with an unsupported DID method (no Universal Resolver) should fail."""
        claims = TestDataBuilder.mdl_claims()
        issuance = await gateway_client.issue_credential(
            organization_id=test_organization["id"],
            credential_template_id=sd_jwt_mdl_template["id"],
            claims=claims,
        )

        with pytest.raises(GatewayClientError, match="4[0-9]{2}|5[0-9]{2}"):
            await gateway_client.didcomm_deliver(
                organization_id=test_organization["id"],
                transaction_id=issuance["id"],
                holder_did="did:unsupported:abc123",
            )
