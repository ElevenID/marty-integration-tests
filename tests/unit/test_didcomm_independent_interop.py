"""Guards for the independent DIDComm decryption oracle."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from tests.integration.gateway import test_didcomm_v2_delivery as didcomm


def envelope(holder_did: str) -> dict[str, Any]:
    kid = f"{holder_did}#key-1"
    protected = {
        "typ": "application/didcomm-encrypted+json",
        "alg": "ECDH-ES+A256KW",
        "enc": "A256CBC-HS512",
        "epk": {
            "kty": "OKP",
            "crv": "X25519",
            "x": base64.urlsafe_b64encode(b"e" * 32).rstrip(b"=").decode(),
        },
        "apv": base64.urlsafe_b64encode(hashlib.sha256(kid.encode()).digest()).rstrip(b"=").decode(),
    }
    return {
        "protected": base64.urlsafe_b64encode(json.dumps(protected).encode()).rstrip(b"=").decode(),
        "recipients": [
            {
                "header": {"kid": kid},
                "encrypted_key": "wrapped",
            }
        ],
        "iv": "iv",
        "ciphertext": "ciphertext",
        "tag": "tag",
    }


def test_selected_profile_requires_normative_protected_headers() -> None:
    message = envelope("did:peer:2.test")
    protected = didcomm._assert_selected_anoncrypt_profile(message)

    assert protected["enc"] == "A256CBC-HS512"
    assert "epk" not in message["recipients"][0]["header"]


def test_selected_profile_rejects_unprotected_ephemeral_key() -> None:
    message = envelope("did:peer:2.test")
    protected = json.loads(didcomm._base64url_decode(message["protected"]))
    message["recipients"][0]["header"]["epk"] = protected.pop("epk")
    message["protected"] = base64.urlsafe_b64encode(json.dumps(protected).encode()).rstrip(b"=").decode()

    with pytest.raises(AssertionError, match="integrity protected"):
        didcomm._assert_selected_anoncrypt_profile(message)


def test_independent_verifier_is_optional_outside_release_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DIDCOMM_INDEPENDENT_VERIFIER_REQUIRED", raising=False)
    monkeypatch.delenv("DIDCOMM_INTEROP_CLI", raising=False)
    assert didcomm._independent_didcomm_decrypt(envelope("did:peer:2.test"), "did:peer:2.test", b"k" * 32) is None


def test_pinned_independent_verifier_decrypts_anoncrypt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    holder_did = "did:peer:2.test"
    private_key = bytes(range(32))
    cli = tmp_path / "didcomm-verifier"
    cli.touch()
    monkeypatch.setenv("DIDCOMM_INDEPENDENT_VERIFIER_REQUIRED", "true")
    monkeypatch.setenv("DIDCOMM_INTEROP_CLI", str(cli))
    monkeypatch.setenv("DIDCOMM_INTEROP_IMPLEMENTATION", didcomm.INDEPENDENT_IMPLEMENTATION)
    captured: dict[str, object] = {}

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["command"] = command
        captured["input"] = kwargs["input"]
        keys = Path(command[command.index("--key-file") + 1])
        key_material = json.loads(keys.read_text(encoding="utf-8"))
        captured["key_material"] = key_material
        output = {
            "message": {"id": "message-1", "from": "did:example:issuer"},
            "encrypted": True,
            "anonymous": True,
            "signed": False,
        }
        return subprocess.CompletedProcess(command, 0, json.dumps(output), "")

    monkeypatch.setattr(didcomm.subprocess, "run", run)
    result = didcomm._independent_didcomm_decrypt(envelope(holder_did), holder_did, private_key)

    assert result == {"id": "message-1", "from": "did:example:issuer"}
    assert captured["input"] == json.dumps(envelope(holder_did))
    command = captured["command"]
    assert isinstance(command, list)
    assert command[:3] == [str(cli), "unpack", "--key-file"]
    key_material = captured["key_material"]
    assert isinstance(key_material, dict)
    assert len(key_material["keys"]) == 1
    private_jwk = key_material["keys"][0]
    assert private_jwk["kid"] == f"{holder_did}#key-1"
    assert private_jwk["kty"] == "OKP"
    assert private_jwk["crv"] == "X25519"
    assert base64.urlsafe_b64decode(private_jwk["d"] + "==") == private_key


def test_independent_verifier_rejects_false_sender_authentication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    holder_did = "did:peer:2.test"
    cli = tmp_path / "didcomm-verifier"
    cli.touch()
    monkeypatch.setenv("DIDCOMM_INDEPENDENT_VERIFIER_REQUIRED", "true")
    monkeypatch.setenv("DIDCOMM_INTEROP_CLI", str(cli))
    monkeypatch.setenv("DIDCOMM_INTEROP_IMPLEMENTATION", didcomm.INDEPENDENT_IMPLEMENTATION)
    monkeypatch.setattr(
        didcomm.subprocess,
        "run",
        lambda *args, **_kwargs: subprocess.CompletedProcess(
            args[0],
            0,
            json.dumps(
                {
                    "message": {"id": "message-1"},
                    "encrypted": True,
                    "anonymous": False,
                    "signed": True,
                }
            ),
            "",
        ),
    )

    with pytest.raises(AssertionError, match="anoncrypt must remain anonymous"):
        didcomm._independent_didcomm_decrypt(envelope(holder_did), holder_did, b"k" * 32)
