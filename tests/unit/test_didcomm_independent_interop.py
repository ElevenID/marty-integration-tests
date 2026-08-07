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


def test_independent_verifier_must_reject_tampered_envelope(
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
        lambda *args, **_kwargs: subprocess.CompletedProcess(args[0], 1, "", "decrypt failed"),
    )

    assert (
        didcomm._assert_independent_didcomm_rejects(
            envelope(holder_did),
            holder_did,
            b"k" * 32,
            "ciphertext",
        )
        is True
    )


def test_independent_verifier_accepting_tampering_fails_evidence(
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
        lambda *args, **_kwargs: subprocess.CompletedProcess(args[0], 0, "{}", ""),
    )

    with pytest.raises(AssertionError, match="accepted a tampered envelope"):
        didcomm._assert_independent_didcomm_rejects(
            envelope(holder_did),
            holder_did,
            b"k" * 32,
            "ciphertext",
        )


def test_tamper_matrix_changes_each_integrity_protected_value() -> None:
    original = envelope("did:peer:2.test")
    cases = didcomm._tampered_envelopes(original)

    assert set(cases) == {
        "ciphertext",
        "authentication-tag",
        "protected-header",
        "wrapped-content-key",
    }
    assert cases["ciphertext"]["ciphertext"] != original["ciphertext"]
    assert cases["authentication-tag"]["tag"] != original["tag"]
    assert cases["protected-header"]["protected"] != original["protected"]
    assert (
        cases["wrapped-content-key"]["recipients"][0]["encrypted_key"]
        != original["recipients"][0]["encrypted_key"]
    )
    assert original == envelope("did:peer:2.test"), "the source envelope must not be mutated"


def test_plaintext_comparison_accepts_only_known_optional_absent_null_members() -> None:
    independent = {
        "id": "message-1",
        "type": "https://didcomm.org/issue-credential/3.0/issue-credential",
        "body": {"goal_code": "issue-vc"},
    }
    released_marty = {
        **independent,
        "expires_time": None,
        "pthid": None,
    }

    didcomm._assert_same_didcomm_plaintext(independent, released_marty)


@pytest.mark.parametrize("member", ["id", "from", "to", "thid", "attachments"])
def test_plaintext_comparison_rejects_other_absent_null_members(member: str) -> None:
    independent = {"id": "message-1", member: None}
    released_marty = {"id": "message-1"}

    with pytest.raises(AssertionError, match=rf"members: {member}"):
        didcomm._assert_same_didcomm_plaintext(independent, released_marty)


def test_plaintext_comparison_rejects_non_null_optional_difference() -> None:
    independent = {"id": "message-1", "pthid": "parent-1"}
    released_marty = {"id": "message-1", "pthid": "parent-2"}

    with pytest.raises(AssertionError, match=r"members: pthid"):
        didcomm._assert_same_didcomm_plaintext(independent, released_marty)


def test_plaintext_comparison_rejects_nested_credential_difference_without_logging_values() -> None:
    independent = {"id": "message-1", "attachments": [{"data": {"json": {"credential": "secret-a"}}}]}
    released_marty = {"id": "message-1", "attachments": [{"data": {"json": {"credential": "secret-b"}}}]}

    with pytest.raises(AssertionError, match=r"members: attachments") as failure:
        didcomm._assert_same_didcomm_plaintext(independent, released_marty)
    assert "secret-a" not in str(failure.value)
    assert "secret-b" not in str(failure.value)
