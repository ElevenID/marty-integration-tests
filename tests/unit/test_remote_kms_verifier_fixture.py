"""Fail-closed ownership checks for the disposable positive-verifier KMS."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from scripts import run_remote_kms_verifier_fixture as fixture


def test_core_source_pin_is_exact_and_reviewed() -> None:
    root = Path(__file__).resolve().parents[2]
    pin = json.loads((root / "config" / "credentials-verifier-positive-producer.json").read_text(encoding="utf-8"))
    assert pin == {
        "schema": "elevenid.credentials-verifier-positive-producer/v1",
        "repository": "ElevenID/marty-core",
        "release_tag": "v0.2.2",
        "commit": "f0819fa0a7783eaebc2efaa105908809244c75a4",
        "source_asset": "marty-core-workspace-0.2.2.tar.gz",
        "source_digest": "sha256:3674878ae6cfbfcdce6270eeb69f0a5e614d820b5e1437ddbcd0f20f61acc8b3",
    }


def public_pem() -> str:
    # P-256 generator point: public-only test data, never a signing key.
    x = int("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
    y = int("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)
    point = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    return point.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode(
        "ascii"
    )


def test_create_role_requires_sign_only_token_and_nonexportable_key(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str, dict | None]] = []

    def api(_base: str, _context: object, token: str, path: str, payload: dict | None = None) -> dict:
        calls.append((token, path, payload))
        if path == "transit/keys/issuer" and payload is None:
            return {
                "data": {
                    "type": "ecdsa-p256",
                    "exportable": False,
                    "allow_plaintext_backup": False,
                    "latest_version": 1,
                    "keys": {"1": {"public_key": public_pem()}},
                }
            }
        if path == "auth/token/create":
            return {"auth": {"client_token": "issuer-scoped-token"}}
        if path == "sys/capabilities":
            return {"data": {"transit/sign/issuer": ["update"], "transit/sign/holder": ["deny"]}}
        return {}

    monkeypatch.setattr(fixture, "api", api)
    jwk, token = fixture.create_role(
        "https://127.0.0.1:8200", object(), "root", "issuer", "holder", kid=fixture.ISSUER_KID
    )
    assert token == "issuer-scoped-token"
    assert set(jwk) == {"kty", "crv", "x", "y", "kid", "alg"}
    assert calls[0][2] == {"type": "ecdsa-p256", "exportable": False, "allow_plaintext_backup": False}
    assert calls[2][2] == {"policy": 'path "transit/sign/issuer" { capabilities = ["update"] }'}
    assert calls[3][2] == {"policies": ["sign-issuer"], "no_default_policy": True, "ttl": "10m", "renewable": False}
    assert calls[4][2] == {"token": token, "paths": ["transit/sign/issuer", "transit/sign/holder"]}


def test_create_role_rejects_cross_key_permission(monkeypatch: pytest.MonkeyPatch) -> None:
    def api(_base: str, _context: object, _token: str, path: str, payload: dict | None = None) -> dict:
        if path == "transit/keys/issuer" and payload is None:
            return {
                "data": {
                    "type": "ecdsa-p256",
                    "exportable": False,
                    "allow_plaintext_backup": False,
                    "latest_version": 1,
                    "keys": {"1": {"public_key": public_pem()}},
                }
            }
        if path == "auth/token/create":
            return {"auth": {"client_token": "overbroad-token"}}
        if path == "sys/capabilities":
            return {"data": {"transit/sign/issuer": ["update"], "transit/sign/holder": ["update"]}}
        return {}

    monkeypatch.setattr(fixture, "api", api)
    with pytest.raises(RuntimeError, match="independently scoped"):
        fixture.create_role("https://127.0.0.1:8200", object(), "root", "issuer", "holder", kid=None)


def test_startup_failure_removes_only_owned_container(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    producer = tmp_path / "marty-kms-positive-verifier-input.exe"
    agent = tmp_path / "marty-test-signer-agent.exe"
    producer.touch()
    agent.touch()
    calls: list[tuple[str, ...]] = []

    def docker(*args: str, timeout: int = 30) -> str:
        del timeout
        calls.append(args)
        if args[0] == "port":
            return "127.0.0.1:49201"
        if args[0] == "exec":
            return "placeholder-ca"
        return ""

    def api(_base: str, _context: object, _token: str, path: str, _payload: dict | None = None) -> dict:
        if path == "sys/mounts/transit":
            raise RuntimeError("synthetic OpenBao mount failure")
        return {}

    monkeypatch.setattr(fixture, "docker", docker)
    monkeypatch.setattr(fixture, "api", api)
    monkeypatch.setattr(fixture.ssl, "create_default_context", lambda **_kwargs: object())
    with pytest.raises(RuntimeError, match="synthetic OpenBao mount failure"):
        fixture.run(producer, agent, ["unused-command"])
    name = calls[0][calls[0].index("--name") + 1]
    assert name.startswith("marty-verifier-kms-")
    assert calls[-1] == ("rm", "-f", name)
    assert sum(call[:1] == ("rm",) for call in calls) == 1


def test_timed_out_startup_removes_only_labelled_container(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    producer = tmp_path / "marty-kms-positive-verifier-input.exe"
    agent = tmp_path / "marty-test-signer-agent.exe"
    producer.touch()
    agent.touch()
    calls: list[tuple[str, ...]] = []

    def docker(*args: str, timeout: int = 30) -> str:
        del timeout
        calls.append(args)
        if args[0] == "run":
            raise subprocess.TimeoutExpired("docker run", 60)
        if args[0] == "ps":
            return "owned-container-id"
        return ""

    monkeypatch.setattr(fixture, "docker", docker)
    with pytest.raises(subprocess.TimeoutExpired):
        fixture.run(producer, agent, ["unused-command"])
    label = calls[0][calls[0].index("--label") + 1]
    assert calls[1] == ("ps", "-aq", "--filter", "label=" + label)
    assert calls[2] == ("rm", "-f", "owned-container-id")


def test_windows_requires_both_signer_pipes_to_accept_connections(monkeypatch: pytest.MonkeyPatch) -> None:
    ready = {r"\\.\pipe\issuer"}
    monkeypatch.setattr(fixture, "windows_pipe_ready", lambda endpoint: endpoint in ready)
    endpoints = [r"\\.\pipe\issuer", r"\\.\pipe\holder"]
    assert not fixture.endpoints_ready(endpoints, windows=True)
    ready.add(r"\\.\pipe\holder")
    assert fixture.endpoints_ready(endpoints, windows=True)
