#!/usr/bin/env python3
"""Run a verifier command with two scoped signers on owned Docker OpenBao.

This fixture emits no key material. OpenBao owns non-exportable issuer and
holder keys; the Core producer emits only a presentation and public JWK.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import json
import os
import re
import secrets
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

OPENBAO_IMAGE = "quay.io/openbao/openbao@sha256:6150c4a6b62067db6141c8da7a6a6b5763f4f47c315343d0c848b40fecdfd452"
ISSUER_KID = "did:example:verifier-runtime-gate-issuer#key-1"
HOLDER_KID = "did:example:runtime-gate-holder"


def docker(*args: str, timeout: int = 30) -> str:
    result = subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(f"disposable Docker command failed: {args[0]}")
    return result.stdout.strip()


def api(base: str, context: ssl.SSLContext, token: str, path: str, payload: dict | None = None) -> dict:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        base + "/v1/" + path,
        data=data,
        headers={"X-Vault-Token": token, "Content-Type": "application/json"},
        method="GET" if data is None else "POST",
    )
    try:
        with urllib.request.urlopen(request, context=context, timeout=5) as response:
            body = response.read()
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"disposable OpenBao request failed: {path} (HTTP {exc.code})") from exc
    except (urllib.error.URLError, ValueError) as exc:
        raise RuntimeError(f"disposable OpenBao request failed: {path}") from exc


def public_jwk(pem: str, *, kid: str | None) -> dict[str, str]:
    key = serialization.load_pem_public_key(pem.encode("ascii"))
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise RuntimeError("disposable KMS key is not P-256")
    point = key.public_numbers()

    def encode(value: int) -> str:
        return base64.urlsafe_b64encode(value.to_bytes(32, "big")).rstrip(b"=").decode("ascii")

    jwk = {"kty": "EC", "crv": "P-256", "x": encode(point.x), "y": encode(point.y)}
    if kid is not None:
        jwk.update({"kid": kid, "alg": "ES256"})
    return jwk


def create_role(
    base: str, context: ssl.SSLContext, root: str, name: str, other: str, *, kid: str | None
) -> tuple[dict, str]:
    api(
        base,
        context,
        root,
        f"transit/keys/{name}",
        {
            "type": "ecdsa-p256",
            "exportable": False,
            "allow_plaintext_backup": False,
        },
    )
    key = api(base, context, root, f"transit/keys/{name}")["data"]
    if (
        key.get("type") != "ecdsa-p256"
        or key.get("exportable") is not False
        or key.get("allow_plaintext_backup") is not False
    ):
        raise RuntimeError("disposable KMS key policy changed")
    public = public_jwk(key["keys"][str(key["latest_version"])]["public_key"], kid=kid)
    policy = "sign-" + name
    api(
        base,
        context,
        root,
        f"sys/policies/acl/{policy}",
        {
            "policy": f'path "transit/sign/{name}" {{ capabilities = ["update"] }}',
        },
    )
    scoped = api(
        base,
        context,
        root,
        "auth/token/create",
        {
            "policies": [policy],
            "no_default_policy": True,
            "ttl": "10m",
            "renewable": False,
        },
    )["auth"]["client_token"]
    own = api(
        base,
        context,
        root,
        "sys/capabilities",
        {
            "token": scoped,
            "paths": [f"transit/sign/{name}", f"transit/sign/{other}"],
        },
    )["data"]
    if "update" not in own[f"transit/sign/{name}"] or own[f"transit/sign/{other}"] != ["deny"]:
        raise RuntimeError("disposable signer tokens are not independently scoped")
    return public, scoped


def start_agent(
    path: Path,
    env: dict[str, str],
    endpoint: str,
    authentication: str,
    base: str,
    key_name: str,
    key_id: str,
    token: str,
    ca: Path,
) -> subprocess.Popen:
    agent_env = env | {
        "MARTY_TEST_WALLET_HOLDER_SIGNER_ENDPOINT": endpoint,
        "MARTY_TEST_WALLET_HOLDER_SIGNER_AUTHENTICATION_KEY": authentication,
        "MARTY_TEST_SIGNER_AGENT_KMS_PROVIDER": "openbao-transit",
        "MARTY_TEST_SIGNER_AGENT_KMS_URL": base + "/v1/transit/sign/" + key_name,
        "MARTY_TEST_SIGNER_AGENT_KMS_BEARER_TOKEN": token,
        "MARTY_TEST_SIGNER_AGENT_KMS_CA_CERT_PEM": str(ca),
        "MARTY_TEST_SIGNER_AGENT_ALLOWED_KEY_ID": key_id,
    }
    return subprocess.Popen([str(path)], env=agent_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def windows_pipe_ready(endpoint: str) -> bool:
    # WaitNamedPipeW tests for an accepting server without consuming a signer connection.
    return bool(ctypes.windll.kernel32.WaitNamedPipeW(ctypes.c_wchar_p(endpoint), 0))


def endpoints_ready(endpoints: list[str], *, windows: bool) -> bool:
    if windows:
        return all(windows_pipe_ready(endpoint) for endpoint in endpoints)
    return all(Path(endpoint).is_socket() for endpoint in endpoints)


def run(producer: Path, agent: Path, command: list[str]) -> int:
    if (
        not producer.is_file()
        or producer.name not in {"marty-kms-positive-verifier-input", "marty-kms-positive-verifier-input.exe"}
        or not agent.is_file()
        or agent.name not in {"marty-test-signer-agent", "marty-test-signer-agent.exe"}
    ):
        raise RuntimeError("Core producer or signer executable is missing")
    if not command:
        raise RuntimeError("a verifier qualification command is required")
    suffix = secrets.token_hex(8)
    name = "marty-verifier-kms-" + suffix
    root = secrets.token_hex(32)
    processes: list[subprocess.Popen] = []
    started = False
    attempted = False
    with tempfile.TemporaryDirectory(prefix="marty-verifier-kms-") as temporary:
        private = Path(temporary)
        if os.name == "posix":
            private.chmod(0o700)
        try:
            attempted = True
            docker(
                "run",
                "--rm",
                "-d",
                "--name",
                name,
                "--label",
                "marty.verifier.fixture=" + suffix,
                "--tmpfs",
                "/tmp/certs:mode=0777",
                "-e",
                "BAO_DEV_ROOT_TOKEN_ID=" + root,
                "-p",
                "127.0.0.1::8200",
                OPENBAO_IMAGE,
                "server",
                "-dev-tls",
                "-dev-tls-cert-dir=/tmp/certs",
                "-dev-listen-address=:8200",
                timeout=60,
            )
            started = True
            binding = docker("port", name, "8200/tcp")
            match = re.fullmatch(r"127\.0\.0\.1:([0-9]+)", binding)
            if match is None:
                raise RuntimeError("disposable OpenBao port is not loopback-bound")
            base = "https://127.0.0.1:" + match.group(1)
            ca = private / "openbao-ca.pem"
            for attempt in range(30):
                try:
                    pem = docker("exec", name, "cat", "/tmp/certs/vault-ca.pem")
                    ca.write_text(pem + "\n", encoding="ascii")
                    context = ssl.create_default_context(cafile=str(ca))
                    api(base, context, root, "sys/health")
                    break
                except (RuntimeError, OSError) as exc:
                    if attempt == 29:
                        raise RuntimeError("disposable OpenBao did not become ready") from exc
                    time.sleep(1)
            api(base, context, root, "sys/mounts/transit", {"type": "transit"})
            issuer_name, holder_name = "issuer-" + suffix, "holder-" + suffix
            issuer_jwk, issuer_token = create_role(base, context, root, issuer_name, holder_name, kid=ISSUER_KID)
            holder_jwk, holder_token = create_role(base, context, root, holder_name, issuer_name, kid=None)
            if (issuer_jwk["x"], issuer_jwk["y"]) == (holder_jwk["x"], holder_jwk["y"]):
                raise RuntimeError("issuer and holder share a KMS key")
            auth = [base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii") for _ in range(2)]
            if os.name == "nt":
                endpoints = [rf"\\.\pipe\marty-test-wallet-{suffix}-{role}" for role in ("issuer", "holder")]
            else:
                endpoints = [str(private / (role + ".sock")) for role in ("issuer", "holder")]
            env = os.environ.copy()
            processes.append(
                start_agent(agent, env, endpoints[0], auth[0], base, issuer_name, ISSUER_KID, issuer_token, ca)
            )
            processes.append(
                start_agent(agent, env, endpoints[1], auth[1], base, holder_name, HOLDER_KID, holder_token, ca)
            )
            for attempt in range(100):
                if any(process.poll() is not None for process in processes):
                    raise RuntimeError("disposable signer agent exited early")
                if endpoints_ready(endpoints, windows=os.name == "nt"):
                    break
                if attempt == 99:
                    raise RuntimeError("disposable signer agents did not become ready")
                time.sleep(0.2)
            env.update(
                {
                    "MARTY_POSITIVE_GATE_ISSUER_PUBLIC_JWK": json.dumps(issuer_jwk),
                    "MARTY_POSITIVE_GATE_ISSUER_KID": ISSUER_KID,
                    "MARTY_POSITIVE_GATE_ISSUER_SIGNER_ENDPOINT": endpoints[0],
                    "MARTY_POSITIVE_GATE_ISSUER_SIGNER_AUTHENTICATION_KEY": auth[0],
                    "MARTY_TEST_WALLET_HOLDER_PUBLIC_JWK": json.dumps(holder_jwk),
                    "MARTY_TEST_WALLET_HOLDER_KID": HOLDER_KID,
                    "MARTY_TEST_WALLET_HOLDER_SIGNER_ENDPOINT": endpoints[1],
                    "MARTY_TEST_WALLET_HOLDER_SIGNER_AUTHENTICATION_KEY": auth[1],
                    "MARTY_VERIFIER_POSITIVE_PRODUCER": str(producer.resolve()),
                    "MARTY_VERIFIER_POSITIVE_PRODUCER_SHA256": hashlib.sha256(producer.read_bytes()).hexdigest(),
                }
            )
            return subprocess.run(command, env=env, check=False).returncode
        finally:
            for process in processes:
                process.terminate()
            for process in processes:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            if started:
                docker("rm", "-f", name)
            elif attempted:
                # A timed-out Docker CLI may still have started its container.
                # Only remove a container carrying this invocation's random label.
                owned = docker("ps", "-aq", "--filter", "label=marty.verifier.fixture=" + suffix)
                for container_id in owned.splitlines():
                    docker("rm", "-f", container_id)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--producer", required=True, type=Path)
    parser.add_argument("--agent", required=True, type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    try:
        return run(args.producer, args.agent, command)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"Disposable verifier KMS fixture failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
