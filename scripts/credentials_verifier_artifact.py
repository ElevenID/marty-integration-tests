#!/usr/bin/env python3
"""Exercise the immutable Marty Credentials verification service image."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import secrets
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, NamedTuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PIN = ROOT / "config" / "credentials-verifier-under-test.json"
BASE_IMAGES = ROOT / "config" / "base-images.json"
PIN_SCHEMA = "elevenid.credentials-verifier-artifact-pin/v1"
RUST_PIN_SCHEMA = "elevenid.credentials-verifier-artifact-pin/v2"
EVIDENCE_SCHEMA = "elevenid.credentials-verifier-artifact-evidence/v1"
RUST_EVIDENCE_SCHEMA = "elevenid.credentials-verifier-artifact-evidence/v2"
EXPECTED_REPOSITORY = "ElevenID/marty-credentials"
EXPECTED_IMAGE_URI = "ghcr.io/elevenid/marty-credentials-verification"
RUST_REPOSITORY = "ElevenID/marty-ui"
RUST_IMAGE_URI = "ghcr.io/elevenid/marty-ui-oss/services"
EXPECTED_COMPONENT_ID = "marty-credentials"
EXPECTED_ADAPTER_ID = "verification-service"
EXPECTED_SBOM_PACKAGES = {"marty-rs", "marty-verification-py"}
VDS_PURPOSE = "verification.vds-nc"
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SEMVER_TAG = re.compile(r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
VERSION = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")


class ArtifactTarget(NamedTuple):
    repository: str
    image_uri: str
    sbom_asset: str
    service_port: int
    service_name: str | None
    migration_entrypoint: str | None
    migration_args: tuple[str, ...]
    evidence_schema: str


LEGACY_TARGET = ArtifactTarget(
    repository=EXPECTED_REPOSITORY,
    image_uri=EXPECTED_IMAGE_URI,
    sbom_asset="marty-credentials-verification.spdx.json",
    service_port=8006,
    service_name=None,
    migration_entrypoint=None,
    migration_args=("python", "manage_migrations.py", "upgrade"),
    evidence_schema=EVIDENCE_SCHEMA,
)
RUST_TARGET = ArtifactTarget(
    repository=RUST_REPOSITORY,
    image_uri=RUST_IMAGE_URI,
    sbom_asset="marty-ui-services-sbom.cdx.json",
    service_port=8012,
    service_name="verification",
    migration_entrypoint="/app/services/entrypoint.sh",
    migration_args=("migrate",),
    evidence_schema=RUST_EVIDENCE_SCHEMA,
)


def artifact_target(pin: dict[str, Any]) -> ArtifactTarget:
    schema = pin.get("schema")
    if schema == PIN_SCHEMA:
        return LEGACY_TARGET
    if schema == RUST_PIN_SCHEMA:
        return RUST_TARGET
    raise ValueError(f"artifact pin must use {PIN_SCHEMA} or {RUST_PIN_SCHEMA}")


class ArtifactRuntimeError(RuntimeError):
    """A fixed-category artifact test failure that never includes test secrets."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def canonical_digest(value: Any) -> str:
    return f"sha256:{hashlib.sha256(canonical_json(value)).hexdigest()}"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load_pin(path: Path = DEFAULT_PIN) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    target = artifact_target(value)
    _require(value.get("state") == "ready", "artifact pin must be ready")
    _require(value.get("repository") == target.repository, "artifact repository does not match its schema")
    _require(bool(SEMVER_TAG.fullmatch(str(value.get("release_tag", "")))), "release_tag must be stable SemVer")
    _require(bool(VERSION.fullmatch(str(value.get("version", "")))), "version must be stable SemVer")
    _require(value["release_tag"] == f"v{value['version']}", "release_tag and version must agree")
    _require(bool(COMMIT.fullmatch(str(value.get("commit", "")))), "commit must be a full lowercase SHA")
    expected_source_ref = "refs/heads/main" if target is LEGACY_TARGET else f"refs/tags/{value['release_tag']}"
    _require(
        value.get("source_ref") == expected_source_ref,
        "source_ref must identify the attested release source",
    )

    image = value.get("image")
    _require(isinstance(image, dict), "image pin is required")
    _require(image.get("uri") == target.image_uri, "unexpected verification image URI")
    _require(
        "@" not in image["uri"] and ":" not in image["uri"].split("/", 1)[1],
        "image URI must not contain a mutable tag",
    )
    _require(bool(SHA256.fullmatch(str(image.get("digest", "")))), "image digest must be sha256:<64 lowercase hex>")

    sbom = value.get("sbom")
    _require(isinstance(sbom, dict), "SBOM pin is required")
    _require(sbom.get("asset") == target.sbom_asset, "unexpected verification SBOM asset")
    _require(bool(SHA256.fullmatch(str(sbom.get("digest", "")))), "SBOM digest must be sha256:<64 lowercase hex>")
    return value


def image_reference(pin: dict[str, Any]) -> str:
    return f"{pin['image']['uri']}@{pin['image']['digest']}"


def validate_sbom(path: Path, pin: dict[str, Any]) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    _require(isinstance(value, dict), "verification SBOM must be a JSON object")
    target = artifact_target(pin)
    if target is LEGACY_TARGET:
        _require(value.get("spdxVersion") == "SPDX-2.3", "verification SBOM must use SPDX 2.3")
        _require(value.get("name") == target.image_uri, "verification SBOM describes an unexpected image")
        packages = value.get("packages")
        _require(isinstance(packages, list), "verification SBOM packages are required")
        package_objects = [package for package in packages if isinstance(package, dict)]
        roots = [package for package in package_objects if package.get("name") == target.image_uri]
        _require(len(roots) == 1, "verification SBOM must contain exactly one image root package")
        _require(
            roots[0].get("versionInfo") == pin["image"]["digest"],
            "verification SBOM root is not bound to the pinned image digest",
        )
        package_names = {str(package.get("name")) for package in package_objects}
        _require(
            EXPECTED_SBOM_PACKAGES.issubset(package_names),
            "verification SBOM is missing required native Marty packages",
        )
    else:
        _require(value.get("bomFormat") == "CycloneDX", "verification SBOM must use CycloneDX")
        _require(value.get("specVersion") == "1.6", "verification SBOM must use CycloneDX 1.6")
        metadata = value.get("metadata")
        _require(isinstance(metadata, dict), "verification SBOM metadata is required")
        component = metadata.get("component")
        _require(isinstance(component, dict), "verification SBOM image component is required")
        _require(component.get("name") == target.image_uri, "verification SBOM describes an unexpected image")
        _require(
            component.get("version") == pin["image"]["digest"],
            "verification SBOM root is not bound to the pinned image digest",
        )
    return value


def load_postgres_image(path: Path = BASE_IMAGES) -> str:
    value = json.loads(path.read_text(encoding="utf-8")).get("postgres")
    _require(isinstance(value, str), "PostgreSQL base image pin is required")
    _require(
        bool(re.fullmatch(r"docker\.io/library/postgres@sha256:[0-9a-f]{64}", value)),
        "PostgreSQL image must be digest-pinned",
    )
    return value


def build_governance(pin: dict[str, Any], api_key: str, organization_id: str, issuer_did: str) -> dict[str, Any]:
    policy_content = {
        "verifier_id": "did:web:vds-verifier.integration.invalid",
        "presentation_definition_digest": pin["image"]["digest"],
        "required_checks": ["credential.proof", "issuer.trust"],
    }
    trust_content = {
        "trusted_issuers": [issuer_did],
        "allow_public_did_fallback": False,
    }
    return {
        "component": {
            "component_id": EXPECTED_COMPONENT_ID,
            "version": pin["version"],
            "artifact_digest": pin["image"]["digest"],
            "adapter_id": EXPECTED_ADAPTER_ID,
            "adapter_version": "1.0.0",
        },
        "policies": [
            {
                "organization_id": organization_id,
                "id": "policy:vds-artifact-integration",
                "version": "1.0.0",
                "content_digest": canonical_digest(policy_content),
                "content": policy_content,
            }
        ],
        "trust_profiles": [
            {
                "organization_id": organization_id,
                "id": "trust:vds-artifact-integration",
                "version": "1.0.0",
                "content_digest": canonical_digest(trust_content),
                "content": trust_content,
            }
        ],
        "clients": [
            {
                "client_id": "artifact-integration-client",
                "api_key_sha256": hashlib.sha256(api_key.encode("utf-8")).hexdigest(),
                "organization_id": organization_id,
                "purposes": {
                    VDS_PURPOSE: {
                        "policy_id": "policy:vds-artifact-integration",
                        "trust_profile_id": "trust:vds-artifact-integration",
                    }
                },
            }
        ],
    }


def invalid_governance_missing_required_check(governance: dict[str, Any]) -> dict[str, Any]:
    value = json.loads(json.dumps(governance))
    content = value["policies"][0]["content"]
    content["required_checks"] = ["credential.proof"]
    value["policies"][0]["content_digest"] = canonical_digest(content)
    return value


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def make_vds_key_material(
    issuer_did: str,
) -> tuple[ec.EllipticCurvePrivateKey, dict[str, Any], str]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public = private_key.public_key().public_numbers()
    method_id = f"{issuer_did}#vdsnc-key"
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "x": _b64url(public.x.to_bytes(32, "big")),
        "y": _b64url(public.y.to_bytes(32, "big")),
        "kid": method_id,
    }
    return private_key, jwk, method_id


def make_vds_barcode(
    issuer_did: str,
    method_id: str,
    private_key: ec.EllipticCurvePrivateKey,
) -> str:
    today = datetime.now(UTC).date()
    claims = {
        "dateOfBirth": "19900102",
        "dateOfExpiry": (today + timedelta(days=365)).strftime("%Y%m%d"),
        "dateOfIssue": (today - timedelta(days=1)).strftime("%Y%m%d"),
        "docType": "CMC",
        "documentNumber": "X123456",
        "gender": "F",
        "givenNames": "ADA",
        "issuingCountry": "USA",
        "nationality": "USA",
        "surname": "EXAMPLE",
    }
    payload = {
        **claims,
        "_vds": {
            "version": "1.0",
            "documentType": "CMC",
            "issuerId": issuer_did,
            "keyId": method_id,
            "algorithm": "ES256",
        },
    }
    signing_input = f"DC03{claims['issuingCountry']}~{canonical_json(payload).decode('utf-8')}"

    der = private_key.sign(signing_input.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    r_value, s_value = decode_dss_signature(der)
    raw_signature = r_value.to_bytes(32, "big") + s_value.to_bytes(32, "big")
    barcode = f"{signing_input}~{base64.b64encode(raw_signature).decode('ascii')}"
    _require(barcode.count("~") == 2, "VDS-NC fixture assembly returned a malformed barcode")
    return barcode


class ResolverState:
    def __init__(
        self,
        *,
        api_key: str,
        organization_id: str,
        issuer_did: str,
        method_id: str,
        public_jwk: dict[str, Any],
    ) -> None:
        self.api_key = api_key
        self.organization_id = organization_id
        self.issuer_did = issuer_did
        self.method_id = method_id
        self.public_jwk = public_jwk
        self.request_count = 0

    def response(self) -> dict[str, Any]:
        method = {
            "id": self.method_id,
            "controller": self.issuer_did,
            "type": "JsonWebKey2020",
            "publicKeyJwk": self.public_jwk,
        }
        return {
            "ok": True,
            "organization_id": self.organization_id,
            "issuer_did": self.issuer_did,
            "verification_method_id": self.method_id,
            "verification_method": method,
            "public_jwk": self.public_jwk,
            "did_document": {
                "id": self.issuer_did,
                "verificationMethod": [method],
                "assertionMethod": [self.method_id],
            },
            "resolver": {
                "type": "organization_issuer_profile",
                "public_fallback_used": False,
            },
        }


def _resolver_handler(state: ResolverState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urllib.parse.urlsplit(self.path)
            params = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
            expected = {
                "organization_id": [state.organization_id],
                "issuer_did": [state.issuer_did],
                "verification_method_id": [state.method_id],
                "credential_format": ["vds_nc"],
                "key_purpose": ["vdsnc_signing"],
                "algorithm": ["ES256"],
            }
            if self.headers.get("X-API-Key") != state.api_key:
                self._json(401, {"detail": "unauthorized"})
                return
            if parsed.path != "/internal/signing-keys/resolve-issuer-did" or params != expected:
                self._json(422, {"detail": "request binding mismatch"})
                return
            state.request_count += 1
            self._json(200, state.response())

        def _json(self, status: int, value: dict[str, Any]) -> None:
            body = canonical_json(value)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: Any) -> None:
            return

    return Handler


@contextmanager
def resolver_server(state: ResolverState) -> Iterator[int]:
    server = ThreadingHTTPServer(("0.0.0.0", 0), _resolver_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _run(command: list[str], *, label: str, timeout: int = 120) -> str:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ArtifactRuntimeError(f"{label} could not complete") from exc
    if completed.returncode != 0:
        raise ArtifactRuntimeError(f"{label} failed with exit code {completed.returncode}")
    return completed.stdout.strip()


def _docker_remove(kind: str, name: str) -> None:
    subprocess.run(
        ["docker", kind, "rm", "-f", name] if kind == "container" else ["docker", "network", "rm", name],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def _wait_for_postgres(container: str) -> None:
    for _ in range(60):
        completed = subprocess.run(
            ["docker", "exec", container, "pg_isready", "-U", "postgres", "-d", "verifier"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if completed.returncode == 0:
            return
        time.sleep(1)
    raise ArtifactRuntimeError("postgres readiness timed out")


def _http_json(
    method: str,
    url: str,
    *,
    body: dict[str, Any] | None = None,
    api_key: str | None = None,
    expected_status: int,
) -> dict[str, Any]:
    headers = {"Accept": "application/json"}
    data = None
    if body is not None:
        data = canonical_json(body)
        headers["Content-Type"] = "application/json"
    if api_key is not None:
        headers["X-API-Key"] = api_key
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            status = response.status
            payload = response.read()
    except urllib.error.HTTPError as error:
        status = error.code
        payload = error.read()
    except OSError as exc:
        raise ArtifactRuntimeError("verification service request failed") from exc
    if status != expected_status:
        raise ArtifactRuntimeError(f"verification service returned unexpected HTTP status for {method}")
    try:
        value = json.loads(payload) if payload else {}
    except json.JSONDecodeError as exc:
        raise ArtifactRuntimeError("verification service returned malformed JSON") from exc
    if not isinstance(value, dict):
        raise ArtifactRuntimeError("verification service returned a non-object response")
    return value


def _wait_for_health(base_url: str, container: str) -> dict[str, Any]:
    for _ in range(90):
        running = _run(
            ["docker", "inspect", "--format", "{{.State.Running}}", container],
            label="inspect verification service",
        )
        if running != "true":
            raise ArtifactRuntimeError("verification service exited before becoming healthy")
        try:
            return _http_json("GET", f"{base_url}/health", expected_status=200)
        except ArtifactRuntimeError:
            time.sleep(1)
    raise ArtifactRuntimeError("verification service health timed out")


def _assert_health(value: dict[str, Any], target: ArtifactTarget) -> None:
    _require(value.get("status") == "healthy", "verification health is not healthy")
    backend = value.get("native_backend")
    if target is RUST_TARGET:
        _require(value.get("service") == "verification", "verification health reported the wrong service")
        _require(isinstance(backend, dict) and backend.get("available") is True, "Rust backend is unavailable")
        _require(
            backend.get("module") == "marty-verification-service",
            "verification health did not report the canonical Rust service",
        )
        _require(bool(VERSION.fullmatch(str(backend.get("version", "")))), "Rust verification version is invalid")
        _require(backend.get("missing_capabilities") == [], "Rust verification capabilities are incomplete")
        _require(backend.get("error") is None, "Rust verification diagnostic reported an error")
        return
    _require(isinstance(backend, dict) and backend.get("available") is True, "native backend is unavailable")
    _require(backend.get("module") == "_marty_rs", "verification health reported an unexpected native module")
    _require(bool(VERSION.fullmatch(str(backend.get("version", "")))), "native backend version is invalid")
    _require(backend.get("missing_capabilities") == [], "verification image is missing required native capabilities")
    _require(backend.get("error") is None, "verification native diagnostic reported an error")


def _assert_canonical(value: dict[str, Any], *, decision: str) -> dict[str, Any]:
    canonical = value.get("canonical_result")
    _require(isinstance(canonical, dict), "verification response omitted canonical_result")
    _require(canonical.get("decision") == decision, f"canonical decision was not {decision}")
    _require(value.get("decision") == decision, "legacy decision projection diverged")
    _require(value.get("overall_result") == decision, "overall_result projection diverged")
    _require(value.get("valid") is (decision == "PASS"), "valid projection diverged")
    _require(canonical.get("valid") is (decision == "PASS"), "canonical valid diverged")
    _require(canonical.get("processing_status") == "COMPLETED", "canonical processing did not complete")
    checks = canonical.get("checks")
    _require(isinstance(checks, list) and len(checks) == 2, "VDS canonical result must contain exactly two checks")
    ids = {check.get("check_id") for check in checks if isinstance(check, dict)}
    _require(ids == {"credential.proof", "issuer.trust"}, "VDS canonical check floor changed")
    if decision == "PASS":
        _require(all(check.get("outcome") == "PASSED" for check in checks), "PASS contained a non-passing check")
    else:
        _require(any(check.get("outcome") == "FAILED" for check in checks), "FAIL contained no failing check")
    return canonical


def _assert_private_material_absent(value: dict[str, Any], prohibited: list[str]) -> None:
    serialized = json.dumps(value, sort_keys=True)
    for item in prohibited:
        _require(item not in serialized, "canonical response retained private test material")


def _service_port(container: str, target: ArtifactTarget) -> int:
    output = _run(
        ["docker", "port", container, f"{target.service_port}/tcp"],
        label="resolve service port",
    )
    line = output.splitlines()[0]
    try:
        return int(line.rsplit(":", 1)[1])
    except (IndexError, ValueError) as exc:
        raise ArtifactRuntimeError("verification service port mapping was invalid") from exc


def _migration_command(
    reference: str,
    target: ArtifactTarget,
    network: str,
    database_url: str,
) -> list[str]:
    command = [
        "docker",
        "run",
        "--rm",
        "--network",
        network,
        "-e",
        f"DATABASE_URL={database_url}",
    ]
    if target.service_name is not None:
        command.extend(["-e", f"SERVICE_NAME={target.service_name}"])
    if target.migration_entrypoint is not None:
        command.extend(["--entrypoint", target.migration_entrypoint])
    command.append(reference)
    command.extend(target.migration_args)
    return command


def run_artifact_test(pin: dict[str, Any], evidence_path: Path, *, provenance_verified: bool) -> dict[str, Any]:
    _require(provenance_verified, "artifact provenance must be verified before runtime testing")
    target = artifact_target(pin)
    postgres_image = load_postgres_image()
    reference = image_reference(pin)
    suffix = uuid.uuid4().hex[:12]
    network = f"marty-verifier-{suffix}"
    postgres = f"marty-verifier-db-{suffix}"
    service = f"marty-verifier-api-{suffix}"
    invalid_service = f"marty-verifier-invalid-{suffix}"
    database_password = secrets.token_urlsafe(32)
    api_key = secrets.token_urlsafe(32)
    resolver_key = secrets.token_urlsafe(32)
    organization_id = str(uuid.uuid4())
    issuer_did = "did:web:vds-issuer.integration.invalid"
    private_key, public_jwk, method_id = make_vds_key_material(issuer_did)
    barcode = make_vds_barcode(issuer_did, method_id, private_key)
    governance = build_governance(pin, api_key, organization_id, issuer_did)
    database_url = f"postgresql+asyncpg://postgres:{database_password}@{postgres}:5432/verifier"
    completed_checks: list[str] = []
    state = ResolverState(
        api_key=resolver_key,
        organization_id=organization_id,
        issuer_did=issuer_did,
        method_id=method_id,
        public_jwk=public_jwk,
    )
    started = datetime.now(UTC)

    try:
        _run(["docker", "network", "create", network], label="create isolated network")
        _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                postgres,
                "--network",
                network,
                "--network-alias",
                postgres,
                "-e",
                f"POSTGRES_PASSWORD={database_password}",
                "-e",
                "POSTGRES_DB=verifier",
                postgres_image,
            ],
            label="start digest-pinned postgres",
        )
        _wait_for_postgres(postgres)
        completed_checks.append("postgres.ready")

        _run(
            _migration_command(reference, target, network, database_url),
            label="apply released verification migrations",
            timeout=180,
        )
        migration_table_count = _run(
            [
                "docker",
                "exec",
                postgres,
                "psql",
                "-U",
                "postgres",
                "-d",
                "verifier",
                "-tAc",
                (
                    "SELECT count(*) FROM information_schema.tables "
                    "WHERE table_schema='verification_service' "
                    "AND table_name='alembic_version'"
                ),
            ],
            label="verify migration version table",
        )
        _require(migration_table_count == "1", "verification migration version table is missing")
        completed_checks.append("migrations.applied")

        invalid_governance = invalid_governance_missing_required_check(governance)
        invalid_command = [
            "docker",
            "run",
            "--rm",
            "--name",
            invalid_service,
            "-e",
            f"VERIFICATION_GOVERNANCE_JSON={json.dumps(invalid_governance, separators=(',', ':'))}",
        ]
        if target is RUST_TARGET:
            invalid_command.extend(
                [
                    "--network",
                    network,
                    "-e",
                    f"SERVICE_NAME={target.service_name}",
                    "-e",
                    "VERIFICATION_CREDENTIALS_COMPAT_ENABLED=true",
                    "-e",
                    f"DATABASE_URL={database_url}",
                    "-e",
                    f"SIGNING_KEYS_INTERNAL_API_KEY={resolver_key}",
                    "-e",
                    "ENVIRONMENT=test",
                    reference,
                ]
            )
        else:
            invalid_command.extend(
                [
                    reference,
                    "python",
                    "-c",
                    "from verification.application.governance import load_governance; load_governance()",
                ]
            )
        try:
            invalid = subprocess.run(
                invalid_command,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ArtifactRuntimeError("invalid governance was not rejected at startup") from exc
        finally:
            _docker_remove("container", invalid_service)
        _require(invalid.returncode != 0, "governance missing mandatory checks was accepted")
        completed_checks.append("governance.missing-required-check-rejected")

        with resolver_server(state) as resolver_port:
            service_command = [
                "docker",
                "run",
                "-d",
                "--name",
                service,
                "--network",
                network,
                "--add-host",
                "host.docker.internal:host-gateway",
                "-p",
                f"127.0.0.1::{target.service_port}",
                "-e",
                f"DATABASE_URL={database_url}",
                "-e",
                f"VERIFICATION_GOVERNANCE_JSON={json.dumps(governance, separators=(',', ':'))}",
                "-e",
                f"SIGNING_KEYS_INTERNAL_URL=http://host.docker.internal:{resolver_port}/internal/signing-keys",
                "-e",
                f"SIGNING_KEYS_INTERNAL_API_KEY={resolver_key}",
                "-e",
                "ENVIRONMENT=test",
            ]
            if target.service_name is not None:
                service_command.extend(
                    [
                        "-e",
                        f"SERVICE_NAME={target.service_name}",
                        "-e",
                        "VERIFICATION_CREDENTIALS_COMPAT_ENABLED=true",
                    ]
                )
            service_command.append(reference)
            _run(
                service_command,
                label="start released verification image",
            )
            base_url = f"http://127.0.0.1:{_service_port(service, target)}"
            health = _wait_for_health(base_url, service)
            _assert_health(health, target)
            compatibility_health = _http_json(
                "GET",
                f"{base_url}/v1/verification/health",
                expected_status=200,
            )
            _require(compatibility_health == {"status": "healthy"}, "compatibility health contract changed")
            completed_checks.append("health.native-capabilities")

            endpoint = f"{base_url}/v1/verification/verify/vds-nc"
            request_body = {
                "barcode": barcode,
                "issuer_did": issuer_did,
                "verification_method_id": method_id,
                "algorithm": "ES256",
            }
            _http_json("POST", endpoint, body=request_body, expected_status=401)
            _http_json("POST", endpoint, body=request_body, api_key="invalid", expected_status=401)
            completed_checks.append("authorization.missing-and-invalid-rejected")

            caller_selected = {**request_body, "organization_id": organization_id}
            _http_json("POST", endpoint, body=caller_selected, api_key=api_key, expected_status=422)
            completed_checks.append("authority.caller-selection-rejected")

            resolver_before = state.request_count
            untrusted = {**request_body, "issuer_did": "did:web:attacker.integration.invalid"}
            _http_json("POST", endpoint, body=untrusted, api_key=api_key, expected_status=500)
            _require(state.request_count == resolver_before, "untrusted issuer reached the internal resolver")
            completed_checks.append("trust.unregistered-issuer-rejected-before-resolution")

            positive = _http_json("POST", endpoint, body=request_body, api_key=api_key, expected_status=200)
            _assert_canonical(positive, decision="PASS")
            _assert_private_material_absent(positive, [api_key, resolver_key, barcode])
            completed_checks.append("canonical.vds-positive-pass")

            tampered_signature = base64.b64encode(bytes(64)).decode("ascii")
            tampered = {**request_body, "barcode": barcode.rsplit("~", 1)[0] + "~" + tampered_signature}
            rejected = _http_json("POST", endpoint, body=tampered, api_key=api_key, expected_status=200)
            _assert_canonical(rejected, decision="FAIL")
            _assert_private_material_absent(rejected, [api_key, resolver_key, barcode])
            completed_checks.append("canonical.tampered-signature-fail")

            malformed = {**request_body, "barcode": "DC03USA~{}~not-base64"}
            malformed_result = _http_json("POST", endpoint, body=malformed, api_key=api_key, expected_status=200)
            _assert_canonical(malformed_result, decision="FAIL")
            _assert_private_material_absent(
                malformed_result,
                [api_key, resolver_key, malformed["barcode"]],
            )
            completed_checks.append("canonical.malformed-evidence-fail")

        evidence = {
            "schema": target.evidence_schema,
            "classification": "ElevenID-owned artifact integration",
            "official_suite_invoked": False,
            "official_suite_source_modified": False,
            "status": "passed",
            "subject": {
                "repository": pin["repository"],
                "release_tag": pin["release_tag"],
                "version": pin["version"],
                "commit": pin["commit"],
                "image_reference": reference,
                "sbom_digest": pin["sbom"]["digest"],
                "provenance_verified": True,
            },
            "checks": completed_checks,
            "resolver_request_count": state.request_count,
            "started_at": started.isoformat().replace("+00:00", "Z"),
            "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return evidence
    finally:
        _docker_remove("container", invalid_service)
        _docker_remove("container", service)
        _docker_remove("container", postgres)
        _docker_remove("network", network)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate-pin")
    validate.add_argument("--pin", type=Path, default=DEFAULT_PIN)
    sbom = commands.add_parser("validate-sbom")
    sbom.add_argument("--pin", type=Path, default=DEFAULT_PIN)
    sbom.add_argument("--sbom", type=Path, required=True)
    run = commands.add_parser("run")
    run.add_argument("--pin", type=Path, default=DEFAULT_PIN)
    run.add_argument("--evidence", type=Path, required=True)
    run.add_argument("--provenance-verified", action="store_true", required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    pin = load_pin(args.pin.resolve())
    if args.command == "validate-pin":
        print(json.dumps(pin, indent=2, sort_keys=True))
        return 0
    if args.command == "validate-sbom":
        value = validate_sbom(args.sbom.resolve(), pin)
        target = artifact_target(pin)
        summary = (
            {"name": value["name"], "format": value["spdxVersion"]}
            if target is LEGACY_TARGET
            else {"name": value["metadata"]["component"]["name"], "format": value["specVersion"]}
        )
        print(json.dumps(summary, sort_keys=True))
        return 0
    evidence = run_artifact_test(
        pin,
        args.evidence.resolve(),
        provenance_verified=args.provenance_verified,
    )
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ArtifactRuntimeError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Credentials verifier artifact error: {exc}")
        raise SystemExit(2) from exc
