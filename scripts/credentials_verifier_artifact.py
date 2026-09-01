#!/usr/bin/env python3
"""Exercise the immutable Marty Credentials verification service image."""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import gzip
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import tarfile
import tempfile
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
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, NamedTuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PIN = ROOT / "config" / "credentials-verifier-oracle.json"
BASE_IMAGES = ROOT / "config" / "base-images.json"
PIN_SCHEMA = "elevenid.credentials-verifier-artifact-pin/v1"
RUST_PIN_SCHEMA = "elevenid.credentials-verifier-artifact-pin/v2"
CANDIDATE_PIN_SCHEMA = "elevenid.credentials-verifier-candidate-pin/v1"
EVIDENCE_SCHEMA = "elevenid.credentials-verifier-artifact-evidence/v1"
RUST_EVIDENCE_SCHEMA = "elevenid.credentials-verifier-artifact-evidence/v2"
CANDIDATE_EVIDENCE_SCHEMA = "elevenid.credentials-verifier-candidate-evidence/v1"
CANDIDATE_PROVENANCE_SCHEMA = "elevenid.marty-ui.services-candidate-provenance/v1"
CANDIDATE_METADATA_SCHEMA = "elevenid.marty-ui.services-candidate-build-metadata/v1"
EXPECTED_REPOSITORY = "ElevenID/marty-credentials"
EXPECTED_IMAGE_URI = "ghcr.io/elevenid/marty-credentials-verification"
RUST_REPOSITORY = "ElevenID/marty-ui"
RUST_IMAGE_URI = "ghcr.io/elevenid/marty-ui-oss/services"
CANDIDATE_LOCAL_IMAGE_REPOSITORY = "docker.io/elevenid/marty-ui-verification-candidate"
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_SBOM_BYTES = 128 * 1024 * 1024
MAX_CANDIDATE_METADATA_BYTES = 4 * 1024 * 1024
MAX_CANDIDATE_PROVENANCE_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 512
MAX_ARCHIVE_REGULAR_MEMBERS = 256
MAX_LAYERS = 64
MAX_COMPRESSED_LAYER_BYTES = 128 * 1024 * 1024
MAX_TOTAL_COMPRESSED_LAYER_BYTES = 512 * 1024 * 1024
MAX_EXPANDED_LAYER_BYTES = 256 * 1024 * 1024
MAX_TOTAL_EXPANDED_LAYER_BYTES = 1024 * 1024 * 1024
MAX_LAYER_MEMBERS = 20_000
MAX_TOTAL_LAYER_MEMBERS = 50_000
MAX_TAR_SPECIAL_HEADER_BYTES = 64 * 1024
MAX_TOTAL_TAR_SPECIAL_HEADER_BYTES = 4 * 1024 * 1024
MAX_TAR_SPECIAL_HEADERS = 256
MAX_SBOM_TOP_LEVEL_KEYS = 64
MAX_SBOM_COMPONENTS = 100_000
MAX_SBOM_DEPENDENCIES = 100_000
MAX_SBOM_DEPENDENCY_EDGES_PER_ENTRY = 20_000
MAX_TOTAL_SBOM_DEPENDENCY_EDGES = 100_000
MAX_SBOM_PROPERTIES = 4_096
MAX_SBOM_SCANNER_COMPONENTS = 64
TAR_BLOCK_BYTES = 512
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_GZIP_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"
OCI_PLATFORM_QUALIFIER_KEYS = frozenset({"variant", "os.version", "os.features"})
TAR_SPECIAL_HEADER_TYPES = frozenset(
    {
        tarfile.XHDTYPE,
        tarfile.XGLTYPE,
        tarfile.GNUTYPE_LONGNAME,
        tarfile.GNUTYPE_LONGLINK,
        tarfile.SOLARIS_XHDTYPE,
    }
)
# Python's tar reader does not consume data blocks for these supported types,
# even when a malformed raw header declares a non-zero size.
TAR_NON_DATA_HEADER_TYPES = frozenset(
    {
        tarfile.LNKTYPE,
        tarfile.SYMTYPE,
        tarfile.CHRTYPE,
        tarfile.BLKTYPE,
        tarfile.DIRTYPE,
        tarfile.FIFOTYPE,
    }
)
CYCLONEDX_COMPONENT_TYPES = {
    "application",
    "container",
    "cryptographic-asset",
    "data",
    "device",
    "device-driver",
    "file",
    "firmware",
    "framework",
    "library",
    "machine-learning-model",
    "operating-system",
    "platform",
}
EXPECTED_COMPONENT_ID = "marty-credentials"
EXPECTED_ADAPTER_ID = "verification-service"
EXPECTED_SBOM_PACKAGES = {"marty-rs", "marty-verification-py"}
SESSION_PURPOSE = "verification.session.create"
DIRECT_PURPOSE = "verification.direct"
VDS_PURPOSE = "verification.vds-nc"
VDS_PASS_CHECK_PROJECTION = {
    "credential.proof": ("PASSED", "CREDENTIAL_PROOFS_VALID"),
    "issuer.trust": ("PASSED", "ISSUER_TRUST_VALID"),
}
VDS_FAIL_CHECK_PROJECTION = {
    "credential.proof": ("FAILED", "CREDENTIAL_PROOFS_INVALID"),
    "issuer.trust": ("PASSED", "ISSUER_TRUST_VALID"),
}
VDS_SENSITIVE_SENTINELS = [
    "dateOfBirth",
    "dateOfExpiry",
    "dateOfIssue",
    "documentNumber",
    "gender",
    "givenNames",
    "issuingCountry",
    "nationality",
    "surname",
    "19900102",
    "X123456",
    "ADA",
    "EXAMPLE",
]
OID4VP_REQUIRED_CHECKS = [
    "presentation.structure",
    "presentation.proof",
    "credential.proof",
    "issuer.trust",
    "credential.status",
    "holder.binding",
    "transaction.binding",
    "claim.constraints",
]
OID4VP_PASS_CHECK_PROJECTION = {
    "presentation.structure": ("PASSED", "PRESENTATION_STRUCTURE_VALID"),
    "presentation.proof": ("PASSED", "PRESENTATION_PROOF_VALID"),
    "credential.proof": ("PASSED", "CREDENTIAL_PROOFS_VALID"),
    "issuer.trust": ("PASSED", "ISSUER_TRUST_VALID"),
    "credential.status": ("PASSED", "CREDENTIAL_STATUS_VALID"),
    "holder.binding": ("PASSED", "HOLDER_BINDING_VALID"),
    "transaction.binding": ("PASSED", "TRANSACTION_BINDING_VALID"),
    "claim.constraints": ("PASSED", "CLAIM_CONSTRAINTS_SATISFIED"),
}
KNOWN_INELIGIBLE_FAILURE_ID = "session.transaction-id-unscoped"
KNOWN_INELIGIBLE_FAILURE_MESSAGE = "session transaction ID changed outside the approved compatibility correction"
SAFE_SESSION_MAX_CREATIONS = 8
OID4VP_POSITIVE_RUNTIME_BLOCKER = "canonical.oid4vp-positive-runtime-not-exercised"
RELEASE_CLEARANCE_BLOCKED = "blocked"
RELEASE_CLEARANCE_ELIGIBLE = "eligible"
VALIDATION_PRIVACY_DIFFERENCE_ID = "validation.unknown-field-detail-minimized"
DOCUMENTED_DIFFERENCE_DETAILS = {
    KNOWN_INELIGIBLE_FAILURE_ID: (
        "Rejected Rust v1.1.208 leaves the session transaction ID unscoped; "
        "an eligible Rust candidate must use transaction:<session-id>."
    ),
    VALIDATION_PRIVACY_DIFFERENCE_ID: (
        "Both targets reject caller-selected authority with HTTP 422; Rust deliberately "
        "minimizes the response detail instead of echoing the rejected field name."
    ),
}
DOCUMENTED_TARGET_DIFFERENCES = frozenset({VALIDATION_PRIVACY_DIFFERENCE_ID})
RUST_ONLY_CHECKS = frozenset({"compatibility.default-disabled-routes-absent"})
EXPECTED_LANGUAGE_NEUTRAL_CHECKS = frozenset(
    {
        "postgres.ready",
        "migrations.applied",
        "migrations.idempotent-reapplication",
        "governance.missing-required-check-rejected",
        "health.native-capabilities",
        "compatibility.adapter-enabled",
        "session.malformed-presentation-fails-closed",
        "session.create-auth-policy-and-reload-parity",
        "session.postgres-restart-minimization-and-replay-parity",
        "session.not-found-expiry-and-conflict-errors",
        "session.concurrent-claim-and-fencing-parity",
        "direct.auth-policy-jwt-no-nonce-structured-and-malformed-fail-closed",
        "authorization.missing-invalid-and-wrong-purpose-rejected",
        "authority.caller-selection-rejected",
        "trust.unregistered-issuer-rejected-before-resolution",
        "resolver.unusable-jwk-fails-closed",
        "canonical.vds-positive-pass",
        "canonical.tampered-signature-fail",
        "canonical.malformed-evidence-fail",
    }
)
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SEMVER_TAG = re.compile(r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
VERSION = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
FROZEN_LEGACY_SAFE_SESSION_PIN = {
    "schema": PIN_SCHEMA,
    "state": "ready",
    "repository": EXPECTED_REPOSITORY,
    "release_tag": "v0.1.71",
    "version": "0.1.71",
    "commit": "94f19ad369e7e41883f2aa3d77656ce561bb6534",
    "source_ref": "refs/heads/main",
    "image": {
        "uri": EXPECTED_IMAGE_URI,
        "digest": "sha256:fcec33e259c2d7856606f434e5c9830e392e820a548ab7a6ff4bd4afb3395b3b",
    },
    "sbom": {
        "asset": "marty-credentials-verification.spdx.json",
        "digest": "sha256:0eda6aecc2791e9bfa5fff5c47f0cbd98fdffdacf3594ed06041b83e71c6b91d",
    },
}
REJECTED_RUST_SAFE_SESSION_PIN = {
    "schema": RUST_PIN_SCHEMA,
    "state": "ineligible",
    "repository": RUST_REPOSITORY,
    "release_tag": "v1.1.208",
    "version": "1.1.208",
    "commit": "7c8fa31500acd8f2ec589781232c444fe81dd22e",
    "source_ref": "refs/tags/v1.1.208",
    "image": {
        "uri": RUST_IMAGE_URI,
        "digest": "sha256:ec38eda3dacb3e2f86238f6dd35e3485dd3689a5c76ec13fe896136826db3ff5",
    },
    "sbom": {
        "asset": "marty-ui-services-sbom.cdx.json",
        "digest": "sha256:aa898add22bd0e5e13e7e5fc6a93a35dffda44794855a9757f2ec16aca30d198",
    },
    "expected_failure": {
        "id": KNOWN_INELIGIBLE_FAILURE_ID,
        "message": KNOWN_INELIGIBLE_FAILURE_MESSAGE,
    },
}
CANDIDATE_VERSION = re.compile(r"^0\.0\.0-candidate\.([0-9a-f]{12})$")
RUN_ID = re.compile(r"^[1-9][0-9]*$")
CANDIDATE_BUILD_WORKFLOW = ".github/workflows/verification-candidate-build.yml"
CANDIDATE_SIGNER_WORKFLOW = f"{RUST_REPOSITORY}/{CANDIDATE_BUILD_WORKFLOW}"
INTEGRATION_REPOSITORY = "ElevenID/marty-integration-tests"
HARDENED_HARNESS_FLOOR = "f0062b4e48ea1a7a489d2576bcea0e5d1fce484b"
EXPECTED_MIGRATION_HEAD = "202608091200"
COMPATIBILITY_OPERATIONS = [
    ("GET", "/v1/verification/health"),
    ("POST", "/v1/verification/sessions"),
    ("GET", "/v1/verification/sessions/A"),
    ("POST", "/v1/verification/sessions/A/submit"),
    ("POST", "/v1/verification/verify"),
    ("POST", "/v1/verification/verify/vds-nc"),
]
POSITIVE_OID4VP_CHECK = "canonical.oid4vp-positive-pass-with-claims"
POSITIVE_LANGUAGE_NEUTRAL_CHECKS = EXPECTED_LANGUAGE_NEUTRAL_CHECKS | {POSITIVE_OID4VP_CHECK}
CANDIDATE_REQUIRED_CHECKS = POSITIVE_LANGUAGE_NEUTRAL_CHECKS | RUST_ONLY_CHECKS


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
    if schema in {RUST_PIN_SCHEMA, CANDIDATE_PIN_SCHEMA}:
        return RUST_TARGET
    raise ValueError(f"artifact pin must use {PIN_SCHEMA}, {RUST_PIN_SCHEMA}, or {CANDIDATE_PIN_SCHEMA}")


class ArtifactRuntimeError(RuntimeError):
    """A fixed-category artifact test failure that never includes test secrets."""


class ArtifactRunError(ValueError):
    """An artifact failure carrying only sanitized output-boundary metadata."""

    def __init__(self, message: str, safe_session_selection: dict[str, Any]) -> None:
        super().__init__(message)
        self.safe_session_selection = safe_session_selection


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


def _require_digest(value: Any, message: str) -> str:
    digest = str(value)
    _require(bool(SHA256.fullmatch(digest)), message)
    return digest


def _require_asset(value: Any, *, asset: str, label: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{label} pin is required")
    _require(set(value) == {"asset", "digest"}, f"{label} pin shape changed")
    _require(value.get("asset") == asset, f"unexpected {label} asset")
    _require_digest(value.get("digest"), f"{label} digest must be sha256:<64 lowercase hex>")
    return value


def _validate_candidate_pin(value: dict[str, Any]) -> None:
    _require("release_tag" not in value, "candidate pin must not reserve a release tag")
    _require(
        set(value)
        == {
            "schema",
            "state",
            "repository",
            "version",
            "commit",
            "source_ref",
            "run",
            "archive",
            "image",
            "sbom",
            "metadata",
            "provenance",
        },
        "candidate pin shape changed",
    )
    version_match = CANDIDATE_VERSION.fullmatch(str(value.get("version", "")))
    _require(bool(version_match), "candidate version must be commit-bound and non-release")
    _require(
        version_match is not None and version_match.group(1) == value["commit"][:12],
        "candidate version must agree with the source commit",
    )
    _require(value.get("source_ref") == "refs/heads/main", "candidate source_ref must identify protected main")

    run = value.get("run")
    _require(isinstance(run, dict), "candidate run identity is required")
    _require(
        set(run) == {"repository", "workflow", "id", "attempt"},
        "candidate run identity shape changed",
    )
    _require(run.get("repository") == RUST_REPOSITORY, "candidate run repository changed")
    _require(run.get("workflow") == CANDIDATE_BUILD_WORKFLOW, "candidate run workflow changed")
    _require(bool(RUN_ID.fullmatch(str(run.get("id", "")))), "candidate run ID must be a positive integer")
    _require(type(run.get("attempt")) is int and run["attempt"] > 0, "candidate run attempt must be positive")

    _require_asset(value.get("archive"), asset="marty-ui-services.oci.tar", label="candidate archive")
    _require_asset(value.get("metadata"), asset="marty-ui-services-build-metadata.json", label="candidate metadata")
    _require_asset(value.get("provenance"), asset="marty-ui-services-provenance.json", label="candidate provenance")

    image = value["image"]
    _require(
        set(image) == {"uri", "digest", "config_digest", "archive_tag"},
        "candidate image pin shape changed",
    )
    _require(set(value["sbom"]) == {"asset", "digest"}, "candidate SBOM pin shape changed")
    _require_digest(image.get("config_digest"), "image config digest must be sha256:<64 lowercase hex>")
    _require(
        image.get("archive_tag") == f"candidate-{value['commit']}",
        "candidate archive tag changed",
    )
    _require(value.get("expected_failure") is None, "candidate pin must not declare an expected failure")


def load_pin(path: Path = DEFAULT_PIN, *, expected_state: str = "ready") -> dict[str, Any]:
    _require(expected_state in {"ready", "ineligible", "candidate"}, "unsupported artifact pin state")
    value = json.loads(path.read_text(encoding="utf-8"))
    target = artifact_target(value)
    _require(value.get("state") == expected_state, f"artifact pin must be {expected_state}")
    _require(value.get("repository") == target.repository, "artifact repository does not match its schema")
    _require(bool(COMMIT.fullmatch(str(value.get("commit", "")))), "commit must be a full lowercase SHA")

    if value["schema"] == CANDIDATE_PIN_SCHEMA:
        _require(expected_state == "candidate", "candidate pin must be validated as candidate")
    else:
        _require(expected_state != "candidate", "release pin cannot be validated as candidate")
        _require(bool(SEMVER_TAG.fullmatch(str(value.get("release_tag", "")))), "release_tag must be stable SemVer")
        _require(bool(VERSION.fullmatch(str(value.get("version", "")))), "version must be stable SemVer")
        _require(value["release_tag"] == f"v{value['version']}", "release_tag and version must agree")
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
    _require_digest(image.get("digest"), "image digest must be sha256:<64 lowercase hex>")

    sbom = value.get("sbom")
    _require(isinstance(sbom, dict), "SBOM pin is required")
    _require(sbom.get("asset") == target.sbom_asset, "unexpected verification SBOM asset")
    _require_digest(sbom.get("digest"), "SBOM digest must be sha256:<64 lowercase hex>")
    if value["schema"] == CANDIDATE_PIN_SCHEMA:
        _validate_candidate_pin(value)
        return value
    expected_failure = value.get("expected_failure")
    if expected_state == "ineligible":
        _require(
            expected_failure
            == {
                "id": KNOWN_INELIGIBLE_FAILURE_ID,
                "message": KNOWN_INELIGIBLE_FAILURE_MESSAGE,
            },
            "ineligible artifact pin must bind the known expected failure",
        )
    else:
        _require(expected_failure is None, "ready artifact pin must not declare an expected failure")
    return value


def image_reference(pin: dict[str, Any]) -> str:
    if pin["schema"] == CANDIDATE_PIN_SCHEMA:
        return f"{CANDIDATE_LOCAL_IMAGE_REPOSITORY}:verified-{pin['commit']}"
    return f"{pin['image']['uri']}@{pin['image']['digest']}"


def evidence_subject(pin: dict[str, Any]) -> dict[str, Any]:
    if pin["schema"] == CANDIDATE_PIN_SCHEMA:
        return {
            "repository": pin["repository"],
            "commit": pin["commit"],
            "source_ref": pin["source_ref"],
            "version": pin["version"],
            "run": pin["run"],
            "archive": pin["archive"],
            "image": pin["image"],
            "sbom": pin["sbom"],
            "metadata": pin["metadata"],
            "provenance": pin["provenance"],
            "provenance_verified": True,
        }
    return {
        "repository": pin["repository"],
        "release_tag": pin["release_tag"],
        "version": pin["version"],
        "commit": pin["commit"],
        "image_reference": image_reference(pin),
        "sbom_digest": pin["sbom"]["digest"],
        "provenance_verified": True,
    }


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _bytes_digest(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _preflight_regular_file(path: Path, *, label: str, maximum_bytes: int) -> int:
    metadata = path.lstat()
    _require(stat.S_ISREG(metadata.st_mode), f"{label} must be a regular file")
    _require(0 < metadata.st_size <= maximum_bytes, f"{label} is too large or empty")
    return metadata.st_size


def _read_bounded_regular_file(path: Path, *, label: str, maximum_bytes: int) -> bytes:
    metadata = path.lstat()
    _require(stat.S_ISREG(metadata.st_mode), f"{label} must be a regular file")
    _require(0 < metadata.st_size <= maximum_bytes, f"{label} is too large or empty")
    with path.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        _require(
            stat.S_ISREG(opened.st_mode)
            and opened.st_dev == metadata.st_dev
            and opened.st_ino == metadata.st_ino
            and opened.st_size == metadata.st_size,
            f"{label} changed before it was read",
        )
        raw = handle.read(maximum_bytes + 1)
    _require(len(raw) == metadata.st_size, f"{label} size changed while it was read")
    return raw


def _tar_number(field: bytes, *, label: str) -> int:
    try:
        value = tarfile.nti(field)
    except tarfile.InvalidHeaderError as exc:
        raise ValueError(f"{label} contains a malformed tar size") from exc
    _require(value >= 0, f"{label} contains a negative tar size")
    return value


def _validate_pax_metadata(payload: bytes, *, label: str) -> None:
    position = 0
    while position < len(payload):
        if payload[position:] == bytes(len(payload) - position):
            break
        separator = payload.find(b" ", position)
        _require(separator > position, f"{label} contains malformed PAX metadata")
        length_bytes = payload[position:separator]
        _require(length_bytes.isdigit(), f"{label} contains malformed PAX metadata")
        length = int(length_bytes)
        end = position + length
        _require(length >= 5 and end <= len(payload), f"{label} contains malformed PAX metadata")
        record = payload[separator + 1 : end]
        _require(record.endswith(b"\n") and b"=" in record, f"{label} contains malformed PAX metadata")
        key, value = record[:-1].split(b"=", 1)
        _require(bool(key), f"{label} contains malformed PAX metadata")
        _require(not key.startswith(b"GNU.sparse."), f"{label} contains unsupported sparse PAX metadata")
        if key == b"size":
            _require(value.isdigit(), f"{label} contains malformed PAX size metadata")
            # Candidate and layer caps fit in the ordinary tar size field. Reject
            # this unnecessary offset override instead of duplicating tarfile's
            # recursive local/global PAX precedence rules.
            raise ValueError(f"{label} contains unsupported PAX size metadata")
        position = end


def _scan_tar_headers(
    source: BinaryIO,
    *,
    stream_bytes: int,
    maximum_members: int,
    label: str,
) -> None:
    """Bound special tar metadata before tarfile can allocate it."""
    _require(
        stream_bytes % TAR_BLOCK_BYTES == 0,
        f"{label} contains a truncated tar block",
    )
    source.seek(0)
    offset = 0
    member_count = 0
    special_count = 0
    special_bytes = 0
    while offset + TAR_BLOCK_BYTES <= stream_bytes:
        source.seek(offset)
        header = source.read(TAR_BLOCK_BYTES)
        _require(len(header) == TAR_BLOCK_BYTES, f"{label} contains a truncated tar header")
        if header == bytes(TAR_BLOCK_BYTES):
            remaining = stream_bytes - offset - TAR_BLOCK_BYTES
            _require(
                remaining >= TAR_BLOCK_BYTES,
                f"{label} is missing the canonical tar end-of-archive",
            )
            while remaining:
                chunk = source.read(min(1024 * 1024, remaining))
                _require(
                    bool(chunk) and not any(chunk),
                    f"{label} contains non-zero data after its end-of-archive",
                )
                remaining -= len(chunk)
            return
        member_count += 1
        _require(
            member_count <= maximum_members + MAX_TAR_SPECIAL_HEADERS,
            f"{label} contains too many raw tar headers",
        )
        raw_size = _tar_number(header[124:136], label=label)
        typeflag = header[156:157] or tarfile.REGTYPE
        _require(typeflag != tarfile.GNUTYPE_SPARSE, f"{label} contains unsupported GNU sparse metadata")
        if typeflag in TAR_SPECIAL_HEADER_TYPES:
            special_count += 1
            special_bytes += raw_size
            _require(special_count <= MAX_TAR_SPECIAL_HEADERS, f"{label} contains too many special tar headers")
            _require(
                raw_size <= MAX_TAR_SPECIAL_HEADER_BYTES,
                f"{label} special tar header is too large",
            )
            _require(
                special_bytes <= MAX_TOTAL_TAR_SPECIAL_HEADER_BYTES,
                f"{label} aggregate special tar headers are too large",
            )
            payload_size = raw_size
        else:
            _require(
                typeflag not in TAR_NON_DATA_HEADER_TYPES or raw_size == 0,
                f"{label} non-data tar member declares a payload",
            )
            payload_size = raw_size
        padded_size = ((payload_size + TAR_BLOCK_BYTES - 1) // TAR_BLOCK_BYTES) * TAR_BLOCK_BYTES
        next_offset = offset + TAR_BLOCK_BYTES + padded_size
        _require(next_offset <= stream_bytes, f"{label} contains a truncated tar member")
        if typeflag in {tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE}:
            payload = source.read(raw_size)
            _require(len(payload) == raw_size, f"{label} contains truncated PAX metadata")
            _validate_pax_metadata(payload, label=label)
        offset = next_offset
    raise ValueError(f"{label} is missing the canonical tar end-of-archive")


def _assert_candidate_runtime_config(runtime_config: Any, pin: dict[str, Any]) -> dict[str, Any]:
    _require(isinstance(runtime_config, dict), "candidate runtime config changed")
    environment = runtime_config.get("Env")
    _require(isinstance(environment, list), "candidate image environment is missing")
    for name, expected in {
        "SERVICE_NAME": "verification",
        "MARTY_RELEASE_VERSION": pin["version"],
        "MARTY_UI_SHA": pin["commit"],
    }.items():
        bindings = [item for item in environment if isinstance(item, str) and item.startswith(f"{name}=")]
        _require(bindings == [f"{name}={expected}"], f"candidate image {name} binding changed")
    labels = runtime_config.get("Labels")
    _require(isinstance(labels, dict), "candidate image labels are missing")
    _require(
        {
            "org.opencontainers.image.source": labels.get("org.opencontainers.image.source"),
            "org.opencontainers.image.revision": labels.get("org.opencontainers.image.revision"),
            "org.opencontainers.image.version": labels.get("org.opencontainers.image.version"),
        }
        == {
            "org.opencontainers.image.source": "https://github.com/ElevenID/marty-ui",
            "org.opencontainers.image.revision": pin["commit"],
            "org.opencontainers.image.version": pin["version"],
        },
        "candidate image source labels changed",
    )
    return labels


def inspect_oci_archive(path: Path, pin: dict[str, Any]) -> dict[str, Any]:
    archive_bytes = _preflight_regular_file(
        path,
        label="OCI archive",
        maximum_bytes=MAX_ARCHIVE_BYTES,
    )
    with path.open("rb") as raw_archive:
        _require(
            raw_archive.read(2) != b"\x1f\x8b",
            "candidate archive is not a readable OCI archive: outer wrapper must be uncompressed",
        )
        _scan_tar_headers(
            raw_archive,
            stream_bytes=archive_bytes,
            maximum_members=MAX_ARCHIVE_MEMBERS,
            label="OCI archive",
        )
    reachable_members = {"oci-layout", "index.json"}

    def normalized(member: tarfile.TarInfo) -> str:
        name = member.name.removeprefix("./")
        parts = PurePosixPath(name).parts
        _require(bool(parts) and bool(parts[0]), "OCI archive path changed")
        _require(".." not in parts and not name.startswith("/"), "OCI archive contains an unsafe path")
        return name

    def read_member(archive: tarfile.TarFile, members: dict[str, tarfile.TarInfo], name: str) -> bytes:
        member = members.get(name)
        _require(member is not None and member.isfile(), f"OCI archive member is missing: {name}")
        _require(member.size <= 16 * 1024 * 1024, f"OCI metadata member is too large: {name}")
        extracted = archive.extractfile(member)
        _require(extracted is not None, f"OCI archive member could not be read: {name}")
        return extracted.read()

    def descriptor_blob(
        archive: tarfile.TarFile,
        members: dict[str, tarfile.TarInfo],
        descriptor: dict[str, Any],
        *,
        metadata: bool,
        sink: BinaryIO | None = None,
    ) -> tuple[str, bytes]:
        digest = _require_digest(descriptor.get("digest"), "OCI descriptor digest changed")
        _require(isinstance(descriptor.get("size"), int) and descriptor["size"] >= 0, "OCI descriptor size changed")
        algorithm, encoded = digest.split(":", 1)
        _require(algorithm == "sha256", "OCI descriptor algorithm changed")
        name = f"blobs/{algorithm}/{encoded}"
        member = members.get(name)
        _require(member is not None and member.isfile(), f"OCI archive member is missing: {name}")
        _require(member.size == descriptor["size"], "OCI descriptor size does not match its blob")
        if metadata:
            _require(member.size <= 16 * 1024 * 1024, f"OCI metadata member is too large: {name}")
        else:
            _require(member.size <= MAX_COMPRESSED_LAYER_BYTES, "OCI compressed layer is too large")
        reachable_members.add(name)
        extracted = archive.extractfile(member)
        _require(extracted is not None, f"OCI archive member could not be read: {name}")
        digest_state = hashlib.sha256()
        chunks: list[bytes] = []
        size = 0
        for chunk in iter(lambda: extracted.read(1024 * 1024), b""):
            size += len(chunk)
            digest_state.update(chunk)
            if sink is not None:
                sink.write(chunk)
            if metadata:
                chunks.append(chunk)
        raw = b"".join(chunks)
        _require(size == descriptor["size"], "OCI descriptor size does not match its blob")
        _require(f"sha256:{digest_state.hexdigest()}" == digest, "OCI descriptor digest does not match its blob")
        return digest, raw

    def read_descriptor(
        archive: tarfile.TarFile,
        members: dict[str, tarfile.TarInfo],
        descriptor: dict[str, Any],
    ) -> tuple[str, dict[str, Any]]:
        digest, raw = descriptor_blob(archive, members, descriptor, metadata=True)
        value = json.loads(raw)
        _require(isinstance(value, dict), "OCI descriptor blob must be a JSON object")
        return digest, value

    @contextmanager
    def open_archive() -> Iterator[tarfile.TarFile]:
        try:
            with tarfile.open(path, mode="r:") as archive:
                yield archive
        except (OSError, tarfile.TarError) as exc:
            raise ValueError("candidate archive is not a readable OCI archive") from exc

    with open_archive() as archive:
        members: dict[str, tarfile.TarInfo] = {}
        directories: set[str] = set()
        member_names: set[str] = set()
        member_count = 0
        regular_member_count = 0
        for member in archive:
            member_count += 1
            _require(member_count <= MAX_ARCHIVE_MEMBERS, "OCI archive contains too many members")
            name = normalized(member)
            _require(name not in member_names, "OCI archive contains duplicate members")
            member_names.add(name)
            if member.isdir():
                directories.add(name)
                continue
            _require(member.isfile(), "OCI archive contains a non-regular member")
            regular_member_count += 1
            _require(
                regular_member_count <= MAX_ARCHIVE_REGULAR_MEMBERS,
                "OCI archive contains too many regular members",
            )
            members[name] = member
        layout = json.loads(read_member(archive, members, "oci-layout"))
        _require(layout == {"imageLayoutVersion": "1.0.0"}, "OCI layout version changed")
        index = json.loads(read_member(archive, members, "index.json"))
        _require(isinstance(index, dict) and index.get("schemaVersion") == 2, "OCI index schema changed")
        _require(index.get("mediaType", OCI_INDEX) == OCI_INDEX, "OCI index media type changed")
        descriptors = index.get("manifests")
        _require(isinstance(descriptors, list) and len(descriptors) == 1, "OCI archive must contain one image")
        descriptor = descriptors[0]
        _require(isinstance(descriptor, dict), "OCI image descriptor changed")
        annotations = descriptor.get("annotations")
        _require(
            isinstance(annotations, dict)
            and annotations.get("org.opencontainers.image.ref.name") == pin["image"]["archive_tag"],
            "OCI archive tag changed",
        )

        descriptor_digest, value = read_descriptor(archive, members, descriptor)
        if descriptor.get("mediaType") == OCI_INDEX:
            _require("platform" not in descriptor, "OCI image index descriptor platform changed")
            _require(value.get("schemaVersion") == 2, "OCI image index schema changed")
            _require(value.get("mediaType", OCI_INDEX) == OCI_INDEX, "OCI image index media type changed")
            nested = value.get("manifests")
            _require(isinstance(nested, list) and len(nested) == 1, "OCI image index must contain one platform")
            descriptor = nested[0]
            _require(isinstance(descriptor, dict), "OCI platform descriptor changed")
            _require(
                descriptor.get("platform") == {"architecture": "amd64", "os": "linux"},
                "OCI candidate platform changed",
            )
            descriptor_digest, value = read_descriptor(archive, members, descriptor)
        else:
            _require(
                descriptor.get("platform") == {"architecture": "amd64", "os": "linux"},
                "OCI candidate platform changed",
            )
        _require(
            descriptor.get("mediaType") == OCI_MANIFEST,
            "OCI candidate descriptor is not an image manifest",
        )
        _require(value.get("schemaVersion") == 2, "OCI manifest schema changed")
        _require(value.get("mediaType", OCI_MANIFEST) == OCI_MANIFEST, "OCI manifest media type changed")
        _require(descriptor_digest == pin["image"]["digest"], "OCI manifest digest does not match the candidate pin")

        config_descriptor = value.get("config")
        _require(isinstance(config_descriptor, dict), "OCI image config descriptor is missing")
        _require(
            config_descriptor.get("mediaType") == OCI_CONFIG,
            "OCI config media type changed",
        )
        config_digest, config = read_descriptor(archive, members, config_descriptor)
        _require(config_digest == pin["image"]["config_digest"], "OCI config digest does not match the candidate pin")
        _require(
            config.get("architecture") == "amd64"
            and config.get("os") == "linux"
            and OCI_PLATFORM_QUALIFIER_KEYS.isdisjoint(config),
            "OCI image config platform changed",
        )
        labels = _assert_candidate_runtime_config(config.get("config"), pin)
        layers = value.get("layers")
        _require(isinstance(layers, list) and layers, "OCI image layers are missing")
        _require(len(layers) <= MAX_LAYERS, "OCI image contains too many layers")
        rootfs = config.get("rootfs")
        _require(isinstance(rootfs, dict) and rootfs.get("type") == "layers", "OCI rootfs changed")
        diff_ids = rootfs.get("diff_ids")
        _require(
            isinstance(diff_ids, list)
            and len(diff_ids) == len(layers)
            and all(isinstance(item, str) and SHA256.fullmatch(item) for item in diff_ids),
            "OCI rootfs diff IDs changed",
        )
        compressed_sizes = [layer.get("size") for layer in layers if isinstance(layer, dict)]
        _require(
            len(compressed_sizes) == len(layers)
            and all(type(size) is int and 0 <= size <= MAX_COMPRESSED_LAYER_BYTES for size in compressed_sizes),
            "OCI compressed layer is too large",
        )
        _require(
            sum(compressed_sizes) <= MAX_TOTAL_COMPRESSED_LAYER_BYTES, "OCI aggregate compressed layers are too large"
        )
        total_expanded = 0
        total_layer_members = 0
        for layer, diff_id in zip(layers, diff_ids, strict=True):
            _require(isinstance(layer, dict), "OCI layer descriptor changed")
            _require(layer.get("mediaType") == OCI_GZIP_LAYER, "OCI layer media type changed")
            with tempfile.TemporaryFile() as compressed, tempfile.TemporaryFile() as uncompressed:
                descriptor_blob(archive, members, layer, metadata=False, sink=compressed)
                compressed.seek(0)
                digest_state = hashlib.sha256()
                layer_expanded = 0
                try:
                    with gzip.GzipFile(fileobj=compressed, mode="rb") as source:
                        for chunk in iter(lambda: source.read(1024 * 1024), b""):
                            next_layer_size = layer_expanded + len(chunk)
                            next_total_size = total_expanded + len(chunk)
                            _require(next_layer_size <= MAX_EXPANDED_LAYER_BYTES, "OCI expanded layer is too large")
                            _require(
                                next_total_size <= MAX_TOTAL_EXPANDED_LAYER_BYTES,
                                "OCI aggregate expanded layers are too large",
                            )
                            layer_expanded = next_layer_size
                            total_expanded = next_total_size
                            digest_state.update(chunk)
                            uncompressed.write(chunk)
                except (EOFError, OSError) as exc:
                    raise ValueError("OCI layer is not valid gzip content") from exc
                _require(f"sha256:{digest_state.hexdigest()}" == diff_id, "OCI layer does not match its rootfs diff ID")
                uncompressed.seek(0)
                _scan_tar_headers(
                    uncompressed,
                    stream_bytes=layer_expanded,
                    maximum_members=MAX_LAYER_MEMBERS,
                    label="OCI layer",
                )
                uncompressed.seek(0)
                try:
                    with tarfile.open(fileobj=uncompressed, mode="r|") as layer_archive:
                        layer_member_count = 0
                        for _member in layer_archive:
                            layer_member_count += 1
                            total_layer_members += 1
                            _require(
                                layer_member_count <= MAX_LAYER_MEMBERS,
                                "OCI layer contains too many members",
                            )
                            _require(
                                total_layer_members <= MAX_TOTAL_LAYER_MEMBERS,
                                "OCI aggregate layer members are too large",
                            )
                        _require(layer_member_count > 0, "OCI layer tar is empty")
                except tarfile.TarError as exc:
                    raise ValueError("OCI layer is not a readable tar archive") from exc
        _require(
            set(members) == reachable_members,
            "OCI archive contains an unreferenced regular member",
        )
        reachable_directories = {
            str(parent) for name in reachable_members for parent in PurePosixPath(name).parents if str(parent) != "."
        }
        _require(
            directories <= reachable_directories,
            "OCI archive contains an unreferenced directory member",
        )
        return {
            "manifest_digest": descriptor_digest,
            "config_digest": config_digest,
            "platform": "linux/amd64",
            "labels": labels,
        }


def verify_candidate_attestations(
    pin: dict[str, Any],
    pin_path: Path,
    archive_path: Path,
) -> dict[str, dict[str, Any]]:
    run = pin["run"]
    expected_invocation = f"https://github.com/{RUST_REPOSITORY}/actions/runs/{run['id']}/attempts/{run['attempt']}"
    expected_builder = f"https://github.com/{RUST_REPOSITORY}/{CANDIDATE_BUILD_WORKFLOW}@{pin['source_ref']}"

    def verify_subject(path: Path, label: str) -> dict[str, Any]:
        verification = json.loads(
            _run(
                [
                    "gh",
                    "attestation",
                    "verify",
                    str(path),
                    "--repo",
                    RUST_REPOSITORY,
                    "--signer-workflow",
                    CANDIDATE_SIGNER_WORKFLOW,
                    "--signer-digest",
                    pin["commit"],
                    "--source-digest",
                    pin["commit"],
                    "--source-ref",
                    pin["source_ref"],
                    "--deny-self-hosted-runners",
                    "--format",
                    "json",
                ],
                label=f"verify candidate {label} attestation",
            )
        )
        _require(
            isinstance(verification, list) and verification,
            f"candidate {label} attestation verification returned no result",
        )
        accepted = []
        for item in verification:
            if not isinstance(item, dict):
                continue
            verification_result = item.get("verificationResult")
            if not isinstance(verification_result, dict):
                continue
            statement = verification_result.get("statement")
            if not isinstance(statement, dict):
                continue
            predicate = statement.get("predicate")
            if not isinstance(predicate, dict):
                continue
            build_definition = predicate.get("buildDefinition")
            run_details = predicate.get("runDetails")
            if not isinstance(build_definition, dict) or not isinstance(run_details, dict):
                continue
            external_parameters = build_definition.get("externalParameters")
            builder = run_details.get("builder")
            run_metadata = run_details.get("metadata")
            if not all(isinstance(value, dict) for value in (external_parameters, builder, run_metadata)):
                continue
            workflow = external_parameters.get("workflow")
            dependencies = build_definition.get("resolvedDependencies")
            source_dependency = {
                "uri": f"git+https://github.com/{RUST_REPOSITORY}@{pin['source_ref']}",
                "digest": {"gitCommit": pin["commit"]},
            }
            if (
                isinstance(dependencies, list)
                and workflow
                == {
                    "ref": pin["source_ref"],
                    "repository": f"https://github.com/{RUST_REPOSITORY}",
                    "path": CANDIDATE_BUILD_WORKFLOW,
                }
                and source_dependency in dependencies
                and builder.get("id") == expected_builder
                and run_metadata.get("invocationId") == expected_invocation
            ):
                accepted.append(item)
        _require(
            len(accepted) == 1,
            f"candidate {label} attestation did not bind the exact producer run",
        )
        return accepted[0]

    accepted = {
        "pin": verify_subject(pin_path, "pin"),
        "archive": verify_subject(archive_path, "archive"),
    }

    run_record = json.loads(
        _run(
            [
                "gh",
                "api",
                f"repos/{RUST_REPOSITORY}/actions/runs/{run['id']}/attempts/{run['attempt']}",
            ],
            label="verify candidate producer run",
        )
    )
    _require(isinstance(run_record, dict), "candidate producer run response changed")
    status = run_record.get("status")
    conclusion = run_record.get("conclusion")
    _require(
        (status, conclusion) == ("completed", "success"),
        "candidate producer run has not completed successfully",
    )
    _require(
        {
            "head_sha": run_record.get("head_sha"),
            "head_branch": run_record.get("head_branch"),
            "event": run_record.get("event"),
            "run_attempt": run_record.get("run_attempt"),
            "path": run_record.get("path"),
        }
        == {
            "head_sha": pin["commit"],
            "head_branch": "main",
            "event": "workflow_dispatch",
            "run_attempt": run["attempt"],
            "path": CANDIDATE_BUILD_WORKFLOW,
        },
        "candidate producer run identity or conclusion changed",
    )
    return accepted


def _assert_loaded_candidate_inspection(
    inspected: Any,
    pin: dict[str, Any],
    *,
    exported_config_digest: str | None = None,
) -> None:
    _require(isinstance(inspected, dict), "loaded candidate image inspection changed")
    image_id = inspected.get("Id")
    descriptor = inspected.get("Descriptor")
    manifest_bound = isinstance(descriptor, dict) and descriptor.get("digest") == pin["image"]["digest"]
    config_bound = image_id == pin["image"]["config_digest"] or (
        image_id == pin["image"]["digest"] and exported_config_digest == pin["image"]["config_digest"]
    )
    _require(manifest_bound and config_bound, "loaded candidate image identity changed")
    _require(
        inspected.get("Os") == "linux" and inspected.get("Architecture") == "amd64",
        "loaded candidate platform changed",
    )
    _assert_candidate_runtime_config(inspected.get("Config"), pin)


def _exported_candidate_config_digest(reference: str, pin: dict[str, Any], inspected: dict[str, Any]) -> str:
    image_id = inspected.get("Id")
    if image_id == pin["image"]["config_digest"]:
        return image_id
    _require(image_id == pin["image"]["digest"], "loaded candidate image identity changed")
    with tempfile.TemporaryDirectory(prefix="marty-candidate-export-") as temporary:
        exported = Path(temporary) / "loaded.oci.tar"
        _run(
            ["docker", "image", "save", "--output", str(exported), reference],
            label="export loaded candidate identity",
            timeout=300,
        )
        exported_bytes = _preflight_regular_file(
            exported,
            label="exported candidate image",
            maximum_bytes=MAX_ARCHIVE_BYTES,
        )
        with exported.open("rb") as raw:
            _scan_tar_headers(
                raw,
                stream_bytes=exported_bytes,
                maximum_members=MAX_ARCHIVE_MEMBERS,
                label="exported candidate image",
            )
        manifest_name = f"blobs/sha256/{pin['image']['digest'].split(':', 1)[1]}"
        config_name = f"blobs/sha256/{pin['image']['config_digest'].split(':', 1)[1]}"
        selected: dict[str, bytes] = {}
        try:
            with tarfile.open(exported, mode="r:") as archive:
                members = 0
                regular_members = 0
                names: set[str] = set()
                for member in archive:
                    members += 1
                    _require(members <= MAX_ARCHIVE_MEMBERS, "exported candidate image contains too many members")
                    name = member.name.removeprefix("./")
                    _require(name not in names, "exported candidate image contains duplicate members")
                    names.add(name)
                    if member.isdir():
                        continue
                    _require(member.isfile(), "exported candidate image contains a non-regular member")
                    regular_members += 1
                    _require(
                        regular_members <= MAX_ARCHIVE_REGULAR_MEMBERS,
                        "exported candidate image contains too many regular members",
                    )
                    if name not in {manifest_name, config_name}:
                        continue
                    _require(member.size <= 16 * 1024 * 1024, "exported candidate identity member is too large")
                    handle = archive.extractfile(member)
                    _require(handle is not None, "exported candidate identity member could not be read")
                    selected[name] = handle.read()
        except (OSError, tarfile.TarError) as exc:
            raise ValueError("exported candidate image is not a readable OCI archive") from exc
        _require(set(selected) == {manifest_name, config_name}, "exported candidate identity members are missing")
        config_raw = selected[config_name]
        _require(
            f"sha256:{hashlib.sha256(config_raw).hexdigest()}" == pin["image"]["config_digest"],
            "exported candidate config digest changed",
        )
        manifest_raw = selected[manifest_name]
        _require(
            f"sha256:{hashlib.sha256(manifest_raw).hexdigest()}" == pin["image"]["digest"],
            "exported candidate manifest digest changed",
        )
        manifest = json.loads(manifest_raw)
        _require(isinstance(manifest, dict), "exported candidate manifest changed")
        config = manifest.get("config")
        _require(
            isinstance(config, dict)
            and config.get("mediaType") == "application/vnd.oci.image.config.v1+json"
            and config.get("digest") == pin["image"]["config_digest"]
            and config.get("size") == len(config_raw),
            "exported candidate config identity changed",
        )
        return pin["image"]["config_digest"]


def _verify_staged_candidate_archive(pin: dict[str, Any], archive_path: Path) -> None:
    metadata = archive_path.lstat()
    _require(stat.S_ISREG(metadata.st_mode), "staged candidate archive must be a regular file")
    _require(0 < metadata.st_size <= MAX_ARCHIVE_BYTES, "staged candidate archive is too large or empty")
    if os.name != "nt":
        _require(stat.S_IMODE(metadata.st_mode) & 0o077 == 0, "staged candidate archive is not private")
        getuid = getattr(os, "getuid", None)
        if getuid is not None:
            _require(metadata.st_uid == getuid(), "staged candidate archive is not owned by this user")
    _require(file_digest(archive_path) == pin["archive"]["digest"], "staged candidate archive digest changed")
    inspect_oci_archive(archive_path, pin)


@contextmanager
def stage_candidate_archive(pin: dict[str, Any], archive_path: Path) -> Iterator[Path]:
    source_metadata = archive_path.lstat()
    _require(stat.S_ISREG(source_metadata.st_mode), "OCI archive must be a regular file")
    _require(0 < source_metadata.st_size <= MAX_ARCHIVE_BYTES, "OCI archive is too large or empty")
    with tempfile.TemporaryDirectory(prefix="marty-candidate-private-") as temporary:
        directory = Path(temporary)
        if os.name != "nt":
            directory.chmod(0o700)
        staged = directory / "candidate.oci.tar"
        digest = hashlib.sha256()
        copied = 0
        descriptor = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with archive_path.open("rb") as source, os.fdopen(descriptor, "wb") as destination:
                descriptor = -1
                opened = os.fstat(source.fileno())
                _require(
                    stat.S_ISREG(opened.st_mode)
                    and opened.st_dev == source_metadata.st_dev
                    and opened.st_ino == source_metadata.st_ino
                    and opened.st_size == source_metadata.st_size,
                    "candidate archive changed before private staging",
                )
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    copied += len(chunk)
                    _require(copied <= MAX_ARCHIVE_BYTES, "OCI archive is too large or empty")
                    digest.update(chunk)
                    destination.write(chunk)
                destination.flush()
                os.fsync(destination.fileno())
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        _require(copied == source_metadata.st_size, "candidate archive size changed during private staging")
        _require(
            f"sha256:{digest.hexdigest()}" == pin["archive"]["digest"],
            "candidate archive digest changed during private staging",
        )
        if os.name != "nt":
            staged.chmod(0o600)
        _verify_staged_candidate_archive(pin, staged)
        yield staged


def _inspect_optional_docker_image(reference: str) -> dict[str, Any] | None:
    try:
        completed = subprocess.run(
            ["docker", "image", "inspect", reference, "--format", "{{json .}}"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ArtifactRuntimeError("inspect candidate image could not complete") from exc
    if completed.returncode != 0:
        if re.search(r"No such (?:image|object)", completed.stderr, flags=re.IGNORECASE):
            return None
        raise ArtifactRuntimeError(f"inspect candidate image failed with exit code {completed.returncode}")
    try:
        inspected = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ArtifactRuntimeError("inspect candidate image returned invalid output") from exc
    if not isinstance(inspected, dict):
        raise ArtifactRuntimeError("inspect candidate image returned invalid output")
    return inspected


def _remove_candidate_image(reference: str) -> None:
    try:
        subprocess.run(
            ["docker", "image", "rm", "-f", reference],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ArtifactRuntimeError("remove candidate image could not complete") from exc
    if _inspect_optional_docker_image(reference) is not None:
        raise ArtifactRuntimeError("remove candidate image did not remove its scoped reference")


def _remove_candidate_images(*references: str) -> None:
    failures = 0
    for reference in dict.fromkeys(references):
        try:
            _remove_candidate_image(reference)
        except ArtifactRuntimeError:
            failures += 1
    if failures:
        raise ArtifactRuntimeError("candidate image cleanup did not remove every scoped reference")


def load_candidate_archive(pin: dict[str, Any], archive_path: Path) -> str:
    _verify_staged_candidate_archive(pin, archive_path)
    load_report_reference = f"{pin['image']['archive_tag']}:latest"
    expected_reference = f"{pin['image']['archive_tag']}@{pin['image']['digest']}"
    verified_reference = image_reference(pin)
    _require(
        _inspect_optional_docker_image(load_report_reference) is None,
        "candidate archive tag already exists locally",
    )
    _require(
        _inspect_optional_docker_image(expected_reference) is None,
        "candidate archive digest selection already exists locally",
    )
    _require(
        _inspect_optional_docker_image(verified_reference) is None, "verified candidate tag already exists locally"
    )
    loaded = False
    bound = False
    try:
        loaded = True
        output = _run(
            ["docker", "load", "--input", str(archive_path)],
            label="load verified candidate archive",
            timeout=300,
        )
        _require(
            f"Loaded image: {load_report_reference}" in {line.strip() for line in output.splitlines()},
            "candidate archive load did not report the expected image tag",
        )
        inspected = _inspect_optional_docker_image(expected_reference)
        _require(inspected is not None, "loaded candidate image could not be resolved by its new archive tag")
        exported_config_digest = _exported_candidate_config_digest(expected_reference, pin, inspected)
        _assert_loaded_candidate_inspection(
            inspected,
            pin,
            exported_config_digest=exported_config_digest,
        )
        _run(
            ["docker", "image", "tag", expected_reference, verified_reference],
            label="bind loaded candidate runtime reference",
        )
        bound = True
        rebound = _inspect_optional_docker_image(verified_reference)
        _require(rebound is not None, "bound candidate runtime image could not be resolved")
        _assert_loaded_candidate_inspection(
            rebound,
            pin,
            exported_config_digest=exported_config_digest,
        )
        _remove_candidate_images(load_report_reference, expected_reference)
        loaded = False
        bound = False
        return verified_reference
    finally:
        cleanup_references = []
        if loaded:
            cleanup_references.extend((load_report_reference, expected_reference))
        if bound:
            cleanup_references.append(verified_reference)
        if cleanup_references:
            _remove_candidate_images(*cleanup_references)


def validate_candidate_inputs(
    pin: dict[str, Any],
    *,
    archive_path: Path,
    sbom_path: Path,
    metadata_path: Path,
    provenance_path: Path,
) -> dict[str, Any]:
    _require(pin["schema"] == CANDIDATE_PIN_SCHEMA, "candidate validation requires a candidate pin")
    for path, label, maximum_bytes in (
        (archive_path, "OCI archive", MAX_ARCHIVE_BYTES),
        (sbom_path, "candidate SBOM", MAX_SBOM_BYTES),
        (metadata_path, "candidate metadata", MAX_CANDIDATE_METADATA_BYTES),
        (provenance_path, "candidate provenance", MAX_CANDIDATE_PROVENANCE_BYTES),
    ):
        _preflight_regular_file(path, label=label, maximum_bytes=maximum_bytes)
    _require(file_digest(archive_path) == pin["archive"]["digest"], "candidate archive digest changed")
    sbom_raw = _read_bounded_regular_file(
        sbom_path,
        label="candidate SBOM",
        maximum_bytes=MAX_SBOM_BYTES,
    )
    metadata_raw = _read_bounded_regular_file(
        metadata_path,
        label="candidate metadata",
        maximum_bytes=MAX_CANDIDATE_METADATA_BYTES,
    )
    provenance_raw = _read_bounded_regular_file(
        provenance_path,
        label="candidate provenance",
        maximum_bytes=MAX_CANDIDATE_PROVENANCE_BYTES,
    )
    _require(_bytes_digest(sbom_raw) == pin["sbom"]["digest"], "candidate SBOM digest changed")
    _require(_bytes_digest(metadata_raw) == pin["metadata"]["digest"], "candidate metadata digest changed")
    _require(_bytes_digest(provenance_raw) == pin["provenance"]["digest"], "candidate provenance digest changed")
    inspect_oci_archive(archive_path, pin)
    validate_sbom(sbom_path, pin, raw=sbom_raw)

    source = {
        "repository": pin["repository"],
        "commit": pin["commit"],
        "ref": pin["source_ref"],
    }
    metadata = json.loads(metadata_raw)
    _require(isinstance(metadata, dict), "candidate metadata must be a JSON object")
    _require(
        set(metadata) == {"schema", "source", "builder", "build", "image"},
        "candidate metadata shape changed",
    )
    _require(metadata.get("schema") == CANDIDATE_METADATA_SCHEMA, "candidate metadata schema changed")
    _require(metadata.get("source") == source, "candidate metadata source changed")
    _require(metadata.get("builder") == pin["run"], "candidate metadata builder changed")
    build = metadata.get("build")
    _require(isinstance(build, dict), "candidate build metadata is required")
    _require(
        build
        == {
            "context": ".",
            "dockerfile": "services/Dockerfile",
            "dockerfile_digest": build.get("dockerfile_digest"),
            "platform": "linux/amd64",
            "version": pin["version"],
            "arguments": {
                "SERVICE_NAME": "verification",
                "MARTY_RELEASE_VERSION": pin["version"],
                "MARTY_UI_SHA": pin["commit"],
            },
        },
        "candidate build metadata changed",
    )
    _require_digest(
        build["dockerfile_digest"],
        "candidate Dockerfile digest must be sha256:<64 lowercase hex>",
    )
    _require(metadata.get("image") == pin["image"], "candidate metadata image changed")

    provenance = json.loads(provenance_raw)
    _require(isinstance(provenance, dict), "candidate provenance must be a JSON object")
    _require(
        set(provenance) == {"schema", "source", "builder", "subjects"},
        "candidate provenance shape changed",
    )
    _require(provenance.get("schema") == CANDIDATE_PROVENANCE_SCHEMA, "candidate provenance schema changed")
    _require(
        provenance.get("source") == source,
        "candidate provenance source changed",
    )
    _require(provenance.get("builder") == pin["run"], "candidate provenance builder changed")
    _require(
        provenance.get("subjects")
        == {
            "archive": pin["archive"],
            "image": pin["image"],
            "sbom": pin["sbom"],
            "metadata": pin["metadata"],
        },
        "candidate provenance subjects changed",
    )
    return provenance


def harness_subject() -> dict[str, Any]:
    _run(
        ["git", "-C", str(ROOT), "diff", "--quiet", "--ignore-submodules", "--"],
        label="verify clean verification harness worktree",
    )
    _run(
        ["git", "-C", str(ROOT), "diff", "--cached", "--quiet", "--ignore-submodules", "--"],
        label="verify clean verification harness index",
    )
    commit = _run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        label="resolve verification harness commit",
    )
    _require(bool(COMMIT.fullmatch(commit)), "verification harness commit changed")
    _run(
        [
            "git",
            "-C",
            str(ROOT),
            "merge-base",
            "--is-ancestor",
            HARDENED_HARNESS_FLOOR,
            commit,
        ],
        label="verify hardened harness ancestry",
    )
    return {
        "repository": INTEGRATION_REPOSITORY,
        "commit": commit,
        "hardened_floor": HARDENED_HARNESS_FLOOR,
        "script": {
            "path": "scripts/credentials_verifier_artifact.py",
            "digest": file_digest(Path(__file__).resolve()),
        },
    }


def compare_oracle_candidate_evidence(
    oracle_path: Path,
    candidate_path: Path,
    oracle_pin: dict[str, Any],
    candidate_pin: dict[str, Any],
) -> dict[str, Any]:
    oracle = json.loads(oracle_path.read_text(encoding="utf-8"))
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    _require(oracle_pin == FROZEN_LEGACY_SAFE_SESSION_PIN, "oracle pin changed")
    _require(candidate_pin.get("schema") == CANDIDATE_PIN_SCHEMA, "candidate pin changed")
    _require(isinstance(oracle, dict) and isinstance(candidate, dict), "artifact evidence must be JSON objects")
    _require(oracle.get("schema") == EVIDENCE_SCHEMA, "oracle evidence schema changed")
    _require(candidate.get("schema") == CANDIDATE_EVIDENCE_SCHEMA, "candidate evidence schema changed")
    evidence_shape = {
        "schema",
        "classification",
        "official_suite_invoked",
        "official_suite_source_modified",
        "status",
        "release_clearance",
        "blockers",
        "subject",
        "harness",
        "checks",
        "safe_session_selection",
        "documented_differences",
        "resolver_request_count",
        "started_at",
        "completed_at",
    }
    _require(set(oracle) == evidence_shape, "oracle evidence shape changed")
    _require(set(candidate) == evidence_shape, "candidate evidence shape changed")
    _require(oracle.get("subject") == evidence_subject(oracle_pin), "oracle evidence subject changed")
    _require(
        candidate.get("subject") == evidence_subject(candidate_pin),
        "candidate evidence subject changed",
    )
    current_harness = harness_subject()
    _require(oracle.get("harness") == current_harness, "oracle evidence harness changed")
    _require(candidate.get("harness") == current_harness, "candidate evidence harness changed")
    for label, evidence in (("oracle", oracle), ("candidate", candidate)):
        _require(
            evidence.get("classification") == "ElevenID-owned artifact integration",
            f"{label} evidence classification changed",
        )
        _require(evidence.get("official_suite_invoked") is False, f"{label} suite claim changed")
        _require(
            evidence.get("official_suite_source_modified") is False,
            f"{label} suite-source claim changed",
        )
        _require(evidence.get("status") == "passed", f"{label} artifact evidence did not pass")
        _require(
            evidence.get("release_clearance") == RELEASE_CLEARANCE_BLOCKED,
            f"{label} evidence did not remain fail-closed",
        )
        _require(
            evidence.get("blockers") == [OID4VP_POSITIVE_RUNTIME_BLOCKER],
            f"{label} evidence omitted the positive-runtime blocker",
        )
        _require(
            isinstance(evidence.get("started_at"), str) and isinstance(evidence.get("completed_at"), str),
            f"{label} evidence timestamps changed",
        )

    _require(oracle.get("documented_differences") == [], "oracle evidence contained a difference")
    candidate_differences = candidate.get("documented_differences")
    _require(
        isinstance(candidate_differences, list)
        and all(isinstance(difference, str) for difference in candidate_differences)
        and len(candidate_differences) == len(set(candidate_differences))
        and set(candidate_differences) == DOCUMENTED_TARGET_DIFFERENCES,
        "candidate evidence contained an undocumented difference",
    )
    _require(
        candidate.get("resolver_request_count") == oracle.get("resolver_request_count"),
        "candidate and oracle resolver evidence counts diverged",
    )

    oracle_selection = oracle.get("safe_session_selection")
    candidate_selection = candidate.get("safe_session_selection")
    _require(
        isinstance(oracle_selection, dict)
        and set(oracle_selection) == {"reason", "resampled_unsafe_ids"}
        and oracle_selection.get("reason") == "frozen_python_v0.1.71_invalid_leading_identifier"
        and type(oracle_selection.get("resampled_unsafe_ids")) is int
        and oracle_selection["resampled_unsafe_ids"] >= 0,
        "oracle safe-session evidence changed",
    )
    _require(
        candidate_selection
        == {
            "reason": "not_allowlisted_no_resampling",
            "resampled_unsafe_ids": 0,
        },
        "candidate safe-session evidence changed",
    )
    oracle_checks = _check_set(oracle)
    candidate_checks = _check_set(candidate)
    _require(oracle_checks == EXPECTED_LANGUAGE_NEUTRAL_CHECKS, "frozen oracle evidence set changed")
    _require(
        candidate_checks == EXPECTED_LANGUAGE_NEUTRAL_CHECKS | RUST_ONLY_CHECKS,
        "frozen candidate evidence set changed",
    )
    return {
        "schema": "elevenid.credentials-verifier-candidate-comparison/v1",
        "status": "matched_with_runtime_blocker",
        "release_clearance": RELEASE_CLEARANCE_BLOCKED,
        "blockers": [OID4VP_POSITIVE_RUNTIME_BLOCKER],
        "language_neutral_checks": sorted(oracle_checks),
        "candidate_only_checks": sorted(candidate_checks - oracle_checks),
        "documented_differences": sorted(DOCUMENTED_TARGET_DIFFERENCES),
    }


def validate_sbom(path: Path, pin: dict[str, Any], *, raw: bytes | None = None) -> dict[str, Any]:
    value = json.loads(
        raw
        if raw is not None
        else _read_bounded_regular_file(
            path,
            label="verification SBOM",
            maximum_bytes=MAX_SBOM_BYTES,
        )
    )
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
    elif pin["schema"] == CANDIDATE_PIN_SCHEMA:
        _require(len(value) <= MAX_SBOM_TOP_LEVEL_KEYS, "candidate SBOM contains too many top-level fields")
        _require(value.get("bomFormat") == "CycloneDX", "verification SBOM must use CycloneDX")
        _require(value.get("specVersion") == "1.6", "verification SBOM must use CycloneDX 1.6")
        components = value.get("components")
        _require(
            isinstance(components, list) and bool(components) and len(components) <= MAX_SBOM_COMPONENTS,
            "candidate SBOM components are missing",
        )
        component_refs: set[str] = set()
        for item in components:
            _require(isinstance(item, dict), "candidate SBOM component changed")
            _require(item.get("type") in CYCLONEDX_COMPONENT_TYPES, "candidate SBOM component type changed")
            _require(
                isinstance(item.get("name"), str) and bool(item["name"].strip()),
                "candidate SBOM component name is missing",
            )
            reference = item.get("bom-ref")
            _require(
                isinstance(reference, str) and bool(reference),
                "candidate SBOM component reference is missing",
            )
            _require(reference not in component_refs, "candidate SBOM component reference is duplicated")
            component_refs.add(reference)
        metadata = value.get("metadata")
        _require(isinstance(metadata, dict), "verification SBOM metadata is required")
        tools = metadata.get("tools")
        _require(isinstance(tools, dict), "candidate SBOM scanner identity is missing")
        scanner_components = tools.get("components")
        _require(
            isinstance(scanner_components, list)
            and len(scanner_components) <= MAX_SBOM_SCANNER_COMPONENTS
            and any(isinstance(tool, dict) and tool.get("name") == "syft" for tool in scanner_components),
            "candidate SBOM was not generated by Syft",
        )
        component = metadata.get("component")
        _require(isinstance(component, dict), "verification SBOM image component is required")
        _require(component.get("type") == "container", "candidate SBOM root is not a container")
        _require(component.get("name") == target.image_uri, "verification SBOM describes an unexpected image")
        _require(
            component.get("version") == pin["image"]["digest"],
            "verification SBOM root is not bound to the pinned image digest",
        )
        root_reference = component.get("bom-ref")
        _require(
            isinstance(root_reference, str) and bool(root_reference),
            "candidate SBOM root reference is missing",
        )
        _require(root_reference not in component_refs, "candidate SBOM root reference is duplicated")
        all_references = component_refs | {root_reference}
        dependencies = value.get("dependencies", [])
        _require(
            isinstance(dependencies, list) and len(dependencies) <= MAX_SBOM_DEPENDENCIES,
            "candidate SBOM dependencies changed",
        )
        dependency_roots: set[str] = set()
        total_dependency_edges = 0
        for dependency in dependencies:
            _require(isinstance(dependency, dict), "candidate SBOM dependency changed")
            reference = dependency.get("ref")
            depends_on = dependency.get("dependsOn")
            _require(
                isinstance(reference, str) and reference in all_references and reference not in dependency_roots,
                "candidate SBOM dependency reference changed",
            )
            _require(isinstance(depends_on, list), "candidate SBOM dependency edge changed")
            _require(
                len(depends_on) <= MAX_SBOM_DEPENDENCY_EDGES_PER_ENTRY,
                "candidate SBOM dependency fan-out is too large",
            )
            _require(
                all(isinstance(item, str) and item in all_references for item in depends_on),
                "candidate SBOM dependency edge changed",
            )
            _require(len(set(depends_on)) == len(depends_on), "candidate SBOM dependency edge is duplicated")
            total_dependency_edges += len(depends_on)
            _require(
                total_dependency_edges <= MAX_TOTAL_SBOM_DEPENDENCY_EDGES,
                "candidate SBOM aggregate dependency edges are too large",
            )
            dependency_roots.add(reference)
        _require(
            not ({"purl", "cpe", "hashes", "properties", "swid"} & set(component)),
            "candidate SBOM root identity is contradictory",
        )
        properties = metadata.get("properties")
        _require(
            isinstance(properties, list) and len(properties) <= MAX_SBOM_PROPERTIES,
            "candidate SBOM image labels are missing",
        )
        property_values: dict[str, str] = {}
        for item in properties:
            _require(isinstance(item, dict), "candidate SBOM image property changed")
            name = item.get("name")
            property_value = item.get("value")
            _require(
                isinstance(name, str) and isinstance(property_value, str),
                "candidate SBOM image property changed",
            )
            _require(name not in property_values, "candidate SBOM image property is duplicated")
            property_values[name] = property_value
        expected_labels = {
            "syft:image:labels:org.opencontainers.image.source": "https://github.com/ElevenID/marty-ui",
            "syft:image:labels:org.opencontainers.image.revision": pin["commit"],
            "syft:image:labels:org.opencontainers.image.version": pin["version"],
        }
        _require(
            all(property_values.get(name) == expected for name, expected in expected_labels.items()),
            "candidate SBOM image labels changed",
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


def presentation_definition() -> dict[str, Any]:
    return {"id": "artifact-differential", "input_descriptors": []}


def build_governance(
    pin: dict[str, Any],
    api_key: str,
    organization_id: str,
    issuer_did: str,
    *,
    vds_only_api_key: str | None = None,
    oid4vp_only_api_key: str | None = None,
) -> dict[str, Any]:
    vds_policy_content = {
        "verifier_id": "did:web:vds-verifier.integration.invalid",
        "presentation_definition_digest": pin["image"]["digest"],
        "required_checks": ["credential.proof", "issuer.trust"],
    }
    oid4vp_policy_content = {
        "verifier_id": "did:web:verifier.integration.invalid",
        "presentation_definition_digest": canonical_digest(presentation_definition()),
        "required_checks": OID4VP_REQUIRED_CHECKS,
    }
    trust_content = {
        "trusted_issuers": [issuer_did],
        "allow_public_did_fallback": False,
    }
    trust_binding = {"trust_profile_id": "trust:vds-artifact-integration"}
    all_purposes = {
        SESSION_PURPOSE: {
            "policy_id": "policy:oid4vp-artifact-integration",
            **trust_binding,
        },
        DIRECT_PURPOSE: {
            "policy_id": "policy:oid4vp-artifact-integration",
            **trust_binding,
        },
        VDS_PURPOSE: {
            "policy_id": "policy:vds-artifact-integration",
            **trust_binding,
        },
    }
    clients = [
        {
            "client_id": "artifact-integration-client",
            "api_key_sha256": hashlib.sha256(api_key.encode("utf-8")).hexdigest(),
            "organization_id": organization_id,
            "purposes": all_purposes,
        }
    ]
    if vds_only_api_key is not None:
        clients.append(
            {
                "client_id": "artifact-integration-vds-only",
                "api_key_sha256": hashlib.sha256(vds_only_api_key.encode("utf-8")).hexdigest(),
                "organization_id": organization_id,
                "purposes": {VDS_PURPOSE: all_purposes[VDS_PURPOSE]},
            }
        )
    if oid4vp_only_api_key is not None:
        clients.append(
            {
                "client_id": "artifact-integration-oid4vp-only",
                "api_key_sha256": hashlib.sha256(oid4vp_only_api_key.encode("utf-8")).hexdigest(),
                "organization_id": organization_id,
                "purposes": {purpose: all_purposes[purpose] for purpose in (SESSION_PURPOSE, DIRECT_PURPOSE)},
            }
        )
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
                "content_digest": canonical_digest(vds_policy_content),
                "content": vds_policy_content,
            },
            {
                "organization_id": organization_id,
                "id": "policy:oid4vp-artifact-integration",
                "version": "1.0.0",
                "content_digest": canonical_digest(oid4vp_policy_content),
                "content": oid4vp_policy_content,
            },
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
        "clients": clients,
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


def make_oid4vp_jwt(nonce: str | None, audience: str, *, fixture_id: str = "primary") -> str:
    """Create a valid holder-signed proof whose embedded credential remains unverified.

    The frozen compatibility service intentionally treats a presentation proof
    as insufficient for a final PASS until issuer proof, trust, status, holder,
    and claim checks are independently established.
    """
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    header = {
        "alg": "EdDSA",
        "typ": "JWT",
        "jwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _b64url(public),
        },
    }
    now = int(time.time())
    payload: dict[str, Any] = {
        "iss": "did:example:artifact-holder",
        "sub": "did:example:artifact-holder",
        "aud": audience,
        "jti": f"artifact-{fixture_id}",
        "iat": now,
        "exp": now + 300,
        "vp": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "verifiableCredential": [
                {
                    "type": ["VerifiableCredential"],
                    "credentialSubject": {"artifact_marker": "sensitive-holder-claim"},
                }
            ],
        },
    }
    if nonce is not None:
        payload["nonce"] = nonce
    encoded_header = _b64url(canonical_json(header))
    encoded_payload = _b64url(canonical_json(payload))
    signing_input = f"{encoded_header}.{encoded_payload}"
    signature = private_key.sign(signing_input.encode("ascii"))
    return f"{signing_input}.{_b64url(signature)}"


def trusted_oid4vp_pass_fixture() -> dict[str, Any]:
    """Return the language-neutral projection required from a trusted adapter.

    This fixture is deliberately an adapter-result contract, not fabricated
    runtime evidence. The released oracle has no path that authenticates every
    OID4VP check, so the artifact runner must not report this fixture as an
    exercised runtime gate until a released adapter can produce it.
    """
    checks = [
        {"check_id": check_id, "outcome": outcome, "code": code}
        for check_id, (outcome, code) in OID4VP_PASS_CHECK_PROJECTION.items()
    ]
    return {
        "processing_status": "COMPLETED",
        "decision": "PASS",
        "decision_code": "ALL_REQUIRED_CHECKS_PASSED",
        "valid": True,
        "overall_result": "PASS",
        "verification_method": "jwt_vp",
        "verified_claims": None,
        "claim_results": [],
        "canonical_result": {
            "verification_id": "verification:trusted-oid4vp-fixture",
            "decision": "PASS",
            "valid": True,
            "processing_status": "COMPLETED",
            "input_digest": "sha256:" + "a" * 64,
            "context": {"transaction_id": "transaction:trusted-oid4vp-fixture"},
            "checks": checks,
        },
    }


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
        self.return_usable_jwk = True

    def response(self) -> dict[str, Any]:
        method = {
            "id": self.method_id,
            "controller": self.issuer_did,
            "type": "JsonWebKey2020",
            "publicKeyJwk": self.public_jwk,
        }
        response = {
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
        if not self.return_usable_jwk:
            response["public_jwk"] = {}
        return response


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


def _request_json(
    method: str,
    url: str,
    *,
    body: dict[str, Any] | None = None,
    api_key: str | None = None,
) -> tuple[int, dict[str, Any]]:
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
    try:
        value = json.loads(payload) if payload else {}
    except json.JSONDecodeError as exc:
        raise ArtifactRuntimeError("verification service returned malformed JSON") from exc
    if not isinstance(value, dict):
        raise ArtifactRuntimeError("verification service returned a non-object response")
    return status, value


def _http_json(
    method: str,
    url: str,
    *,
    body: dict[str, Any] | None = None,
    api_key: str | None = None,
    expected_status: int,
) -> dict[str, Any]:
    status, value = _request_json(method, url, body=body, api_key=api_key)
    if status != expected_status:
        raise ArtifactRuntimeError(f"verification service returned unexpected HTTP status for {method}")
    return value


def _http_status(method: str, url: str) -> int:
    request = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except (OSError, TimeoutError, urllib.error.URLError) as exc:
        raise ArtifactRuntimeError("verification HTTP request failed") from exc


def _assert_compatibility_routes_absent(base_url: str) -> None:
    for method, path in COMPATIBILITY_OPERATIONS:
        _require(
            _http_status(method, f"{base_url}{path}") == 404,
            f"credentials compatibility route was active by default: {method} {path}",
        )


def _parallel_submissions(
    base_url: str,
    session_id: str,
    presentations: list[str],
) -> list[tuple[int, dict[str, Any]]]:
    barrier = threading.Barrier(len(presentations))

    def submit(presentation: str) -> tuple[int, dict[str, Any]]:
        barrier.wait(timeout=10)
        return _request_json(
            "POST",
            f"{base_url}/v1/verification/sessions/{session_id}/submit",
            body={"presentation": presentation},
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(presentations)) as executor:
        futures = [executor.submit(submit, presentation) for presentation in presentations]
        return [future.result(timeout=30) for future in futures]


def _partition_submission_outcomes(
    outcomes: list[tuple[int, dict[str, Any]]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    _require(
        all(status in {200, 409} for status, _value in outcomes),
        "parallel submission returned an unexpected status",
    )
    accepted = [value for status, value in outcomes if status == 200]
    conflicts = [value for status, value in outcomes if status == 409]
    for conflict in conflicts:
        _assert_error(conflict, "Verification session submission conflicts")
    return accepted, conflicts


def _assert_error(value: dict[str, Any], detail: str) -> None:
    _require(value == {"detail": detail}, "verification error response contract changed")


def _assert_extra_field_error(
    value: dict[str, Any],
    field: str,
    *,
    allow_minimized_detail: bool = False,
) -> str | None:
    details = value.get("detail")
    if allow_minimized_detail and details == "Request validation failed":
        _require(field not in json.dumps(value), "minimized validation response disclosed the rejected field")
        return VALIDATION_PRIVACY_DIFFERENCE_ID
    _require(isinstance(details, list) and len(details) == 1, "validation error shape changed")
    error = details[0]
    _require(isinstance(error, dict), "validation error entry changed")
    location = error.get("loc")
    _require(
        isinstance(location, list) and location[-1:] == [field],
        "validation error field binding changed",
    )
    _require(error.get("type") == "extra_forbidden", "validation error category changed")
    return None


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


def _assert_canonical(
    value: dict[str, Any],
    *,
    decision: str,
    expected_checks: set[str] | None = None,
    expected_transaction_id: str | None = None,
    expected_passed_checks: set[str] | None = None,
    expected_check_projection: dict[str, tuple[str, str]] | None = None,
    expected_input_digest: str | None = None,
    expected_verification_method: str | None = None,
    transaction_error: str = "canonical transaction ID changed",
) -> dict[str, Any]:
    canonical = value.get("canonical_result")
    _require(isinstance(canonical, dict), "verification response omitted canonical_result")
    actual_decision = canonical.get("decision")
    _require(
        actual_decision == decision,
        f"canonical decision was not {decision} (got {actual_decision})",
    )
    _require(value.get("decision") == decision, "legacy decision projection diverged")
    _require(value.get("overall_result") == decision, "overall_result projection diverged")
    _require(value.get("valid") is (decision == "PASS"), "valid projection diverged")
    if expected_verification_method is not None:
        _require(
            value.get("verification_method") == expected_verification_method,
            "verification method projection changed",
        )
    _require(canonical.get("valid") is (decision == "PASS"), "canonical valid diverged")
    _require(canonical.get("processing_status") == "COMPLETED", "canonical processing did not complete")
    _require(
        bool(re.fullmatch(r"verification:[A-Za-z0-9_-]+", str(canonical.get("verification_id", "")))),
        "canonical verification ID is not scoped",
    )
    context = canonical.get("context")
    _require(isinstance(context, dict), "canonical context is missing")
    transaction_id = context.get("transaction_id")
    if expected_transaction_id is None:
        _require(
            bool(re.fullmatch(r"transaction:[A-Za-z0-9_-]+", str(transaction_id or ""))),
            "canonical transaction ID is not scoped",
        )
    else:
        _require(transaction_id == expected_transaction_id, transaction_error)
    if expected_input_digest is not None:
        _require(canonical.get("input_digest") == expected_input_digest, "canonical input digest changed")
    checks = canonical.get("checks")
    expected = {"credential.proof", "issuer.trust"} if expected_checks is None else expected_checks
    _require(isinstance(checks, list) and len(checks) == len(expected), "canonical check count changed")
    ids = {check.get("check_id") for check in checks if isinstance(check, dict)}
    _require(ids == expected, "canonical check floor changed")
    if decision == "PASS":
        _require(all(check.get("outcome") == "PASSED" for check in checks), "PASS contained a non-passing check")
    elif decision == "FAIL":
        _require(any(check.get("outcome") == "FAILED" for check in checks), "FAIL contained no failing check")
    else:
        _require(
            decision == "INDETERMINATE" and not any(check.get("outcome") == "FAILED" for check in checks),
            "INDETERMINATE contained a failed check",
        )
    if expected_passed_checks is not None:
        passed = {
            check.get("check_id") for check in checks if isinstance(check, dict) and check.get("outcome") == "PASSED"
        }
        _require(
            passed == expected_passed_checks,
            "canonical passing-check projection changed "
            f"(got {[(check.get('check_id'), check.get('outcome'), check.get('code')) for check in checks]})",
        )
    if expected_check_projection is not None:
        projection = {
            str(check.get("check_id")): (str(check.get("outcome")), str(check.get("code")))
            for check in checks
            if isinstance(check, dict)
        }
        _require(projection == expected_check_projection, "canonical check projection changed")
    return canonical


def _assert_session(
    value: dict[str, Any],
    *,
    organization_id: str,
    expected_status: str,
    nonce_present: bool,
) -> None:
    _require(
        set(value)
        == {
            "id",
            "organization_id",
            "verifier_did",
            "status",
            "request_uri",
            "nonce",
            "expires_at",
            "created_at",
        },
        "session response shape changed",
    )
    _require(isinstance(value["id"], str) and value["id"], "session ID is missing")
    _require(value["organization_id"] == organization_id, "session organization binding changed")
    _require(
        value["verifier_did"] == "did:web:verifier.integration.invalid",
        "session verifier binding changed",
    )
    _require(value["status"] == expected_status, "session status changed")
    _require(isinstance(value["request_uri"], str) and value["request_uri"], "session request URI is missing")
    nonce = value["nonce"]
    _require(isinstance(nonce, str), "session nonce is not a string")
    _require((len(nonce) > 40) if nonce_present else nonce == "", "session nonce lifecycle changed")
    for field in ("expires_at", "created_at"):
        _require(isinstance(value[field], str) and value[field], f"session {field} is missing")
        datetime.fromisoformat(value[field].replace("Z", "+00:00"))


def _safe_session_resample_reason(pin: dict[str, Any]) -> str | None:
    if pin == FROZEN_LEGACY_SAFE_SESSION_PIN:
        return "frozen_python_v0.1.71_invalid_leading_identifier"
    if pin == REJECTED_RUST_SAFE_SESSION_PIN:
        return "rejected_rust_v1.1.208_invalid_leading_identifier"
    return None


def _create_safe_session(
    base_url: str,
    session_body: dict[str, Any],
    api_key: str,
    pin: dict[str, Any],
    organization_id: str,
    *,
    max_creations: int = SAFE_SESSION_MAX_CREATIONS,
) -> tuple[dict[str, Any], int, str]:
    reason = _safe_session_resample_reason(pin)
    _require(max_creations > 0, "safe session creation bound must be positive")
    for creation in range(1, max_creations + 1):
        session = _http_json(
            "POST",
            f"{base_url}/v1/verification/sessions",
            body=session_body,
            api_key=api_key,
            expected_status=200,
        )
        _assert_session(
            session,
            organization_id=organization_id,
            expected_status="pending",
            nonce_present=True,
        )
        if reason is None or session["id"][:1] not in {"-", "_"}:
            return session, creation - 1, reason or "not_allowlisted_no_resampling"
    raise ValueError("safe session creation exhausted its bounded artifact-specific resampling")


def _session_selection_evidence(reason: str, resampled_unsafe_ids: int) -> dict[str, Any]:
    _require(resampled_unsafe_ids >= 0, "safe session resample count was negative")
    return {
        "reason": reason,
        "resampled_unsafe_ids": resampled_unsafe_ids,
    }


def _assert_session_result(
    value: dict[str, Any],
    session_id: str,
    target: ArtifactTarget,
    *,
    expected_decision: str = "FAIL",
    expected_passed_checks: set[str] | None = None,
    defer_known_difference: bool = False,
) -> str | None:
    candidate = value.get("canonical_result")
    candidate_context = candidate.get("context") if isinstance(candidate, dict) else None
    observed_transaction_id = candidate_context.get("transaction_id") if isinstance(candidate_context, dict) else None
    known_unscoped_rust_id = target is RUST_TARGET and observed_transaction_id == session_id
    expected_transaction_id = (
        session_id if target is LEGACY_TARGET or known_unscoped_rust_id else f"transaction:{session_id}"
    )
    canonical = _assert_canonical(
        value,
        decision=expected_decision,
        expected_checks=set(OID4VP_REQUIRED_CHECKS),
        expected_transaction_id=expected_transaction_id,
        expected_passed_checks=expected_passed_checks,
    )
    _require(
        canonical.get("verification_id") == f"verification:{session_id}",
        "session verification ID is not scoped to the session",
    )
    if known_unscoped_rust_id:
        if defer_known_difference:
            return KNOWN_INELIGIBLE_FAILURE_ID
        raise ValueError(KNOWN_INELIGIBLE_FAILURE_MESSAGE)
    # The canonical Rust owner deliberately scopes this identifier before it
    # crosses the Core boundary. The frozen Python oracle is retained exactly
    # as released, including its unscoped legacy projection.
    return None


def _assert_private_material_absent(value: dict[str, Any], prohibited: list[str]) -> None:
    serialized = json.dumps(value, sort_keys=True)
    for item in prohibited:
        _require(item not in serialized, "canonical response retained private test material")


def _vds_private_material(submitted_barcode: str) -> list[str]:
    return [submitted_barcode, *VDS_SENSITIVE_SENTINELS]


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


def _verification_database_snapshot(postgres: str) -> str:
    dump = _run(
        [
            "docker",
            "exec",
            postgres,
            "pg_dump",
            "-U",
            "postgres",
            "-d",
            "verifier",
            "--no-owner",
            "--no-privileges",
            "--no-comments",
            "--no-security-labels",
        ],
        label="snapshot verification database",
    )
    # PostgreSQL 17 emits a fresh psql safety token on each invocation. It is
    # transport metadata, not database state, so normalize only those two lines.
    return "\n".join(line for line in dump.splitlines() if not line.startswith(("\\restrict ", "\\unrestrict ")))


def _verification_migration_heads(postgres: str) -> list[str]:
    output = _run(
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
            ("SELECT version_num FROM verification_service.alembic_version ORDER BY version_num"),
        ],
        label="read verification migration heads",
    )
    return [line.strip() for line in output.splitlines() if line.strip()]


def _start_service(
    command: list[str],
    service: str,
    target: ArtifactTarget,
    *,
    label: str,
    compatibility_enabled: bool = True,
) -> str:
    _run(command, label=label)
    base_url = f"http://127.0.0.1:{_service_port(service, target)}"
    health = _wait_for_health(base_url, service)
    if compatibility_enabled:
        _assert_health(health, target)
    else:
        _require(target is RUST_TARGET, "only the Rust service has a compatibility switch")
        _require(health.get("status") == "healthy", "default-disabled service is unhealthy")
        _require(isinstance(health.get("components"), dict), "default-disabled health components changed")
        _require("native_backend" not in health, "compatibility health leaked while disabled")
        _assert_compatibility_routes_absent(base_url)
        return base_url
    compatibility_health = _http_json(
        "GET",
        f"{base_url}/v1/verification/health",
        expected_status=200,
    )
    _require(
        compatibility_health == {"status": "healthy"},
        "compatibility health contract changed",
    )
    return base_url


def _assert_native_service_health(value: dict[str, Any], pin: dict[str, Any]) -> None:
    _require(
        set(value) == {"status", "service", "backend", "version", "build_revision"},
        "native Rust verification health shape changed",
    )
    _require(value.get("status") == "healthy", "native Rust verification service is unhealthy")
    _require(value.get("service") == "verification", "native Rust verification service identity changed")
    _require(value.get("backend") == "rust", "native Rust verification backend identity changed")
    _require(value.get("version") == pin["version"], "native Rust verification version changed")
    _require(value.get("build_revision") == pin["commit"], "native Rust verification revision changed")


def _session_row(postgres: str, session_id: str) -> dict[str, Any]:
    _require(
        bool(re.fullmatch(r"[A-Za-z0-9_-]{32,64}", session_id)),
        "session ID is unsafe for the persistence assertion",
    )
    query = (
        "SELECT json_build_object("
        "'status', lower(status),"
        "'presentation_data', presentation_data,"
        "'verified_claims', verified_claims,"
        "'verification_evidence', verification_evidence,"
        "'nonce', nonce,"
        "'submission_sha256', submission_sha256,"
        "'processing_token_sha256', processing_token_sha256,"
        "'processing_started_at', processing_started_at,"
        "'processing_expires_at', processing_expires_at"
        f") FROM public.verification_sessions WHERE id='{session_id}'"
    )
    output = _run(
        ["docker", "exec", postgres, "psql", "-U", "postgres", "-d", "verifier", "-tAc", query],
        label="read minimized verification session",
    )
    try:
        value = json.loads(output)
    except json.JSONDecodeError as exc:
        raise ArtifactRuntimeError("verification session row was not valid JSON") from exc
    _require(isinstance(value, dict), "verification session row is missing")
    return value


def _expire_session(postgres: str, session_id: str) -> None:
    _require(
        bool(re.fullmatch(r"[A-Za-z0-9_-]{32,64}", session_id)),
        "session ID is unsafe for the expiry assertion",
    )
    result = _run(
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
                "UPDATE public.verification_sessions "
                "SET expires_at=clock_timestamp() - interval '1 second' "
                f"WHERE id='{session_id}'"
            ),
        ],
        label="expire verification session",
    )
    _require(result == "UPDATE 1", "verification session expiry fixture did not update one row")


def _assert_terminal_row_minimized(
    postgres: str,
    session_id: str,
    presentation: str,
    prohibited: list[str],
) -> None:
    row = _session_row(postgres, session_id)
    presentation_digest = hashlib.sha256(presentation.encode("utf-8")).hexdigest()
    _require(row["status"] == "failed", "terminal database status changed")
    _require(row["presentation_data"] is None, "raw presentation was persisted")
    _require(row["verified_claims"] in (None, {}), "raw verified claims were persisted")
    _require(row["nonce"] is None, "terminal nonce was not cleared")
    _require(row["submission_sha256"] == presentation_digest, "submission digest changed")
    for field in (
        "processing_token_sha256",
        "processing_started_at",
        "processing_expires_at",
    ):
        _require(row[field] is None, f"terminal {field} was not cleared")
    _require(
        presentation_digest in json.dumps(row["verification_evidence"], sort_keys=True),
        "terminal evidence omitted the submission digest",
    )
    _assert_private_material_absent(row, prohibited)


def _assert_expired_row_minimized(postgres: str, session_id: str, prohibited: list[str]) -> None:
    row = _session_row(postgres, session_id)
    _require(row["status"] == "expired", "expired session status was not persisted")
    _require(row["presentation_data"] is None, "expired session retained raw presentation")
    _require(row["verified_claims"] in (None, {}), "expired session retained raw verified claims")
    _require(row["nonce"] is None, "expired session nonce was retained")
    _require(row["submission_sha256"] is None, "expired session retained a rejected submission digest")
    for field in (
        "processing_token_sha256",
        "processing_started_at",
        "processing_expires_at",
    ):
        _require(row[field] is None, f"expired session {field} was not cleared")
    _assert_private_material_absent(row, prohibited)


def run_artifact_test(pin: dict[str, Any], evidence_path: Path, *, provenance_verified: bool) -> dict[str, Any]:
    evidence_path.unlink(missing_ok=True)
    return _run_artifact_test(pin, evidence_path, provenance_verified=provenance_verified)


def _run_artifact_test(pin: dict[str, Any], evidence_path: Path, *, provenance_verified: bool) -> dict[str, Any]:
    _require(provenance_verified, "artifact provenance must be verified before runtime testing")
    target = artifact_target(pin)
    postgres_image = load_postgres_image()
    reference = image_reference(pin)
    if pin["schema"] == CANDIDATE_PIN_SCHEMA:
        inspected = json.loads(
            _run(
                ["docker", "image", "inspect", reference, "--format", "{{json .}}"],
                label="inspect loaded candidate image",
            )
        )
        exported_config_digest = _exported_candidate_config_digest(reference, pin, inspected)
        _assert_loaded_candidate_inspection(
            inspected,
            pin,
            exported_config_digest=exported_config_digest,
        )
    suffix = uuid.uuid4().hex[:12]
    network = f"marty-verifier-{suffix}"
    postgres = f"marty-verifier-db-{suffix}"
    service = f"marty-verifier-api-{suffix}"
    invalid_service = f"marty-verifier-invalid-{suffix}"
    disabled_service = f"marty-verifier-disabled-{suffix}"
    database_password = secrets.token_urlsafe(32)
    api_key = secrets.token_urlsafe(32)
    vds_only_api_key = secrets.token_urlsafe(32)
    oid4vp_only_api_key = secrets.token_urlsafe(32)
    resolver_key = secrets.token_urlsafe(32)
    private_material = [api_key, vds_only_api_key, oid4vp_only_api_key, resolver_key]
    organization_id = str(uuid.uuid4())
    issuer_did = "did:web:vds-issuer.integration.invalid"
    private_key, public_jwk, method_id = make_vds_key_material(issuer_did)
    barcode = make_vds_barcode(issuer_did, method_id, private_key)
    governance = build_governance(
        pin,
        api_key,
        organization_id,
        issuer_did,
        vds_only_api_key=vds_only_api_key,
        oid4vp_only_api_key=oid4vp_only_api_key,
    )
    database_url = f"postgresql+asyncpg://postgres:{database_password}@{postgres}:5432/verifier"
    completed_checks: list[str] = []
    session_resample_count = 0
    session_resample_reason = _safe_session_resample_reason(pin) or "not_allowlisted_no_resampling"
    documented_differences: set[str] = set()
    state = ResolverState(
        api_key=resolver_key,
        organization_id=organization_id,
        issuer_did=issuer_did,
        method_id=method_id,
        public_jwk=public_jwk,
    )
    harness = harness_subject()
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

        migration_command = _migration_command(reference, target, network, database_url)
        _run(migration_command, label="apply verification migrations first pass", timeout=180)
        first_database = _verification_database_snapshot(postgres)
        first_heads = _verification_migration_heads(postgres)
        _require(first_heads == [EXPECTED_MIGRATION_HEAD], "first migration application reached an unexpected head")
        completed_checks.append("migrations.applied")
        _run(migration_command, label="apply verification migrations second pass", timeout=180)
        second_database = _verification_database_snapshot(postgres)
        second_heads = _verification_migration_heads(postgres)
        _require(
            first_database == second_database,
            "second migration application changed the verification database",
        )
        _require(
            second_heads == [EXPECTED_MIGRATION_HEAD],
            "second migration application reached an unexpected head",
        )
        completed_checks.append("migrations.idempotent-reapplication")

        if target is RUST_TARGET:
            disabled_command = [
                "docker",
                "run",
                "-d",
                "--name",
                disabled_service,
                "--network",
                network,
                "-p",
                f"127.0.0.1::{target.service_port}",
                "-e",
                f"SERVICE_NAME={target.service_name}",
                "-e",
                "ENVIRONMENT=test",
                reference,
            ]
            disabled_base_url = _start_service(
                disabled_command,
                disabled_service,
                target,
                label="start Rust verification image with compatibility default disabled",
                compatibility_enabled=False,
            )
            _assert_native_service_health(
                _http_json(
                    "GET",
                    f"{disabled_base_url}/v1/verify/health",
                    expected_status=200,
                ),
                pin,
            )
            completed_checks.append("compatibility.default-disabled-routes-absent")
            _docker_remove("container", disabled_service)

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
            base_url = _start_service(
                service_command,
                service,
                target,
                label="start released verification image",
            )
            completed_checks.append("health.native-capabilities")
            completed_checks.append("compatibility.adapter-enabled")

            definition = presentation_definition()
            session_body = {
                "verifier_did": "did:web:verifier.integration.invalid",
                "presentation_definition": definition,
                "session_duration_seconds": 600,
            }
            missing_auth = _http_json(
                "POST",
                f"{base_url}/v1/verification/sessions",
                body=session_body,
                expected_status=401,
            )
            _assert_error(missing_auth, "X-API-Key header is missing")
            wrong_purpose = _http_json(
                "POST",
                f"{base_url}/v1/verification/sessions",
                body=session_body,
                api_key=vds_only_api_key,
                expected_status=401,
            )
            _assert_error(wrong_purpose, "Invalid or unauthorized API key")
            policy_mismatch = _http_json(
                "POST",
                f"{base_url}/v1/verification/sessions",
                body={**session_body, "verifier_did": "did:web:wrong-verifier.integration.invalid"},
                api_key=api_key,
                expected_status=422,
            )
            _assert_error(policy_mismatch, "Verification request does not match its governed policy")
            malformed_session, resampled, _reason = _create_safe_session(
                base_url,
                session_body,
                api_key,
                pin,
                organization_id,
            )
            session_resample_count += resampled
            malformed_result = _http_json(
                "POST",
                f"{base_url}/v1/verification/sessions/{malformed_session['id']}/submit",
                body={"presentation": "header.payload.signature"},
                expected_status=200,
            )
            difference = _assert_session_result(
                malformed_result,
                malformed_session["id"],
                target,
                defer_known_difference=True,
            )
            if difference is not None:
                documented_differences.add(difference)
            _assert_terminal_row_minimized(
                postgres,
                malformed_session["id"],
                "header.payload.signature",
                private_material + ["header.payload.signature"],
            )
            completed_checks.append("session.malformed-presentation-fails-closed")

            session, resampled, _reason = _create_safe_session(
                base_url,
                session_body,
                api_key,
                pin,
                organization_id,
            )
            session_resample_count += resampled
            session_id = session["id"]
            pending = _http_json(
                "GET",
                f"{base_url}/v1/verification/sessions/{session_id}",
                expected_status=200,
            )
            _require(pending == session, "created and retrieved pending sessions diverged")
            session_nonce = session["nonce"]
            signed_presentation = make_oid4vp_jwt(
                session_nonce,
                "did:web:verifier.integration.invalid",
            )
            completed_checks.append("session.create-auth-policy-and-reload-parity")

            submitted = _http_json(
                "POST",
                f"{base_url}/v1/verification/sessions/{session_id}/submit",
                body={"presentation": signed_presentation},
                expected_status=200,
            )
            difference = _assert_session_result(
                submitted,
                session_id,
                target,
                expected_decision="INDETERMINATE",
                expected_passed_checks={"presentation.proof", "transaction.binding"},
                defer_known_difference=True,
            )
            if difference is not None:
                documented_differences.add(difference)
            _assert_private_material_absent(
                submitted,
                private_material + [signed_presentation, session_nonce, "sensitive-holder-claim"],
            )
            _assert_terminal_row_minimized(
                postgres,
                session_id,
                signed_presentation,
                private_material + [signed_presentation, session_nonce, "sensitive-holder-claim"],
            )

            _docker_remove("container", service)
            base_url = _start_service(
                service_command,
                service,
                target,
                label="restart released verification image",
            )
            terminal = _http_json(
                "GET",
                f"{base_url}/v1/verification/sessions/{session_id}",
                expected_status=200,
            )
            _assert_session(
                terminal,
                organization_id=organization_id,
                expected_status="failed",
                nonce_present=False,
            )
            _require(terminal["id"] == session_id, "terminal reload returned a different session")
            replay = _http_json(
                "POST",
                f"{base_url}/v1/verification/sessions/{session_id}/submit",
                body={"presentation": signed_presentation},
                expected_status=200,
            )
            _require(replay == submitted, "same-digest terminal retry changed the frozen decision")
            conflict = _http_json(
                "POST",
                f"{base_url}/v1/verification/sessions/{session_id}/submit",
                body={"presentation": "header.payload.signature"},
                expected_status=409,
            )
            _assert_error(conflict, "Verification session submission conflicts")
            completed_checks.append("session.postgres-restart-minimization-and-replay-parity")

            missing_session = "A" * 43
            not_found = _http_json(
                "GET",
                f"{base_url}/v1/verification/sessions/{missing_session}",
                expected_status=404,
            )
            _assert_error(not_found, "Session not found")
            submit_not_found = _http_json(
                "POST",
                f"{base_url}/v1/verification/sessions/{missing_session}/submit",
                body={"presentation": signed_presentation},
                expected_status=404,
            )
            _assert_error(submit_not_found, "Verification session not found")

            expiring, resampled, _reason = _create_safe_session(
                base_url,
                session_body,
                oid4vp_only_api_key,
                pin,
                organization_id,
            )
            session_resample_count += resampled
            expiring_id = expiring["id"]
            expiring_presentation = make_oid4vp_jwt(
                expiring["nonce"],
                "did:web:verifier.integration.invalid",
            )
            _expire_session(postgres, expiring_id)
            expired = _http_json(
                "POST",
                f"{base_url}/v1/verification/sessions/{expiring_id}/submit",
                body={"presentation": expiring_presentation},
                expected_status=410,
            )
            _assert_error(expired, "Verification session has expired")
            _assert_expired_row_minimized(
                postgres,
                expiring_id,
                private_material + [expiring_presentation, expiring["nonce"], "sensitive-holder-claim"],
            )
            completed_checks.append("session.not-found-expiry-and-conflict-errors")

            same_digest_session, resampled, _reason = _create_safe_session(
                base_url,
                session_body,
                oid4vp_only_api_key,
                pin,
                organization_id,
            )
            session_resample_count += resampled
            same_digest_presentation = make_oid4vp_jwt(
                same_digest_session["nonce"],
                "did:web:verifier.integration.invalid",
            )
            same_accepted, same_conflicts = _partition_submission_outcomes(
                _parallel_submissions(
                    base_url,
                    same_digest_session["id"],
                    [same_digest_presentation, same_digest_presentation],
                )
            )
            _require(same_accepted, "same-digest race produced no terminal result")
            _require(
                len(same_accepted) + len(same_conflicts) == 2,
                "same-digest race lost an outcome",
            )
            for accepted in same_accepted:
                difference = _assert_session_result(
                    accepted,
                    same_digest_session["id"],
                    target,
                    expected_decision="INDETERMINATE",
                    expected_passed_checks={"presentation.proof", "transaction.binding"},
                    defer_known_difference=True,
                )
                if difference is not None:
                    documented_differences.add(difference)
            _require(
                all(value == same_accepted[0] for value in same_accepted),
                "same-digest race produced divergent terminal decisions",
            )
            same_retry = _http_json(
                "POST",
                f"{base_url}/v1/verification/sessions/{same_digest_session['id']}/submit",
                body={"presentation": same_digest_presentation},
                expected_status=200,
            )
            _require(same_retry == same_accepted[0], "same-digest retry changed the race decision")
            _assert_terminal_row_minimized(
                postgres,
                same_digest_session["id"],
                same_digest_presentation,
                private_material + [same_digest_presentation, same_digest_session["nonce"]],
            )

            different_digest_session, resampled, _reason = _create_safe_session(
                base_url,
                session_body,
                oid4vp_only_api_key,
                pin,
                organization_id,
            )
            session_resample_count += resampled
            competing_presentations = [
                make_oid4vp_jwt(
                    different_digest_session["nonce"],
                    "did:web:verifier.integration.invalid",
                    fixture_id=f"competing-{index}",
                )
                for index in range(2)
            ]
            different_accepted, different_conflicts = _partition_submission_outcomes(
                _parallel_submissions(
                    base_url,
                    different_digest_session["id"],
                    competing_presentations,
                )
            )
            _require(
                len(different_accepted) == 1 and len(different_conflicts) == 1,
                "different-digest race did not produce one decision and one conflict",
            )
            winner = different_accepted[0]
            difference = _assert_session_result(
                winner,
                different_digest_session["id"],
                target,
                expected_decision="INDETERMINATE",
                expected_passed_checks={"presentation.proof", "transaction.binding"},
                defer_known_difference=True,
            )
            if difference is not None:
                documented_differences.add(difference)
            winning_presentations = []
            for presentation in competing_presentations:
                status, value = _request_json(
                    "POST",
                    f"{base_url}/v1/verification/sessions/{different_digest_session['id']}/submit",
                    body={"presentation": presentation},
                )
                if status == 200:
                    _require(value == winner, "winning digest retry changed the race decision")
                    winning_presentations.append(presentation)
                else:
                    _require(status == 409, "losing digest retry returned an unexpected status")
                    _assert_error(value, "Verification session submission conflicts")
            _require(len(winning_presentations) == 1, "race winner digest was not deterministic")
            _assert_terminal_row_minimized(
                postgres,
                different_digest_session["id"],
                winning_presentations[0],
                private_material + competing_presentations + [different_digest_session["nonce"]],
            )
            completed_checks.append("session.concurrent-claim-and-fencing-parity")

            direct_body = {
                "presentation": "header.payload.signature",
                "presentation_definition": definition,
                "verifier_did": "did:web:verifier.integration.invalid",
            }
            direct_missing = _http_json(
                "POST",
                f"{base_url}/v1/verification/verify",
                body=direct_body,
                expected_status=401,
            )
            _assert_error(direct_missing, "X-API-Key header is missing")
            direct_wrong_purpose = _http_json(
                "POST",
                f"{base_url}/v1/verification/verify",
                body=direct_body,
                api_key=vds_only_api_key,
                expected_status=401,
            )
            _assert_error(direct_wrong_purpose, "Invalid or unauthorized API key")
            direct_policy_mismatch = _http_json(
                "POST",
                f"{base_url}/v1/verification/verify",
                body={**direct_body, "verifier_did": "did:web:wrong-verifier.integration.invalid"},
                api_key=api_key,
                expected_status=422,
            )
            _assert_error(
                direct_policy_mismatch,
                "Verification request does not match its governed policy",
            )
            direct = _http_json(
                "POST",
                f"{base_url}/v1/verification/verify",
                body=direct_body,
                api_key=api_key,
                expected_status=200,
            )
            _assert_canonical(
                direct,
                decision="FAIL",
                expected_checks=set(OID4VP_REQUIRED_CHECKS),
            )
            _assert_private_material_absent(
                direct,
                private_material + ["header.payload.signature"],
            )
            direct_signed_presentation = make_oid4vp_jwt(None, "did:web:verifier.integration.invalid")
            direct_signed = _http_json(
                "POST",
                f"{base_url}/v1/verification/verify",
                body={**direct_body, "presentation": direct_signed_presentation},
                api_key=oid4vp_only_api_key,
                expected_status=200,
            )
            _assert_canonical(
                direct_signed,
                decision="FAIL",
                expected_checks=set(OID4VP_REQUIRED_CHECKS),
                expected_passed_checks=set(),
                expected_input_digest=(
                    "sha256:" + hashlib.sha256(direct_signed_presentation.encode("utf-8")).hexdigest()
                ),
                expected_verification_method="jwt_vp",
                expected_check_projection={
                    "presentation.structure": (
                        "NOT_PERFORMED",
                        "PRESENTATION_STRUCTURE_NOT_PERFORMED",
                    ),
                    "presentation.proof": (
                        "NOT_PERFORMED",
                        "PRESENTATION_PROOF_NOT_PERFORMED",
                    ),
                    "credential.proof": (
                        "NOT_PERFORMED",
                        "CREDENTIAL_PROOF_NOT_PERFORMED",
                    ),
                    "issuer.trust": ("NOT_PERFORMED", "ISSUER_TRUST_NOT_PERFORMED"),
                    "credential.status": (
                        "NOT_PERFORMED",
                        "CREDENTIAL_STATUS_NOT_CHECKED",
                    ),
                    "holder.binding": (
                        "NOT_PERFORMED",
                        "HOLDER_BINDING_NOT_PERFORMED",
                    ),
                    "transaction.binding": ("FAILED", "TRANSACTION_BINDING_INVALID"),
                    "claim.constraints": (
                        "NOT_PERFORMED",
                        "CLAIM_CONSTRAINTS_NOT_PERFORMED",
                    ),
                },
            )
            _assert_private_material_absent(
                direct_signed,
                private_material + [direct_signed_presentation, "sensitive-holder-claim"],
            )

            structured_presentation: dict[str, Any] = {}
            direct_structured = _http_json(
                "POST",
                f"{base_url}/v1/verification/verify",
                body={**direct_body, "presentation": structured_presentation},
                api_key=oid4vp_only_api_key,
                expected_status=200,
            )
            _assert_canonical(
                direct_structured,
                decision="FAIL",
                expected_checks=set(OID4VP_REQUIRED_CHECKS),
                expected_passed_checks=set(),
                expected_input_digest="sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
                expected_verification_method="w3c_vc",
                expected_check_projection={
                    "presentation.structure": (
                        "NOT_PERFORMED",
                        "PRESENTATION_STRUCTURE_NOT_PERFORMED",
                    ),
                    "presentation.proof": (
                        "NOT_PERFORMED",
                        "PRESENTATION_PROOF_NOT_PERFORMED",
                    ),
                    "credential.proof": ("FAILED", "CREDENTIAL_PROOFS_INVALID"),
                    "issuer.trust": ("NOT_PERFORMED", "ISSUER_TRUST_NOT_PERFORMED"),
                    "credential.status": (
                        "NOT_PERFORMED",
                        "CREDENTIAL_STATUS_NOT_CHECKED",
                    ),
                    "holder.binding": (
                        "NOT_PERFORMED",
                        "HOLDER_BINDING_NOT_PERFORMED",
                    ),
                    "transaction.binding": (
                        "NOT_PERFORMED",
                        "TRANSACTION_BINDING_NOT_PERFORMED",
                    ),
                    "claim.constraints": (
                        "NOT_PERFORMED",
                        "CLAIM_CONSTRAINTS_NOT_PERFORMED",
                    ),
                },
            )
            _require(
                {
                    "processing_status": direct_structured.get("processing_status"),
                    "decision_code": direct_structured.get("decision_code"),
                    "error": direct_structured.get("error"),
                    "verified_claims": direct_structured.get("verified_claims"),
                    "claim_results": direct_structured.get("claim_results"),
                }
                == {
                    "processing_status": "COMPLETED",
                    "decision_code": "REQUIRED_CHECK_FAILED",
                    "error": "Canonical verification did not pass",
                    "verified_claims": None,
                    "claim_results": [],
                },
                "structured direct response projection changed",
            )
            completed_checks.append("direct.auth-policy-jwt-no-nonce-structured-and-malformed-fail-closed")

            endpoint = f"{base_url}/v1/verification/verify/vds-nc"
            request_body = {
                "barcode": barcode,
                "issuer_did": issuer_did,
                "verification_method_id": method_id,
                "algorithm": "ES256",
            }
            vds_missing = _http_json("POST", endpoint, body=request_body, expected_status=401)
            _assert_error(vds_missing, "X-API-Key header is missing")
            vds_invalid = _http_json(
                "POST",
                endpoint,
                body=request_body,
                api_key="invalid",
                expected_status=401,
            )
            _assert_error(vds_invalid, "Invalid or unauthorized API key")
            vds_wrong_purpose = _http_json(
                "POST",
                endpoint,
                body=request_body,
                api_key=oid4vp_only_api_key,
                expected_status=401,
            )
            _assert_error(vds_wrong_purpose, "Invalid or unauthorized API key")
            completed_checks.append("authorization.missing-invalid-and-wrong-purpose-rejected")

            caller_selected = {**request_body, "organization_id": organization_id}
            caller_rejected = _http_json(
                "POST",
                endpoint,
                body=caller_selected,
                api_key=api_key,
                expected_status=422,
            )
            difference = _assert_extra_field_error(
                caller_rejected,
                "organization_id",
                allow_minimized_detail=target is RUST_TARGET,
            )
            if difference is not None:
                documented_differences.add(difference)
            completed_checks.append("authority.caller-selection-rejected")

            resolver_before = state.request_count
            untrusted = {**request_body, "issuer_did": "did:web:attacker.integration.invalid"}
            untrusted_result = _http_json(
                "POST",
                endpoint,
                body=untrusted,
                api_key=api_key,
                expected_status=500,
            )
            _assert_error(untrusted_result, "VDS-NC verification failed")
            _require(state.request_count == resolver_before, "untrusted issuer reached the internal resolver")
            completed_checks.append("trust.unregistered-issuer-rejected-before-resolution")

            state.return_usable_jwk = False
            unusable_status = 500 if target is LEGACY_TARGET else 422
            try:
                unusable_jwk = _http_json(
                    "POST",
                    endpoint,
                    body=request_body,
                    api_key=api_key,
                    expected_status=unusable_status,
                )
            finally:
                state.return_usable_jwk = True
            unusable_detail = (
                "VDS-NC verification failed"
                if target is LEGACY_TARGET
                else "issuer_did did not resolve to a usable public JWK"
            )
            _assert_error(unusable_jwk, unusable_detail)
            completed_checks.append("resolver.unusable-jwk-fails-closed")

            positive = _http_json(
                "POST",
                endpoint,
                body=request_body,
                api_key=vds_only_api_key,
                expected_status=200,
            )
            _assert_canonical(
                positive,
                decision="PASS",
                expected_check_projection=VDS_PASS_CHECK_PROJECTION,
            )
            _assert_private_material_absent(
                positive,
                private_material + _vds_private_material(barcode),
            )
            completed_checks.append("canonical.vds-positive-pass")

            tampered_signature = base64.b64encode(bytes(64)).decode("ascii")
            tampered = {**request_body, "barcode": barcode.rsplit("~", 1)[0] + "~" + tampered_signature}
            rejected = _http_json("POST", endpoint, body=tampered, api_key=api_key, expected_status=200)
            _assert_canonical(
                rejected,
                decision="FAIL",
                expected_check_projection=VDS_FAIL_CHECK_PROJECTION,
            )
            _assert_private_material_absent(
                rejected,
                private_material + _vds_private_material(tampered["barcode"]),
            )
            completed_checks.append("canonical.tampered-signature-fail")

            malformed = {**request_body, "barcode": "DC03USA~{}~not-base64"}
            malformed_result = _http_json("POST", endpoint, body=malformed, api_key=api_key, expected_status=200)
            _assert_canonical(
                malformed_result,
                decision="FAIL",
                expected_check_projection=VDS_FAIL_CHECK_PROJECTION,
            )
            _assert_private_material_absent(
                malformed_result,
                private_material + _vds_private_material(malformed["barcode"]),
            )
            completed_checks.append("canonical.malformed-evidence-fail")

        evidence = {
            "schema": (CANDIDATE_EVIDENCE_SCHEMA if pin["schema"] == CANDIDATE_PIN_SCHEMA else target.evidence_schema),
            "classification": "ElevenID-owned artifact integration",
            "official_suite_invoked": False,
            "official_suite_source_modified": False,
            "status": ("ineligible" if KNOWN_INELIGIBLE_FAILURE_ID in documented_differences else "passed"),
            "release_clearance": RELEASE_CLEARANCE_BLOCKED,
            "blockers": [OID4VP_POSITIVE_RUNTIME_BLOCKER],
            "subject": evidence_subject(pin),
            "harness": harness,
            "checks": completed_checks,
            "safe_session_selection": _session_selection_evidence(
                session_resample_reason,
                session_resample_count,
            ),
            "documented_differences": sorted(documented_differences),
            "resolver_request_count": state.request_count,
            "started_at": started.isoformat().replace("+00:00", "Z"),
            "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        _require(
            documented_differences <= DOCUMENTED_TARGET_DIFFERENCES | {KNOWN_INELIGIBLE_FAILURE_ID},
            "artifact produced an undocumented language-neutral difference",
        )
        if KNOWN_INELIGIBLE_FAILURE_ID in documented_differences:
            raise ValueError(KNOWN_INELIGIBLE_FAILURE_MESSAGE)
        return evidence
    except (ArtifactRuntimeError, ValueError) as exc:
        raise ArtifactRunError(
            str(exc),
            _session_selection_evidence(
                session_resample_reason,
                session_resample_count,
            ),
        ) from exc
    finally:
        _docker_remove("container", disabled_service)
        _docker_remove("container", invalid_service)
        _docker_remove("container", service)
        _docker_remove("container", postgres)
        _docker_remove("network", network)


def run_expected_failure(
    pin: dict[str, Any],
    evidence_path: Path,
    *,
    provenance_verified: bool,
) -> dict[str, Any]:
    expected = pin["expected_failure"]
    harness = harness_subject()
    started = datetime.now(UTC)
    evidence_path.unlink(missing_ok=True)
    selection = _session_selection_evidence(
        _safe_session_resample_reason(pin) or "not_allowlisted_no_resampling",
        0,
    )
    runtime_observation: dict[str, Any] | None = None
    with tempfile.TemporaryDirectory(prefix="marty-verifier-negative-") as temporary_directory:
        private_evidence = Path(temporary_directory) / "artifact.json"
        try:
            run_artifact_test(pin, private_evidence, provenance_verified=provenance_verified)
        except (ArtifactRuntimeError, ValueError) as exc:
            if str(exc) != expected["message"]:
                raise ValueError("ineligible artifact failed for an unexpected reason") from exc
            if isinstance(exc, ArtifactRunError):
                selection = exc.safe_session_selection
            if private_evidence.exists():
                candidate = json.loads(private_evidence.read_text(encoding="utf-8"))
                _require(isinstance(candidate, dict), "negative-control observation was invalid")
                runtime_observation = candidate
        else:
            raise ValueError("known-ineligible artifact unexpectedly passed")
    _require(runtime_observation is not None, "known failure omitted its sanitized runtime observation")
    _require(
        runtime_observation.get("release_clearance") == RELEASE_CLEARANCE_BLOCKED
        and runtime_observation.get("blockers") == [OID4VP_POSITIVE_RUNTIME_BLOCKER],
        "negative-control observation omitted the positive-runtime release blocker",
    )
    _require(
        set(runtime_observation.get("documented_differences", [])) == DOCUMENTED_TARGET_DIFFERENCES | {expected["id"]},
        "negative-control observation contained an undocumented difference",
    )
    _require(
        runtime_observation.get("safe_session_selection") == selection,
        "negative-control observation changed safe session selection evidence",
    )

    evidence = {
        "schema": RUST_EVIDENCE_SCHEMA,
        "classification": "ElevenID-owned artifact negative control",
        "official_suite_invoked": False,
        "official_suite_source_modified": False,
        "status": "expected_failure_observed",
        "release_clearance": RELEASE_CLEARANCE_BLOCKED,
        "blockers": [OID4VP_POSITIVE_RUNTIME_BLOCKER],
        "subject": evidence_subject(pin),
        "harness": harness,
        "failure_id": expected["id"],
        "safe_session_selection": selection,
        "checks": runtime_observation["checks"],
        "documented_differences": runtime_observation["documented_differences"],
        "resolver_request_count": runtime_observation["resolver_request_count"],
        "attempts": 1,
        "started_at": started.isoformat().replace("+00:00", "Z"),
        "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return evidence


def _check_set(evidence: dict[str, Any]) -> frozenset[str]:
    checks = evidence.get("checks")
    _require(
        isinstance(checks, list) and all(isinstance(check, str) for check in checks),
        "artifact evidence checks were invalid",
    )
    _require(len(checks) == len(set(checks)), "artifact evidence repeated a check")
    return frozenset(checks)


def compare_artifact_evidence(
    oracle: dict[str, Any],
    candidate: dict[str, Any],
) -> dict[str, Any]:
    """Compare only portable behavioral coverage from two artifact runs."""
    _require(oracle.get("status") == "passed", "oracle artifact evidence did not pass")
    _require(
        candidate.get("status") == "expected_failure_observed",
        "candidate evidence was not the bound negative control",
    )
    _require(
        candidate.get("failure_id") == KNOWN_INELIGIBLE_FAILURE_ID,
        "candidate failed for an undocumented reason",
    )
    _require(
        set(candidate.get("documented_differences", []))
        == DOCUMENTED_TARGET_DIFFERENCES | {KNOWN_INELIGIBLE_FAILURE_ID},
        "candidate evidence contained undocumented differences",
    )
    _require(
        oracle.get("documented_differences") == [],
        "oracle evidence contained a behavioral difference",
    )
    for label, evidence in (("oracle", oracle), ("candidate", candidate)):
        _require(
            evidence.get("release_clearance") == RELEASE_CLEARANCE_BLOCKED,
            f"{label} evidence did not block release clearance",
        )
        _require(
            evidence.get("blockers") == [OID4VP_POSITIVE_RUNTIME_BLOCKER],
            f"{label} evidence omitted the positive-runtime blocker",
        )
    oracle_raw_checks = _check_set(oracle)
    candidate_raw_checks = _check_set(candidate)
    _require(
        oracle_raw_checks == EXPECTED_LANGUAGE_NEUTRAL_CHECKS,
        "oracle raw check set diverged",
    )
    _require(
        candidate_raw_checks == EXPECTED_LANGUAGE_NEUTRAL_CHECKS | RUST_ONLY_CHECKS,
        "candidate raw check set diverged",
    )
    _require(
        candidate.get("resolver_request_count") == oracle.get("resolver_request_count"),
        "candidate and oracle resolver evidence counts diverged",
    )
    return {
        "schema": "elevenid.credentials-verifier-artifact-comparison/v1",
        "status": "matched_with_documented_negative_control",
        "release_clearance": RELEASE_CLEARANCE_BLOCKED,
        "blockers": [OID4VP_POSITIVE_RUNTIME_BLOCKER],
        "language_neutral_checks": sorted(oracle_raw_checks),
        "candidate_only_checks": sorted(candidate_raw_checks - oracle_raw_checks),
        "documented_differences": candidate["documented_differences"],
        "documented_difference_details": {
            difference: DOCUMENTED_DIFFERENCE_DETAILS[difference] for difference in candidate["documented_differences"]
        },
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate-pin")
    validate.add_argument("--pin", type=Path, default=DEFAULT_PIN)
    validate.add_argument("--state", choices=("ready", "ineligible"), default="ready")
    sbom = commands.add_parser("validate-sbom")
    sbom.add_argument("--pin", type=Path, default=DEFAULT_PIN)
    sbom.add_argument("--state", choices=("ready", "ineligible"), default="ready")
    sbom.add_argument("--sbom", type=Path, required=True)
    candidate = commands.add_parser("validate-candidate")
    candidate.add_argument("--pin", type=Path, required=True)
    candidate.add_argument("--archive", type=Path, required=True)
    candidate.add_argument("--sbom", type=Path, required=True)
    candidate.add_argument("--metadata", type=Path, required=True)
    candidate.add_argument("--provenance", type=Path, required=True)
    run = commands.add_parser("run")
    run.add_argument("--pin", type=Path, default=DEFAULT_PIN)
    run.add_argument("--evidence", type=Path, required=True)
    run.add_argument("--provenance-verified", action="store_true", required=True)
    rejected = commands.add_parser("run-expected-failure")
    rejected.add_argument("--pin", type=Path, required=True)
    rejected.add_argument("--evidence", type=Path, required=True)
    rejected.add_argument("--provenance-verified", action="store_true", required=True)
    comparison = commands.add_parser("compare-evidence")
    comparison.add_argument("--oracle", type=Path, required=True)
    comparison.add_argument("--candidate", type=Path, required=True)
    comparison.add_argument("--evidence", type=Path, required=True)
    candidate_run = commands.add_parser("run-candidate")
    candidate_run.add_argument("--pin", type=Path, required=True)
    candidate_run.add_argument("--archive", type=Path, required=True)
    candidate_run.add_argument("--sbom", type=Path, required=True)
    candidate_run.add_argument("--metadata", type=Path, required=True)
    candidate_run.add_argument("--provenance", type=Path, required=True)
    candidate_run.add_argument("--evidence", type=Path, required=True)
    candidate_comparison = commands.add_parser("compare-candidate-evidence")
    candidate_comparison.add_argument("--oracle", type=Path, required=True)
    candidate_comparison.add_argument("--candidate", type=Path, required=True)
    candidate_comparison.add_argument("--oracle-pin", type=Path, required=True)
    candidate_comparison.add_argument("--candidate-pin", type=Path, required=True)
    candidate_comparison.add_argument("--evidence", type=Path, required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command in {
        "compare-evidence",
        "compare-candidate-evidence",
        "run",
        "run-expected-failure",
        "run-candidate",
    }:
        args.evidence.resolve().unlink(missing_ok=True)
    if args.command == "compare-evidence":
        oracle = json.loads(args.oracle.resolve().read_text(encoding="utf-8"))
        candidate = json.loads(args.candidate.resolve().read_text(encoding="utf-8"))
        evidence = compare_artifact_evidence(oracle, candidate)
        args.evidence.resolve().parent.mkdir(parents=True, exist_ok=True)
        args.evidence.resolve().write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(json.dumps(evidence, sort_keys=True))
        return 0
    if args.command == "compare-candidate-evidence":
        oracle_pin = load_pin(args.oracle_pin.resolve())
        candidate_pin = load_pin(args.candidate_pin.resolve(), expected_state="candidate")
        evidence = compare_oracle_candidate_evidence(
            args.oracle.resolve(),
            args.candidate.resolve(),
            oracle_pin,
            candidate_pin,
        )
        args.evidence.resolve().parent.mkdir(parents=True, exist_ok=True)
        args.evidence.resolve().write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(json.dumps(evidence, sort_keys=True))
        return 0
    if args.command in {"validate-candidate", "run-candidate"}:
        expected_state = "candidate"
    elif args.command == "run-expected-failure":
        expected_state = "ineligible"
    else:
        expected_state = getattr(args, "state", "ready")
    pin = load_pin(args.pin.resolve(), expected_state=expected_state)
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
    if args.command == "validate-candidate":
        provenance = validate_candidate_inputs(
            pin,
            archive_path=args.archive.resolve(),
            sbom_path=args.sbom.resolve(),
            metadata_path=args.metadata.resolve(),
            provenance_path=args.provenance.resolve(),
        )
        print(
            json.dumps(
                {
                    "schema": provenance["schema"],
                    "archive_digest": pin["archive"]["digest"],
                    "image_config_digest": pin["image"]["config_digest"],
                },
                sort_keys=True,
            )
        )
        return 0
    if args.command == "run-candidate":
        validate_candidate_inputs(
            pin,
            archive_path=args.archive.resolve(),
            sbom_path=args.sbom.resolve(),
            metadata_path=args.metadata.resolve(),
            provenance_path=args.provenance.resolve(),
        )
        verify_candidate_attestations(
            pin,
            args.pin.resolve(),
            args.archive.resolve(),
        )
        loaded_reference: str | None = None
        try:
            with stage_candidate_archive(pin, args.archive.resolve()) as staged_archive:
                loaded_reference = load_candidate_archive(pin, staged_archive)
            evidence = run_artifact_test(
                pin,
                args.evidence.resolve(),
                provenance_verified=True,
            )
            print(json.dumps(evidence, sort_keys=True))
            return 0
        finally:
            if loaded_reference is not None:
                _remove_candidate_images(
                    f"{pin['image']['archive_tag']}:latest",
                    loaded_reference,
                )
    runner = run_expected_failure if args.command == "run-expected-failure" else run_artifact_test
    evidence = runner(pin, args.evidence.resolve(), provenance_verified=args.provenance_verified)
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ArtifactRuntimeError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Credentials verifier artifact error: {exc}")
        raise SystemExit(2) from exc
