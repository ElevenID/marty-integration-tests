#!/usr/bin/env python3
"""Exercise the immutable Marty Credentials verification service image."""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import json
import re
import secrets
import subprocess
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
from pathlib import Path
from typing import Any, NamedTuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PIN = ROOT / "config" / "credentials-verifier-oracle.json"
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


def load_pin(path: Path = DEFAULT_PIN, *, expected_state: str = "ready") -> dict[str, Any]:
    _require(expected_state in {"ready", "ineligible"}, "unsupported artifact pin state")
    value = json.loads(path.read_text(encoding="utf-8"))
    target = artifact_target(value)
    _require(value.get("state") == expected_state, f"artifact pin must be {expected_state}")
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
    return f"{pin['image']['uri']}@{pin['image']['digest']}"


def evidence_subject(pin: dict[str, Any]) -> dict[str, Any]:
    return {
        "repository": pin["repository"],
        "release_tag": pin["release_tag"],
        "version": pin["version"],
        "commit": pin["commit"],
        "image_reference": image_reference(pin),
        "sbom_digest": pin["sbom"]["digest"],
        "provenance_verified": True,
    }


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
    routes = (
        ("GET", "/v1/verification/health"),
        ("POST", "/v1/verification/sessions"),
        ("GET", "/v1/verification/sessions/A"),
        ("POST", "/v1/verification/sessions/A/submit"),
        ("POST", "/v1/verification/verify"),
        ("POST", "/v1/verification/verify/vds-nc"),
    )
    for method, path in routes:
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


def _migration_version(postgres: str) -> str:
    value = _run(
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
            "SELECT version_num FROM verification_service.alembic_version",
        ],
        label="read verification migration version",
    )
    _require(bool(re.fullmatch(r"[0-9A-Za-z_.-]+", value)), "verification migration version is invalid")
    return value


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
        _require(isinstance(health, dict), "native Rust health response was not an object")
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
    suffix = uuid.uuid4().hex[:12]
    network = f"marty-verifier-{suffix}"
    postgres = f"marty-verifier-db-{suffix}"
    service = f"marty-verifier-api-{suffix}"
    disabled_service = f"marty-verifier-native-{suffix}"
    invalid_service = f"marty-verifier-invalid-{suffix}"
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
        first_migration_version = _migration_version(postgres)
        _run(
            _migration_command(reference, target, network, database_url),
            label="reapply released verification migrations",
            timeout=180,
        )
        _require(
            _migration_version(postgres) == first_migration_version,
            "verification migration head changed after idempotent reapplication",
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
            _require(
                _http_status("GET", f"{disabled_base_url}/v1/verify/health") == 200,
                "native Rust verification routes were unavailable with compatibility disabled",
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
            "schema": target.evidence_schema,
            "classification": "ElevenID-owned artifact integration",
            "official_suite_invoked": False,
            "official_suite_source_modified": False,
            "status": (
                "ineligible" if KNOWN_INELIGIBLE_FAILURE_ID in documented_differences else "passed"
            ),
            "release_clearance": RELEASE_CLEARANCE_BLOCKED,
            "blockers": [OID4VP_POSITIVE_RUNTIME_BLOCKER],
            "subject": evidence_subject(pin),
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
            documented_differences
            <= DOCUMENTED_TARGET_DIFFERENCES | {KNOWN_INELIGIBLE_FAILURE_ID},
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
        set(runtime_observation.get("documented_differences", []))
        == DOCUMENTED_TARGET_DIFFERENCES | {expected["id"]},
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
            difference: DOCUMENTED_DIFFERENCE_DETAILS[difference]
            for difference in candidate["documented_differences"]
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
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
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
    expected_state = "ineligible" if args.command == "run-expected-failure" else getattr(args, "state", "ready")
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
