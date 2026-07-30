#!/usr/bin/env python3
"""Run one isolated official-interoperability lane against released artifacts."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import stat
import subprocess
import sys
import time
from contextlib import suppress
from hashlib import sha256
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from haip_test_certificates import (  # noqa: E402
    OID4VP_TRUST_ANCHOR_FILE_ENV,
    load_verifier_environment,
)
from official_suite_checkout import verify_checkout  # noqa: E402
from oidf_mdoc_binding_audit import audit as audit_oidf_mdoc_binding  # noqa: E402

LANES = {
    "oid4vci-issuer",
    "oid4vp-final",
    "oid4vp-url-query",
    "oid4vp-mdoc",
    "haip",
    "w3c-v2",
    "eudi",
}
RUN_ID = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
DIGEST_IMAGE = re.compile(r"^[a-z0-9.-]+/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$")
W3C_API_KEY = re.compile(r"^mk_test_[A-Za-z0-9_-]{1,120}$")
W3C_CONFORMANCE_RATE_LIMIT_RPM = "100000"
W3C_CONFORMANCE_TOKEN_RATE_LIMIT = "100000"
W3C_MANIFEST = ROOT / "conformance" / "w3c-vc-data-model-v2.json"
# Public OID4VCI credential-configuration identifiers are opaque JSON object
# keys.  Marty uses a fragment-like suffix (for example, ``PID#sd-jwt``) to
# distinguish formats for the same credential type, so ``#`` is intentional.
# Keep the fixture channel narrowly printable because these values are also
# copied into runner configuration and diagnostic output.
IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:#/+%@-]{1,256}$")
INITIALIZER_SECRET = re.compile(
    r"(?i)(\b(?:authorization|cookie|password|secret|session(?:_id)?|token|private[_-]?key|api[_-]?key)\b\s*(?:=|:|is)\s*)([^\s,;]+)"
)
W3C_DIAGNOSTIC_LINE = re.compile(
    r"(?i)(?:credential creation failed|credential status allocation|exception|traceback|error|failed)"
)
PROXY_DIAGNOSTIC_CLASSES = {
    "dns-resolution": re.compile(r"(?i)(?:host not found|could not be resolved)"),
    "upstream-connect": re.compile(r"(?i)(?:connect\(\) failed|connection refused)"),
    "upstream-timeout": re.compile(r"(?i)(?:upstream timed out|connection timed out)"),
    "no-live-upstream": re.compile(r"(?i)no live upstreams"),
}


def w3c_related_resource_allowlist() -> str:
    """Return the reviewed exact-URL allowlist for the pinned official lane."""
    manifest = json.loads(W3C_MANIFEST.read_text(encoding="utf-8"))
    values = manifest.get("deployment", {}).get("related_resource_allowlist")
    if not isinstance(values, list) or not values:
        raise ValueError("W3C deployment related-resource allowlist must be non-empty")

    reviewed: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value:
            raise ValueError("W3C related-resource allowlist entries must be strings")
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "W3C related-resource allowlist entries must be exact HTTPS URLs "
                "without credentials, query strings, or fragments"
            )
        reviewed.append(value)
    if len(set(reviewed)) != len(reviewed):
        raise ValueError("W3C related-resource allowlist entries must be unique")
    return ",".join(reviewed)


EUDI_RUNTIME_DIAGNOSTIC_CLASSES = {
    "tls-trust": re.compile(
        r"(?i)(?:PKIX path building failed|SSLHandshakeException|"
        r"certificate verify failed|unable to find valid certification path)"
    ),
    "hostname-resolution": re.compile(
        r"(?i)(?:UnknownHostException|name or service not known|temporary failure in name resolution)"
    ),
    "connect-failure": re.compile(r"(?i)(?:connection refused|ConnectException|connect timed out)"),
    "metadata-deserialization": re.compile(
        r"(?i)(?:CredentialIssuerMetadata|issuer metadata|JsonDecodingException|"
        r"MissingFieldException|SerializationException)"
    ),
    "metadata-missing-required-field": re.compile(r"(?i)(?:MissingFieldException|field\b[^\n]{0,80}\bis required)"),
    "metadata-json-type-mismatch": re.compile(
        r"(?i)(?:JsonDecodingException|unexpected JSON token|expected\b[^\n]{0,80}\bbut had)"
    ),
    "metadata-field-credential-configurations-supported": re.compile(r"(?i)credential_configurations_supported"),
    "metadata-field-credential-definition": re.compile(r"(?i)credential_definition"),
    "metadata-field-cryptographic-binding-methods": re.compile(r"(?i)cryptographic_binding_methods_supported"),
    "metadata-field-proof-types": re.compile(r"(?i)proof_types_supported"),
    "metadata-field-signing-algorithms": re.compile(r"(?i)credential_signing_alg_values_supported"),
    "metadata-field-claims": re.compile(r"(?i)(?:\bclaims\b|credentialSubject)"),
    "metadata-field-doctype": re.compile(r"(?i)\bdoctype\b"),
    "metadata-field-vct": re.compile(r"(?i)\bvct\b"),
    "credential-offer": re.compile(r"(?i)(?:credential[_ -]?offer|CredentialOffer|resolveOffer)"),
    "invalid-proof": re.compile(r"(?i)(?:invalid_proof|proof validation failed)"),
    "invalid-nonce": re.compile(r"(?i)(?:invalid_nonce|nonce validation failed)"),
    "unsupported-format": re.compile(
        r"(?i)(?:unsupported_credential_format|unsupported credential format|UnsupportedFormat)"
    ),
    "issuer-profile": re.compile(r"(?i)(?:issuer[_ -]?profile|issuer DID|remote sign|signing service)"),
    "issuer-profile-not-found": re.compile(r"(?i)active issuer profile not found"),
    "issuer-profile-binding-incomplete": re.compile(r"(?i)issuer profile has an incomplete signing identity binding"),
    "issuer-profile-identity-mismatch": re.compile(
        r"(?i)(?:issuer profile DID binding resolved to a different identity|"
        r"issuer-profile signer returned a different (?:profile identity|issuer DID|DID verification method))"
    ),
    "issuer-profile-algorithm-mismatch": re.compile(r"(?i)signing algorithm must match the issuer profile binding"),
    "mdoc-namespace": re.compile(r"(?i)no mDoc namespace mapping is defined"),
    "mdoc-certificate-chain": re.compile(r"(?i)(?:_mdoc_x5c|x5chain|invalid certificate|certificate chain)"),
    "mdoc-signature-missing": re.compile(
        r"(?i)(?:remote signing service returned no mDoc signature|"
        r"issuer-profile signer did not return a signature)"
    ),
    "mdoc-signature-length": re.compile(r"(?i)P1363 signature length"),
    "mdoc-signature-encoding": re.compile(r"(?i)remote mDoc signature encoding"),
    "mdoc-signature-der": re.compile(r"(?i)(?:remote mDoc signature is not valid DER ECDSA|DER signature coordinate)"),
    "mdoc-claims": re.compile(r"(?i)(?:mDoc claims must be|invalid claims JSON)"),
    "mdoc-prepare": re.compile(r"(?i)(?:oid4vci_prepare_mdoc|mDoc preparation|prepare mDoc)"),
    "mdoc-assemble": re.compile(
        r"(?i)(?:oid4vci_assemble_mdoc|mDoc assembl|COSE serialization failed|issuer_auth CBOR)"
    ),
    "mdoc-credential-id-mismatch": re.compile(
        r"(?i)(?:remote|issuer-profile) credential builder changed the reserved credential ID"
    ),
    "upstream-http-4xx": re.compile(r"(?i)(?:status(?: code)?[=: ]+4\d\d\b|HTTP(?:/\S+)?\s+4\d\d\b)"),
    "upstream-http-5xx": re.compile(r"(?i)(?:status(?: code)?[=: ]+5\d\d\b|HTTP(?:/\S+)?\s+5\d\d\b)"),
    "verifier-invalid-request": re.compile(r"(?i)\binvalid_request\b"),
    "verifier-invalid-vp-token": re.compile(r"(?i)\binvalid_(?:vp|presentation)(?:_token)?\b"),
    "verifier-presentation-submission": re.compile(r"(?i)presentation_submission"),
    "verifier-dcql": re.compile(r"(?i)\bdcql\b"),
    "verifier-vct": re.compile(r"(?i)\bvct(?:_values)?\b"),
    "verifier-key-binding": re.compile(r"(?i)(?:key binding|kb-jwt|kb_jwt)"),
}
MDOC_RUNTIME_DIAGNOSTIC_CLASSES = {
    "api-key-transport-type": re.compile(
        r"(?i)(?:gRPC error validating API key|bad argument type for built-in operation)"
    ),
    "credential-format-undetected": re.compile(
        r"(?i)(?:unsupported credential format(?:: unknown)?|credential format.*unknown)"
    ),
    "empty-disclosure-decode": re.compile(r"(?i)(?:cannot construct a non-empty vec|empty issuer disclosure)"),
    "issuer-signature-invalid": re.compile(
        r"(?i)(?:issuer signature.{0,80}(?:invalid|failed)|issuer_signature_valid.{0,20}false)"
    ),
    "issuer-untrusted": re.compile(r"(?i)(?:issuer.{0,80}(?:not trusted|untrusted)|issuer_trusted.{0,20}false)"),
    "device-authentication-invalid": re.compile(
        r"(?i)(?:device authentication.{0,80}(?:invalid|failed)|device_authentication_valid.{0,20}false)"
    ),
    "session-transcript-invalid": re.compile(
        r"(?i)(?:session transcript.{0,80}(?:invalid|mismatch|failed)|invalid session transcript)"
    ),
    "required-claim-missing": re.compile(
        r"(?i)(?:(?:required|requested) claim.{0,80}(?:missing|absent|not found)|"
        r"missing.{0,80}(?:required|requested) claim)"
    ),
    "presentation-policy-denied": re.compile(
        r"(?i)(?:presentation policy.{0,80}(?:denied|failed|rejected)|policy evaluation.{0,80}(?:denied|failed))"
    ),
    "presentation-invalid": re.compile(r"(?i)(?:invalid_presentation|invalid presentation)"),
    "dcql-contract": re.compile(r"(?i)(?:\bdcql\b|mso_mdoc.{0,80}\bclaims\b)"),
}
MDOC_DEVICE_AUTH_ERROR_KINDS = frozenset(
    {
        "detached-issuer-auth",
        "device-response-parse-failed",
        "session-transcript-parse-failed",
        "device-response-status-invalid",
        "device-response-documents-missing",
        "device-response-version-unsupported",
        "mso-parse-failed",
        "device-key-coordinates-missing",
        "device-key-type-unsupported",
        "device-auth-method-unsupported",
        "device-signature-invalid",
        "device-signature-processing-error",
        "device-signature-malformed",
        "device-signature-algorithm-mismatch",
        "device-key-invalid",
        "device-auth-cbor-error",
        "unclassified",
    }
)
MDOC_DEVICE_AUTH_ERROR_KIND = re.compile(r"\bdevice_auth_error_kind=([a-z0-9-]+)\b")
STACK_ENV_KEYS = {
    "MARTY_UI_IMAGE",
    "MARTY_SERVICES_IMAGE",
    "MARTY_MIGRATIONS_IMAGE",
    "MARTY_ISSUANCE_IMAGE",
    "POSTGRES_IMAGE",
    "REDIS_IMAGE",
    "MARTY_RS_URI",
    "MARTY_RS_DIGEST",
    "MARTY_COMMON_URI",
    "MARTY_COMMON_DIGEST",
}
STACK_ARTIFACT_ENVIRONMENT = {
    "MARTY_RS": ("marty-core-python", "python"),
    "MARTY_COMMON": ("marty-common", "python"),
}
STACK_IMAGE_REPOSITORIES = {
    "MARTY_UI_IMAGE": "ui",
    "MARTY_SERVICES_IMAGE": "services",
    "MARTY_MIGRATIONS_IMAGE": "migrations",
    "MARTY_ISSUANCE_IMAGE": "marty-credentials-issuance",
}
BASE_IMAGE_CONFIG_KEYS = {"POSTGRES_IMAGE": "postgres", "REDIS_IMAGE": "redis"}
MATERIAL_ENV_KEYS = {
    "EUDI_TEST_MATERIAL_MODE",
    "EUDI_TEST_CA_FILE",
    "SSL_CERT_FILE",
    "OIDF_PUBLIC_BASE_URL",
    "OIDF_TLS_HOST_PORT",
    "OIDF_INTERNAL_TLS_PORT",
    "OIDF_CONFORMANCE_BRIDGE_ALIAS",
    "OIDF_TLS_CERT_DIR",
    "OIDF_MARTY_RESOLVE_IP",
    "EUDI_WALLET_TESTER_PUBLIC_URL",
    "EUDI_WALLET_TESTER_TLS_HOST_PORT",
    "EUDI_VERIFIER_PUBLIC_URL",
    "EUDI_VERIFIER_TLS_HOST_PORT",
    "EUDI_WALLET_KIT_HOST_PORT",
    "EUDI_WALLET_KIT_URL",
    "EUDI_VERIFIER_KEYSTORE_FILE",
    "EUDI_VERIFIER_KEYSTORE_TYPE",
    "EUDI_VERIFIER_KEYSTORE_PASSWORD",
    "EUDI_VERIFIER_KEYSTORE_ALIAS",
    "EUDI_VERIFIER_KEY_PASSWORD",
    "EUDI_VERIFIER_SIGNING_ALGORITHM",
    "EUDI_VERIFIER_CLIENT_ID_PREFIX",
    "EUDI_VERIFIER_ORIGINAL_CLIENT_ID",
    "EUDI_TLS_TRUSTSTORE_PASSWORD",
    "EUDI_TLS_TRUSTSTORE_ALIAS",
    OID4VP_TRUST_ANCHOR_FILE_ENV,
}


def load_stack_environment(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw or raw.startswith("#"):
            continue
        key, separator, value = raw.partition("=")
        if not separator or key not in STACK_ENV_KEYS or not value:
            raise ValueError(f"unsupported stack environment entry on line {number}")
        if key.endswith("_URI") and not (
            value.startswith("https://github.com/ElevenID/") and "/releases/download/" in value and "?" not in value
        ):
            raise ValueError(f"{key} must be an immutable GitHub release artifact")
        if key.endswith("_DIGEST") and not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            raise ValueError(f"{key} must be a sha256 digest")
        if not key.endswith(("_URI", "_DIGEST")) and not DIGEST_IMAGE.fullmatch(value):
            raise ValueError(f"{key} must be an OCI image pinned by sha256 digest")
        result[key] = value
    missing = STACK_ENV_KEYS - result.keys()
    if missing:
        raise ValueError("stack environment is missing: " + ", ".join(sorted(missing)))
    return result


def load_material_environment(material: Path) -> dict[str, str]:
    environment_path = material / "environment.json"
    data = json.loads(environment_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema") != "elevenid.eudi-test-material/v1":
        raise ValueError("material environment.json has an unsupported schema")
    values = data.get("environment")
    if not isinstance(values, dict) or not values:
        raise ValueError("material environment.json must contain a non-empty environment object")
    unknown = set(values) - MATERIAL_ENV_KEYS
    if unknown:
        raise ValueError("material environment contains unsupported keys: " + ", ".join(sorted(unknown)))
    if any(not isinstance(value, str) or not value for value in values.values()):
        raise ValueError("every material environment value must be a non-empty string")
    result = {str(key): str(value) for key, value in values.items()}
    # The generator contract places all public TLS files at the material root.
    result.setdefault("OIDF_TLS_CERT_DIR", str(material.resolve()))
    result.setdefault("EUDI_VERIFIER_KEYSTORE_FILE", str((material / "keystore.jks").resolve()))
    for filename in ("tls.crt", "tls.key", "root-ca.pem", "truststore.jks", "keystore.jks"):
        if not (material / filename).is_file():
            raise ValueError(f"official test material is missing {filename}")
    return result


def load_stack_metadata(path: Path) -> dict[str, object]:
    raw: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("stack metadata must be a JSON object")
    data = cast(dict[str, object], raw)
    commit = data.get("marty_commit")
    manifest = data.get("manifest_path")
    if data.get("schema") != "elevenid.official-stack-material/v1":
        raise ValueError("stack metadata has an unsupported schema")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("stack metadata has no immutable Marty commit")
    expected_manifest = path.parent.joinpath("stack-manifest.json").resolve()
    if not isinstance(manifest, str) or Path(manifest).resolve() != expected_manifest:
        raise ValueError("stack metadata and stack manifest must share the verified release directory")
    return data


def file_sha256(path: Path) -> str:
    return f"sha256:{sha256(path.read_bytes()).hexdigest()}"


def manifest_image_references(manifest: object) -> set[str]:
    if not isinstance(manifest, dict) or manifest.get("schema") != "marty.stack/v1":
        raise ValueError("stack manifest has an unsupported schema")
    components = manifest.get("components")
    if not isinstance(components, list) or not components:
        raise ValueError("stack manifest contains no components")
    references: set[str] = set()
    for component in components:
        if not isinstance(component, dict):
            raise ValueError("stack manifest components must be objects")
        artifacts = component.get("artifacts")
        if not isinstance(artifacts, list):
            raise ValueError("stack manifest component artifacts must be a list")
        for artifact in artifacts:
            if not isinstance(artifact, dict) or artifact.get("type") != "oci":
                continue
            uri = artifact.get("uri")
            digest = artifact.get("digest")
            reference = f"{uri}@{digest}"
            if not isinstance(uri, str) or not isinstance(digest, str) or not DIGEST_IMAGE.fullmatch(reference):
                raise ValueError("stack manifest contains an invalid OCI reference")
            if reference in references:
                raise ValueError("stack manifest contains a duplicate OCI reference")
            references.add(reference)
    if not references:
        raise ValueError("stack manifest contains no OCI images")
    return references


def metadata_image_references(metadata: dict[str, object]) -> set[str]:
    images = metadata.get("images")
    if not isinstance(images, list) or not images:
        raise ValueError("stack metadata contains no images")
    references: set[str] = set()
    for image in images:
        if not isinstance(image, dict):
            raise ValueError("stack metadata images must be objects")
        reference = image.get("reference")
        if not isinstance(reference, str) or not DIGEST_IMAGE.fullmatch(reference):
            raise ValueError("stack metadata contains an invalid image reference")
        if reference in references:
            raise ValueError("stack metadata contains a duplicate image reference")
        references.add(reference)
    return references


def validate_stack_binding(
    manifest_path: Path,
    metadata: dict[str, object],
    stack_environment: dict[str, str],
) -> None:
    """Bind deployed image inputs to the exact attested manifest recorded as evidence."""
    recorded_path = metadata.get("manifest_path")
    if not isinstance(recorded_path, str) or manifest_path.resolve() != Path(recorded_path).resolve():
        raise ValueError("the deployed stack manifest does not match the attested metadata path")
    recorded_digest = metadata.get("manifest_sha256")
    actual_digest = file_sha256(manifest_path)
    if not isinstance(recorded_digest, str) or actual_digest != recorded_digest:
        raise ValueError("the deployed stack manifest does not match the attested metadata digest")

    manifest_references = manifest_image_references(json.loads(manifest_path.read_text(encoding="utf-8")))
    if metadata_image_references(metadata) != manifest_references:
        raise ValueError("stack metadata images do not match the attested manifest")

    for variable, repository_name in STACK_IMAGE_REPOSITORIES.items():
        matches = {
            reference
            for reference in manifest_references
            if reference.split("@", 1)[0].rstrip("/").rsplit("/", 1)[-1] == repository_name
        }
        if len(matches) != 1 or stack_environment[variable] not in matches:
            raise ValueError(f"{variable} does not match the attested stack manifest")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    components = manifest.get("components", []) if isinstance(manifest, dict) else []
    for prefix, (component_name, artifact_type) in STACK_ARTIFACT_ENVIRONMENT.items():
        matches = [
            artifact
            for component in components
            if isinstance(component, dict) and component.get("name") == component_name
            for artifact in component.get("artifacts", [])
            if isinstance(artifact, dict) and artifact.get("type") == artifact_type
        ]
        if len(matches) != 1:
            raise ValueError(f"attested stack must contain one {artifact_type} artifact for {component_name}")
        artifact = matches[0]
        if stack_environment[f"{prefix}_URI"] != artifact.get("uri") or stack_environment[
            f"{prefix}_DIGEST"
        ] != artifact.get("digest"):
            raise ValueError(f"{prefix} artifact does not match the attested stack manifest")

    base_images_raw: object = json.loads((ROOT / "config" / "base-images.json").read_text(encoding="utf-8"))
    if not isinstance(base_images_raw, dict):
        raise ValueError("base image configuration must be a JSON object")
    for variable, key in BASE_IMAGE_CONFIG_KEYS.items():
        expected = base_images_raw.get(key)
        if not isinstance(expected, str) or not DIGEST_IMAGE.fullmatch(expected):
            raise ValueError(f"base image configuration has no immutable {key} image")
        if stack_environment[variable] != expected:
            raise ValueError(f"{variable} does not match the reviewed base image configuration")


def write_private_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def standard_verifier_config(haip_material: Path, gateway_url: str) -> Path:
    destination = haip_material / "marty-verifier.json"
    if destination.is_file():
        return destination
    source = haip_material / "marty-verifier-haip.json"
    data = json.loads(source.read_text(encoding="utf-8"))
    signing_jwk = data.get("credential", {}).get("signing_jwk")
    if not isinstance(signing_jwk, dict) or not all(signing_jwk.get(name) for name in ("kty", "crv", "x", "y", "d")):
        raise ValueError("HAIP material contains no complete official-wallet signing JWK")
    trust_anchor = data.get("client", {}).get("request_object_trust_anchor_pem")
    if not isinstance(trust_anchor, str) or not trust_anchor.strip():
        raise ValueError("verifier material contains no request-object trust anchor")
    write_private_json(
        destination,
        {
            "credential": {"signing_jwk": signing_jwk},
            "client": {"request_object_trust_anchor_pem": trust_anchor},
            "verifier": {"gateway_url": gateway_url, "profile": "oid4vp-1.0-final"},
        },
    )
    return destination


def oidf_wallet_jwks() -> tuple[dict[str, list[dict[str, str]]], dict[str, list[dict[str, str]]]]:
    """Create one disposable OIDF wallet keypair and its public registration.

    These are external test-wallet keys, not Marty issuer keys. The private
    parameter is written only to the mode-0600 OIDF runner configuration.
    """

    private_key = ec.generate_private_key(ec.SECP256R1())
    private_numbers = private_key.private_numbers()
    public_numbers = private_numbers.public_numbers

    def b64url(value: int) -> str:
        return base64.urlsafe_b64encode(value.to_bytes(32, "big")).decode("ascii").rstrip("=")

    public_key = {
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "use": "sig",
        "x": b64url(public_numbers.x),
        "y": b64url(public_numbers.y),
    }
    thumbprint_input = json.dumps(
        {name: public_key[name] for name in ("crv", "kty", "x", "y")},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    public_key["kid"] = base64.urlsafe_b64encode(sha256(thumbprint_input).digest()).decode("ascii").rstrip("=")
    private_key_jwk = {**public_key, "d": b64url(private_numbers.private_value)}
    return {"keys": [private_key_jwk]}, {"keys": [public_key]}


def oid4vci_issuer_config(
    output_dir: Path,
    gateway_url: str,
    fixtures: dict[str, str],
) -> tuple[Path, Path]:
    """Write the official runner config and fixed public issuance request."""
    private_dir = output_dir / "private"
    config = private_dir / "marty-issuer.json"
    request = private_dir / "marty-issuer-request.json"
    credential_issuer_url = f"{gateway_url}/org/{fixtures['organization_id']}"
    client_id = f"marty-official-wallet-{fixtures['organization_id']}"
    client2_id = f"marty-official-wallet-2-{fixtures['organization_id']}"
    client_jwks, client_public_jwks = oidf_wallet_jwks()
    client2_jwks, client2_public_jwks = oidf_wallet_jwks()
    write_private_json(
        config,
        {
            "description": "Disposable Marty OID4VCI issuer under official test",
            "vci": {
                "credential_issuer_url": credential_issuer_url,
                # Marty advertises the organization-specific credential
                # issuer as its authorization server. The official runner
                # requires an explicit override to match that advertised
                # issuer exactly; the gateway origin alone is not equivalent.
                "authorization_server": credential_issuer_url,
                "credential_configuration_id": fixtures["oid4vci_credential_configuration_id"],
                "credential_proof_type_hint": "jwt",
            },
            "client": {
                "client_id": client_id,
                "jwks": client_jwks,
            },
            "client2": {
                "client_id": client2_id,
                "jwks": client2_jwks,
            },
            "client_attestation": {"key_attestation_jwks": {"keys": []}},
        },
    )
    write_private_json(
        request,
        {
            "authorized_clients": [
                {"client_id": client_id, "jwks": client_public_jwks},
                {"client_id": client2_id, "jwks": client2_public_jwks},
            ],
            "claims": {
                "given_name": "Conformance",
                "family_name": "Test",
                "email": "conformance@example.test",
                "employee_id": "oidf-conformance",
            },
        },
    )
    return config, request


def run(command: list[str], environment: dict[str, str], *, capture: Path | None = None) -> int:
    print("+", subprocess.list2cmdline(command), flush=True)
    if capture is None:
        return subprocess.run(command, env=environment, check=False).returncode
    completed = subprocess.run(command, env=environment, check=False, text=True, capture_output=True)
    capture.parent.mkdir(parents=True, exist_ok=True)
    capture.write_text(completed.stdout + completed.stderr, encoding="utf-8")
    return completed.returncode


def mask_github_secret(value: str) -> None:
    """Mask a validated disposable secret before third-party suite output."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::add-mask::{value}", flush=True)


def redact_initializer_log(text: str) -> str:
    """Preserve actionable initializer output without exposing disposable secrets."""
    return INITIALIZER_SECRET.sub(r"\1<redacted>", text)


def emit_keycloak_initializer_diagnostic(run_id: str) -> None:
    """Print redacted Keycloak startup logs before project teardown.

    Every official lane uses the same project-scoped Keycloak initializer. A
    targeted, redacted diagnostic turns a shared startup failure into an
    actionable production configuration error without publishing the full
    Compose environment or private test material.  The configurator is useful
    after Keycloak starts; on an earlier health-check failure only the Keycloak
    service exists, so inspect both project-scoped containers.
    """
    project = f"marty-conformance-{run_id}"
    for service in ("keycloak", "keycloak-configurator"):
        lookup = subprocess.run(
            [
                "docker",
                "ps",
                "--all",
                "--quiet",
                "--filter",
                f"label=com.docker.compose.project={project}",
                "--filter",
                f"label=com.docker.compose.service={service}",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        container = next((line for line in lookup.stdout.splitlines() if line), "")
        print(f"--- {service} diagnostic (redacted) ---", flush=True)
        if not container:
            print(f"No {service} container was created.", flush=True)
        else:
            logs = subprocess.run(
                ["docker", "logs", "--tail", "200", container],
                capture_output=True,
                text=True,
                check=False,
            )
            output = redact_initializer_log(logs.stdout + logs.stderr).strip()
            print(output or f"No {service} output was available.", flush=True)
        print(f"--- end {service} diagnostic ---", flush=True)


def emit_w3c_issuance_diagnostic(run_id: str) -> None:
    """Print a tightly scoped, redacted W3C failure slice before teardown.

    The official W3C client deliberately reports only an HTTP status for a
    failed VC-API call.  When a released production service rejects an
    issuance or verification request, this preserves the relevant service error without
    exposing the full Compose environment, request headers, credentials, or
    private test material.
    """
    project = f"marty-conformance-{run_id}"
    for service in (
        "gateway",
        "issuance",
        "presentation-policy",
        "revocation-profile",
        "credential-template",
    ):
        lookup = subprocess.run(
            [
                "docker",
                "ps",
                "--all",
                "--quiet",
                "--filter",
                f"label=com.docker.compose.project={project}",
                "--filter",
                f"label=com.docker.compose.service={service}",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        container = next((line for line in lookup.stdout.splitlines() if line), "")
        if not container:
            continue
        logs = subprocess.run(
            # The official suite deliberately exercises many negative vectors.
            # Keep a broad in-memory window so an early, valid-credential
            # failure category is not displaced by later expected rejections;
            # only the final bounded set of redacted error lines is printed.
            ["docker", "logs", "--tail", "2000", container],
            capture_output=True,
            text=True,
            check=False,
        )
        lines = [
            redact_initializer_log(line)[:500]
            for line in (logs.stdout + logs.stderr).splitlines()
            if W3C_DIAGNOSTIC_LINE.search(line)
        ]
        if not lines:
            continue
        print(f"--- {service} W3C issuance diagnostic (redacted) ---", flush=True)
        print("\n".join(lines[-80:]), flush=True)
        print(f"--- end {service} W3C issuance diagnostic ---", flush=True)


def classify_public_proxy_diagnostics(text: str) -> list[str]:
    """Return fixed, non-sensitive categories for TLS-proxy upstream errors."""
    return [name for name, pattern in PROXY_DIAGNOSTIC_CLASSES.items() if pattern.search(text)]


def classify_eudi_runtime_diagnostics(text: str) -> list[str]:
    """Return fixed EUDI runtime categories without exposing source log text."""
    categories = [name for name, pattern in EUDI_RUNTIME_DIAGNOSTIC_CLASSES.items() if pattern.search(text)]
    return categories or ["unclassified-runtime-failure"]


def emit_eudi_runtime_diagnostic(path: Path) -> None:
    """Print only allowlisted classes from the private Compose log."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        categories = ["runtime-log-unavailable"]
    else:
        categories = classify_eudi_runtime_diagnostics(text)
    print("--- EUDI runtime diagnostic (redacted) ---", file=sys.stderr)
    print(f"categories={','.join(categories)}", file=sys.stderr)
    print("--- end EUDI runtime diagnostic ---", file=sys.stderr)


def classify_mdoc_runtime_diagnostics(text: str) -> list[str]:
    """Return fixed mdoc verifier categories without exposing source logs."""
    categories = [name for name, pattern in MDOC_RUNTIME_DIAGNOSTIC_CLASSES.items() if pattern.search(text)]
    observed_error_kinds = {
        match.group(1)
        for match in MDOC_DEVICE_AUTH_ERROR_KIND.finditer(text)
        if match.group(1) in MDOC_DEVICE_AUTH_ERROR_KINDS
    }
    categories.extend(f"device-auth-error-kind-{kind}" for kind in sorted(observed_error_kinds))
    return categories or ["unclassified-runtime-failure"]


def emit_mdoc_runtime_diagnostic(path: Path) -> None:
    """Print only allowlisted mdoc verifier classes from the private log."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        categories = ["runtime-log-unavailable"]
    else:
        categories = classify_mdoc_runtime_diagnostics(text)
    print("--- mdoc verifier runtime diagnostic (redacted) ---", file=sys.stderr)
    print(f"categories={','.join(categories)}", file=sys.stderr)
    print("--- end mdoc verifier runtime diagnostic ---", file=sys.stderr)


def emit_public_proxy_diagnostic(project: str, environment: dict[str, str]) -> None:
    """Classify proxy failures before Compose teardown without publishing logs."""
    containers = subprocess.run(
        [
            "docker",
            "ps",
            "--quiet",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--filter",
            "label=com.docker.compose.service=oidf-tls-proxy",
        ],
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    container_ids = [value for value in containers.stdout.splitlines() if value]
    if containers.returncode or len(container_ids) != 1:
        print(
            "--- public TLS proxy diagnostic (redacted) ---\n"
            "diagnostic-unavailable\n"
            "--- end public TLS proxy diagnostic ---",
            flush=True,
        )
        return
    completed = subprocess.run(
        ["docker", "logs", "--tail", "250", container_ids[0]],
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    classes = classify_public_proxy_diagnostics(completed.stdout + completed.stderr)
    if completed.returncode:
        classes.append("diagnostic-unavailable")
    if classes:
        print(
            "--- public TLS proxy diagnostic (redacted) ---\n"
            + ", ".join(classes)
            + "\n--- end public TLS proxy diagnostic ---",
            flush=True,
        )


def wait_for_public_stack(environment: dict[str, str], *, timeout: float = 300, poll: float = 3) -> None:
    """Wait for the released gateway's real readiness boundary over verified TLS."""
    origin = environment["OIDF_MARTY_GATEWAY_URL"]
    parsed = urlsplit(origin)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("OIDF_MARTY_GATEWAY_URL must be an HTTPS origin")
    port = parsed.port or 443
    command = [
        "curl",
        "--silent",
        "--show-error",
        # --resolve changes DNS, but curl otherwise still honors an HTTPS
        # proxy inherited from a hosted runner. This loopback-only hostname
        # must remain on the runner and never be sent to an outbound proxy.
        "--noproxy",
        parsed.hostname,
        "--max-time",
        "10",
        "--cacert",
        environment["SSL_CERT_FILE"],
        # The gateway response itself is never printed. This fixed marker lets
        # the timeout distinguish a gateway 503 from a proxy-generated 502.
        "--write-out",
        "\n__MARTY_PUBLIC_HTTP_STATUS__:%{http_code}\n",
    ]
    address = environment.get("OIDF_MARTY_RESOLVE_IP", "").strip()
    if address:
        command.extend(["--resolve", f"{parsed.hostname}:{port}:{address}"])
    if os.name == "nt":
        # Windows curl uses Schannel, which otherwise requires an online
        # revocation endpoint even for this disposable, locally generated CA.
        # The generated CA is still required and verified through --cacert;
        # only the unavailable Windows revocation lookup is disabled.
        command.append("--ssl-no-revoke")
    command.append(f"{origin}/ready")
    deadline = time.monotonic() + timeout
    last_detail = "no HTTPS response received"
    while True:
        completed = subprocess.run(command, env=environment, text=True, capture_output=True, check=False)
        body, marker, status_code = completed.stdout.rpartition("__MARTY_PUBLIC_HTTP_STATUS__:")
        if marker:
            status_code = status_code.strip()
        else:
            body = completed.stdout
            status_code = "000"
        payload: object = None
        with suppress(json.JSONDecodeError):
            payload = json.loads(body)
        if (
            completed.returncode == 0
            and status_code == "200"
            and isinstance(payload, dict)
            and payload.get("status") == "ready"
        ):
            return

        # Preserve the production TLS boundary but make a timeout actionable.
        # Do not print arbitrary response content: readiness responses can
        # contain service URLs and transport errors, neither of which belongs
        # in public evidence. Service names and health states are enough to
        # identify the stalled deployment dependency.
        if isinstance(payload, dict):
            status = payload.get("status")
            services = payload.get("services")
            if isinstance(services, dict):
                states = ", ".join(
                    f"{name}={details.get('status', 'unknown')}"
                    for name, details in sorted(services.items())
                    if isinstance(name, str) and isinstance(details, dict)
                )
                last_detail = f"status={status!r}; services: {states or 'none'}"
            else:
                last_detail = f"status={status!r}; no service readiness map"
        elif completed.returncode:
            last_detail = f"curl exit status {completed.returncode}; HTTP {status_code}; non-JSON readiness response"
        else:
            last_detail = f"HTTP {status_code}; non-JSON readiness response"
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"released Marty stack did not become ready through its public TLS endpoint ({last_detail})"
            )
        time.sleep(poll)


def compose_command(
    args: argparse.Namespace,
    action: str,
    *,
    oidf: bool = False,
    eudi: bool = False,
    haip: bool = False,
) -> list[str]:
    command = [
        sys.executable,
        str(ROOT / "scripts" / "official_suite_compose.py"),
        action,
        "--run-id",
        args.run_id,
        "--marty-ui",
        str(args.marty_ui),
    ]
    if oidf:
        command.extend(["--oidf-runner", str(args.oidf_runner), "--oidf"])
    if eudi:
        command.append("--eudi")
    if haip:
        command.extend(["--haip", "--haip-material", str(args.haip_material)])
    return command


def bootstrap_fixtures(
    args: argparse.Namespace,
    environment: dict[str, str],
    *,
    mode: str,
) -> dict[str, str]:
    destination = args.output_dir / "private" / f"{mode}-fixtures.json"
    command = [
        sys.executable,
        str(ROOT / "scripts" / "official_fixture_bootstrap.py"),
        "--mode",
        mode,
        "--run-id",
        args.run_id,
        "--gateway-url",
        environment["OIDF_MARTY_GATEWAY_URL"],
        "--output",
        str(destination),
    ]
    if mode == "oid4vp":
        command.extend(
            [
                "--oidf-runner-config",
                str(args.haip_material / "marty-verifier-haip.json"),
            ]
        )
    elif mode == "oid4vp-mdoc":
        if args.oidf_runner is None:
            raise RuntimeError("oid4vp-mdoc fixture bootstrap requires the exact OIDF runner checkout")
        command.extend(["--oidf-runner-source", str(args.oidf_runner)])
    result = run(command, environment)
    if result:
        raise RuntimeError(f"{mode} public fixture bootstrap failed with exit code {result}")
    fixtures = json.loads(destination.read_text(encoding="utf-8"))
    if not isinstance(fixtures, dict):
        raise RuntimeError(f"{mode} public fixture bootstrap returned invalid identifiers")
    api_key = fixtures.get("w3c_api_key")
    if mode == "w3c" and (not isinstance(api_key, str) or not W3C_API_KEY.fullmatch(api_key)):
        raise RuntimeError("w3c public fixture bootstrap returned an invalid API key")
    identifiers = {key: value for key, value in fixtures.items() if key != "w3c_api_key"}
    if any(not isinstance(value, str) or not IDENTIFIER.fullmatch(value) for value in identifiers.values()):
        raise RuntimeError(f"{mode} public fixture bootstrap returned invalid identifiers")
    return fixtures


def base_environment(args: argparse.Namespace) -> tuple[dict[str, str], dict[str, object]]:
    if args.lane not in LANES:
        raise ValueError(f"unknown lane: {args.lane}")
    if not RUN_ID.fullmatch(args.run_id):
        raise ValueError("run id must use lowercase letters, digits, and internal hyphens")
    launcher = args.marty_ui / "scripts" / "conformance_stack.py"
    if not launcher.is_file():
        raise ValueError(
            "released marty-ui checkout has no scripts/conformance_stack.py; "
            "publish a fresh stack release containing the official-suite lifecycle"
        )
    if args.lane == "haip" and "--haip" not in launcher.read_text(encoding="utf-8"):
        raise ValueError("released marty-ui conformance launcher does not support --haip")
    if args.lane in {
        "oid4vci-issuer",
        "oid4vp-final",
        "oid4vp-url-query",
        "oid4vp-mdoc",
        "haip",
    } and (
        args.oidf_runner is None or not args.oidf_runner.is_dir()
    ):
        raise ValueError(f"{args.lane} requires the exact pinned OIDF runner checkout")
    if args.lane == "w3c-v2" and (args.w3c_suite is None or not args.w3c_suite.is_dir()):
        raise ValueError("w3c-v2 requires the exact pinned W3C suite checkout")
    if args.lane in {
        "oid4vp-final",
        "oid4vp-url-query",
        "oid4vp-mdoc",
        "haip",
        "eudi",
    } and (
        args.haip_material is None or not args.haip_material.is_dir()
    ):
        raise ValueError(f"{args.lane} requires generated verifier test material")

    metadata = load_stack_metadata(args.stack_metadata)
    stack_environment = load_stack_environment(args.stack_env)
    validate_stack_binding(args.stack_manifest, metadata, stack_environment)
    environment = os.environ.copy()
    environment.update(stack_environment)
    environment.update(load_material_environment(args.material))
    gateway_url = environment.get("OIDF_PUBLIC_BASE_URL", "https://marty-oidf.test:18443").rstrip("/")
    gateway = urlsplit(gateway_url)
    if gateway.scheme != "https" or not gateway.hostname or gateway.path:
        raise ValueError("generated OIDF_PUBLIC_BASE_URL must be an HTTPS origin")
    gateway_port = gateway.port or 443
    environment.update(
        {
            "OFFICIAL_SUITE_RUN_ID": args.run_id,
            "MARTY_COMMIT": str(metadata["marty_commit"]),
            "MARTY_CONFORMANCE_ORGANIZATION_ID": environment.get(
                "MARTY_CONFORMANCE_ORGANIZATION_ID", "00000000-0000-0000-0000-000000000001"
            ),
            "OIDF_PUBLIC_BASE_URL": gateway_url,
            "OIDF_TLS_HOST_PORT": environment.get("OIDF_TLS_HOST_PORT", str(gateway_port)),
            "OIDF_CONFORMANCE_BRIDGE_ALIAS": environment.get("OIDF_CONFORMANCE_BRIDGE_ALIAS", gateway.hostname),
            "OIDF_MARTY_GATEWAY_URL": gateway_url,
            "OIDF_MARTY_RESOLVE_IP": environment.get("OIDF_MARTY_RESOLVE_IP", "127.0.0.1"),
            "GATEWAY_URL": gateway_url,
            "EUDI_TEST_VCT_ORIGIN": gateway_url,
            "PUBLIC_DOMAIN": gateway.hostname,
            "SSL_CERT_FILE": str((args.material / "root-ca.pem").resolve()),
            "REQUESTS_CA_BUNDLE": str((args.material / "root-ca.pem").resolve()),
            "CURL_CA_BUNDLE": str((args.material / "root-ca.pem").resolve()),
            "NODE_EXTRA_CA_CERTS": str((args.material / "root-ca.pem").resolve()),
        }
    )
    for name in ("MARTY_CONFORMANCE_ADMIN_PASSWORD", "MARTY_CONFORMANCE_REVIEWER_PASSWORD"):
        if not environment.get(name, "").strip():
            raise ValueError(f"{name} is required and must be generated for this disposable run")
    environment.setdefault("MARTY_CONFORMANCE_ADMIN_EMAIL", "conformance@elevenid.dev")
    environment.setdefault("MARTY_CONFORMANCE_REVIEWER_EMAIL", "conformance.reviewer@elevenid.dev")
    environment["OIDF_MARTY_OPERATOR_EMAIL"] = environment["MARTY_CONFORMANCE_ADMIN_EMAIL"]
    environment["OIDF_MARTY_OPERATOR_PASSWORD"] = environment["MARTY_CONFORMANCE_ADMIN_PASSWORD"]
    return environment, metadata


def run_oidf(args: argparse.Namespace, environment: dict[str, str]) -> int:
    haip = args.lane == "haip"
    mdoc = args.lane == "oid4vp-mdoc"
    url_query = args.lane == "oid4vp-url-query"
    profile = (
        "oid4vp-haip-verifier"
        if haip
        else "oid4vp-mdoc-verifier"
        if mdoc
        else "oid4vp-url-query-verifier"
        if url_query
        else "oid4vp-verifier"
    )
    # Signed request_uri plans use an x509_hash client identifier and require a
    # short-lived certificate over the issuer profile's public DID key.
    # Request signing still happens only through the issuer profile and managed
    # custody. The url_query plan is deliberately unsigned and instead uses the
    # upstream plan's redirect_uri client identifier.
    up = compose_command(args, "up", oidf=True, haip=True)
    started = run(up, environment) == 0
    if not started:
        emit_keycloak_initializer_diagnostic(args.run_id)
        return 1
    result = 1
    try:
        wait_for_public_stack(environment)
        fixture_prefix = "oid4vp_mdoc" if mdoc else "oid4vp"
        fixtures = bootstrap_fixtures(args, environment, mode="oid4vp-mdoc" if mdoc else "oid4vp")
        environment["OIDF_MARTY_ORGANIZATION_ID"] = fixtures["organization_id"]
        environment["OIDF_MARTY_PRESENTATION_POLICY_ID"] = fixtures[f"{fixture_prefix}_policy_id"]
        environment["OIDF_MARTY_TRUST_PROFILE_ID"] = fixtures[f"{fixture_prefix}_trust_profile_id"]
        environment["OIDF_MARTY_ISSUER_DID"] = fixtures[f"{fixture_prefix}_issuer_did"]
        if args.lane == "oid4vp-final":
            environment["OIDF_MARTY_BROWSER_CREDENTIAL_TEMPLATE_ID"] = fixtures["browser_credential_template_id"]
            environment["OIDF_MARTY_BROWSER_APPLICATION_TEMPLATE_ID"] = fixtures["browser_application_template_id"]
        environment.update(
            {
                "CONFORMANCE_SERVER": "https://localhost.emobix.co.uk:8443/",
                "CONFORMANCE_SERVER_MTLS": "https://localhost.emobix.co.uk:8443/",
                "CONFORMANCE_DEV_MODE": "1",
                "OIDF_CONFORMANCE_RESOLVE_IP": "127.0.0.1",
                "OIDF_CONFORMANCE_INSECURE_TLS": "1",
                "OIDF_VERIFIER_COMMAND": str((ROOT / "scripts" / "oidf_marty_start_verification.py").resolve()),
                "OIDF_MARTY_VERIFIER_PROFILE": "haip" if haip else "standard",
                "OIDF_VERIFIER_REQUEST_METHOD": (
                    "url_query" if url_query else "request_uri_signed"
                ),
            }
        )
        config = (
            args.haip_material / "marty-verifier-haip.json"
            if haip
            else standard_verifier_config(args.haip_material, environment["OIDF_MARTY_GATEWAY_URL"])
        )
        browser_result = 0
        if args.lane == "oid4vp-final":
            browser_result = run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "oidf_marty_browser_smoke.py"),
                    "--output",
                    str(args.output_dir / "raw" / "browser" / "browser-evidence.json"),
                ],
                environment,
            )
        official_command = [
                sys.executable,
                str(ROOT / "scripts" / "oidf_conformance.py"),
                "run",
                "--runner",
                str(args.oidf_runner),
                "--profile",
                profile,
                "--config",
                str(config),
                "--stack-manifest",
                str(args.stack_manifest),
                "--output-dir",
                str(args.output_dir / "raw" / profile),
                "--interaction-script",
                str(ROOT / "scripts" / "oidf_marty_verifier.py"),
            ]
        if url_query:
            official_command.append("--allow-planned-profile")
        official_result = run(
            official_command,
            environment,
        )
        result = browser_result or official_result
    finally:
        compose_log = args.output_dir / "private" / "compose.log"
        run(
            compose_command(args, "logs", oidf=True, haip=True),
            environment,
            capture=compose_log,
        )
        if mdoc and result:
            emit_mdoc_runtime_diagnostic(compose_log)
        if mdoc:
            try:
                binding_audit = audit_oidf_mdoc_binding(
                    args.output_dir / "raw" / profile,
                    compose_log,
                )
                binding_audit_path = args.output_dir / "private" / "oidf-mdoc-binding-audit.json"
                binding_audit_path.write_text(
                    json.dumps(binding_audit, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                print("--- OIDF mdoc binding audit (redacted) ---")
                for module in binding_audit["modules"]:
                    mismatches = ",".join(field for field, matched in module["binding_matches"].items() if not matched)
                    print(f"{module['test_name']}: status={module['status']} mismatches={mismatches or 'none'}")
                print("--- end OIDF mdoc binding audit ---")
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                print(
                    "--- OIDF mdoc binding audit (redacted) ---\n"
                    f"diagnostic-unavailable={type(exc).__name__}\n"
                    "--- end OIDF mdoc binding audit ---",
                    file=sys.stderr,
                )
        run(compose_command(args, "down", oidf=True, haip=True), environment)
    return result


def run_oid4vci_issuer(
    args: argparse.Namespace,
    environment: dict[str, str],
) -> int:
    """Run the active official issuer plan against the public Marty boundary."""
    started = run(compose_command(args, "up", oidf=True), environment) == 0
    if not started:
        emit_keycloak_initializer_diagnostic(args.run_id)
        return 1
    try:
        wait_for_public_stack(environment)
        fixtures = bootstrap_fixtures(args, environment, mode="oid4vci")
        config, issuance_request = oid4vci_issuer_config(
            args.output_dir,
            environment["OIDF_MARTY_GATEWAY_URL"],
            fixtures,
        )
        suite_environment = dict(environment)
        suite_environment.update(
            {
                "CONFORMANCE_SERVER": "https://localhost.emobix.co.uk:8443/",
                "CONFORMANCE_SERVER_MTLS": "https://localhost.emobix.co.uk:8443/",
                "CONFORMANCE_DEV_MODE": "1",
                "OIDF_CONFORMANCE_RESOLVE_IP": "127.0.0.1",
                "OIDF_CONFORMANCE_INSECURE_TLS": "1",
                "OIDF_ISSUANCE_COMMAND": str((ROOT / "scripts" / "oidf_marty_public_issuance.py").resolve()),
                "OIDF_ISSUANCE_REQUEST": str(issuance_request),
                "OIDF_MARTY_ORGANIZATION_ID": fixtures["organization_id"],
                "OIDF_MARTY_CREDENTIAL_TEMPLATE_ID": fixtures["oid4vci_template_id"],
                "OIDF_MARTY_ISSUER_DID": fixtures["oid4vci_issuer_did"],
            }
        )
        return run(
            [
                sys.executable,
                str(ROOT / "scripts" / "oidf_conformance.py"),
                "run",
                "--runner",
                str(args.oidf_runner),
                "--profile",
                "oid4vci-issuer",
                "--config",
                str(config),
                "--stack-manifest",
                str(args.stack_manifest),
                "--output-dir",
                str(args.output_dir / "raw" / "oid4vci-issuer"),
                "--interaction-script",
                str(ROOT / "scripts" / "oidf_marty_offer.py"),
            ],
            suite_environment,
        )
    finally:
        run(
            compose_command(args, "logs", oidf=True),
            environment,
            capture=args.output_dir / "private" / "compose.log",
        )
        run(compose_command(args, "down", oidf=True), environment)


def run_w3c(args: argparse.Namespace, environment: dict[str, str]) -> int:
    environment = dict(environment)
    # The official suite intentionally exercises a dense request matrix. Keep
    # the production limiter enabled with a finite, disposable-stack budget so
    # transport throttling does not masquerade as a normative VCDM failure.
    environment["RATE_LIMIT_RPM"] = W3C_CONFORMANCE_RATE_LIMIT_RPM
    # Every official issuance follows the real OID4VCI flow and redeems a
    # pre-authorized code. Raise that independently enforced token-endpoint
    # limiter only for this disposable stack; the production default remains
    # 30 requests per window.
    environment["TOKEN_RATE_LIMIT"] = W3C_CONFORMANCE_TOKEN_RATE_LIMIT
    # This configures the product's fail-closed related-resource validator; it
    # does not alter the pinned upstream suite, its fixtures, or its expected
    # results. The reviewed exact URL is versioned beside the suite pin so a
    # monthly upstream update must review deployment inputs explicitly.
    environment["VCDM_RELATED_RESOURCE_URLS"] = w3c_related_resource_allowlist()
    launcher = args.marty_ui / "scripts" / "conformance_stack.py"
    project = f"marty-conformance-{args.run_id}"
    base = [sys.executable, str(launcher), "--project", project]
    try:
        if run([*base, "up"], environment):
            emit_keycloak_initializer_diagnostic(args.run_id)
            return 1
        wait_for_public_stack(environment)
        fixtures = bootstrap_fixtures(args, environment, mode="w3c")
        mask_github_secret(fixtures["w3c_api_key"])
        suite_environment = dict(environment)
        suite_environment["W3C_VC_API_KEY"] = fixtures["w3c_api_key"]
        result = run(
            [
                sys.executable,
                str(ROOT / "scripts" / "w3c_vc_conformance.py"),
                "run",
                "--suite",
                str(args.w3c_suite),
                "--adapter-url",
                f"{environment['OIDF_MARTY_GATEWAY_URL']}/v1/vc-api",
                "--issuer-id",
                fixtures["w3c_issuer_did"],
                "--organization-id",
                fixtures["organization_id"],
                "--credential-template-id",
                fixtures["w3c_template_id"],
                "--credential-policy-id",
                fixtures["w3c_credential_policy_id"],
                "--presentation-policy-id",
                fixtures["w3c_presentation_policy_id"],
                "--stack-manifest",
                str(args.stack_manifest),
                "--output-dir",
                str(args.output_dir / "raw" / "w3c-v2"),
                "--install",
            ],
            suite_environment,
        )
        if result:
            emit_w3c_issuance_diagnostic(args.run_id)
        return result
    except RuntimeError as error:
        if "public TLS endpoint" in str(error):
            emit_public_proxy_diagnostic(project, environment)
        raise
    finally:
        run([*base, "down"], environment)


def run_eudi(args: argparse.Namespace, environment: dict[str, str]) -> int:
    # EUDI's official wallet library must exercise the same production HAIP
    # request-object path as a real wallet. The dedicated HAIP chain signs the
    # JAR and supplies its request-object root; the separately generated EUDI
    # material continues to own TLS trust.
    # Keep HAIP verifier material out of the launcher process environment.
    # official_suite_compose loads the explicitly selected --haip-material
    # *after* it merges EUDI material, so EUDI's TLS CA cannot accidentally
    # replace the independent request-object trust anchor.
    environment = dict(environment)
    up = compose_command(args, "up", eudi=True, haip=True)
    started = run(up, environment) == 0
    if not started:
        emit_keycloak_initializer_diagnostic(args.run_id)
        return 1
    result = 1
    try:
        wait_for_public_stack(environment)
        fixtures = bootstrap_fixtures(args, environment, mode="eudi")
        suite_environment = dict(environment)
        suite_environment.update(load_verifier_environment(args.haip_material))
        # The runner selects only organization-scoped templates. Each template
        # is bound to an issuer profile and its DID, which together are the
        # runtime signing interface. KMS custody and backend references remain
        # private profile-administration data and are never runtime inputs.
        suite_environment.update(
            {
                "TEST_ORG_ID": fixtures["organization_id"],
                "EUDI_TEST_ISSUER_DID": fixtures["eudi_issuer_did"],
                "EUDI_TEST_REQUEST_ISSUER_DID": fixtures["eudi_request_issuer_did"],
                "EUDI_TEST_PASSPORT_TEMPLATE_ID": fixtures["eudi_passport_template_id"],
                "EUDI_TEST_MDL_TEMPLATE_ID": fixtures["eudi_mdl_template_id"],
                "EUDI_TEST_OPEN_BADGE_TEMPLATE_ID": fixtures["eudi_open_badge_template_id"],
            }
        )
        result = run(
            [
                sys.executable,
                str(ROOT / "scripts" / "eudi_reference_interop.py"),
                "run",
                "--gateway-url",
                environment["OIDF_MARTY_GATEWAY_URL"],
                "--wallet-tester-url",
                environment["EUDI_WALLET_TESTER_PUBLIC_URL"],
                "--verifier-url",
                environment["EUDI_VERIFIER_PUBLIC_URL"],
                "--wallet-kit-url",
                environment["EUDI_WALLET_KIT_URL"],
                "--stack-manifest",
                str(args.stack_manifest),
                "--output-dir",
                str(args.output_dir / "raw" / "eudi"),
            ],
            suite_environment,
        )
    finally:
        compose_log = args.output_dir / "private" / "compose.log"
        run(
            compose_command(args, "logs", eudi=True, haip=True),
            environment,
            capture=compose_log,
        )
        if result:
            emit_eudi_runtime_diagnostic(compose_log)
        run(compose_command(args, "down", eudi=True, haip=True), environment)
    return result


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--lane", choices=sorted(LANES), required=True)
    result.add_argument("--run-id", required=True)
    result.add_argument("--marty-ui", type=Path, required=True)
    result.add_argument("--stack-manifest", type=Path, required=True)
    result.add_argument("--stack-metadata", type=Path, required=True)
    result.add_argument("--stack-env", type=Path, required=True)
    result.add_argument("--material", type=Path, required=True)
    result.add_argument("--haip-material", type=Path)
    result.add_argument("--oidf-runner", type=Path)
    result.add_argument("--w3c-suite", type=Path)
    result.add_argument("--output-dir", type=Path, required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    for name in ("marty_ui", "stack_manifest", "stack_metadata", "stack_env", "material"):
        setattr(args, name, getattr(args, name).resolve())
    if args.haip_material:
        args.haip_material = args.haip_material.resolve()
    if args.oidf_runner:
        args.oidf_runner = args.oidf_runner.resolve()
    if args.w3c_suite:
        args.w3c_suite = args.w3c_suite.resolve()
    args.output_dir = args.output_dir.resolve()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    environment, _metadata = base_environment(args)
    official_checkout = (
        ("w3c", args.w3c_suite)
        if args.lane == "w3c-v2"
        else ("oidf", args.oidf_runner)
        if args.lane
        in {
            "oid4vci-issuer",
            "oid4vp-final",
            "oid4vp-url-query",
            "oid4vp-mdoc",
            "haip",
        }
        else None
    )
    if official_checkout:
        verify_checkout(*official_checkout)
    try:
        if args.lane == "oid4vci-issuer":
            return run_oid4vci_issuer(args, environment)
        if args.lane in {
            "oid4vp-final",
            "oid4vp-url-query",
            "oid4vp-mdoc",
            "haip",
        }:
            return run_oidf(args, environment)
        if args.lane == "w3c-v2":
            return run_w3c(args, environment)
        return run_eudi(args, environment)
    finally:
        if official_checkout:
            verify_checkout(*official_checkout)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"Official interoperability lane error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
