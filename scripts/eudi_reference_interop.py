#!/usr/bin/env python3
"""Validate immutable inputs for EUDI reference-wallet interoperability."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ElementTree
from hashlib import sha256
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from eudi_test_material import (
    OID4VP_TRUST_ANCHOR_FILE_ENV,
    merged_material_environment,
    validate_environment,
)

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "conformance" / "eudi-reference-interop.json"
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST_IMAGE = re.compile(r"^ghcr\.io/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$")
OCI_IMAGE = re.compile(r"^[a-z0-9.-]+/[a-z0-9._/-]+:[a-zA-Z0-9._-]+@sha256:[0-9a-f]{64}$")
EUDI_HAIP_EVIDENCE_ID = "eudi.oid4vp.haip.resolve-dispatch.v1"
EUDI_HOLDER_BINDING_EVIDENCE_ID = "eudi.sd-jwt.missing-holder-binding-key.v1"
EUDI_MDOC_ISSUANCE_EVIDENCE_ID = "eudi.oid4vci.mdoc-issuance.v1"
REQUIRED_EVIDENCE_CLAIMS = {
    EUDI_MDOC_ISSUANCE_EVIDENCE_ID: frozenset({"issuance:mso_mdoc"}),
    EUDI_HAIP_EVIDENCE_ID: frozenset(
        {
            "issuance:sd_jwt_vc",
            "presentation:sd_jwt_vc",
            "request_object_trust:signed_jar_x509_hash_pkix",
            "response_mode:direct_post.jwt",
        }
    ),
    EUDI_HOLDER_BINDING_EVIDENCE_ID: frozenset({"negative:missing_holder_binding_key"}),
}


def coverage_claims(coverage: Any) -> set[str]:
    """Return normalized manifest claims, rejecting ambiguous coverage."""
    if not isinstance(coverage, dict) or not coverage:
        raise ValueError("EUDI coverage must be a non-empty object")
    claims: set[str] = set()
    for dimension, values in coverage.items():
        if not isinstance(dimension, str) or not dimension or ":" in dimension:
            raise ValueError("EUDI coverage dimensions must be non-empty names")
        if (
            not isinstance(values, list)
            or not values
            or any(not isinstance(value, str) or not value or ":" in value for value in values)
            or len(values) != len(set(values))
        ):
            raise ValueError(f"EUDI coverage {dimension} must contain unique non-empty names")
        claims.update(f"{dimension}:{value}" for value in values)
    return claims


def load_manifest(path: Path = MANIFEST) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("EUDI interop manifest must be a JSON object")
    if data.get("schema") != "elevenid.eudi-reference-interop/v1":
        raise ValueError("unsupported EUDI interop manifest schema")
    components = data.get("components", {})
    for name in ("wallet_tester", "verifier_endpoint"):
        component = components.get(name, {})
        if not component.get("repository", "").startswith("https://github.com/eu-digital-identity-wallet/"):
            raise ValueError(f"{name} must point to an official EUDI repository")
        if not SHA.fullmatch(component.get("commit", "")):
            raise ValueError(f"{name} must pin a full commit SHA")
        image = component.get("image")
        if image is not None and not DIGEST_IMAGE.fullmatch(image):
            raise ValueError(f"{name} image must be pinned by sha256 digest")
    wallet_kit = components.get("wallet_kit", {})
    build = wallet_kit.get("build", {})
    for name in ("builder_image", "runtime_image", "public_url_bridge_image"):
        if not OCI_IMAGE.fullmatch(build.get(name, "")):
            raise ValueError(f"wallet_kit {name} must be pinned by sha256 digest")
    libraries = wallet_kit.get("libraries", {})
    if set(libraries) != {"oid4vp", "oid4vci", "sd_jwt"}:
        raise ValueError("wallet_kit must record the OID4VP, OID4VCI, and SD-JWT libraries")
    for name, library in libraries.items():
        if not library.get("repository", "").startswith("https://github.com/eu-digital-identity-wallet/"):
            raise ValueError(f"wallet_kit {name} must point to an official EUDI repository")
        if not SHA.fullmatch(library.get("commit", "")):
            raise ValueError(f"wallet_kit {name} must pin a full commit SHA")
        version = library.get("version", "")
        coordinate = library.get("maven_coordinate", "")
        if library.get("release") != f"v{version}" or coordinate.rsplit(":", 1)[-1] != version:
            raise ValueError(f"wallet_kit {name} release and Maven coordinate must match its version")
    coverage = data.get("coverage", {})
    declared_coverage_claims = coverage_claims(coverage)
    if not {"sd_jwt_vc", "mso_mdoc"} <= set(coverage.get("issuance", [])):
        raise ValueError("EUDI issuance coverage must include SD-JWT VC and mdoc")
    if "sd_jwt_vc" not in coverage.get("presentation", []):
        raise ValueError("EUDI official-library presentation coverage must include SD-JWT VC")
    if "signed_jar_x509_hash_pkix" not in coverage.get("request_object_trust", []):
        raise ValueError("EUDI presentation coverage must prove signed-JAR x509_hash PKIX trust")
    if "direct_post.jwt" not in coverage.get("response_mode", []):
        raise ValueError("EUDI presentation coverage must prove encrypted direct_post.jwt")
    if "mso_mdoc" in coverage.get("presentation", []):
        raise ValueError("mDoc cannot be claimed until an ISO device response is exercised")
    unsupported_negative_claims = {
        "replayed_response",
        "invalid_signature",
        "expired_or_invalid_request",
    } & set(coverage.get("negative", []))
    if unsupported_negative_claims:
        raise ValueError(
            "EUDI negative coverage contains planned-only claims: " + ", ".join(sorted(unsupported_negative_claims))
        )
    required_evidence = data.get("required_evidence")
    if not isinstance(required_evidence, dict) or set(required_evidence) != set(REQUIRED_EVIDENCE_CLAIMS):
        raise ValueError("EUDI manifest must declare the complete stable evidence contract")
    bound_claim_counts: dict[str, int] = {}
    for evidence_id, expected_claims in REQUIRED_EVIDENCE_CLAIMS.items():
        record = required_evidence.get(evidence_id)
        claims = record.get("claims", []) if isinstance(record, dict) else []
        if not isinstance(claims, list) or len(claims) != len(set(claims)) or set(claims) != set(expected_claims):
            raise ValueError(f"EUDI evidence {evidence_id} must bind its exact coverage claims")
        for claim in claims:
            bound_claim_counts[claim] = bound_claim_counts.get(claim, 0) + 1
    multiply_bound = sorted(claim for claim, count in bound_claim_counts.items() if count != 1)
    bound_claims = set(bound_claim_counts)
    if multiply_bound or declared_coverage_claims != bound_claims:
        unbound = sorted(declared_coverage_claims - bound_claims)
        undeclared = sorted(bound_claims - declared_coverage_claims)
        details = []
        if unbound:
            details.append("unbound coverage: " + ", ".join(unbound))
        if undeclared:
            details.append("evidence without coverage: " + ", ".join(undeclared))
        if multiply_bound:
            details.append("multiply-bound coverage: " + ", ".join(multiply_bound))
        raise ValueError("EUDI coverage and stable evidence claims must be a bijection (" + "; ".join(details) + ")")
    limitations = data.get("limitations", {})
    if not {"mso_mdoc_presentation", "oid4vp_negative_vectors"} <= set(limitations):
        raise ValueError("EUDI manifest must record current presentation limitations")
    return data


def absolute_url(value: str, field: str) -> str:
    if not re.match(r"^https?://[^/]+", value):
        raise ValueError(f"{field} must be an absolute http(s) URL")
    return value.rstrip("/")


def file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def junit_skip_count(path: Path) -> int:
    if not path.is_file():
        raise ValueError("EUDI runner did not produce JUnit output")
    root = ElementTree.parse(path).getroot()
    return sum(int(node.attrib.get("skipped", "0")) for node in root.iter() if node.tag == "testsuite")


def _xml_local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _http_status_pattern(code: int) -> re.Pattern[str]:
    label = "Client" if code < 500 else "Server"
    return re.compile(
        rf"(?i)(?:HTTP(?:/\S+)?\s+{code}\b|{code}\s+{label}\s+Error|"
        rf"failed\s+with\s+{code}\b|status(?:_code)?[^\n]{{0,24}}\b{code}\b)"
    )


EUDI_FAILURE_DIAGNOSTIC_PATTERNS = {
    "http-400": _http_status_pattern(400),
    "http-401": _http_status_pattern(401),
    "http-403": _http_status_pattern(403),
    "http-404": _http_status_pattern(404),
    "http-409": _http_status_pattern(409),
    "http-422": _http_status_pattern(422),
    "http-500": _http_status_pattern(500),
    "http-502": _http_status_pattern(502),
    "http-503": _http_status_pattern(503),
    "invalid-credential-request": re.compile(r"(?i)\berror=invalid_credential_request\b"),
    "invalid-grant": re.compile(r"(?i)\berror=invalid_grant\b"),
    "invalid-nonce": re.compile(r"(?i)\berror=invalid_nonce\b"),
    "invalid-proof": re.compile(r"(?i)\berror=invalid_proof\b"),
    "invalid-token": re.compile(r"(?i)\berror=invalid_token\b"),
    "unknown-credential-configuration": re.compile(r"(?i)\berror=unknown_credential_configuration\b"),
    "unsupported-credential-format": re.compile(r"(?i)\berror=unsupported_credential_format\b"),
    "connectivity": re.compile(
        r"(?i)(?:connection refused|connect timeout|read timeout|name or service not known|dns)"
    ),
    "metadata-contract": re.compile(
        r"(?i)(?:token_endpoint|nonce_endpoint|credential_issuer|openid-credential-issuer|issuer metadata)"
    ),
    "credential-offer": re.compile(r"(?i)(?:credential[_ -]?offer|resolve[_ -]?offer)"),
    "issuer-profile-or-did": re.compile(
        r"(?i)(?:issuer[_ -]?profile|issuer DID|DID resolution|remote sign|signing service)"
    ),
    "request-object": re.compile(r"(?i)(?:request_uri|request object|authorization request|x509_hash|direct_post)"),
    "holder-binding": re.compile(r"(?i)(?:holder[_ -]?binding|holder key|key binding)"),
    "sd-jwt": re.compile(r"(?i)(?:sd[-_ ]jwt|selective disclosure)"),
    "mdoc": re.compile(r"(?i)(?:mso_mdoc|mdoc|device response)"),
    "wallet-kit": re.compile(r"(?i)(?:wallet[_ -]?kit|official library)"),
    "signing-service-resolution": re.compile(r"(?i)/v1/signing-keys/config/resolve\b"),
    "issuer-profile-provisioning": re.compile(r"(?i)/v1/signing-keys/issuer-profiles\b"),
    "credential-template-provisioning": re.compile(r"(?i)/v1/credential-templates\b"),
    "verification-flow-start": re.compile(r"(?i)/v1/flows/verify\b"),
    "wallet-offer-resolution": re.compile(r"(?i)/issuance/resolve-offer\b"),
    "wallet-preauthorized-issuance": re.compile(r"(?i)/issuance/pre-auth\b"),
    "wallet-presentation": re.compile(r"(?i)/presentation/(?:submit|direct-post|build-vp-token)\b"),
    "offer-parameter-invalid": re.compile(
        r"(?i)offer-(?:endpoint-url|parameter-selection|reference-url)-(?:invalid)\b"
    ),
    "offer-document-invalid": re.compile(r"(?i)offer-(?:json|issuer-id|credential-configuration|grants)-invalid\b"),
    "offer-fetch-failed": re.compile(r"(?i)offer-fetch-failed\b"),
    "issuer-metadata-fetch-failed": re.compile(r"(?i)issuer-metadata-fetch-failed\b"),
    "issuer-metadata-json-invalid": re.compile(r"(?i)issuer-metadata-json-invalid\b"),
    "issuer-metadata-field-invalid": re.compile(
        r"(?i)issuer-metadata-(?:issuer-id|authorization-server-url|credential-endpoint|nonce-endpoint|"
        r"deferred-endpoint|notification-endpoint|credential-configuration|batch-size)-invalid\b"
    ),
    "issuer-metadata-configurations-empty": re.compile(r"(?i)issuer-metadata-credential-configurations-empty\b"),
    "authorization-server-metadata-failed": re.compile(r"(?i)authorization-server-metadata-[a-z-]+\b"),
    "wallet-tls-trust-failed": re.compile(r"(?i)(?:issuer|authorization-server)-metadata-tls-trust-failed\b"),
    "wallet-hostname-resolution-failed": re.compile(
        r"(?i)(?:issuer|authorization-server)-metadata-hostname-resolution-failed\b"
    ),
    "wallet-connection-failed": re.compile(r"(?i)(?:issuer|authorization-server)-metadata-connection-failed\b"),
}


def classify_eudi_failure_text(text: str) -> list[str]:
    """Return fixed public categories without returning any source text."""
    categories = [category for category, pattern in EUDI_FAILURE_DIAGNOSTIC_PATTERNS.items() if pattern.search(text)]
    return categories or ["unclassified"]


def junit_required_evidence(
    path: Path,
    required_ids: set[str],
) -> dict[str, dict[str, str]]:
    """Require each stable evidence ID to occur exactly once and pass."""
    if not path.is_file():
        raise ValueError("EUDI runner did not produce JUnit output")
    root = ElementTree.parse(path).getroot()
    observed: dict[str, dict[str, str]] = {}
    for testcase in root.iter():
        if _xml_local_name(testcase.tag) != "testcase":
            continue
        evidence_ids = [
            str(node.attrib.get("value", ""))
            for node in testcase.iter()
            if _xml_local_name(node.tag) == "property" and node.attrib.get("name") == "evidence_id"
        ]
        if not evidence_ids:
            continue
        if len(evidence_ids) != 1 or not evidence_ids[0]:
            raise ValueError("an EUDI JUnit testcase emitted an ambiguous evidence_id")
        evidence_id = evidence_ids[0]
        if evidence_id not in required_ids:
            raise ValueError(f"EUDI JUnit contains undeclared evidence_id {evidence_id}")
        if evidence_id in observed:
            raise ValueError(f"EUDI JUnit contains duplicate evidence_id {evidence_id}")
        outcomes = [
            _xml_local_name(node.tag)
            for node in testcase
            if _xml_local_name(node.tag) in {"failure", "error", "skipped"}
        ]
        if outcomes:
            raise ValueError(f"EUDI evidence {evidence_id} did not pass: {', '.join(outcomes)}")
        observed[evidence_id] = {
            "status": "passed",
            "classname": testcase.attrib.get("classname", ""),
            "testcase": testcase.attrib.get("name", ""),
        }
    missing = required_ids - set(observed)
    if missing:
        raise ValueError("EUDI JUnit is missing required evidence_id values: " + ", ".join(sorted(missing)))
    return {evidence_id: observed[evidence_id] for evidence_id in sorted(observed)}


def junit_failure_summary(path: Path) -> list[dict[str, object]]:
    """Return safe test identities, outcomes, and fixed diagnostic categories."""
    root = ElementTree.parse(path).getroot()
    failures: list[dict[str, object]] = []
    for testcase in root.iter():
        if _xml_local_name(testcase.tag) != "testcase":
            continue
        outcomes = sorted(
            {
                _xml_local_name(node.tag)
                for node in testcase
                if _xml_local_name(node.tag) in {"failure", "error", "skipped"}
            }
        )
        if outcomes:
            failure_text = "\n".join(
                " ".join(value for value in (node.attrib.get("message", ""), node.text or "") if value)
                for node in testcase
                if _xml_local_name(node.tag) in {"failure", "error"}
            )
            failures.append(
                {
                    "classname": testcase.attrib.get("classname", ""),
                    "testcase": testcase.attrib.get("name", ""),
                    "outcomes": outcomes,
                    "categories": classify_eudi_failure_text(failure_text),
                }
            )
    return failures


def stack_manifest_metadata(path: Path) -> dict:
    """Return immutable Marty deployment provenance for a conformance run."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("schema") != "marty.stack/v1":
        raise ValueError("stack manifest must use marty.stack/v1")
    images: list[dict[str, str]] = []
    for component in raw.get("components", []):
        if not isinstance(component, dict):
            continue
        for artifact in component.get("artifacts", []):
            if not isinstance(artifact, dict) or artifact.get("type") != "oci":
                continue
            uri, digest = artifact.get("uri"), artifact.get("digest")
            if (
                not isinstance(uri, str)
                or not isinstance(digest, str)
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
            ):
                raise ValueError("every OCI artifact in the stack manifest must have a sha256 digest")
            images.append({"component": str(component.get("name", "unknown")), "uri": uri, "digest": digest})
    if not images:
        raise ValueError("stack manifest contains no immutable OCI artifacts")
    return {"path": str(path), "sha256": file_sha256(path), "release": raw.get("release"), "images": images}


def request_object_trust_metadata(environment: dict[str, str]) -> dict[str, object]:
    """Bind EUDI presentation evidence to a non-TLS HAIP trust root."""
    anchor_value = environment.get(OID4VP_TRUST_ANCHOR_FILE_ENV, "").strip()
    tls_value = environment.get("SSL_CERT_FILE", "").strip()
    if not anchor_value or not tls_value:
        raise ValueError("EUDI HAIP evidence requires request-object and TLS trust files")
    anchor = Path(anchor_value).resolve()
    tls_ca = Path(tls_value).resolve()
    if not anchor.is_file() or not tls_ca.is_file():
        raise ValueError("EUDI HAIP request-object and TLS trust files must exist")
    anchor_digest = file_sha256(anchor)
    tls_digest = file_sha256(tls_ca)
    if anchor_digest == tls_digest:
        raise ValueError("EUDI HAIP request-object trust must be independent from TLS trust")
    return {
        "profile": "haip",
        "client_id_prefix": "x509_hash",
        "validation": "pkix",
        "response_mode": "direct_post.jwt",
        "anchor_sha256": anchor_digest,
        "tls_ca_sha256": tls_digest,
        "separate_from_tls": True,
    }


def write_evidence(
    output: Path,
    manifest: dict,
    endpoints: dict[str, str],
    result: int,
    skipped: int = 0,
    stack_manifest: Path | None = None,
    request_object_trust: dict[str, object] | None = None,
    observed_evidence: dict[str, dict[str, str]] | None = None,
    failure_summary: list[dict[str, object]] | None = None,
) -> None:
    observed_evidence = observed_evidence or {}
    required_ids = set(manifest["required_evidence"])
    if result == 0 and (
        set(observed_evidence) != required_ids
        or any(record.get("status") != "passed" for record in observed_evidence.values())
    ):
        raise ValueError("passing EUDI evidence requires every stable evidence assertion")
    artifacts = [
        {"path": str(path.relative_to(output)).replace("\\", "/"), "sha256": file_sha256(path)}
        for path in sorted(output.rglob("*"))
        if path.is_file() and path.name != "evidence.json"
    ]
    evidence = {
        "schema": "elevenid.official-interop-evidence/v1",
        "components": manifest["components"],
        "coverage": manifest["coverage"],
        "required_evidence": manifest["required_evidence"],
        "observed_evidence": observed_evidence,
        "failure_summary": failure_summary or [],
        "compatibility_only": manifest.get("compatibility_only", {}),
        "planned_coverage": manifest.get("planned_coverage", {}),
        "limitations": manifest.get("limitations", {}),
        "marty": {
            "commit": os.environ.get("MARTY_COMMIT", "unrecorded"),
            "stack_manifest": stack_manifest_metadata(stack_manifest) if stack_manifest else None,
        },
        "endpoints": endpoints,
        "request_object_trust": request_object_trust,
        "result": {"exit_code": result, "passed": result == 0, "skipped": skipped},
        "artifacts": artifacts,
    }
    (output / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def public_gateway_session(environment: dict[str, str]) -> str:
    """Obtain a normal public OIDC session for the disposable EUDI run.

    The EUDI runner must not authenticate through a private Docker address or
    invent a session cookie.  Reuse the production-shaped OIDF helper, which
    follows the gateway's published Keycloak redirects and returns only the
    gateway-issued session ID.
    """
    existing = environment.get("MARTY_TEST_SESSION_ID", "").strip()
    if existing:
        return existing
    command = Path(
        environment.get("EUDI_MARTY_PUBLIC_LOGIN_COMMAND", "") or ROOT / "scripts" / "oidf_marty_public_login.py"
    )
    if not command.is_file():
        raise ValueError("EUDI public login helper is missing")
    completed = subprocess.run(
        [sys.executable, str(command)],
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    session = completed.stdout.strip()
    if completed.returncode or not session or "\n" in session:
        detail = completed.stderr.strip()
        raise ValueError(f"EUDI public OIDC login failed: {detail[:300]}")
    return session


def run_environment(args: argparse.Namespace) -> tuple[dict[str, str], dict[str, str]]:
    """Load the same generated trust and endpoint contract used by Compose."""
    environment = os.environ.copy()
    material_values: dict[str, str] = {}
    if args.eudi_material is not None:
        _mode, environment = merged_material_environment(args.eudi_material.resolve(), environment)
        validate_environment(environment, validate_java=False)
        material_values = {
            "gateway": environment["OIDF_PUBLIC_BASE_URL"],
            "wallet_tester": environment["EUDI_WALLET_TESTER_PUBLIC_URL"],
            "verifier": environment["EUDI_VERIFIER_PUBLIC_URL"],
            "wallet_kit": environment.get("EUDI_WALLET_KIT_URL", ""),
        }
    if environment.get("OIDF_INSECURE_TLS", "").strip().lower() in {"1", "true", "yes"}:
        raise ValueError("OIDF_INSECURE_TLS is prohibited for EUDI interoperability evidence")
    explicit = {
        "gateway": args.gateway_url,
        "wallet_tester": args.wallet_tester_url,
        "verifier": args.verifier_url,
        "wallet_kit": args.wallet_kit_url,
    }
    endpoints: dict[str, str] = {}
    for name, value in explicit.items():
        selected = value or material_values.get(name, "")
        if not selected:
            raise ValueError(f"{name.replace('_', ' ')} URL is required without --eudi-material")
        endpoint = absolute_url(selected, f"{name.replace('_', ' ')} URL")
        material_endpoint = material_values.get(name, "")
        if value and material_endpoint and endpoint != absolute_url(material_endpoint, f"material {name} URL"):
            raise ValueError(f"{name.replace('_', ' ')} URL must match --eudi-material")
        endpoints[name] = endpoint
    environment.update(
        {
            "RUN_EUDI_TESTS": "true",
            "GATEWAY_URL": endpoints["gateway"],
            "OIDF_MARTY_GATEWAY_URL": endpoints["gateway"],
            "EUDI_WALLET_TESTER_URL": endpoints["wallet_tester"],
            "EUDI_VERIFIER_URL": endpoints["verifier"],
            "EUDI_WALLET_KIT_URL": endpoints["wallet_kit"],
        }
    )
    return environment, endpoints


def run(args: argparse.Namespace) -> int:
    manifest = load_manifest()
    environment, endpoints = run_environment(args)
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    stack_manifest = args.stack_manifest.resolve()
    # Validate before any external calls so an evidence run cannot silently use
    # mutable image tags or an unrelated deployment.
    stack_manifest_metadata(stack_manifest)
    request_object_trust = request_object_trust_metadata(environment)
    environment["MARTY_TEST_SESSION_ID"] = public_gateway_session(environment)
    command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "--junitxml",
        str(output / "junit.xml"),
        "tests/integration/gateway/test_eudi_interop.py",
        "tests/integration/gateway/test_eudi_wallet_kit.py",
        "tests/integration/gateway/test_eudi_wallet_kit_vp.py",
        "tests/integration/gateway/test_eudi_wallet_kit_dtc.py",
    ]
    completed = subprocess.run(command, cwd=ROOT, env=environment, text=True, capture_output=True, check=False)
    result = completed.returncode
    skipped = 0
    observed_evidence: dict[str, dict[str, str]] = {}
    failure_summary: list[dict[str, object]] = []
    detail = completed.stdout + completed.stderr
    try:
        junit_path = output / "junit.xml"
        skipped = junit_skip_count(junit_path)
        failure_summary = junit_failure_summary(junit_path)
        observed_evidence = junit_required_evidence(
            junit_path,
            set(manifest["required_evidence"]),
        )
    except (ElementTree.ParseError, ValueError) as exc:
        result = 1
        detail += f"\nEUDI evidence failure: {exc}\n"
    if skipped:
        result = 1
        detail += f"\nEUDI evidence failure: {skipped} test(s) were skipped.\n"
    (output / "runner.log").write_text(detail, encoding="utf-8")
    if failure_summary:
        print(
            "EUDI failing tests (names, outcome classes, and fixed diagnostic categories only):",
            file=sys.stderr,
        )
        print(json.dumps(failure_summary, sort_keys=True), file=sys.stderr)
    write_evidence(
        output,
        manifest,
        endpoints,
        result,
        skipped,
        stack_manifest,
        request_object_trust,
        observed_evidence,
        failure_summary,
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate")
    run_parser = sub.add_parser("run")
    run_parser.add_argument("--eudi-material", type=Path, help="generated trust and endpoint environment")
    run_parser.add_argument("--gateway-url")
    run_parser.add_argument("--wallet-tester-url")
    run_parser.add_argument("--verifier-url")
    run_parser.add_argument("--wallet-kit-url")
    run_parser.add_argument("--output-dir", type=Path, required=True)
    run_parser.add_argument(
        "--stack-manifest",
        type=Path,
        required=True,
        help="attested marty.stack/v1 manifest for the deployment under test",
    )
    args = parser.parse_args()
    if args.command == "validate":
        manifest = load_manifest()
        print("EUDI reference interop manifest is valid:", manifest["components"]["wallet_tester"]["commit"])
        return 0
    return run(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError, subprocess.CalledProcessError) as exc:
        print(f"EUDI reference interop setup error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
