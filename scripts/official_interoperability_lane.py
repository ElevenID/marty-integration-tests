#!/usr/bin/env python3
"""Run one isolated official-interoperability lane against released artifacts."""

from __future__ import annotations

import argparse
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

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from haip_test_certificates import (  # noqa: E402
    OID4VP_TRUST_ANCHOR_FILE_ENV,
    load_verifier_environment,
)

LANES = {"oid4vp-final", "haip", "w3c-v2", "eudi"}
RUN_ID = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
DIGEST_IMAGE = re.compile(r"^[a-z0-9.-]+/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
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
    write_private_json(
        destination,
        {
            "credential": {"signing_jwk": signing_jwk},
            "verifier": {"gateway_url": gateway_url, "profile": "oid4vp-1.0-final"},
        },
    )
    return destination


def run(command: list[str], environment: dict[str, str], *, capture: Path | None = None) -> int:
    print("+", subprocess.list2cmdline(command), flush=True)
    if capture is None:
        return subprocess.run(command, env=environment, check=False).returncode
    completed = subprocess.run(command, env=environment, check=False, text=True, capture_output=True)
    capture.parent.mkdir(parents=True, exist_ok=True)
    capture.write_text(completed.stdout + completed.stderr, encoding="utf-8")
    return completed.returncode


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
            ["docker", "logs", "--tail", "300", container],
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
    result = run(command, environment)
    if result:
        raise RuntimeError(f"{mode} public fixture bootstrap failed with exit code {result}")
    fixtures = json.loads(destination.read_text(encoding="utf-8"))
    if not isinstance(fixtures, dict) or any(
        not isinstance(value, str) or not IDENTIFIER.fullmatch(value) for value in fixtures.values()
    ):
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
    if args.lane in {"oid4vp-final", "haip"} and (args.oidf_runner is None or not args.oidf_runner.is_dir()):
        raise ValueError(f"{args.lane} requires the exact pinned OIDF runner checkout")
    if args.lane == "w3c-v2" and (args.w3c_suite is None or not args.w3c_suite.is_dir()):
        raise ValueError("w3c-v2 requires the exact pinned W3C suite checkout")
    if args.lane in {"oid4vp-final", "haip", "eudi"} and (
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
    up = compose_command(args, "up", oidf=True, haip=haip)
    started = run(up, environment) == 0
    if not started:
        emit_keycloak_initializer_diagnostic(args.run_id)
        return 1
    try:
        wait_for_public_stack(environment)
        fixtures = bootstrap_fixtures(args, environment, mode="oid4vp")
        environment["OIDF_MARTY_PRESENTATION_POLICY_ID"] = fixtures["oid4vp_policy_id"]
        environment["OIDF_MARTY_TRUST_PROFILE_ID"] = fixtures["oid4vp_trust_profile_id"]
        environment.update(
            {
                "CONFORMANCE_SERVER": "https://localhost.emobix.co.uk:8443/",
                "CONFORMANCE_SERVER_MTLS": "https://localhost.emobix.co.uk:8443/",
                "CONFORMANCE_DEV_MODE": "1",
                "OIDF_CONFORMANCE_RESOLVE_IP": "127.0.0.1",
                "OIDF_CONFORMANCE_INSECURE_TLS": "1",
                "OIDF_VERIFIER_COMMAND": str((ROOT / "scripts" / "oidf_marty_start_verification.py").resolve()),
                "OIDF_MARTY_VERIFIER_PROFILE": "haip" if haip else "standard",
                "OIDF_VERIFIER_REQUEST_METHOD": "request_uri_signed" if haip else "url_query",
            }
        )
        config = (
            args.haip_material / "marty-verifier-haip.json"
            if haip
            else standard_verifier_config(args.haip_material, environment["OIDF_MARTY_GATEWAY_URL"])
        )
        profile = "oid4vp-haip-verifier" if haip else "oid4vp-verifier"
        return run(
            [
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
                "--allow-planned-profile",
                "--output-dir",
                str(args.output_dir / "raw" / profile),
                "--interaction-script",
                str(ROOT / "scripts" / "oidf_marty_verifier.py"),
            ],
            environment,
        )
    finally:
        run(
            compose_command(args, "logs", oidf=True, haip=haip),
            environment,
            capture=args.output_dir / "private" / "compose.log",
        )
        run(compose_command(args, "down", oidf=True, haip=haip), environment)


def run_w3c(args: argparse.Namespace, environment: dict[str, str]) -> int:
    launcher = args.marty_ui / "scripts" / "conformance_stack.py"
    project = f"marty-conformance-{args.run_id}"
    base = [sys.executable, str(launcher), "--project", project]
    include_w3c = False
    try:
        if run([*base, "up"], environment):
            emit_keycloak_initializer_diagnostic(args.run_id)
            return 1
        wait_for_public_stack(environment)
        fixtures = bootstrap_fixtures(args, environment, mode="w3c")
        environment.update(
            {
                "W3C_VC_TEST_ORGANIZATION_ID": fixtures["organization_id"],
                "W3C_VC_TEST_TEMPLATE_ID": fixtures["w3c_template_id"],
                "W3C_VC_TEST_CREDENTIAL_POLICY_ID": fixtures["w3c_credential_policy_id"],
                "W3C_VC_TEST_PRESENTATION_POLICY_ID": fixtures["w3c_presentation_policy_id"],
            }
        )
        include_w3c = True
        if run([*base, "--include-w3c", "--resume", "up"], environment):
            return 1
        wait_for_public_stack(environment)
        result = run(
            [
                sys.executable,
                str(ROOT / "scripts" / "w3c_vc_conformance.py"),
                "run",
                "--suite",
                str(args.w3c_suite),
                "--adapter-url",
                f"{environment['OIDF_MARTY_GATEWAY_URL']}/__test__/vc-api",
                "--stack-manifest",
                str(args.stack_manifest),
                "--output-dir",
                str(args.output_dir / "raw" / "w3c-v2"),
                "--install",
            ],
            environment,
        )
        if result:
            emit_w3c_issuance_diagnostic(args.run_id)
        return result
    except RuntimeError as error:
        if "public TLS endpoint" in str(error):
            emit_public_proxy_diagnostic(project, environment)
        raise
    finally:
        down = [*base]
        if include_w3c:
            down.append("--include-w3c")
        down.append("down")
        run(down, environment)


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
    try:
        wait_for_public_stack(environment)
        fixtures = bootstrap_fixtures(args, environment, mode="eudi")
        suite_environment = dict(environment)
        suite_environment.update(load_verifier_environment(args.haip_material))
        # The runner selects only organization-scoped templates. Each template
        # is bound to an issuer profile whose DID is the signing identity; KMS
        # service and key references remain private profile-administration data.
        suite_environment.update(
            {
                "TEST_ORG_ID": fixtures["organization_id"],
                "EUDI_TEST_PASSPORT_TEMPLATE_ID": fixtures["eudi_passport_template_id"],
                "EUDI_TEST_MDL_TEMPLATE_ID": fixtures["eudi_mdl_template_id"],
                "EUDI_TEST_OPEN_BADGE_TEMPLATE_ID": fixtures["eudi_open_badge_template_id"],
            }
        )
        return run(
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
        run(
            compose_command(args, "logs", eudi=True, haip=True),
            environment,
            capture=args.output_dir / "private" / "compose.log",
        )
        run(compose_command(args, "down", eudi=True, haip=True), environment)


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
    if args.lane in {"oid4vp-final", "haip"}:
        return run_oidf(args, environment)
    if args.lane == "w3c-v2":
        return run_w3c(args, environment)
    return run_eudi(args, environment)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"Official interoperability lane error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
