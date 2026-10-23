#!/usr/bin/env python3
"""Stage disposable, keyless OpenBao inputs for the released official stack.

The product's own OpenBao and released TLS bootstrap binary create the keys.
Only public certificates and short-lived scoped tokens are copied to this
private runner directory. No product image is rebuilt or substituted.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import re
import runpy
import secrets
import stat
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from urllib.error import HTTPError
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


RUN_ID = re.compile(r"[a-z0-9][a-z0-9-]{1,46}[a-z0-9]\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
REQUIRED = re.compile(r"\$\{([A-Z][A-Z0-9_]*):\?[^}]*\}")
EXTENDS = re.compile(r"^\s*file:\s*(docker-compose[^\s]+\.yml)\s*$", re.MULTILINE)
KMS_ORIGIN = "https://openbao:8200"


class SafeBootstrapError(ValueError):
    """A fixed, credential-free bootstrap reason suitable for CI output."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


ENV_ROLES = {
    "SIGNING_KEYS": ("signing_keys_workload_server_cert", "signing_keys_tls_kms_token", "workload-tls-signing-keys-server"),
    "GATEWAY": ("gateway_workload_client_cert", "gateway_tls_kms_token", "workload-tls-gateway-auth-client"),
    "AUTH": ("auth_workload_client_cert", "auth_tls_kms_token", "workload-tls-auth-client"),
    "AUTH_SERVER": ("auth_workload_server_cert", "auth_server_tls_kms_token", "workload-tls-auth-server"),
    "COMPLIANCE_PROFILE": ("compliance_profile_workload_client_cert", "compliance_profile_tls_kms_token", "workload-tls-compliance-profile-client"),
    "DEPLOYMENT_PROFILE": ("deployment_profile_workload_client_cert", "deployment_profile_tls_kms_token", "workload-tls-deployment-profile-client"),
    "ORG": ("org_workload_server_cert", "org_tls_kms_token", "workload-tls-organization-server"),
    "ES": ("es_workload_server_cert", "es_tls_kms_token", "workload-tls-event-stream-server"),
    "RP": ("rp_workload_server_cert", "rp_tls_kms_token", "workload-tls-revocation-profile-server"),
    "CT": ("ct_workload_server_cert", "ct_tls_kms_token", "workload-tls-credential-template-server"),
    "ISSUANCE": ("issuance_workload_server_cert", "issuance_tls_kms_token", "workload-tls-issuance-server"),
    "FLOW_CLIENT": ("flow_workload_client_cert", "flow_client_tls_kms_token", "workload-tls-flow-client"),
    "FLOW_SERVER": ("flow_workload_server_cert", "flow_server_tls_kms_token", "workload-tls-flow-server"),
    "PP": ("pp_workload_server_cert", "pp_tls_kms_token", "workload-tls-presentation-policy-server"),
    "VERIFICATION": ("verification_workload_client_cert", "verification_tls_kms_token", "workload-tls-verification-client"),
    "ENVOY_ISSUANCE": ("envoy_issuance_client_cert", "envoy_issuance_tls_kms_token", "workload-tls-envoy-issuance-client"),
}
KEYCLOAK_FILES = {
    "KEYCLOAK_SIGNING_KMS_TOKEN_FILE": "keycloak_signing_kms_token",
    "KEYCLOAK_MASTER_RS256_CERT_FILE": "keycloak_master_rs256_cert",
    "KEYCLOAK_11ID_RS256_CERT_FILE": "keycloak_11id_rs256_cert",
    "KEYCLOAK_MASTER_COOKIE_TOKEN_FILE": "keycloak_master_cookie_token",
    "KEYCLOAK_MASTER_CIBA_TOKEN_FILE": "keycloak_master_ciba_token",
    "KEYCLOAK_11ID_COOKIE_TOKEN_FILE": "keycloak_11id_cookie_token",
    "KEYCLOAK_11ID_CIBA_TOKEN_FILE": "keycloak_11id_ciba_token",
}
RUNTIME_CREDENTIALS = (
    "MARTY_DB_PASSWORD", "REDIS_PASSWORD", "DEVICE_REGISTRATION_GATEWAY_KEY",
    "DEVICE_REGISTRATION_SIGNING_KEYS_KEY", "FLOW_APPLICATION_EVENT_HMAC_KEY",
    "FLOW_WEBHOOK_SECRET", "GRPC_SERVICE_TOKEN", "ISSUANCE_API_KEY", "TOKEN_HMAC_KEY",
    "SIGNING_KEYS_INTERNAL_API_KEY", "SIGNING_KEYS_ISSUER_SIGN_KEY",
    "SIGNING_KEYS_SERVICE_SIGN_GATEWAY_KEY",
)
def role_environment(tls: Path, extra: Path) -> dict[str, str]:
    """Describe every scoped workload KMS input from the same role inventory."""
    environment = {}
    for prefix, (certificate, token, key_name) in ENV_ROLES.items():
        directory = extra if prefix == "ENVOY_ISSUANCE" else tls
        environment.update({
            f"{prefix}_TLS_KMS_ADDR": KMS_ORIGIN,
            f"{prefix}_TLS_KMS_KEY_NAME": key_name,
            f"{prefix}_TLS_KMS_KEY_VERSION": "1",
            f"{prefix}_TLS_KMS_TOKEN_FILE": str(directory / token),
            f"{certificate.upper()}_FILE": str(directory / certificate),
        })
    return environment


def run(command: list[str], *, env: dict[str, str] | None = None, cwd: Path | None = None,
        capture: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(command, env=env, cwd=cwd, check=True,
                          capture_output=capture, text=capture, timeout=240)


def private_file(path: Path, content: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(content)


def load_assignments(path: Path) -> dict[str, str]:
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if not separator or not key or not value or key in result:
            raise ValueError("released stack environment is invalid")
        result[key] = value
    return result


def validate_runtime_environment(values: dict[str, str], root: Path, origin: str) -> None:
    expected = {
        "KEYCLOAK_KMS_ADDR", "KEYCLOAK_KMS_KEY_VERSION", "OPENBAO_TLS_CA_CERT_FILE",
        "MARTY_WORKLOAD_IDENTITY_CA_CERT_FILE", "DEV_INTEGRATION_SECRET_CA_FILE",
        *RUNTIME_CREDENTIALS,
        "SIGNING_KEYS_INTEGRATION_SECRET_KEY", "PUBLIC_API_URL", "CORS_ORIGINS",
        "OIDF_TLS_KMS_ADDR", "OIDF_TLS_KMS_KEY_NAME", "OIDF_TLS_KMS_KEY_VERSION",
        "OIDF_TLS_KMS_CA_CERT_FILE", "OIDF_TLS_KMS_TOKEN_FILE", "OIDF_EDGE_TLS_CERT_FILE",
        "SIGNING_KEYS_WORKLOAD_SERVER_CERT_FILE", "FLOW_WORKLOAD_CLIENT_CERT_FILE",
        "ENVOY_ISSUANCE_CLIENT_CERT_FILE", *KEYCLOAK_FILES,
    }
    role_values = role_environment(root / "tls", root / "extra")
    expected.update(role_values)
    if set(values) != expected:
        raise ValueError("disposable KMS environment has missing or unsupported inputs")
    for key, value in role_values.items():
        if values[key] != value:
            raise ValueError(f"disposable KMS role input differs from its provisioned binding: {key}")
    for key, filename in KEYCLOAK_FILES.items():
        if values[key] != str(root / "keycloak" / filename):
            raise ValueError(f"disposable Keycloak KMS input differs from its provisioned binding: {key}")
    for key, value in values.items():
        if key.endswith("_FILE"):
            path = Path(value)
            if (not path.is_absolute() or path.is_symlink() or not path.is_file()
                    or not path.resolve().is_relative_to(root)):
                raise ValueError(f"disposable KMS input {key} is missing or outside the run")
        elif key.endswith("_TLS_KMS_ADDR") or key == "KEYCLOAK_KMS_ADDR":
            if value != KMS_ORIGIN:
                raise ValueError(f"disposable KMS origin is invalid: {key}")
        elif key.endswith("_TLS_KMS_KEY_VERSION") or key == "KEYCLOAK_KMS_KEY_VERSION":
            if value != "1":
                raise ValueError(f"disposable KMS key version is invalid: {key}")
        elif key in {"PUBLIC_API_URL", "CORS_ORIGINS"}:
            if value != origin:
                raise ValueError(f"disposable public origin is invalid: {key}")
        elif not value or "\n" in value or "\r" in value:
            raise ValueError(f"disposable KMS input is invalid: {key}")


def prepare_runtime_mount_files(values: dict[str, str], root: Path, origin: str) -> None:
    """Expose only runtime leaf inputs through individual read-only secret mounts.

    Compose bind-backed secrets retain host permissions rather than remapping
    their UID. Runtime service users differ from the provisioning user. The
    private host directory remains 0700; only the reviewed public certificates
    and scoped runtime tokens become readable at their container mount points.
    Root authority and the private environment file are never exportable here.
    """
    if root.is_symlink() or stat.S_IMODE(root.stat().st_mode) != 0o700:
        raise ValueError("runtime KMS mounts require a private 0700 directory")
    validate_runtime_environment(values, root, origin)
    allowed = {
        root / "openbao_tls_ca_cert", root / "tls" / "workload_identity_ca_cert",
        root / "extra" / "oidf_edge_tls_kms_token", root / "extra" / "oidf-edge.crt",
        *(root / "keycloak" / name for name in KEYCLOAK_FILES.values()),
        *(Path(value) for name, value in role_environment(root / "tls", root / "extra").items()
          if name.endswith("_FILE")),
    }
    paths = {Path(value) for name, value in values.items() if name.endswith("_FILE")}
    if not paths.issubset(allowed):
        raise ValueError("runtime KMS mount is not an approved leaf export")
    for path in paths:
        path.chmod(0o444)


def checked_release(args: argparse.Namespace) -> tuple[dict[str, str], list[str], dict]:
    if not RUN_ID.fullmatch(args.run_id):
        raise ValueError("official run id is invalid")
    manifest = json.loads(args.stack_manifest.read_text(encoding="utf-8"))
    components = manifest.get("components", [])
    ui = [item for item in components if item.get("name") == "marty-ui"]
    if len(ui) != 1 or not COMMIT.fullmatch(ui[0].get("commit", "")):
        raise ValueError("released UI revision is missing")
    actual = run(["git", "-C", str(args.marty_ui), "rev-parse", "HEAD"], capture=True).stdout.strip()
    if actual != ui[0]["commit"]:
        raise ValueError("KMS bootstrap source differs from the attested release")
    images = load_assignments(args.stack_env)
    artifacts = ui[0].get("artifacts", [])
    references = {f"{item['uri']}@{item['digest']}" for item in artifacts if item.get("type") == "oci"}
    for key in ("MARTY_SERVICES_IMAGE", "MARTY_OPENBAO_DIDCOMM_IMAGE", "MARTY_KEYCLOAK_IMAGE"):
        if images.get(key) not in references:
            raise ValueError(f"{key} differs from the attested release")
    source = runpy.run_path(str(args.marty_ui / "scripts" / "conformance_stack.py"))
    project = f"marty-conformance-{args.run_id}"
    compose = source["compose_command"](project)
    return images, compose, source


def compose_sources(compose: list[str]) -> set[Path]:
    pending = [Path(compose[index + 1]) for index, value in enumerate(compose[:-1]) if value == "--file"]
    found: set[Path] = set()
    while pending:
        source = pending.pop().resolve()
        if source in found:
            continue
        found.add(source)
        pending.extend(source.parent / name for name in EXTENDS.findall(source.read_text(encoding="utf-8")))
    return found


def placeholder_environment(compose: list[str], images: dict[str, str], private: Path,
                            project: str, material: dict[str, str]) -> dict[str, str]:
    env = {**os.environ, **images, **material, "MARTY_CONFORMANCE_PROJECT": project}
    files = compose_sources(compose)
    placeholder = private / "bootstrap-placeholder"
    private_file(placeholder, "bootstrap-only\n")
    for source in files:
        for key in REQUIRED.findall(source.read_text(encoding="utf-8")):
            if key not in env:
                env[key] = str(placeholder) if key.endswith("_FILE") else "bootstrap-only"
    env["KEYCLOAK_KMS_IMAGE_DIGEST"] = images["MARTY_KEYCLOAK_IMAGE"].rsplit("@", 1)[1]
    for prefix, (_, _, key_name) in ENV_ROLES.items():
        env.setdefault(f"{prefix}_TLS_KMS_KEY_NAME", key_name)
        env.setdefault(f"{prefix}_TLS_KMS_KEY_VERSION", "1")
        env.setdefault(f"{prefix}_TLS_KMS_ADDR", KMS_ORIGIN)
    env.setdefault("KEYCLOAK_KMS_ADDR", KMS_ORIGIN)
    env.setdefault("KEYCLOAK_KMS_KEY_VERSION", "1")
    return env


def require_kms_only_images(compose: list[str], env: dict[str, str], ui: Path,
                            images: dict[str, str]) -> None:
    rendered = json.loads(run([*compose, "config", "--format", "json"],
                              env=env, cwd=ui, capture=True).stdout)
    services = rendered.get("services", {})
    plugin = images["MARTY_OPENBAO_DIDCOMM_IMAGE"]
    if any(services.get(name, {}).get("image") != plugin
           for name in ("openbao", "openbao-tls-init", "openbao-init")):
        raise SafeBootstrapError("released conformance stack replaces its attested KMS-only OpenBao plugin")
    if any(services.get(name, {}).get("image") != images["MARTY_SERVICES_IMAGE"]
           for name in ("issuance-native", "oidf-tls-proxy")):
        raise SafeBootstrapError("released native issuance or official edge differs from the attested services image")


def container_id(compose: list[str], service: str, env: dict[str, str], ui: Path) -> str:
    result = run([*compose, "ps", "--all", "--quiet", service], env=env, cwd=ui, capture=True)
    ids = result.stdout.splitlines()
    if len(ids) != 1 or not re.fullmatch(r"[0-9a-f]{12,64}", ids[0]):
        raise RuntimeError(f"exact {service} container is unavailable")
    return ids[0]


def wait_openbao_init(compose: list[str], env: dict[str, str], ui: Path) -> str:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            service = container_id(compose, "openbao-init", env, ui)
        except RuntimeError:
            time.sleep(1)
            continue
        status = run(["docker", "inspect", "--format", "{{.State.Status}} {{.State.ExitCode}}", service], capture=True).stdout.strip()
        if status == "exited 0":
            return container_id(compose, "openbao", env, ui)
        if status.startswith("exited "):
            raise RuntimeError("released OpenBao initializer failed")
        time.sleep(1)
    raise RuntimeError("released OpenBao initializer did not complete")


def copy_private_from_container(container: str, source: str, target: Path) -> None:
    result = subprocess.run(["docker", "exec", "--user", "0", container, "cat", source],
                            capture_output=True, check=True, timeout=20)
    if not result.stdout or len(result.stdout) > 64 * 1024:
        raise RuntimeError("released OpenBao bootstrap input is invalid")
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(result.stdout)


def openbao_network(container: str, project: str) -> tuple[str, str]:
    detail = json.loads(run(["docker", "inspect", container], capture=True).stdout)[0]
    if detail["Config"]["Labels"].get("com.docker.compose.project") != project:
        raise RuntimeError("OpenBao container belongs to another project")
    networks = detail["NetworkSettings"]["Networks"]
    matches = [(name, value.get("IPAddress", "")) for name, value in networks.items()
               if name.startswith(project + "_") and "openbao" in value.get("Aliases", [])]
    if len(matches) != 1 or not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", matches[0][1]):
        raise RuntimeError("OpenBao project network is ambiguous")
    return matches[0]


def scoped_transit_signing_token(bao, key_name: str, policy_name: str,
                                 authority: str, challenge: bytes) -> str:
    """Issue and exercise a bounded Transit signer token for one key."""
    if (not re.fullmatch(r"[a-z0-9-]+", key_name)
            or not re.fullmatch(r"[a-z0-9-]+", policy_name)
            or not challenge):
        raise ValueError("scoped Transit signer inputs are invalid")
    policy = (f'path "transit/keys/{key_name}" {{ capabilities = ["read"] }}\n'
              f'path "transit/sign/{key_name}" {{ capabilities = ["update"] }}')
    bao.request("PUT", f"sys/policies/acl/{policy_name}", {"policy": policy})
    auth = bao.request("POST", "auth/token/create", {
        "policies": [policy_name], "no_default_policy": True, "ttl": "8h",
    })["auth"]
    token = auth.get("client_token")
    if not isinstance(token, str) or len(token) < 20 or token == authority:
        raise RuntimeError("scoped Transit signer token is invalid")
    signature = bao.request("POST", f"transit/sign/{key_name}", {
        "input": base64.b64encode(challenge).decode("ascii"),
    }, token=token).get("data", {}).get("signature")
    if not isinstance(signature, str) or not signature:
        raise RuntimeError("scoped Transit signer token cannot sign")
    return token


def provision_nonexportable_transit_key(bao, name: str, purpose: str) -> str:
    """Create and attest one version-one P-256 key using the product Bao client."""
    bao.request("POST", f"transit/keys/{name}", {
        "type": "ecdsa-p256", "exportable": False, "allow_plaintext_backup": False,
    })
    metadata = bao.request("GET", f"transit/keys/{name}")["data"]
    if (metadata.get("type") != "ecdsa-p256" or metadata.get("exportable") is not False
            or metadata.get("allow_plaintext_backup") is not False
            or metadata.get("latest_version") != 1):
        raise RuntimeError(f"{purpose} key is not non-exportable version one")
    public_key = metadata.get("keys", {}).get("1", {}).get("public_key")
    if not isinstance(public_key, str):
        raise RuntimeError(f"{purpose} key has no public binding")
    return public_key


def provision_envoy(ui: Path, private: Path, ca: Path, root: Path) -> None:
    sys.path.insert(0, str(ui / "scripts"))
    from selfhost_openbao_client import Bao, certificate_public_key_der, public_key_der

    authority = root.read_text(encoding="ascii").strip()
    bao = Bao(KMS_ORIGIN, ca, authority)
    name = "workload-tls-envoy-issuance-client"
    role = "envoy-issuance-client"
    uri = "spiffe://marty.internal/service/envoy-issuance-bridge"
    public_key = provision_nonexportable_transit_key(bao, name, "Envoy TLS")
    bao.request("POST", f"workload-pki/roles/{role}", {
        "allow_any_name": True, "allow_localhost": True, "allow_ip_sans": True,
        "allowed_uri_sans": uri, "server_flag": False, "client_flag": True,
        "key_type": "ec", "key_bits": 256, "max_ttl": "24h",
        "use_csr_common_name": False, "use_csr_sans": False,
    })
    csr = bao.request("POST", f"transit/keys/{name}/csr", {"version": 1})["data"]["csr"]
    signed = bao.request("POST", f"workload-pki/sign/{role}", {
        "csr": csr, "common_name": "envoy-issuance-bridge", "uri_sans": uri, "ttl": "8h",
    })["data"]
    certificate = signed.get("certificate")
    if (not isinstance(certificate, str) or "private_key" in signed
            or certificate_public_key_der(certificate) != public_key_der(public_key)):
        raise RuntimeError("Envoy certificate is not bound to its remote KMS key")
    private_file(private / "envoy_issuance_client_cert", certificate)
    policy_name = f"official-{secrets.token_hex(6)}-{name}"
    token = scoped_transit_signing_token(bao, name, policy_name, authority,
                                         b"official-envoy-proof")
    private_file(private / "envoy_issuance_tls_kms_token", token)


def provision_oidf_edge(ui: Path, private: Path, material: Path, ca: Path,
                        root: Path, origin: str) -> tuple[str, Path]:
    """Bind the official HTTPS leaf to a new, non-exportable Transit key."""
    from selfhost_openbao_client import Bao, certificate_public_key_der, public_key_der

    hostname = urlsplit(origin).hostname
    if not hostname or not re.fullmatch(r"[a-z0-9.-]+", hostname):
        raise ValueError("official edge hostname is invalid")
    name = f"official-{secrets.token_hex(8)}-oidf-edge"
    authority = root.read_text(encoding="ascii").strip()
    bao = Bao(KMS_ORIGIN, ca, authority)
    public_key = provision_nonexportable_transit_key(bao, name, "official edge")
    csr_pem = bao.request("POST", f"transit/keys/{name}/csr", {"version": 1})["data"]["csr"]
    csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
    if (not csr.is_signature_valid
            or csr.public_key().public_bytes(serialization.Encoding.DER,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)
            != public_key_der(public_key)):
        raise RuntimeError("official edge CSR is not bound to its remote KMS key")
    root_cert = x509.load_pem_x509_certificate((material / "root-ca.pem").read_bytes())
    root_key = serialization.load_pem_private_key((material / "official-ca.key").read_bytes(), password=None)
    if (not isinstance(root_key, ec.EllipticCurvePrivateKey)
            or root_key.public_key().public_numbers() != root_cert.public_key().public_numbers()):
        raise RuntimeError("disposable fixture CA authority does not match")
    now = datetime.now(UTC)
    certificate = (x509.CertificateBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
                   .issuer_name(root_cert.subject).public_key(csr.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(minutes=1))
                   .not_valid_after(min(now + timedelta(hours=8), root_cert.not_valid_after_utc))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                   .sign(root_key, hashes.SHA256()))
    pem = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
    if certificate_public_key_der(pem) != public_key_der(public_key):
        raise RuntimeError("official edge leaf is not bound to its remote KMS key")
    certificate_path = private / "oidf-edge.crt"
    private_file(certificate_path, pem + root_cert.public_bytes(serialization.Encoding.PEM).decode("ascii"))
    policy_name = f"official-{secrets.token_hex(6)}-oidf-edge"
    token = scoped_transit_signing_token(bao, name, policy_name, authority,
                                         b"official-edge-proof")
    private_file(private / "oidf_edge_tls_kms_token", token)
    return name, certificate_path


def runtime_environment(tls: Path, keycloak: Path, extra: Path, ca: Path,
                        material: dict[str, str], edge: tuple[str, Path]) -> dict[str, str]:
    environment = {
        "KEYCLOAK_KMS_ADDR": KMS_ORIGIN,
        "KEYCLOAK_KMS_KEY_VERSION": "1",
        "OPENBAO_TLS_CA_CERT_FILE": str(ca),
        "MARTY_WORKLOAD_IDENTITY_CA_CERT_FILE": str(tls / "workload_identity_ca_cert"),
        "DEV_INTEGRATION_SECRET_CA_FILE": str(tls / "workload_identity_ca_cert"),
        **{key: secrets.token_urlsafe(32) for key in RUNTIME_CREDENTIALS},
        "SIGNING_KEYS_INTEGRATION_SECRET_KEY": base64.urlsafe_b64encode(os.urandom(32)).decode("ascii"),
        "PUBLIC_API_URL": material["OIDF_PUBLIC_BASE_URL"],
        "CORS_ORIGINS": material["OIDF_PUBLIC_BASE_URL"],
        "OIDF_TLS_KMS_ADDR": KMS_ORIGIN,
        "OIDF_TLS_KMS_KEY_NAME": edge[0],
        "OIDF_TLS_KMS_KEY_VERSION": "1",
        "OIDF_TLS_KMS_CA_CERT_FILE": str(ca),
        "OIDF_TLS_KMS_TOKEN_FILE": str(extra / "oidf_edge_tls_kms_token"),
        "OIDF_EDGE_TLS_CERT_FILE": str(edge[1]),
    }
    environment.update({name: str(keycloak / file) for name, file in KEYCLOAK_FILES.items()})
    environment.update(role_environment(tls, extra))
    for name, value in environment.items():
        if name.endswith("_FILE") and not Path(value).is_file():
            raise RuntimeError(f"disposable KMS output is missing {name}")
    return environment


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--marty-ui", required=True, type=Path)
    parser.add_argument("--stack-manifest", required=True, type=Path)
    parser.add_argument("--stack-env", required=True, type=Path)
    parser.add_argument("--material", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    if os.name != "posix":
        raise RuntimeError("official disposable KMS bootstrap requires a Linux Docker host")
    images, compose, _source = checked_release(args)
    private = args.output_dir.resolve()
    private.mkdir(mode=0o700, parents=True, exist_ok=False)
    if stat.S_IMODE(private.stat().st_mode) != 0o700:
        raise RuntimeError("disposable KMS directory is not private")
    project = f"marty-conformance-{args.run_id}"
    material = json.loads((args.material / "environment.json").read_text(encoding="utf-8"))["environment"]
    if not isinstance(material, dict) or not material.get("OIDF_PUBLIC_BASE_URL", "").startswith("https://"):
        raise ValueError("official TLS material is incomplete")
    bootstrap_env = placeholder_environment(compose, images, private, project, material)
    tls = private / "tls"
    keycloak = private / "keycloak"
    extra = private / "extra"
    try:
        require_kms_only_images(compose, bootstrap_env, args.marty_ui, images)
        for directory in (tls, keycloak, extra):
            directory.mkdir(mode=0o700)
        run([*compose, "up", "--detach", "--no-build", "--pull", "never", "openbao-init"],
            env=bootstrap_env, cwd=args.marty_ui)
        container = wait_openbao_init(compose, bootstrap_env, args.marty_ui)
        ca = private / "openbao_tls_ca_cert"
        root = private / "bootstrap-root-token"
        copy_private_from_container(container, "/bao/data/tls/ca.crt", ca)
        copy_private_from_container(container, "/bao/data/root.token", root)
        network, address = openbao_network(container, project)
        # The ephemeral GitHub runner already modifies /etc/hosts for the
        # official TLS origins. Keep the product's OpenBao hostname for TLS SNI.
        with subprocess.Popen(["sudo", "tee", "-a", "/etc/hosts"], stdin=subprocess.PIPE,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as hosts:
            hosts.communicate(f"{address} openbao\n".encode("ascii"), timeout=10)
            if hosts.returncode:
                raise RuntimeError("runner cannot resolve its disposable OpenBao origin")
        run([
            "docker", "run", "--rm", "--pull=never", "--network", network,
            "--user", f"{os.getuid()}:{os.getgid()}", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,mode=1777",
            "--mount", f"type=bind,src={ca},dst=/input/ca.crt,readonly",
            "--mount", f"type=bind,src={root},dst=/input/root.token,readonly",
            "--mount", f"type=bind,src={tls},dst=/output",
            "-e", f"BAO_ADDR={KMS_ORIGIN}", "-e", "BAO_CACERT=/input/ca.crt",
            "-e", "BAO_ROOT_TOKEN_FILE=/input/root.token",
            "-e", "MARTY_TLS_BOOTSTRAP_PROFILE=selfhost-disposable",
            "-e", "MARTY_SELFHOST_DISPOSABLE_OPENBAO=1",
            "-e", f"MARTY_SELFHOST_PROJECT=marty-selfhost-disposable-{secrets.token_hex(5)}",
            "-e", "SELFHOST_TLS_OUTPUT_DIR=/output",
            "--entrypoint", "/usr/local/bin/marty-passport-tls-bootstrap",
            images["MARTY_SERVICES_IMAGE"],
        ])
        keycloak_env = {**os.environ, "BAO_ADDR": KMS_ORIGIN, "BAO_CACERT": str(ca),
                        "BAO_ROOT_TOKEN_FILE": str(root),
                        "SELFHOST_KEYCLOAK_OUTPUT_DIR": str(keycloak)}
        run([sys.executable, str(args.marty_ui / "scripts" / "provision_selfhost_keycloak_kms.py")],
            env=keycloak_env)
        provision_envoy(args.marty_ui, extra, ca, root)
        edge = provision_oidf_edge(args.marty_ui, extra, args.material, ca, root,
                                   material["OIDF_PUBLIC_BASE_URL"])
        (args.material / "official-ca.key").unlink()
        environment = runtime_environment(tls, keycloak, extra, ca, material, edge)
        prepare_runtime_mount_files(environment, private, material["OIDF_PUBLIC_BASE_URL"])
        private_file(private / ".env.kms", "".join(f"{key}={value}\n" for key, value in sorted(environment.items())))
        root.unlink()
        print("Staged disposable KMS-only runtime inputs for the attested released stack.")
        return 0
    except BaseException:
        (args.material / "official-ca.key").unlink(missing_ok=True)
        (private / "bootstrap-root-token").unlink(missing_ok=True)
        subprocess.run([*compose, "down", "--volumes", "--remove-orphans"],
                       env=bootstrap_env, cwd=args.marty_ui, capture_output=True, timeout=90)
        raise


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyError, HTTPError) as error:
        reason = error.code if isinstance(error, SafeBootstrapError) else type(error).__name__
        print(f"Official KMS bootstrap failed: {reason}", file=sys.stderr)
        raise SystemExit(2) from None
