import base64
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

SOURCE = Path(__file__).parents[2] / "scripts" / "official_kms_bootstrap.py"
SPEC = importlib.util.spec_from_file_location("official_kms_bootstrap", SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


@pytest.mark.parametrize("ending", ["", "\n"])
def test_openbao_alias_is_a_separate_record_without_replacing_existing_hosts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ending: str,
) -> None:
    hosts = tmp_path / "hosts"
    original = "127.0.0.1 localhost\nff02::2 ip6-allrouters" + ending
    hosts.write_text(original, encoding="ascii")
    popen = MODULE.subprocess.Popen

    def append_in_private_file(command: list[str], **kwargs: object) -> object:
        assert command == ["sudo", "tee", "-a", "/etc/hosts"]
        return popen([
            sys.executable, "-c",
            "import pathlib,sys; "
            "pathlib.Path(sys.argv[1]).open('ab').write(sys.stdin.buffer.read())",
            str(hosts),
        ], **kwargs)

    monkeypatch.setattr(MODULE.subprocess, "Popen", append_in_private_file)
    MODULE.append_openbao_host("172.26.0.2")
    actual = hosts.read_text(encoding="ascii")
    assert actual.startswith(original)
    assert actual.splitlines()[-1].split() == ["172.26.0.2", "openbao"]
    assert "ff02::2 ip6-allrouters" in actual.splitlines()


@pytest.mark.parametrize("run_id", ["local-oid4vp-url-query-20261023-r1", "production/stack"])
def test_invalid_suite_identity_is_rejected_before_release_reads_or_provisioning(
    tmp_path: Path, run_id: str,
) -> None:
    args = SimpleNamespace(run_id=run_id, stack_manifest=tmp_path / "must-not-be-read.json")
    with pytest.raises(ValueError, match="official run id is invalid"):
        MODULE.checked_release(args)


def test_bootstrap_discovers_required_inputs_in_extended_native_service(tmp_path: Path) -> None:
    base = tmp_path / "docker-compose.base.yml"
    native = tmp_path / "docker-compose.native.yml"
    service = tmp_path / "docker-compose.service.issuance-native.yml"
    base.write_text("services:\n  openbao:\n    image: ${MARTY_OPENBAO_DIDCOMM_IMAGE:?pin plugin}\n", encoding="utf-8")
    native.write_text("services:\n  issuance-native:\n    extends:\n      file: docker-compose.service.issuance-native.yml\n      service: issuance-native\n", encoding="utf-8")
    service.write_text("services:\n  issuance-native:\n    environment:\n      TOKEN_HMAC_KEY: ${TOKEN_HMAC_KEY:?required}\n", encoding="utf-8")
    compose = ["docker", "compose", "--file", str(base), "--file", str(native)]
    assert MODULE.compose_sources(compose) == {base, native, service}
    environment = MODULE.placeholder_environment(
        compose, {"MARTY_OPENBAO_DIDCOMM_IMAGE": "ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:" + "a" * 64,
                  "MARTY_KEYCLOAK_IMAGE": "ghcr.io/elevenid/marty-ui-oss/keycloak@sha256:" + "b" * 64},
        tmp_path, "marty-conformance-test123", {"OIDF_PUBLIC_BASE_URL": "https://marty.test"},
    )
    assert environment["TOKEN_HMAC_KEY"] == "bootstrap-only"
    assert environment["MARTY_CONFORMANCE_PROJECT"] == "marty-conformance-test123"


def test_bootstrap_rejects_plain_openbao_in_released_conformance_graph(monkeypatch, tmp_path: Path) -> None:
    plugin = "ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:" + "a" * 64
    services = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "b" * 64
    graph = {"services": {name: {"image": plugin} for name in ("openbao", "openbao-tls-init", "openbao-init")}}
    graph["services"]["issuance-native"] = {"image": services}
    graph["services"]["oidf-tls-proxy"] = {"image": services}
    monkeypatch.setattr(MODULE, "run", lambda *args, **kwargs: SimpleNamespace(stdout=json.dumps(graph)))
    images = {"MARTY_OPENBAO_DIDCOMM_IMAGE": plugin, "MARTY_SERVICES_IMAGE": services}
    MODULE.require_kms_only_images(["docker", "compose"], {}, tmp_path, images)
    graph["services"]["openbao"]["image"] = "quay.io/openbao/openbao@sha256:" + "c" * 64
    with pytest.raises(ValueError, match="replaces its attested KMS-only OpenBao plugin"):
        MODULE.require_kms_only_images(["docker", "compose"], {}, tmp_path, images)


def runtime_inputs(tmp_path: Path) -> tuple[dict[str, str], str]:
    tls, keycloak, extra = (tmp_path / name for name in ("tls", "keycloak", "extra"))
    for directory in (tls, keycloak, extra):
        directory.mkdir()
    for filename in MODULE.KEYCLOAK_FILES.values():
        (keycloak / filename).write_text("scoped", encoding="ascii")
    for prefix, (certificate, token, _) in MODULE.ENV_ROLES.items():
        directory = extra if prefix in MODULE.EXTRA_WORKLOADS else tls
        (directory / certificate).write_text("certificate", encoding="ascii")
        (directory / token).write_text("scoped", encoding="ascii")
    for path in (tls / "workload_identity_ca_cert", tmp_path / "openbao_tls_ca_cert",
                 extra / "oidf_edge_tls_kms_token", extra / "oidf-edge.crt"):
        path.write_text("certificate", encoding="ascii")
    origin = "https://marty-oidf.test:18443"
    values = MODULE.runtime_environment(tls, keycloak, extra, tmp_path / "openbao_tls_ca_cert",
                                        {"OIDF_PUBLIC_BASE_URL": origin},
                                        ("official-test-oidf-edge", extra / "oidf-edge.crt"))
    return values, origin


def test_runtime_environment_requires_exact_private_kms_inputs(tmp_path: Path) -> None:
    values, origin = runtime_inputs(tmp_path)
    tls, extra = tmp_path / "tls", tmp_path / "extra"
    MODULE.validate_runtime_environment(values, tmp_path, origin)
    assert values["FLOW_WORKLOAD_CLIENT_CERT_FILE"] == str(tls / "flow_workload_client_cert")
    assert values["FLOW_WORKLOAD_SERVER_CERT_FILE"] == str(tls / "flow_workload_server_cert")
    assert values["AUTH_WORKLOAD_SERVER_CERT_FILE"] == str(tls / "auth_workload_server_cert")
    assert values["ENVOY_ISSUANCE_CLIENT_CERT_FILE"] == str(extra / "envoy_issuance_client_cert")
    assert values["TRUST_PROFILE_WORKLOAD_SERVER_CERT_FILE"] == str(extra / "trust_profile_workload_server_cert")
    assert values["TRUST_PROFILE_TLS_KMS_TOKEN_FILE"] == str(extra / "trust_profile_tls_kms_token")
    assert values["TRUST_PROFILE_TLS_KMS_KEY_NAME"] == "workload-tls-trust-profile-server"
    assert values["TRUST_PROFILE_TLS_KMS_KEY_VERSION"] == "1"
    with pytest.raises(ValueError, match="missing or unsupported"):
        MODULE.validate_runtime_environment({key: value for key, value in values.items()
                                             if key != "TRUST_PROFILE_TLS_KMS_KEY_NAME"}, tmp_path, origin)
    with pytest.raises(ValueError, match="role input differs"):
        MODULE.validate_runtime_environment(
            {**values, "TRUST_PROFILE_TLS_KMS_TOKEN_FILE": values["ISSUANCE_TLS_KMS_TOKEN_FILE"]},
            tmp_path, origin)
    with pytest.raises(ValueError, match="origin is invalid"):
        MODULE.validate_runtime_environment({**values, "OIDF_TLS_KMS_ADDR": "http://openbao:8200"},
                                            tmp_path, origin)
    with pytest.raises(ValueError, match="missing or unsupported"):
        MODULE.validate_runtime_environment({key: value for key, value in values.items()
                                             if key != "OIDF_TLS_KMS_TOKEN_FILE"}, tmp_path, origin)
    with pytest.raises(ValueError, match="missing or unsupported"):
        MODULE.validate_runtime_environment({key: value for key, value in values.items()
                                             if key != "FLOW_WORKLOAD_CLIENT_CERT_FILE"}, tmp_path, origin)
    with pytest.raises(ValueError, match="role input differs"):
        MODULE.validate_runtime_environment(
            {**values, "FLOW_CLIENT_TLS_KMS_KEY_NAME": values["FLOW_SERVER_TLS_KMS_KEY_NAME"]},
            tmp_path, origin)
    with pytest.raises(ValueError, match="role input differs"):
        MODULE.validate_runtime_environment(
            {**values, "FLOW_CLIENT_TLS_KMS_TOKEN_FILE": values["FLOW_SERVER_TLS_KMS_TOKEN_FILE"]},
            tmp_path, origin)
    with pytest.raises(ValueError, match="Keycloak KMS input differs"):
        MODULE.validate_runtime_environment(
            {**values, "KEYCLOAK_SIGNING_KMS_TOKEN_FILE": values["KEYCLOAK_MASTER_COOKIE_TOKEN_FILE"]},
            tmp_path, origin)


@pytest.mark.skipif(os.name != "posix", reason="Compose runtime mount permissions require POSIX")
@pytest.mark.parametrize("fault", [None, "public-parent", "root-authority", "symlink", "outside"])
def test_runtime_mount_permissions_preserve_the_private_authority_boundary(tmp_path: Path, fault: str | None) -> None:
    tmp_path.chmod(0o700)
    values, origin = runtime_inputs(tmp_path)
    authority = tmp_path / "bootstrap-root-token"
    MODULE.private_file(authority, "private-authority")
    environment_file = tmp_path / ".env.kms"
    MODULE.private_file(environment_file, "private-environment")
    for name, value in values.items():
        if name.endswith("_FILE"):
            Path(value).chmod(0o600)
    if fault == "public-parent":
        tmp_path.chmod(0o755)
    elif fault == "root-authority":
        values["OPENBAO_TLS_CA_CERT_FILE"] = str(authority)
    elif fault == "symlink":
        source = Path(values["OPENBAO_TLS_CA_CERT_FILE"])
        source.unlink()
        source.symlink_to(authority)
    elif fault == "outside":
        values["OPENBAO_TLS_CA_CERT_FILE"] = str(tmp_path.parent / "outside.pem")
    if fault:
        with pytest.raises(ValueError):
            MODULE.prepare_runtime_mount_files(values, tmp_path, origin)
    else:
        MODULE.prepare_runtime_mount_files(values, tmp_path, origin)
        assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700
        assert all(stat.S_IMODE(Path(value).stat().st_mode) == 0o444
                   for name, value in values.items() if name.endswith("_FILE"))
    assert stat.S_IMODE(authority.stat().st_mode) == 0o600
    assert stat.S_IMODE(environment_file.stat().st_mode) == 0o600


def test_scoped_transit_token_proves_only_its_bound_sign_route() -> None:
    class Bao:
        def __init__(self):
            self.calls = []

        def request(self, method, path, body, *, token=None):
            self.calls.append((method, path, body, token))
            if path == "auth/token/create":
                return {"auth": {"client_token": "s" * 24}}
            return {"data": {"signature": "vault:v1:signature"}}

    bao = Bao()
    token = MODULE.scoped_transit_signing_token(
        bao, "one-key", "one-policy", "root-authority", b"fresh-proof")
    assert token == "s" * 24
    assert bao.calls[0][2]["policy"] == (
        'path "transit/keys/one-key" { capabilities = ["read"] }\n'
        'path "transit/sign/one-key" { capabilities = ["update"] }')
    assert bao.calls[1][2] == {"policies": ["one-policy"],
                                "no_default_policy": True, "ttl": "8h"}
    assert bao.calls[2] == ("POST", "transit/sign/one-key",
                            {"input": base64.b64encode(b"fresh-proof").decode("ascii")}, token)
    with pytest.raises(ValueError, match="inputs are invalid"):
        MODULE.scoped_transit_signing_token(bao, "../other", "one-policy",
                                             "root-authority", b"fresh-proof")
    assert len(bao.calls) == 3


def test_shared_transit_key_provisioning_rejects_exportable_key() -> None:
    class Bao:
        def __init__(self, exportable: bool):
            self.exportable = exportable
            self.calls = []

        def request(self, method, path, body=None):
            self.calls.append((method, path, body))
            if method == "GET":
                return {"data": {"type": "ecdsa-p256", "exportable": self.exportable,
                                 "allow_plaintext_backup": False, "latest_version": 1,
                                 "keys": {"1": {"public_key": "public-pem"}}}}
            return {}

    bao = Bao(False)
    assert MODULE.provision_nonexportable_transit_key(bao, "official-edge", "edge") == "public-pem"
    assert bao.calls[0] == ("POST", "transit/keys/official-edge", {
        "type": "ecdsa-p256", "exportable": False, "allow_plaintext_backup": False,
    })
    with pytest.raises(RuntimeError, match="not non-exportable"):
        MODULE.provision_nonexportable_transit_key(Bao(True), "official-edge", "edge")


@pytest.mark.parametrize("fault", [None, "wrong-key", "exported-private-key"])
def test_extra_workloads_bind_trust_server_to_scoped_remote_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str | None,
) -> None:
    calls = []

    class Bao:
        def __init__(self, origin, ca, authority):
            assert origin == MODULE.KMS_ORIGIN and ca == tmp_path / "ca"
            assert authority == "bootstrap-authority"

        def request(self, method, path, body=None, *, token=None):
            calls.append((method, path, body, token))
            if method == "GET":
                return {"data": {"type": "ecdsa-p256", "exportable": False,
                                 "allow_plaintext_backup": False, "latest_version": 1,
                                 "keys": {"1": {"public_key": "bound-key"}}}}
            if path.endswith("/csr"):
                return {"data": {"csr": "remote-csr"}}
            if path.startswith("workload-pki/sign/"):
                trust = path.endswith("trust-profile-server")
                data = {"certificate": "wrong-key" if trust and fault == "wrong-key" else "bound-key"}
                if trust and fault == "exported-private-key":
                    data["private_key"] = "must-not-be-written"
                return {"data": data}
            if path == "auth/token/create":
                return {"auth": {"client_token": "scoped-token" * 3}}
            return {"data": {"signature": "vault:v1:proof"}}

    monkeypatch.setitem(sys.modules, "selfhost_openbao_client", SimpleNamespace(
        Bao=Bao, certificate_public_key_der=lambda value: value,
        public_key_der=lambda value: value))
    root = tmp_path / "authority"
    root.write_text("bootstrap-authority", encoding="ascii")
    extra = tmp_path / "extra"
    extra.mkdir()
    if fault:
        with pytest.raises(RuntimeError, match="TRUST_PROFILE certificate is not bound"):
            MODULE.provision_extra_workloads(tmp_path, extra, tmp_path / "ca", root)
        assert not (extra / "trust_profile_workload_server_cert").exists()
        assert not (extra / "trust_profile_tls_kms_token").exists()
        return
    MODULE.provision_extra_workloads(tmp_path, extra, tmp_path / "ca", root)
    assert (extra / "envoy_issuance_client_cert").read_text() == "bound-key"
    assert (extra / "trust_profile_workload_server_cert").read_text() == "bound-key"
    assert (extra / "trust_profile_tls_kms_token").read_text() == "scoped-token" * 3
    role = next(body for _, path, body, _ in calls if path == "workload-pki/roles/trust-profile-server")
    assert role["server_flag"] is True and role["client_flag"] is False
    signed = next(body for _, path, body, _ in calls if path == "workload-pki/sign/trust-profile-server")
    assert signed == {"csr": "remote-csr", "common_name": "trust-profile", "uri_sans": "", "ttl": "8h"}
    policy = next(body["policy"] for _, path, body, _ in calls
                  if path.startswith("sys/policies/acl/") and "trust-profile-server" in path)
    assert policy == (
        'path "transit/keys/workload-tls-trust-profile-server" { capabilities = ["read"] }\n'
        'path "transit/sign/workload-tls-trust-profile-server" { capabilities = ["update"] }')
