import base64
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

SOURCE = Path(__file__).parents[2] / "scripts" / "official_kms_bootstrap.py"
SPEC = importlib.util.spec_from_file_location("official_kms_bootstrap", SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


@pytest.mark.parametrize("key", ["DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "COMPOSE_FILE",
                                "COMPOSE_PROJECT_NAME", "GH_TOKEN", "GITHUB_TOKEN", "PATH", "LD_PRELOAD"])
def test_runtime_data_cannot_redirect_controller_authority(key: str) -> None:
    with pytest.raises(MODULE.SafeBootstrapError, match="controller authority"):
        MODULE.reject_controller_overrides({key: "synthetic-untrusted-input"})


def test_project_admission_never_adopts_existing_resources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    args = SimpleNamespace(run_id="owned-run", stack_manifest=manifest)
    calls = []

    def existing(command: list[str], **_kwargs: object) -> SimpleNamespace:
        calls.append(command)
        return SimpleNamespace(stdout=json.dumps("engine-owned-run") if command[1] == "info"
                               else "existing-owned-by-another-controller\n")

    monkeypatch.setattr(MODULE.subprocess, "run", existing)
    with pytest.raises(MODULE.SafeBootstrapError, match="refusing adoption"):
        MODULE.admit_owned_projects(args, tmp_path)
    assert not (tmp_path / "owned-project.json").exists()
    assert len(calls) == 2
    assert all("up" not in command and "down" not in command for command in calls)


@pytest.mark.parametrize("engine", ["engine-owned-run", "engine-other-controller"])
def test_cleanup_attempts_both_projects_and_census_when_runtime_input_is_corrupt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    engine: str,
) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    material = tmp_path / "material"
    material.mkdir()
    (private / ".env.kms").write_text("synthetic-sensitive-corrupt-input", encoding="utf-8")
    projects = ["marty-conformance-owned-run", "marty-conformance-owned-run-trust-registry"]
    ownership = private / "owned-project.json"
    ownership.write_text(json.dumps({
        "schema": "elevenid.disposable-project-ownership/v1", "run_id": "owned-run",
        "projects": projects, "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
        "engine_id": "engine-owned-run", "cleanup_environment": {},
    }), encoding="utf-8")
    ownership.chmod(0o600)
    args = SimpleNamespace(output_dir=private, run_id="owned-run", stack_manifest=manifest,
                           marty_ui=tmp_path, material=material)
    monkeypatch.setattr(MODULE, "checked_release", lambda _args: ({}, ["docker", "compose"], {}))
    monkeypatch.setattr(MODULE, "compose_sources", lambda _compose: set())
    calls = []

    def run(command: list[str], **_kwargs: object) -> SimpleNamespace:
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout=json.dumps(engine) if command[1] == "info" else "")

    monkeypatch.setattr(MODULE.subprocess, "run", run)
    if engine != "engine-owned-run":
        with pytest.raises(MODULE.SafeBootstrapError, match="Engine differs"):
            MODULE.cleanup_owned_projects(args)
        assert len(calls) == 1
        assert "down" not in calls[0]
        return
    assert MODULE.cleanup_owned_projects(args) == 0
    assert sum("down" in command for command in calls) == 2
    assert sum("--filter" in command for command in calls) == 6
    output = capsys.readouterr().out
    assert "synthetic-sensitive" not in output
    assert json.loads(output)["retired"] is True


@pytest.mark.parametrize("stage", ["workload-tls", "keycloak-kms", "extra-workloads", "official-edge", "runtime-files"])
def test_failed_stage_reports_only_a_closed_label_and_preserves_the_error(
    capsys: pytest.CaptureFixture[str], stage: str,
) -> None:
    error = RuntimeError("do-not-log-authority")
    with pytest.raises(RuntimeError) as failure, MODULE.bootstrap_stage(stage):
        raise error
    assert failure.value is error
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == f"Official KMS bootstrap stage failed: {stage}\n"


def test_successful_stage_is_quiet_and_unknown_stage_never_runs(capsys: pytest.CaptureFixture[str]) -> None:
    with MODULE.bootstrap_stage("openbao-initialization"):
        pass
    assert capsys.readouterr().err == ""
    with pytest.raises(MODULE.SafeBootstrapError) as failure, MODULE.bootstrap_stage("do-not-log-authority"):
        pytest.fail("Unsupported stage body was entered")
    assert MODULE.safe_failure_reason(failure.value) == "unsupported bootstrap stage"
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize(
    "error",
    [
        RuntimeError("do-not-log-authority"),
        ValueError("do-not-log-authority"),
        OSError("do-not-log-authority"),
        subprocess.CalledProcessError(1, ["do-not-log-authority"]),
        MODULE.HTTPError("https://do-not-log-authority", 403, "private response", {}, None),
    ],
)
def test_unclassified_failures_never_disclose_their_message_or_command(error: BaseException) -> None:
    error.code = "do-not-log-authority"
    assert MODULE.safe_failure_reason(error) == type(error).__name__


def test_unknown_container_service_is_not_forwarded_to_docker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    def unexpected_command(*_args: object, **_kwargs: object) -> None:
        pytest.fail("Unsupported service reached Docker")

    monkeypatch.setattr(MODULE, "run", unexpected_command)
    with pytest.raises(MODULE.SafeBootstrapError) as failure:
        MODULE.container_id(["docker", "compose"], "do-not-log-authority", {}, tmp_path)
    assert MODULE.safe_failure_reason(failure.value) == "unsupported bootstrap service"


def test_missing_initializer_container_still_uses_the_existing_readiness_wait(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    queries = []
    sleeps = []

    def command(args: list[str], **_kwargs: object) -> SimpleNamespace:
        queries.append(args)
        if args[0:2] == ["docker", "inspect"]:
            return SimpleNamespace(stdout="exited 0 false")
        if args[-1] == "openbao":
            return SimpleNamespace(stdout="b" * 64)
        return SimpleNamespace(stdout="" if len(queries) == 1 else "a" * 64)

    monkeypatch.setattr(MODULE, "run", command)
    monkeypatch.setattr(MODULE.time, "sleep", sleeps.append)
    assert MODULE.wait_openbao_init(["docker", "compose"], {}, tmp_path) == "b" * 64
    assert sleeps == [1]
    assert sum(args[-1] == "openbao-init" for args in queries) == 2


@pytest.mark.parametrize("content", [b"", b"x" * (64 * 1024 + 1)], ids=["empty", "oversized"])
def test_invalid_custody_copy_keeps_its_safe_reason_and_stages_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, content: bytes,
) -> None:
    monkeypatch.setattr(MODULE.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(stdout=content))
    target = tmp_path / "do-not-log-authority"
    with pytest.raises(MODULE.SafeRuntimeBootstrapError) as failure:
        MODULE.copy_private_from_container("a" * 64, "/bao/data/root.token", target)
    assert isinstance(failure.value, RuntimeError)
    assert MODULE.safe_failure_reason(failure.value) == "released OpenBao bootstrap input is invalid"
    assert not target.exists()


@pytest.mark.parametrize("fault", ["type", "exportable", "backup", "version", "public-key"])
def test_key_metadata_refusal_is_safe_even_with_an_untrusted_purpose(fault: str) -> None:
    metadata = {
        "type": "ecdsa-p256", "exportable": False, "allow_plaintext_backup": False,
        "latest_version": 1, "keys": {"1": {"public_key": "public-pem"}},
    }
    replacements = {"type": "rsa-2048", "exportable": True, "backup": True, "version": 2, "public-key": {}}
    fields = {"type": "type", "exportable": "exportable", "backup": "allow_plaintext_backup",
              "version": "latest_version", "public-key": "keys"}
    metadata[fields[fault]] = replacements[fault]

    class Bao:
        def request(self, method: str, _path: str, _body: object = None) -> dict:
            return {"data": metadata} if method == "GET" else {}

    with pytest.raises(MODULE.SafeRuntimeBootstrapError) as failure:
        MODULE.provision_nonexportable_transit_key(Bao(), "one-key", "do-not-log-authority")
    expected = "has no public binding" if fault == "public-key" else "is not non-exportable version one"
    assert MODULE.safe_failure_reason(failure.value) == f"disposable Transit key {expected}"


def test_cli_refusal_prints_only_a_safe_reason_and_creates_no_output(tmp_path: Path) -> None:
    output = tmp_path / "do-not-log-authority"
    result = subprocess.run([
        sys.executable, "-B", str(SOURCE), "--run-id", "not/allowed",
        "--marty-ui", str(output), "--stack-manifest", str(output),
        "--stack-env", str(output), "--material", str(output), "--output-dir", str(output),
    ], capture_output=True, text=True, check=False, timeout=15)
    assert result.returncode == 2
    reason = "official disposable KMS bootstrap requires a Linux Docker host" if os.name != "posix" else "ValueError"
    assert result.stderr.strip() == f"Official KMS bootstrap failed: {reason}"
    assert not output.exists()


@pytest.mark.parametrize(
    ("state", "reason"),
    [
        ("exited 1 false", "released OpenBao initializer failed with exit code 1"),
        ("exited 137 true", "released OpenBao initializer was OOM-killed"),
        ("dead 255 false", "released OpenBao initializer failed with exit code 255"),
        ("exited 0 true", "released OpenBao initializer was OOM-killed"),
        ("exited secret-value false", "released OpenBao initializer state is invalid"),
    ],
)
def test_initializer_failure_has_a_safe_reason_without_retrying_or_exposing_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, state: str, reason: str,
) -> None:
    commands = []
    monkeypatch.setattr(MODULE, "container_id", lambda *_args: "a" * 64)

    def inspect(command: list[str], **_kwargs: object) -> SimpleNamespace:
        commands.append(command)
        return SimpleNamespace(stdout=state)

    monkeypatch.setattr(MODULE, "run", inspect)
    with pytest.raises(MODULE.SafeBootstrapError) as failure:
        MODULE.wait_openbao_init(["docker", "compose"], {}, tmp_path)
    assert failure.value.code == reason
    assert "secret-value" not in str(failure.value)
    assert len(commands) == 1
    assert commands[0] == [
        "docker", "inspect", "--format",
        "{{.State.Status}} {{.State.ExitCode}} {{.State.OOMKilled}}", "a" * 64,
    ]


def test_initializer_wait_accepts_only_a_clean_exit(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    states = iter(["running 0 false", "exited 0 false"])
    monkeypatch.setattr(MODULE, "container_id", lambda _compose, service, _env, _ui: service)
    monkeypatch.setattr(MODULE, "run", lambda *_args, **_kwargs: SimpleNamespace(stdout=next(states)))
    monkeypatch.setattr(MODULE.time, "sleep", lambda _seconds: None)
    assert MODULE.wait_openbao_init(["docker", "compose"], {}, tmp_path) == "openbao"


def test_initializer_timeout_retains_a_safe_distinct_reason(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    clock = iter([0, 0, 91])
    monkeypatch.setattr(MODULE.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(MODULE.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(MODULE, "container_id", lambda *_args: "a" * 64)
    monkeypatch.setattr(MODULE, "run", lambda *_args, **_kwargs: SimpleNamespace(stdout="running 0 false"))
    with pytest.raises(MODULE.SafeBootstrapError) as failure:
        MODULE.wait_openbao_init(["docker", "compose"], {}, tmp_path)
    assert failure.value.code == "released OpenBao initializer did not complete within 90 seconds"


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


@pytest.mark.skipif(sys.platform != "linux", reason="Linux public certificate bind mounts")
@pytest.mark.parametrize("fault", [None, "private-key", "symlink", "hardlink", "public-parent", "writable",
                                   "short-read", "changed"])
def test_public_ca_mount_preserves_keys_and_refuses_other_material(
    tmp_path: Path, fault: str | None, monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path.chmod(0o700)
    key = MODULE.ec.generate_private_key(MODULE.ec.SECP256R1())
    name = MODULE.x509.Name([MODULE.x509.NameAttribute(MODULE.NameOID.COMMON_NAME, "owned fixture CA")])
    now = MODULE.datetime.now(MODULE.UTC)
    certificate = (MODULE.x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(MODULE.x509.random_serial_number())
                   .not_valid_before(now - MODULE.timedelta(minutes=1))
                   .not_valid_after(now + MODULE.timedelta(days=1))
                   .add_extension(MODULE.x509.BasicConstraints(ca=True, path_length=None), critical=True)
                   .sign(key, MODULE.hashes.SHA256()))
    pem = certificate.public_bytes(MODULE.serialization.Encoding.PEM)
    private = key.private_bytes(MODULE.serialization.Encoding.PEM, MODULE.serialization.PrivateFormat.PKCS8,
                                MODULE.serialization.NoEncryption())
    authority = tmp_path / "official-ca.key"
    MODULE.private_file(authority, private.decode("ascii"))
    path = tmp_path / "root-ca.pem"
    MODULE.private_file(path, pem.decode("ascii"))
    if fault == "private-key":
        path.write_bytes(pem + private)
    elif fault == "symlink":
        path.unlink()
        path.symlink_to(authority)
    elif fault == "hardlink":
        os.link(path, tmp_path / "other")
    elif fault == "public-parent":
        tmp_path.chmod(0o755)
    elif fault == "writable":
        path.chmod(0o666)
    elif fault == "short-read":
        path.write_bytes(pem + private)
        read = os.read
        monkeypatch.setattr(MODULE.os, "read", lambda descriptor, _size: read(descriptor, len(pem)))
    elif fault == "changed":
        read = os.read

        def change_after_read(descriptor: int, size: int) -> bytes:
            content = read(descriptor, size)
            metadata = path.stat()
            os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1))
            return content

        monkeypatch.setattr(MODULE.os, "read", change_after_read)
    if fault:
        before = path.read_bytes()
        mode = path.stat().st_mode
        with pytest.raises((ValueError, OSError)):
            MODULE.prepare_public_ca_mount(tmp_path)
        assert path.read_bytes() == before
        assert path.stat().st_mode == mode
    else:
        MODULE.prepare_public_ca_mount(tmp_path)
        MODULE.prepare_public_ca_mount(tmp_path)
        assert path.read_bytes() == pem
        assert stat.S_IMODE(path.stat().st_mode) == 0o444
    assert authority.read_bytes() == private
    assert stat.S_IMODE(authority.stat().st_mode) == 0o600


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


def test_registration_environment_requires_exact_public_bundle_and_pin_pair(tmp_path: Path) -> None:
    values, origin = runtime_inputs(tmp_path)
    path = tmp_path / "eudi-registration.json"
    path.write_text("{}",encoding="ascii")
    fields = {"EUDI_VERIFIER_REGISTRATION_RECORD_FILE":str(path),
              "EUDI_VERIFIER_REGISTRATION_RECORD_SHA256":"a" * 64}
    MODULE.validate_runtime_environment({**values,**fields},tmp_path,origin)
    for name in fields:
        with pytest.raises(ValueError,match="both bootstrap provenance"):
            MODULE.validate_runtime_environment({**values,name:fields[name]},tmp_path,origin)
    for name,value in [("EUDI_VERIFIER_REGISTRATION_RECORD_FILE",str(tmp_path/"other.json")),
                       ("EUDI_VERIFIER_REGISTRATION_RECORD_SHA256","invalid")]:
        with pytest.raises(ValueError,match="provenance is invalid"):
            MODULE.validate_runtime_environment({**values,**fields,name:value},tmp_path,origin)
