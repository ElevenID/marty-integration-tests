"""Tests for the cross-project official-suite Compose lifecycle."""

from __future__ import annotations

import importlib.util
import subprocess
from hashlib import sha256
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("official_suite_compose", ROOT / "scripts" / "official_suite_compose.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load official suite Compose lifecycle")
lifecycle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lifecycle)
haip = importlib.import_module("haip_test_certificates")


def marty_checkout(tmp_path: Path) -> Path:
    checkout = tmp_path / "marty-ui"
    script = checkout / "scripts" / "conformance_stack.py"
    script.parent.mkdir(parents=True)
    script.write_text("# test fixture\n", encoding="utf-8")
    return checkout


def component(command: list[str]) -> str:
    rendered = " ".join(command)
    if "oidf_runner_compose.py" in rendered:
        return "oidf"
    if "eudi_reference_compose.py" in rendered:
        return "eudi"
    if "conformance_stack.py" in rendered:
        return "marty"
    raise AssertionError(f"unknown command: {rendered}")


def action(command: list[str]) -> str:
    for value in ("up", "down", "ps", "logs"):
        if value in command:
            return value
    raise AssertionError(f"no Compose action in {command}")


def haip_material(tmp_path: Path, name: str) -> Path:
    output = tmp_path / name
    haip.generate_material(output, gateway_url="https://verifier.example:8443")
    key = ec.generate_private_key(ec.SECP256R1())
    numbers = key.public_key().public_numbers()
    haip.issue_verifier_certificate(
        output,
        {
            "kty": "EC",
            "crv": "P-256",
            "x": haip._base64url(numbers.x.to_bytes(32, "big")),
            "y": haip._base64url(numbers.y.to_bytes(32, "big")),
        },
        gateway_url="https://verifier.example:8443",
    )
    return output


def test_projects_are_unique_and_scoped() -> None:
    assert lifecycle.project_names("123-1") == {
        "marty": "marty-conformance-123-1",
        "oidf": "oidf-runner-123-1",
        "eudi": "eudi-reference-123-1",
    }
    with pytest.raises(ValueError, match="run id"):
        lifecycle.project_names("production/stack")


def test_compose_project_environment_matches_derived_names() -> None:
    projects = lifecycle.project_names("123-1")
    environment = {
        "MARTY_CONFORMANCE_PROJECT": "wrong",
        "OIDF_CONFORMANCE_PROJECT": "wrong",
        "EUDI_CONFORMANCE_PROJECT": "wrong",
    }
    lifecycle.configure_project_environment(environment, projects)
    assert environment == {
        "MARTY_CONFORMANCE_PROJECT": "marty-conformance-123-1",
        "OIDF_CONFORMANCE_PROJECT": "oidf-runner-123-1",
        "EUDI_CONFORMANCE_PROJECT": "eudi-reference-123-1",
    }


def test_selected_context_is_forwarded_to_marty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []
    monkeypatch.setenv(lifecycle.CONTEXT_ENV, "conformance-vm")
    monkeypatch.setattr(
        lifecycle,
        "docker_command",
        lambda arguments: calls.append(arguments) or ["docker", "--context", "conformance-vm", *arguments],
    )
    environment = lifecycle.child_environment()
    assert calls == [["info"]]
    assert environment["DOCKER_CONTEXT"] == "conformance-vm"


def test_generated_eudi_material_is_rejected_for_a_remote_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(lifecycle.CONTEXT_ENV, "conformance-vm")
    monkeypatch.setattr(
        lifecycle,
        "merged_material_environment",
        lambda *_args: ("generated", {lifecycle.CONTEXT_ENV: "conformance-vm"}),
    )
    monkeypatch.setattr(lifecycle, "docker_endpoint_is_local", lambda *_args: False)

    with pytest.raises(ValueError, match="remote Docker context"):
        lifecycle.child_environment(eudi_material=tmp_path)


def test_external_eudi_material_can_use_a_validated_remote_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []
    monkeypatch.setenv(lifecycle.CONTEXT_ENV, "conformance-vm")
    monkeypatch.setattr(
        lifecycle,
        "merged_material_environment",
        lambda *_args: ("external", {lifecycle.CONTEXT_ENV: "conformance-vm"}),
    )
    monkeypatch.setattr(lifecycle, "docker_endpoint_is_local", lambda *_args: False)
    monkeypatch.setattr(lifecycle, "validate_environment_contract", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(
        lifecycle,
        "docker_command",
        lambda arguments: calls.append(arguments) or ["docker", "--context", "conformance-vm", *arguments],
    )

    environment = lifecycle.child_environment(eudi_material=tmp_path)
    assert calls == [["info"]]
    assert environment["DOCKER_CONTEXT"] == "conformance-vm"


def test_non_start_commands_do_not_require_live_material(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing = tmp_path / "deleted-material"
    monkeypatch.setattr(lifecycle, "docker_endpoint_is_local", lambda *_args: True)
    environment = lifecycle.child_environment(
        require_eudi=True,
        eudi_material=missing,
        validate_eudi=False,
    )

    assert environment["OIDF_TLS_CERT_DIR"] == str(missing.resolve())
    assert environment["EUDI_VERIFIER_KEYSTORE_PASSWORD"] == "unused-cleanup-value"


def test_remote_external_mode_requires_explicit_daemon_bind_roots(tmp_path: Path) -> None:
    ui = marty_checkout(tmp_path)
    oidf = tmp_path / "oidf-runner"
    args = lifecycle.parser().parse_args(
        [
            "up",
            "--run-id",
            "run1",
            "--marty-ui",
            str(ui),
            "--oidf-runner",
            str(oidf),
            "--oidf",
            "--eudi",
        ]
    )
    environment = {
        lifecycle.REMOTE_UI_ROOT: str(ui.resolve()),
        lifecycle.REMOTE_OIDF_ROOT: str(oidf.resolve()),
        lifecycle.REMOTE_EUDI_CONFIG_ROOT: "/srv/elevenid/eudi-config",
        "OIDF_TLS_CERT_DIR": "/srv/elevenid/certificates",
        "EUDI_VERIFIER_KEYSTORE_FILE": "/srv/elevenid/certificates/keystore.jks",
        lifecycle.OID4VP_TRUST_ANCHOR_FILE_ENV: "/srv/elevenid/certificates/oid4vp-roots.pem",
    }

    lifecycle.validate_remote_bind_contract(args, environment)
    environment.pop(lifecycle.REMOTE_EUDI_CONFIG_ROOT)
    with pytest.raises(ValueError, match=lifecycle.REMOTE_EUDI_CONFIG_ROOT):
        lifecycle.validate_remote_bind_contract(args, environment)


def test_eudi_readiness_failure_unwinds_all_started_projects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(lifecycle, "child_environment", lambda **_kwargs: {})
    monkeypatch.setattr(lifecycle, "docker_endpoint_is_local", lambda *_args: True)
    monkeypatch.setattr(
        lifecycle,
        "run",
        lambda command, _environment: calls.append((component(command), action(command))) or 0,
    )
    monkeypatch.setattr(
        lifecycle,
        "wait_for_eudi_readiness",
        lambda _environment: (_ for _ in ()).throw(ValueError("not ready")),
    )

    with pytest.raises(ValueError, match="not ready"):
        lifecycle.main(
            [
                "up",
                "--run-id",
                "run1",
                "--marty-ui",
                str(marty_checkout(tmp_path)),
                "--eudi",
            ]
        )

    assert calls == [("marty", "up"), ("eudi", "up"), ("eudi", "down"), ("marty", "down")]


def test_eudi_readiness_probes_every_public_path_with_generated_ca(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ca_file = tmp_path / "root-ca.pem"
    ca_file.write_text("fixture", encoding="ascii")
    requested: list[str] = []
    options: dict[str, object] = {}

    class Response:
        status_code = 200

    class Client:
        def __init__(self, **kwargs: object) -> None:
            options.update(kwargs)

        def __enter__(self) -> Client:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def get(self, url: str) -> Response:
            requested.append(url)
            return Response()

    monkeypatch.setattr(lifecycle.httpx, "Client", Client)
    lifecycle.wait_for_eudi_readiness(
        {
            "EUDI_READINESS_TIMEOUT_SECONDS": "5",
            "EUDI_TEST_CA_FILE": str(ca_file),
            "OIDF_PUBLIC_BASE_URL": "https://marty.test:8443",
            "EUDI_WALLET_TESTER_PUBLIC_URL": "https://wallet.test:25051",
            "EUDI_VERIFIER_PUBLIC_URL": "https://verifier.test:28091",
            "EUDI_WALLET_KIT_URL": "http://127.0.0.1:29090",
            "EUDI_WALLET_KIT_HOST_PORT": "29090",
        }
    )

    assert options["verify"] == str(ca_file)
    assert requested == [
        "https://marty.test:8443/.well-known/openid-configuration",
        "https://wallet.test:25051/",
        "https://verifier.test:28091/swagger-ui",
        "http://127.0.0.1:29090/health",
    ]


def test_eudi_material_requires_the_eudi_project(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="requires --eudi"):
        lifecycle.main(
            [
                "ps",
                "--run-id",
                "run1",
                "--marty-ui",
                str(marty_checkout(tmp_path)),
                "--w3c",
                "--eudi-material",
                str(tmp_path / "material"),
            ]
        )


def test_generated_haip_material_is_wired_to_marty(tmp_path: Path) -> None:
    material = haip_material(tmp_path, "generated")
    environment: dict[str, str] = {}
    lifecycle.configure_haip_environment(environment, material)
    assert environment["VERIFIER_X509_CERT_PEM"] == (material / haip.CERTIFICATE_FILE).read_text(encoding="ascii")
    assert environment[haip.OID4VP_TRUST_ANCHOR_FILE_ENV] == str((material / haip.TRUST_ANCHOR_FILE).resolve())


def test_haip_stage_certifies_only_the_live_issuer_profile_public_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    material = tmp_path / "prepared"
    haip.generate_material(material, gateway_url="https://verifier.example:8443")
    profile_key = ec.generate_private_key(ec.SECP256R1())
    numbers = profile_key.public_key().public_numbers()
    identity = {
        "issuer_profile_id": "ip-live",
        "public_jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": haip._base64url(numbers.x.to_bytes(32, "big")),
            "y": haip._base64url(numbers.y.to_bytes(32, "big")),
        },
    }
    monkeypatch.setattr(lifecycle, "resolve_issuer_profile_identity", lambda *_args: identity)
    args = type("Args", (), {"haip_material": material, "eudi": False})()
    environment = {"OIDF_PUBLIC_BASE_URL": "https://verifier.example:8443"}

    lifecycle.stage_haip_profile_certificate(args, {}, environment)

    assert "VERIFIER_X509_CERT_PEM" in environment
    certificate = haip.PEM_CERTIFICATE.findall(environment["VERIFIER_X509_CERT_PEM"].encode("ascii"))[0]
    leaf = haip.x509.load_pem_x509_certificate(certificate)
    assert leaf.public_key().public_numbers() == profile_key.public_key().public_numbers()
    assert not (material / haip.AUTHORITY_KEY_FILE).exists()


def test_generated_haip_material_replaces_the_unrelated_tls_root(tmp_path: Path) -> None:
    material = haip_material(tmp_path, "generated-separate-root")
    tls_root = tmp_path / "tls-root.pem"
    tls_root.write_text("not the request-object root", encoding="ascii")
    environment = {haip.OID4VP_TRUST_ANCHOR_FILE_ENV: str(tls_root)}

    lifecycle.configure_haip_environment(
        environment,
        material,
        require_request_object_trust=True,
    )

    assert environment[haip.OID4VP_TRUST_ANCHOR_FILE_ENV] == str((material / haip.TRUST_ANCHOR_FILE).resolve())


def test_child_environment_keeps_haip_root_separate_after_eudi_merge(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    material = haip_material(tmp_path, "generated-child-environment")
    tls_root = tmp_path / "eudi-tls-root.pem"
    tls_root.write_text("independent EUDI TLS root", encoding="ascii")
    monkeypatch.setattr(
        lifecycle,
        "merged_material_environment",
        lambda *_args: (
            "generated",
            {
                "EUDI_TEST_MATERIAL_MODE": "generated",
                "SSL_CERT_FILE": str(tls_root),
                haip.OID4VP_TRUST_ANCHOR_FILE_ENV: str(tls_root),
            },
        ),
    )
    monkeypatch.setattr(lifecycle, "docker_endpoint_is_local", lambda *_args: True)
    monkeypatch.setattr(lifecycle, "validate_environment", lambda *_args: None)

    environment = lifecycle.child_environment(
        require_haip=True,
        require_eudi=True,
        haip_material=material,
        eudi_material=tmp_path / "eudi-material",
    )

    haip_root = Path(environment[haip.OID4VP_TRUST_ANCHOR_FILE_ENV])
    tls_ca = Path(environment["SSL_CERT_FILE"])
    assert haip_root == (material / haip.TRUST_ANCHOR_FILE).resolve()
    assert tls_ca == tls_root
    assert sha256(haip_root.read_bytes()).digest() != sha256(tls_ca.read_bytes()).digest()


def test_external_haip_certificate_takes_precedence(tmp_path: Path) -> None:
    generated = haip_material(tmp_path, "generated")
    external = haip_material(tmp_path, "external")
    certificate = (external / haip.CERTIFICATE_FILE).read_text(encoding="ascii")
    environment = {"VERIFIER_X509_CERT_PEM": certificate}
    lifecycle.configure_haip_environment(environment, generated)
    assert environment == {"VERIFIER_X509_CERT_PEM": certificate}


def test_external_haip_eudi_run_requires_and_validates_separate_trust_anchor(tmp_path: Path) -> None:
    external = haip_material(tmp_path, "external-eudi")
    environment = {"VERIFIER_X509_CERT_PEM": (external / haip.CERTIFICATE_FILE).read_text(encoding="ascii")}
    with pytest.raises(ValueError, match=haip.OID4VP_TRUST_ANCHOR_FILE_ENV):
        lifecycle.configure_haip_environment(environment, None, require_request_object_trust=True)

    environment[haip.OID4VP_TRUST_ANCHOR_FILE_ENV] = str(external / haip.TRUST_ANCHOR_FILE)
    lifecycle.configure_haip_environment(environment, None, require_request_object_trust=True)
    assert environment[haip.OID4VP_TRUST_ANCHOR_FILE_ENV] == str((external / haip.TRUST_ANCHOR_FILE).resolve())


def test_external_haip_eudi_run_rejects_untrusted_root(tmp_path: Path) -> None:
    external = haip_material(tmp_path, "external")
    unrelated = haip_material(tmp_path, "unrelated")
    environment = {
        "VERIFIER_X509_CERT_PEM": (external / haip.CERTIFICATE_FILE).read_text(encoding="ascii"),
        haip.OID4VP_TRUST_ANCHOR_FILE_ENV: str(unrelated / haip.TRUST_ANCHOR_FILE),
    }
    with pytest.raises(ValueError, match="must end at"):
        lifecycle.configure_haip_environment(environment, None, require_request_object_trust=True)


def test_external_haip_eudi_run_accepts_multiple_approved_roots(tmp_path: Path) -> None:
    external = haip_material(tmp_path, "external-multiple")
    unrelated = haip_material(tmp_path, "unrelated-multiple")
    approved_roots = tmp_path / "approved-roots.pem"
    approved_roots.write_text(
        (unrelated / haip.TRUST_ANCHOR_FILE).read_text(encoding="ascii")
        + (external / haip.TRUST_ANCHOR_FILE).read_text(encoding="ascii"),
        encoding="ascii",
    )
    environment = {
        "VERIFIER_X509_CERT_PEM": (external / haip.CERTIFICATE_FILE).read_text(encoding="ascii"),
        haip.OID4VP_TRUST_ANCHOR_FILE_ENV: str(approved_roots),
    }
    lifecycle.configure_haip_environment(environment, None, require_request_object_trust=True)
    assert environment[haip.OID4VP_TRUST_ANCHOR_FILE_ENV] == str(approved_roots.resolve())


def test_haip_rejects_legacy_direct_signing_key_input(tmp_path: Path) -> None:
    material = haip_material(tmp_path, "generated")
    environment = {
        "VERIFIER_" + "SIGNING_KEY_PEM": "legacy-private-material",
    }
    with pytest.raises(ValueError, match="unsupported"):
        lifecycle.configure_haip_environment(environment, material)


def test_eudi_can_enable_haip_without_joining_the_oidf_runner_project(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []
    child_options: dict[str, object] = {}
    monkeypatch.setattr(
        lifecycle,
        "child_environment",
        lambda **kwargs: child_options.update(kwargs) or {},
    )
    monkeypatch.setattr(lifecycle, "docker_endpoint_is_local", lambda *_args: True)
    monkeypatch.setattr(lifecycle, "run", lambda command, _environment: calls.append(command) or 0)
    monkeypatch.setattr(lifecycle, "wait_for_eudi_readiness", lambda _environment: None)
    monkeypatch.setattr(
        lifecycle,
        "stage_haip_profile_certificate",
        lambda _args, _projects, environment: environment.update({"VERIFIER_X509_CERT_PEM": "test-public-certificate"}),
    )

    result = lifecycle.main(
        [
            "up",
            "--run-id",
            "run1",
            "--marty-ui",
            str(marty_checkout(tmp_path)),
            "--eudi",
            "--haip",
            "--haip-material",
            str(tmp_path / "haip-material"),
        ]
    )

    assert result == 0
    assert [component(command) for command in calls] == ["marty", "marty", "eudi"]
    assert "--haip" not in calls[0]
    assert "--haip" in calls[1]
    assert "--resume" in calls[1]
    assert child_options["require_haip"] is False
    assert child_options["require_eudi"] is True


def test_failed_up_unwinds_only_started_projects_in_reverse(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(lifecycle, "child_environment", dict)
    monkeypatch.setattr(lifecycle, "docker_endpoint_is_local", lambda *_args: True)

    def fake_run(command: list[str], _environment: dict[str, str]) -> int:
        call = (component(command), action(command))
        calls.append(call)
        return 17 if call == ("oidf", "up") else 0

    monkeypatch.setattr(lifecycle, "run", fake_run)
    result = lifecycle.main(
        [
            "up",
            "--run-id",
            "run1",
            "--marty-ui",
            str(marty_checkout(tmp_path)),
            "--oidf-runner",
            str(tmp_path / "oidf"),
            "--oidf",
            "--eudi",
        ]
    )
    assert result == 17
    assert calls == [
        ("marty", "up"),
        ("oidf", "up"),
        ("oidf", "down"),
        ("marty", "down"),
    ]


def test_eudi_failure_is_classified_before_teardown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[tuple[str, str]] = []
    diagnostic_calls: list[str] = []
    monkeypatch.setattr(lifecycle, "child_environment", dict)
    monkeypatch.setattr(lifecycle, "docker_endpoint_is_local", lambda *_args: True)

    def fake_run(command: list[str], _environment: dict[str, str]) -> int:
        call = (component(command), action(command))
        calls.append(call)
        return 17 if call == ("eudi", "up") else 0

    def fake_subprocess_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        rendered = " ".join(command)
        diagnostic_calls.append(rendered)
        if " ps " in f" {rendered} ":
            return subprocess.CompletedProcess(command, 0, "verifier-id\n", "")
        if " inspect " in f" {rendered} ":
            return subprocess.CompletedProcess(command, 0, '{"ExitCode":1,"OOMKilled":false}\n', "")
        if " logs " in f" {rendered} ":
            return subprocess.CompletedProcess(
                command,
                0,
                (
                    "APPLICATION FAILED TO START: password was incorrect\n"
                    "Caused by: java.security.UnrecoverableKeyException: password was incorrect"
                ),
                "",
            )
        raise AssertionError(f"unexpected diagnostic command: {rendered}")

    monkeypatch.setattr(lifecycle, "run", fake_run)
    monkeypatch.setattr(lifecycle.subprocess, "run", fake_subprocess_run)
    result = lifecycle.main(
        [
            "up",
            "--run-id",
            "run1",
            "--marty-ui",
            str(marty_checkout(tmp_path)),
            "--eudi",
        ]
    )

    assert result == 17
    assert calls == [("marty", "up"), ("eudi", "up"), ("eudi", "down"), ("marty", "down")]
    assert [
        marker for marker in (" ps ", " inspect ", " logs ") if any(marker in f" {call} " for call in diagnostic_calls)
    ] == [" ps ", " inspect ", " logs "]
    stderr = capsys.readouterr().err
    assert "exit-code=1" in stderr
    assert "oom-killed=false" in stderr
    assert (
        "categories=access-certificate-password,application-startup,root-exception-unrecoverablekeyexception" in stderr
    )
    assert "password was incorrect" not in stderr


def test_eudi_diagnostic_does_not_treat_exit_on_oom_option_as_an_oom(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fake_subprocess_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        rendered = " ".join(command)
        if " ps " in f" {rendered} ":
            return subprocess.CompletedProcess(command, 0, "verifier-id\n", "")
        if " inspect " in f" {rendered} ":
            return subprocess.CompletedProcess(command, 0, '{"ExitCode":1,"OOMKilled":false}\n', "")
        if " logs " in f" {rendered} ":
            return subprocess.CompletedProcess(
                command,
                0,
                (
                    "Picked up JAVA_TOOL_OPTIONS: -XX:+ExitOnOutOfMemoryError\n"
                    "Application run failed\n"
                    "Caused by: java.lang.IllegalArgumentException: redacted configuration detail"
                ),
                "",
            )
        raise AssertionError(f"unexpected diagnostic command: {rendered}")

    monkeypatch.setattr(lifecycle.subprocess, "run", fake_subprocess_run)
    lifecycle.emit_eudi_startup_diagnostic("eudi-project", {})

    stderr = capsys.readouterr().err
    assert "application-startup" in stderr
    assert "root-exception-illegalargumentexception" in stderr
    assert "jvm-memory" not in stderr
    assert "redacted configuration detail" not in stderr


def test_down_always_runs_eudi_oidf_then_marty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(lifecycle, "child_environment", dict)
    monkeypatch.setattr(lifecycle, "docker_endpoint_is_local", lambda *_args: True)
    monkeypatch.setattr(
        lifecycle,
        "run",
        lambda command, _environment: calls.append((component(command), action(command))) or 0,
    )
    assert (
        lifecycle.main(
            [
                "down",
                "--run-id",
                "run1",
                "--marty-ui",
                str(marty_checkout(tmp_path)),
                "--oidf-runner",
                str(tmp_path / "oidf"),
                "--oidf",
                "--eudi",
            ]
        )
        == 0
    )
    assert calls == [
        ("eudi", "down"),
        ("oidf", "down"),
        ("marty", "down"),
    ]
