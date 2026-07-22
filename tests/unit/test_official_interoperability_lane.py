from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "official_interoperability_lane", ROOT / "scripts" / "official_interoperability_lane.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load official interoperability lane")
lane = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lane)
eudi_material = importlib.import_module("eudi_test_material")


def stack_binding_fixture(tmp_path: Path) -> tuple[Path, dict[str, object], dict[str, str]]:
    references = {
        "MARTY_UI_IMAGE": "ghcr.io/elevenid/marty-ui-oss/ui@sha256:" + "1" * 64,
        "MARTY_SERVICES_IMAGE": "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "2" * 64,
        "MARTY_MIGRATIONS_IMAGE": "ghcr.io/elevenid/marty-ui-oss/migrations@sha256:" + "3" * 64,
        "MARTY_ISSUANCE_IMAGE": "ghcr.io/elevenid/marty-credentials-issuance@sha256:" + "4" * 64,
    }
    manifest = tmp_path / "stack-manifest.json"
    artifacts = []
    for reference in references.values():
        uri, digest = reference.split("@", 1)
        artifacts.append({"type": "oci", "uri": uri, "digest": digest})
    manifest.write_text(
        json.dumps(
            {
                "schema": "marty.stack/v1",
                "release": "marty-ui@1.2.3",
                "components": [
                    {"name": "images", "artifacts": artifacts},
                    {
                        "name": "marty-core-python",
                        "artifacts": [
                            {
                                "type": "python",
                                "uri": "https://github.com/ElevenID/marty-core/releases/download/v0.1.0/marty_rs.whl",
                                "digest": "sha256:" + "5" * 64,
                            }
                        ],
                    },
                    {
                        "name": "marty-common",
                        "artifacts": [
                            {
                                "type": "python",
                                "uri": "https://github.com/ElevenID/Marty/releases/download/v0.1.0/marty_common.whl",
                                "digest": "sha256:" + "6" * 64,
                            }
                        ],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    metadata: dict[str, object] = {
        "schema": "elevenid.official-stack-material/v1",
        "manifest_path": str(manifest.resolve()),
        "manifest_sha256": lane.file_sha256(manifest),
        "marty_commit": "a" * 40,
        "images": [{"reference": reference} for reference in references.values()],
    }
    base_images = json.loads((ROOT / "config" / "base-images.json").read_text(encoding="utf-8"))
    environment = {
        **references,
        "MARTY_RS_URI": "https://github.com/ElevenID/marty-core/releases/download/v0.1.0/marty_rs.whl",
        "MARTY_RS_DIGEST": "sha256:" + "5" * 64,
        "MARTY_COMMON_URI": "https://github.com/ElevenID/Marty/releases/download/v0.1.0/marty_common.whl",
        "MARTY_COMMON_DIGEST": "sha256:" + "6" * 64,
        "POSTGRES_IMAGE": base_images["postgres"],
        "REDIS_IMAGE": base_images["redis"],
    }
    return manifest, metadata, environment


def test_stack_environment_accepts_only_complete_digest_pins(tmp_path: Path) -> None:
    path = tmp_path / ".env.stack"
    path.write_text(
        "\n".join(
            (
                f"{name}=https://github.com/ElevenID/example/releases/download/v0.1.0/{name.lower()}.whl"
                if name.endswith("_URI")
                else f"{name}=sha256:{index:064x}"
                if name.endswith("_DIGEST")
                else f"{name}=ghcr.io/elevenid/{name.lower()}@sha256:{index:064x}"
            )
            for index, name in enumerate(sorted(lane.STACK_ENV_KEYS), 1)
        ),
        encoding="utf-8",
    )
    assert set(lane.load_stack_environment(path)) == lane.STACK_ENV_KEYS
    path.write_text("MARTY_UI_IMAGE=ghcr.io/elevenid/ui:latest\n", encoding="utf-8")
    with pytest.raises(ValueError, match="sha256"):
        lane.load_stack_environment(path)


def test_keycloak_initializer_diagnostic_redacts_secret_values() -> None:
    value = "password=private-value token: abc123 Authorization is bearer-value session_id=opaque-cookie"
    redacted = lane.redact_initializer_log(value)
    assert "private-value" not in redacted
    assert "abc123" not in redacted
    assert "bearer-value" not in redacted
    assert "opaque-cookie" not in redacted
    assert redacted.count("<redacted>") == 4


def test_keycloak_startup_diagnostic_includes_service_logs_and_redacts(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class Result:
        def __init__(self, stdout: str = "", stderr: str = "") -> None:
            self.stdout = stdout
            self.stderr = stderr

    calls: list[list[str]] = []

    def docker(command: list[str], **_kwargs: object) -> Result:
        calls.append(command)
        if command[1] == "ps":
            return Result("container-id\n" if command[-1].endswith("=keycloak") else "")
        return Result("Keycloak started with password=private-value\n")

    monkeypatch.setattr(lane.subprocess, "run", docker)

    lane.emit_keycloak_initializer_diagnostic("w3c-v2-1")

    output = capsys.readouterr().out
    assert "--- keycloak diagnostic (redacted) ---" in output
    assert "No keycloak-configurator container was created." in output
    assert "private-value" not in output
    assert "password=<redacted>" in output
    assert any(command[-1].endswith("=keycloak") for command in calls if command[1] == "ps")


def test_w3c_issuance_diagnostic_prints_only_redacted_error_lines(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class Result:
        def __init__(self, stdout: str = "", stderr: str = "") -> None:
            self.stdout = stdout
            self.stderr = stderr

    calls: list[list[str]] = []

    def docker(command: list[str], **_kwargs: object) -> Result:
        calls.append(command)
        if command[1] == "ps":
            return Result("issuance-container\n" if command[-1].endswith("=issuance") else "")
        return Result(
            "routine startup complete\n"
            "credential creation failed: session_id=opaque-cookie reason=remote signer unavailable\n"
        )

    monkeypatch.setattr(lane.subprocess, "run", docker)

    lane.emit_w3c_issuance_diagnostic("w3c-v2-1")

    output = capsys.readouterr().out
    assert "issuance W3C issuance diagnostic" in output
    assert "credential creation failed" in output
    assert "opaque-cookie" not in output
    assert "session_id=<redacted>" in output
    assert "routine startup complete" not in output
    assert any(command[-1].endswith("=presentation-policy") for command in calls if command[1] == "ps")


def test_w3c_lane_emits_issuance_diagnostic_when_the_official_suite_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    args = SimpleNamespace(
        marty_ui=tmp_path,
        run_id="w3c-v2-1",
        w3c_suite=tmp_path / "w3c-suite",
        stack_manifest=tmp_path / "stack-manifest.json",
        output_dir=tmp_path / "evidence",
    )
    exit_codes = iter((0, 0, 1, 0))
    diagnostics: list[str] = []

    monkeypatch.setattr(lane, "run", lambda *_args, **_kwargs: next(exit_codes))
    monkeypatch.setattr(lane, "wait_for_public_stack", lambda _environment: None)
    monkeypatch.setattr(
        lane,
        "bootstrap_fixtures",
        lambda *_args, **_kwargs: {
            "organization_id": "organization",
            "w3c_template_id": "template",
            "w3c_credential_policy_id": "credential-policy",
            "w3c_presentation_policy_id": "presentation-policy",
        },
    )
    monkeypatch.setattr(lane, "emit_w3c_issuance_diagnostic", diagnostics.append)

    assert lane.run_w3c(args, {"OIDF_MARTY_GATEWAY_URL": "https://marty-oidf.test"}) == 1
    assert diagnostics == ["w3c-v2-1"]


def test_material_environment_uses_private_generator_envelope(tmp_path: Path) -> None:
    for filename in ("tls.crt", "tls.key", "root-ca.pem", "truststore.jks", "keystore.jks"):
        (tmp_path / filename).write_text("fixture", encoding="utf-8")
    (tmp_path / "environment.json").write_text(
        json.dumps(
            {
                "schema": "elevenid.eudi-test-material/v1",
                "mode": "generated",
                "environment": {
                    "OIDF_PUBLIC_BASE_URL": "https://marty-oidf.test:18443",
                    "EUDI_VERIFIER_KEYSTORE_PASSWORD": "private-value",
                },
            }
        ),
        encoding="utf-8",
    )
    environment = lane.load_material_environment(tmp_path)
    assert environment["OIDF_TLS_CERT_DIR"] == str(tmp_path.resolve())
    assert environment["EUDI_VERIFIER_KEYSTORE_FILE"].endswith("keystore.jks")
    data = json.loads((tmp_path / "environment.json").read_text(encoding="utf-8"))
    data["environment"]["UNREVIEWED_SECRET"] = "no"
    (tmp_path / "environment.json").write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported keys"):
        lane.load_material_environment(tmp_path)


def test_material_environment_accepts_the_complete_generated_contract(tmp_path: Path) -> None:
    for filename in ("tls.crt", "tls.key", "root-ca.pem", "truststore.jks", "keystore.jks"):
        (tmp_path / filename).write_text("fixture", encoding="utf-8")
    environment = eudi_material._environment(
        tmp_path,
        hostname="marty-oidf.test",
        marty_port=18443,
        wallet_tester_port=25051,
        verifier_port=28091,
        wallet_kit_port=29090,
        store_password="store-password",
        key_password="key-password",
        truststore_password="trust-password",
        alias="eudi-verifier",
    )
    (tmp_path / "environment.json").write_text(
        json.dumps(
            {
                "schema": "elevenid.eudi-test-material/v1",
                "mode": "generated",
                "environment": environment,
            }
        ),
        encoding="utf-8",
    )

    loaded = lane.load_material_environment(tmp_path)

    assert set(environment) <= set(loaded)
    assert loaded[lane.OID4VP_TRUST_ANCHOR_FILE_ENV] == str((tmp_path / "root-ca.pem").resolve())


def test_stack_metadata_must_be_a_json_object(tmp_path: Path) -> None:
    path = tmp_path / "stack-metadata.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        lane.load_stack_metadata(path)


def test_stack_binding_accepts_only_the_attested_manifest_and_rendered_images(tmp_path: Path) -> None:
    manifest, metadata, environment = stack_binding_fixture(tmp_path)
    lane.validate_stack_binding(manifest, metadata, environment)


def test_stack_binding_rejects_a_different_evidence_manifest(tmp_path: Path) -> None:
    manifest, metadata, environment = stack_binding_fixture(tmp_path)
    copy = tmp_path / "evidence-manifest.json"
    copy.write_bytes(manifest.read_bytes())
    with pytest.raises(ValueError, match="metadata path"):
        lane.validate_stack_binding(copy, metadata, environment)


def test_stack_binding_rejects_manifest_tampering(tmp_path: Path) -> None:
    manifest, metadata, environment = stack_binding_fixture(tmp_path)
    manifest.write_text(manifest.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="metadata digest"):
        lane.validate_stack_binding(manifest, metadata, environment)


def test_stack_binding_rejects_a_deployed_image_not_in_evidence(tmp_path: Path) -> None:
    manifest, metadata, environment = stack_binding_fixture(tmp_path)
    environment["MARTY_UI_IMAGE"] = "ghcr.io/elevenid/marty-ui-oss/ui@sha256:" + "f" * 64
    with pytest.raises(ValueError, match="MARTY_UI_IMAGE"):
        lane.validate_stack_binding(manifest, metadata, environment)


def test_standard_verifier_config_reuses_only_generated_signing_jwk(tmp_path: Path) -> None:
    source = {
        "credential": {"signing_jwk": {"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "d": "d"}},
        "client": {"request_object_trust_anchor_pem": "not-for-final"},
    }
    (tmp_path / "marty-verifier-haip.json").write_text(json.dumps(source), encoding="utf-8")
    destination = lane.standard_verifier_config(tmp_path, "https://marty.test")
    config = json.loads(destination.read_text(encoding="utf-8"))
    assert config["verifier"]["profile"] == "oid4vp-1.0-final"
    assert "client" not in config


def test_oidf_fixture_bootstrap_receives_the_private_runner_config_by_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[str] = []
    output_dir = tmp_path / "output"
    haip_material = tmp_path / "haip"
    haip_material.mkdir()

    def fake_run(command: list[str], _environment: dict[str, str], **_kwargs: object) -> int:
        captured.extend(command)
        destination = Path(command[command.index("--output") + 1])
        destination.parent.mkdir(parents=True)
        destination.write_text(
            json.dumps(
                {
                    "organization_id": "org-1",
                    "oid4vp_template_id": "template-1",
                    "oid4vp_policy_id": "policy-1",
                    "oid4vp_trust_profile_id": "trust-1",
                }
            ),
            encoding="utf-8",
        )
        return 0

    monkeypatch.setattr(lane, "run", fake_run)
    args = SimpleNamespace(
        output_dir=output_dir,
        run_id="run-1",
        haip_material=haip_material,
    )

    result = lane.bootstrap_fixtures(
        args,
        {"OIDF_MARTY_GATEWAY_URL": "https://marty.test"},
        mode="oid4vp",
    )

    assert result["oid4vp_trust_profile_id"] == "trust-1"
    assert captured[captured.index("--oidf-runner-config") + 1] == str(haip_material / "marty-verifier-haip.json")


def test_oidf_lane_binds_the_disposable_trust_profile_to_the_real_flow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suite_environment: dict[str, str] = {}

    def fake_run(command: list[str], environment: dict[str, str], **_kwargs: object) -> int:
        if "oidf_conformance.py" in " ".join(command):
            suite_environment.update(environment)
        return 0

    monkeypatch.setattr(lane, "run", fake_run)
    monkeypatch.setattr(lane, "wait_for_public_stack", lambda _environment: None)
    monkeypatch.setattr(
        lane,
        "bootstrap_fixtures",
        lambda *_args, **_kwargs: {
            "organization_id": "org-1",
            "oid4vp_template_id": "template-1",
            "oid4vp_policy_id": "policy-1",
            "oid4vp_trust_profile_id": "trust-1",
        },
    )
    monkeypatch.setattr(
        lane,
        "standard_verifier_config",
        lambda _material, _gateway: tmp_path / "marty-verifier.json",
    )
    args = SimpleNamespace(
        lane="oid4vp-final",
        marty_ui=tmp_path / "marty-ui",
        run_id="run-1",
        oidf_runner=tmp_path / "runner",
        haip_material=tmp_path / "haip",
        output_dir=tmp_path / "output",
        stack_manifest=tmp_path / "stack-manifest.json",
    )

    assert lane.run_oidf(args, {"OIDF_MARTY_GATEWAY_URL": "https://marty.test"}) == 0
    assert suite_environment["OIDF_MARTY_PRESENTATION_POLICY_ID"] == "policy-1"
    assert suite_environment["OIDF_MARTY_TRUST_PROFILE_ID"] == "trust-1"


def test_old_release_fails_before_any_compose_command(tmp_path: Path) -> None:
    args = type(
        "Args",
        (),
        {
            "lane": "eudi",
            "run_id": "run-1",
            "marty_ui": tmp_path / "marty-ui",
        },
    )()
    args.marty_ui.mkdir()
    with pytest.raises(ValueError, match="publish a fresh stack release"):
        lane.base_environment(args)


def test_base_environment_binds_eudi_vct_to_verified_gateway_origin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, metadata, stack_environment = stack_binding_fixture(tmp_path)
    marty_ui = tmp_path / "marty-ui"
    (marty_ui / "scripts").mkdir(parents=True)
    (marty_ui / "scripts" / "conformance_stack.py").write_text("# released launcher\n", encoding="utf-8")
    haip_material = tmp_path / "haip-material"
    haip_material.mkdir()
    monkeypatch.setattr(lane, "load_stack_metadata", lambda _path: metadata)
    monkeypatch.setattr(lane, "load_stack_environment", lambda _path: stack_environment)
    monkeypatch.setattr(
        lane,
        "load_material_environment",
        lambda _path: {"OIDF_PUBLIC_BASE_URL": "https://marty-oidf.test:18443"},
    )
    monkeypatch.setenv("MARTY_CONFORMANCE_ADMIN_PASSWORD", "admin-password")
    monkeypatch.setenv("MARTY_CONFORMANCE_REVIEWER_PASSWORD", "reviewer-password")
    args = SimpleNamespace(
        lane="eudi",
        run_id="run-1",
        marty_ui=marty_ui,
        stack_manifest=manifest,
        stack_metadata=tmp_path / "stack-metadata.json",
        stack_env=tmp_path / ".env.stack",
        material=tmp_path / "material",
        oidf_runner=None,
        w3c_suite=None,
        haip_material=haip_material,
    )

    environment, _ = lane.base_environment(args)

    assert environment["EUDI_TEST_VCT_ORIGIN"] == environment["OIDF_MARTY_GATEWAY_URL"]


def test_public_readiness_uses_generated_ca_and_exact_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    responses = iter(
        [
            type("Result", (), {"returncode": 22, "stdout": ""})(),
            type("Result", (), {"returncode": 0, "stdout": '{"status":"ready"}\n__MARTY_PUBLIC_HTTP_STATUS__:200\n'})(),
        ]
    )

    def fake_run(command: list[str], **_kwargs: object) -> object:
        calls.append(command)
        return next(responses)

    monotonic = iter([0.0, 1.0, 2.0])
    monkeypatch.setattr(lane.subprocess, "run", fake_run)
    monkeypatch.setattr(lane.time, "monotonic", lambda: next(monotonic))
    monkeypatch.setattr(lane.time, "sleep", lambda _seconds: None)
    lane.wait_for_public_stack(
        {
            "OIDF_MARTY_GATEWAY_URL": "https://marty-oidf.test:18443",
            "OIDF_MARTY_RESOLVE_IP": "127.0.0.1",
            "SSL_CERT_FILE": "/material/root-ca.pem",
        },
        timeout=5,
        poll=0,
    )
    assert "--cacert" in calls[0]
    assert "/material/root-ca.pem" in calls[0]
    assert "--noproxy" in calls[0]
    assert "marty-oidf.test" in calls[0]
    assert "--write-out" in calls[0]
    assert any("__MARTY_PUBLIC_HTTP_STATUS__:%{http_code}" in value for value in calls[0])
    assert "marty-oidf.test:18443:127.0.0.1" in calls[0]
    assert calls[0][-1] == "https://marty-oidf.test:18443/ready"


def test_public_readiness_timeout_reports_only_service_states(monkeypatch: pytest.MonkeyPatch) -> None:
    response = type(
        "Result",
        (),
        {
            "returncode": 22,
            "stdout": (
                '{"status":"not_ready","services":{"issuance":{"status":"unreachable",'
                '"error":"secret-looking-detail"},"auth":{"status":"healthy"}}}'
            ),
        },
    )()
    monkeypatch.setattr(lane.subprocess, "run", lambda *_args, **_kwargs: response)
    monotonic = iter([0.0, 1.0])
    monkeypatch.setattr(lane.time, "monotonic", lambda: next(monotonic))
    monkeypatch.setattr(lane.time, "sleep", lambda _seconds: None)

    with pytest.raises(RuntimeError) as error:
        lane.wait_for_public_stack(
            {
                "OIDF_MARTY_GATEWAY_URL": "https://marty-oidf.test:18443",
                "SSL_CERT_FILE": "/material/root-ca.pem",
            },
            timeout=1,
            poll=0,
        )

    message = str(error.value)
    assert "auth=healthy" in message
    assert "issuance=unreachable" in message
    assert "secret-looking-detail" not in message


def test_public_proxy_diagnostics_are_fixed_categories_only() -> None:
    classes = lane.classify_public_proxy_diagnostics(
        "connect() failed (111: Connection refused) while connecting to upstream; "
        "upstream timed out; token=must-not-be-reported"
    )

    assert classes == ["upstream-connect", "upstream-timeout"]


def test_public_proxy_diagnostic_selects_exact_compose_service(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: object) -> object:
        calls.append(command)
        if command[:2] == ["docker", "ps"]:
            return type("Result", (), {"returncode": 0, "stdout": "proxy-id\n", "stderr": ""})()
        return type(
            "Result",
            (),
            {"returncode": 0, "stdout": "", "stderr": "connect() failed while connecting to upstream"},
        )()

    monkeypatch.setattr(lane.subprocess, "run", fake_run)
    lane.emit_public_proxy_diagnostic("marty-conformance-run-1", {})

    assert "label=com.docker.compose.project=marty-conformance-run-1" in calls[0]
    assert "label=com.docker.compose.service=oidf-tls-proxy" in calls[0]
    assert calls[1] == ["docker", "logs", "--tail", "250", "proxy-id"]
    assert "upstream-connect" in capsys.readouterr().out


def test_w3c_lane_rechecks_public_readiness_after_enabling_adapter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []

    def fake_run(command: list[str], _environment: dict[str, str], **_kwargs: object) -> int:
        if "--include-w3c" in command and "up" in command:
            events.append("adapter-up")
        elif "w3c_vc_conformance.py" in " ".join(command):
            events.append("suite")
        return 0

    monkeypatch.setattr(lane, "run", fake_run)
    monkeypatch.setattr(lane, "wait_for_public_stack", lambda _environment: events.append("ready"))
    monkeypatch.setattr(
        lane,
        "bootstrap_fixtures",
        lambda *_args, **_kwargs: {
            "organization_id": "00000000-0000-0000-0000-000000000001",
            "w3c_template_id": "00000000-0000-0000-0000-000000000002",
            "w3c_credential_policy_id": "00000000-0000-0000-0000-000000000003",
            "w3c_presentation_policy_id": "00000000-0000-0000-0000-000000000004",
        },
    )
    args = type(
        "Args",
        (),
        {
            "marty_ui": tmp_path / "marty-ui",
            "run_id": "run-1",
            "output_dir": tmp_path / "output",
            "w3c_suite": tmp_path / "w3c-suite",
            "stack_manifest": tmp_path / "stack-manifest.json",
        },
    )()

    assert lane.run_w3c(args, {"OIDF_MARTY_GATEWAY_URL": "https://marty-oidf.test:18443"}) == 0
    assert events == ["ready", "adapter-up", "ready", "suite"]


def test_eudi_lane_starts_marty_haip_without_the_oidf_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []
    lifecycle_environments: list[dict[str, str]] = []
    suite_environment: dict[str, str] = {}

    def fake_run(command: list[str], environment: dict[str, str], **_kwargs: object) -> int:
        commands.append(command)
        rendered = " ".join(command)
        if "official_suite_compose.py" in rendered:
            lifecycle_environments.append(dict(environment))
        if "eudi_reference_interop.py" in rendered:
            suite_environment.update(environment)
        return 0

    monkeypatch.setattr(lane, "run", fake_run)
    monkeypatch.setattr(lane, "wait_for_public_stack", lambda _environment: None)
    monkeypatch.setattr(
        lane,
        "bootstrap_fixtures",
        lambda *_args, **_kwargs: {
            "organization_id": "org-1",
            "eudi_issuer_profile_id": "profile-1",
            "eudi_issuer_did": "did:web:marty.test:orgs:org-1",
            "eudi_passport_template_id": "passport-1",
            "eudi_mdl_template_id": "mdl-1",
            "eudi_open_badge_template_id": "badge-1",
        },
    )
    monkeypatch.setattr(
        lane,
        "load_verifier_environment",
        lambda _path: {
            "VERIFIER_X509_CERT_PEM": "certificate-chain",
            lane.OID4VP_TRUST_ANCHOR_FILE_ENV: "/haip/request-object-root.pem",
        },
    )
    args = SimpleNamespace(
        marty_ui=tmp_path / "marty-ui",
        run_id="run-1",
        output_dir=tmp_path / "output",
        haip_material=tmp_path / "haip-material",
        stack_manifest=tmp_path / "stack-manifest.json",
    )

    assert (
        lane.run_eudi(
            args,
            {
                "OIDF_MARTY_GATEWAY_URL": "https://marty.test",
                "EUDI_WALLET_TESTER_PUBLIC_URL": "https://wallet.test",
                "EUDI_VERIFIER_PUBLIC_URL": "https://verifier.test",
                "EUDI_WALLET_KIT_URL": "http://wallet-kit:9090",
            },
        )
        == 0
    )

    lifecycle_commands = [command for command in commands if "official_suite_compose.py" in " ".join(command)]
    assert len(lifecycle_commands) == 3
    for command in lifecycle_commands:
        assert "--eudi" in command
        assert "--haip" in command
        assert "--haip-material" in command
        assert "--oidf" not in command
    assert len(lifecycle_environments) == 3
    legacy_private_key_name = "VERIFIER_" + "SIGNING_KEY_PEM"
    assert all(legacy_private_key_name not in item for item in lifecycle_environments)
    assert all("VERIFIER_X509_CERT_PEM" not in item for item in lifecycle_environments)
    assert suite_environment[lane.OID4VP_TRUST_ANCHOR_FILE_ENV] == "/haip/request-object-root.pem"
    assert suite_environment["VERIFIER_X509_CERT_PEM"] == "certificate-chain"
    assert suite_environment["TEST_ORG_ID"] == "org-1"
    assert suite_environment["EUDI_TEST_OPEN_BADGE_TEMPLATE_ID"] == "badge-1"
    assert "eudi_issuer_profile_id" not in suite_environment
    assert "eudi_issuer_did" not in suite_environment
    assert not any("KMS" in name or "KEY_REFERENCE" in name for name in suite_environment)


def test_w3c_lane_cleans_up_a_partial_initial_start(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    commands: list[list[str]] = []

    def fake_run(command: list[str], _environment: dict[str, str], **_kwargs: object) -> int:
        commands.append(command)
        return 1 if command[-1] == "up" else 0

    monkeypatch.setattr(lane, "run", fake_run)
    args = SimpleNamespace(marty_ui=tmp_path / "marty-ui", run_id="run-1")

    assert lane.run_w3c(args, {}) == 1
    assert commands[-1][-1] == "down"
