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
                "components": [{"name": "images", "artifacts": artifacts}],
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
        "POSTGRES_IMAGE": base_images["postgres"],
        "REDIS_IMAGE": base_images["redis"],
    }
    return manifest, metadata, environment


def test_stack_environment_accepts_only_complete_digest_pins(tmp_path: Path) -> None:
    path = tmp_path / ".env.stack"
    path.write_text(
        "\n".join(
            f"{name}=ghcr.io/elevenid/{name.lower()}@sha256:{index:064x}"
            for index, name in enumerate(sorted(lane.STACK_ENV_KEYS), 1)
        ),
        encoding="utf-8",
    )
    assert set(lane.load_stack_environment(path)) == lane.STACK_ENV_KEYS
    path.write_text("MARTY_UI_IMAGE=ghcr.io/elevenid/ui:latest\n", encoding="utf-8")
    with pytest.raises(ValueError, match="sha256"):
        lane.load_stack_environment(path)


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
    assert captured[captured.index("--oidf-runner-config") + 1] == str(
        haip_material / "marty-verifier-haip.json"
    )


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
        haip_material=None,
    )

    environment, _ = lane.base_environment(args)

    assert environment["EUDI_TEST_VCT_ORIGIN"] == environment["OIDF_MARTY_GATEWAY_URL"]


def test_public_readiness_uses_generated_ca_and_exact_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    responses = iter(
        [
            type("Result", (), {"returncode": 22, "stdout": ""})(),
            type("Result", (), {"returncode": 0, "stdout": '{"status":"ready"}'})(),
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
    assert "marty-oidf.test:18443:127.0.0.1" in calls[0]
    assert calls[0][-1] == "https://marty-oidf.test:18443/ready"


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
            "w3c_policy_id": "00000000-0000-0000-0000-000000000003",
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


def test_w3c_lane_cleans_up_a_partial_initial_start(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    commands: list[list[str]] = []

    def fake_run(command: list[str], _environment: dict[str, str], **_kwargs: object) -> int:
        commands.append(command)
        return 1 if command[-1] == "up" else 0

    monkeypatch.setattr(lane, "run", fake_run)
    args = SimpleNamespace(marty_ui=tmp_path / "marty-ui", run_id="run-1")

    assert lane.run_w3c(args, {}) == 1
    assert commands[-1][-1] == "down"
