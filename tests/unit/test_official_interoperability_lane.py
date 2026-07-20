from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "official_interoperability_lane", ROOT / "scripts" / "official_interoperability_lane.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load official interoperability lane")
lane = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lane)


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
