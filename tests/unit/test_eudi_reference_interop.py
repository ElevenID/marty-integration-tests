from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("eudi_reference_interop", ROOT / "scripts" / "eudi_reference_interop.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load EUDI reference interop helper")
eudi = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(eudi)


def test_eudi_reference_components_are_immutable_and_complete() -> None:
    manifest = eudi.load_manifest()
    assert "@sha256:" in manifest["components"]["wallet_tester"]["image"]
    assert "@sha256:" in manifest["components"]["verifier_endpoint"]["image"]
    assert "replayed_response" in manifest["coverage"]["negative"]
    libraries = manifest["components"]["wallet_kit"]["libraries"]
    assert {name: value["version"] for name, value in libraries.items()} == {
        "oid4vp": "0.12.3",
        "oid4vci": "0.9.1",
        "sd_jwt": "0.18.0",
    }
    assert all(value["maven_coordinate"].endswith(value["version"]) for value in libraries.values())
    build = manifest["components"]["wallet_kit"]["build"]
    assert "@sha256:" in build["builder_image"]
    assert "@sha256:" in build["runtime_image"]
    gradle = (ROOT / "services" / "eudi-wallet-harness" / "build.gradle.kts").read_text(encoding="utf-8")
    lock = (ROOT / "services" / "eudi-wallet-harness" / "gradle.lockfile").read_text(encoding="utf-8")
    verification = (ROOT / "services" / "eudi-wallet-harness" / "gradle" / "verification-metadata.xml").read_text(
        encoding="utf-8"
    )
    for library in libraries.values():
        coordinate = library["maven_coordinate"]
        assert f'implementation("{coordinate}")' in gradle
        assert coordinate + "=" in lock
    assert "lockAllConfigurations()" in gradle
    assert "<verify-metadata>true</verify-metadata>" in verification
    assert '<sha256 value="' in verification


def test_eudi_evidence_records_pinned_components(tmp_path: Path) -> None:
    output = tmp_path / "report"
    output.mkdir()
    (output / "junit.xml").write_text("<testsuites/>", encoding="utf-8")
    endpoints = {
        "gateway": "https://marty.test",
        "wallet_tester": "http://wallet:5050",
        "verifier": "http://verifier:8090",
        "wallet_kit": "http://kit:9090",
    }
    eudi.write_evidence(output, eudi.load_manifest(), endpoints, 0)
    evidence = json.loads((output / "evidence.json").read_text(encoding="utf-8"))
    assert evidence["result"] == {"exit_code": 0, "passed": True, "skipped": 0}
    assert evidence["components"]["wallet_tester"]["image"].startswith("ghcr.io/")


def test_eudi_stack_manifest_records_immutable_marty_images(tmp_path: Path) -> None:
    manifest = tmp_path / "stack-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": "marty.stack/v1",
                "release": "marty-ui@1.0.0",
                "components": [
                    {
                        "name": "marty",
                        "artifacts": [
                            {
                                "type": "oci",
                                "uri": "ghcr.io/elevenid/marty",
                                "digest": "sha256:" + "a" * 64,
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    metadata = eudi.stack_manifest_metadata(manifest)
    assert metadata["release"] == "marty-ui@1.0.0"
    assert metadata["images"][0]["digest"] == "sha256:" + "a" * 64


def test_eudi_junit_skip_count_is_visible(tmp_path: Path) -> None:
    report = tmp_path / "junit.xml"
    report.write_text('<testsuites><testsuite tests="2" skipped="1"/></testsuites>', encoding="utf-8")
    assert eudi.junit_skip_count(report) == 1


def test_run_environment_loads_material_trust_and_public_login_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated = {
        "OIDF_PUBLIC_BASE_URL": "https://marty-oidf.test:8443",
        "EUDI_WALLET_TESTER_PUBLIC_URL": "https://marty-oidf.test:25051",
        "EUDI_VERIFIER_PUBLIC_URL": "https://marty-oidf.test:28091",
        "EUDI_WALLET_KIT_URL": "http://127.0.0.1:29090",
        "SSL_CERT_FILE": str(tmp_path / "root-ca.pem"),
        "OIDF_MARTY_RESOLVE_IP": "127.0.0.1",
    }
    monkeypatch.setattr(eudi, "merged_material_environment", lambda *_args: ("generated", dict(generated)))
    monkeypatch.setattr(eudi, "validate_environment", lambda *_args, **_kwargs: {})
    args = argparse.Namespace(
        eudi_material=tmp_path,
        gateway_url=None,
        wallet_tester_url=None,
        verifier_url=None,
        wallet_kit_url=None,
    )

    environment, endpoints = eudi.run_environment(args)

    assert endpoints["gateway"] == generated["OIDF_PUBLIC_BASE_URL"]
    assert environment["OIDF_MARTY_GATEWAY_URL"] == generated["OIDF_PUBLIC_BASE_URL"]
    assert environment["SSL_CERT_FILE"] == generated["SSL_CERT_FILE"]
    assert environment["OIDF_MARTY_RESOLVE_IP"] == "127.0.0.1"


def test_explicit_endpoint_cannot_deviate_from_material(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated = {
        "OIDF_PUBLIC_BASE_URL": "https://marty-oidf.test:8443",
        "EUDI_WALLET_TESTER_PUBLIC_URL": "https://marty-oidf.test:25051",
        "EUDI_VERIFIER_PUBLIC_URL": "https://marty-oidf.test:28091",
        "EUDI_WALLET_KIT_URL": "http://127.0.0.1:29090",
    }
    monkeypatch.setattr(eudi, "merged_material_environment", lambda *_args: ("generated", generated))
    monkeypatch.setattr(eudi, "validate_environment", lambda *_args, **_kwargs: {})
    args = argparse.Namespace(
        eudi_material=tmp_path,
        gateway_url="https://different.test:8443",
        wallet_tester_url=None,
        verifier_url=None,
        wallet_kit_url=None,
    )

    with pytest.raises(ValueError, match="gateway URL must match"):
        eudi.run_environment(args)
