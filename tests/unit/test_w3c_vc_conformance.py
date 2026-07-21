from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("w3c_vc_conformance", ROOT / "scripts" / "w3c_vc_conformance.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load W3C VC conformance helper")
w3c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(w3c)


def test_pinned_w3c_vc_suite_manifest_is_valid() -> None:
    manifest = w3c.load_manifest()
    assert manifest["official_suite"]["repository"].startswith("https://github.com/w3c/")
    assert manifest["official_suite"]["node"] == "24"
    assert manifest["official_suite"]["npm"] == "11.11.0"
    assert w3c.SRI_SHA512.fullmatch(manifest["official_suite"]["npm_integrity"])
    assert w3c.DIGEST.fullmatch(manifest["official_suite"]["package_lock_sha256"])
    assert manifest["adapter"]["path"] == "/__test__/vc-api"
    assert set(manifest["evidence"]["required_capabilities"]) == {
        "issuer",
        "vc_verifier",
        "vp_verifier",
    }
    assert manifest["exclusions"][0]["review_date"]


def test_w3c_manifest_rejects_a_non_object(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        w3c.load_manifest(manifest)


def test_npm_command_uses_the_windows_launcher_when_needed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("W3C_NPM_CLI", raising=False)
    monkeypatch.setattr(w3c.os, "name", "nt")
    assert w3c.npm_command() == ["npm.cmd"]
    monkeypatch.setattr(w3c.os, "name", "posix")
    assert w3c.npm_command() == ["npm"]


def test_npm_command_uses_only_an_existing_private_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cli = (tmp_path / "npm-cli.js").resolve()
    cli.write_text("", encoding="utf-8")
    monkeypatch.setenv("W3C_NPM_CLI", str(cli))
    monkeypatch.setattr(w3c, "node_command", lambda: "node24")
    assert w3c.npm_command() == ["node24", str(cli)]


def test_package_lock_digest_is_identical_for_lf_and_crlf(tmp_path: Path) -> None:
    lf = tmp_path / "lf-package-lock.json"
    crlf = tmp_path / "crlf-package-lock.json"
    lf.write_bytes(b'{\n  "lockfileVersion": 3\n}\n')
    crlf.write_bytes(b'{\r\n  "lockfileVersion": 3\r\n}\r\n')

    assert w3c.package_lock_sha256(lf) == w3c.package_lock_sha256(crlf)
    assert w3c.package_lock_sha256(lf) == (
        "sha256:e9ce8921579ead737c68c3c1025d71d433350255100f96293f5accc0e204871e"
    )


def test_npm_payload_integrity_is_pinned_to_the_official_tarball() -> None:
    manifest = w3c.load_manifest()["official_suite"]
    assert manifest["npm_tarball"] == "https://registry.npmjs.org/npm/-/npm-11.11.0.tgz"
    assert manifest["npm_integrity"] == (
        "sha512-82gRxKrh/eY5UnNorkTFcdBQAGpgjWehkfGVqAGlJjejEtJZGGJUqjo3mbBTNbc5BTnPKGVtGPBZGhElujX5cw=="
    )


def test_npm_bootstrap_rejects_content_before_extraction(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class Response(io.BytesIO):
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            self.close()

    monkeypatch.setattr(w3c.urllib.request, "urlopen", lambda *_args, **_kwargs: Response(b"tampered"))
    output = tmp_path / "npm"
    with pytest.raises(ValueError, match="npm tarball integrity"):
        w3c.bootstrap_npm(output, w3c.load_manifest())
    assert not output.exists()


def test_w3c_test_command_uses_absolute_reporter_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mocha = tmp_path / "node_modules" / "mocha" / "bin" / "mocha.js"
    mocha.parent.mkdir(parents=True)
    mocha.write_text("", encoding="utf-8")
    monkeypatch.setattr(w3c.shutil, "which", lambda _name: "node")
    command = w3c.w3c_test_command(tmp_path)
    assert command[0] == "node"
    assert (tmp_path / "reports").as_posix() in command[command.index("--reporter-options") + 1]


def test_w3c_local_config_registers_the_real_issuer_and_verifiers(tmp_path: Path) -> None:
    output = tmp_path / "localConfig.cjs"
    w3c.write_local_config(output, "https://interop.example.test/__test__/vc-api")
    config = output.read_text(encoding="utf-8")
    assert "/credentials/issue" in config
    assert "/credentials/verify" in config
    assert "/presentations/verify" in config
    assert "issuers:" in config


def capability_row(
    manifest: dict[str, object],
    capability: str,
    *,
    state: str = "passed",
    column: str = "ElevenID",
) -> dict[str, object]:
    evidence = manifest["evidence"]
    assert isinstance(evidence, dict)
    requirements = evidence["required_capabilities"]
    assert isinstance(requirements, dict)
    markers = requirements[capability]
    assert isinstance(markers, list)
    return {
        "id": f"{markers[0]} in the conforming documents it processes.",
        "cells": [{"state": state, "cell": {"columnId": column}}],
    }


def capability_report(rows: list[dict[str, object]]) -> dict[str, object]:
    return {"matrices": [{"columns": ["ElevenID"], "rows": rows}]}


def test_w3c_report_requires_passed_issuer_vc_verifier_and_vp_verifier_rows() -> None:
    manifest = w3c.load_manifest()
    rows = [capability_row(manifest, capability) for capability in ("issuer", "vc_verifier", "vp_verifier")]
    rows.append(
        {
            "id": "An unrelated official suite row may be added without changing a total-count gate.",
            "cells": [{"state": "passed", "cell": {"columnId": "ElevenID"}}],
        }
    )

    assert w3c.executed_capabilities_from_report(capability_report(rows), manifest) == {
        "issuer",
        "vc_verifier",
        "vp_verifier",
    }


@pytest.mark.parametrize("missing", ["issuer", "vc_verifier", "vp_verifier"])
def test_w3c_report_rejects_each_missing_required_capability(missing: str) -> None:
    manifest = w3c.load_manifest()
    rows = [
        capability_row(manifest, capability)
        for capability in ("issuer", "vc_verifier", "vp_verifier")
        if capability != missing
    ]

    executed = w3c.executed_capabilities_from_report(capability_report(rows), manifest)

    assert missing not in executed
    assert w3c.REQUIRED_EVIDENCE_CAPABILITIES - executed == {missing}


def test_w3c_report_does_not_count_failed_pending_or_other_implementation_rows() -> None:
    manifest = w3c.load_manifest()
    report = capability_report(
        [
            capability_row(manifest, "issuer", state="failed"),
            capability_row(manifest, "vc_verifier", state="pending"),
            capability_row(manifest, "vp_verifier", column="Another implementation"),
        ]
    )

    assert w3c.executed_capabilities_from_report(report, manifest) == set()


def test_w3c_evidence_preserves_the_narrow_exclusion_and_immutable_stack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    suite = tmp_path / "suite"
    suite.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    (output / "result.json").write_text("{}", encoding="utf-8")
    stack = tmp_path / "stack-manifest.json"
    stack.write_text(
        json.dumps(
            {
                "schema": "marty.stack/v1",
                "release": "marty-ui@1.0.0",
                "components": [
                    {
                        "name": "marty-ui",
                        "artifacts": [
                            {
                                "type": "oci",
                                "uri": "ghcr.io/elevenid/marty-ui-oss/services",
                                "digest": "sha256:" + "a" * 64,
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(w3c, "revision", lambda _path: "a" * 40)
    # Even a zero process exit is not a pass without all three role sentinels.
    w3c.write_evidence(output, w3c.load_manifest(), suite, "https://marty.test/__test__/vc-api", 0, stack)
    evidence = json.loads((output / "evidence.json").read_text(encoding="utf-8"))
    assert evidence["result"] == {
        "exit_code": 0,
        "passed": False,
        "required_capabilities": ["issuer", "vc_verifier", "vp_verifier"],
        "executed_capabilities": [],
    }
    assert evidence["exclusions"][0]["capability"] == "JSON-LD Data Integrity eddsa-rdfc-2022"
    assert evidence["marty"]["stack_manifest"]["images"][0]["digest"] == "sha256:" + "a" * 64
