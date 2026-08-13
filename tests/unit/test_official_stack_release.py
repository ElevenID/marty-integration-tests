from __future__ import annotations

import importlib.util
import json
from hashlib import sha256
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("official_stack_release", ROOT / "scripts" / "official_stack_release.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load official stack release helper")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


def write_pin(path: Path, *, digest: str = "sha256:" + "a" * 64) -> dict[str, str]:
    value = {
        "schema": release.PIN_SCHEMA,
        "state": "ready",
        "repository": release.REPOSITORY,
        "release_tag": "v1.2.3",
        "manifest_asset": release.ASSET,
        "manifest_sha256": digest,
        "marty_commit": "b" * 40,
        "marty_checkout_commit": "b" * 40,
    }
    path.write_text(json.dumps(value), encoding="utf-8")
    return value


def stack_bytes() -> bytes:
    return (
        json.dumps(
            {
                "schema": "marty.stack/v1",
                "release": "marty-ui@1.2.3",
                "components": [
                    {
                        "name": "marty-ui",
                        "repository": "ElevenID/marty-ui",
                        "commit": "b" * 40,
                        "artifacts": [
                            {
                                "type": "oci",
                                "uri": "ghcr.io/elevenid/marty-ui-oss/ui",
                                "digest": "sha256:" + "c" * 64,
                            }
                        ],
                    }
                ],
            },
            sort_keys=True,
        )
        + "\n"
    ).encode()


def test_privileged_workflow_uses_only_repository_reviewed_pin(tmp_path: Path) -> None:
    write_pin_path = tmp_path / "pin.json"
    write_pin(write_pin_path)
    pin = release.load_pin(write_pin_path)
    assert release.resolve_pin(pin) == pin


def test_awaiting_release_pin_cannot_execute_without_reviewed_digest(tmp_path: Path) -> None:
    path = tmp_path / "pin.json"
    value = write_pin(path)
    value.update({"state": "awaiting_release", "manifest_sha256": None})
    path.write_text(json.dumps(value), encoding="utf-8")
    pin = release.load_pin(path)
    with pytest.raises(ValueError, match="awaiting the signed v1.2.3 release"):
        release.resolve_pin(pin)


def test_stack_manifest_records_exact_commit_and_digest_image(tmp_path: Path) -> None:
    content = stack_bytes()
    manifest = tmp_path / "stack-manifest.json"
    manifest.write_bytes(content)
    pin_path = tmp_path / "pin.json"
    pin = write_pin(pin_path, digest=f"sha256:{sha256(content).hexdigest()}")
    metadata = release.validate_stack_manifest(manifest, pin)
    assert metadata["marty_commit"] == "b" * 40
    assert metadata["images"][0]["reference"].endswith("@sha256:" + "c" * 64)


def test_stack_manifest_rejects_commit_outside_reviewed_pin(tmp_path: Path) -> None:
    content = stack_bytes()
    manifest = tmp_path / "stack-manifest.json"
    manifest.write_bytes(content)
    pin_path = tmp_path / "pin.json"
    pin = write_pin(pin_path, digest=f"sha256:{sha256(content).hexdigest()}")
    pin["marty_commit"] = "c" * 40
    with pytest.raises(ValueError, match="expected"):
        release.validate_stack_manifest(manifest, pin)


@pytest.mark.parametrize(
    "workflow",
    ["official-interoperability.yml", "public-tenant-boundary.yml"],
)
def test_privileged_workflow_checkout_is_the_literal_reviewed_commit(workflow: str) -> None:
    pin = release.load_pin()
    content = (ROOT / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
    assert f"ref: {pin['marty_checkout_commit']}" in content
    assert "steps.stack.outputs.marty_commit" not in content
    assert "steps.stack.outputs.marty_checkout_commit" not in content


def test_stack_manifest_rejects_mutable_oci_uri(tmp_path: Path) -> None:
    value = json.loads(stack_bytes())
    value["components"][0]["artifacts"][0]["uri"] += ":latest"
    manifest = tmp_path / "stack-manifest.json"
    manifest.write_text(json.dumps(value), encoding="utf-8")
    pin = write_pin(tmp_path / "pin.json", digest=release.file_sha256(manifest))
    with pytest.raises(ValueError, match="immutable registry path"):
        release.validate_stack_manifest(manifest, pin)


def test_download_checks_reviewed_hash_before_attestation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    content = stack_bytes()
    pin = write_pin(tmp_path / "pin.json", digest=f"sha256:{sha256(content).hexdigest()}")
    output = tmp_path / "download"
    calls: list[list[str]] = []

    def fake_run(command: list[str], *, check: bool) -> object:
        assert check
        calls.append(command)
        if command[1:3] == ["release", "download"]:
            output.mkdir(parents=True, exist_ok=True)
            (output / "stack-manifest.json").write_bytes(content)
        return object()

    monkeypatch.setattr(release, "require_gh", lambda: "gh")
    monkeypatch.setattr(release.subprocess, "run", fake_run)
    assert release.download_and_attest(pin, output) == output / "stack-manifest.json"
    assert calls[0][1:3] == ["release", "download"]
    assert calls[1][1:3] == ["attestation", "verify"]


def test_bad_download_is_deleted_and_never_attested(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pin = write_pin(tmp_path / "pin.json")
    output = tmp_path / "download"
    calls: list[list[str]] = []

    def fake_run(command: list[str], *, check: bool) -> object:
        assert check
        calls.append(command)
        output.mkdir(parents=True, exist_ok=True)
        (output / "stack-manifest.json").write_text("tampered", encoding="utf-8")
        return object()

    monkeypatch.setattr(release, "require_gh", lambda: "gh")
    monkeypatch.setattr(release.subprocess, "run", fake_run)
    with pytest.raises(ValueError, match="expected"):
        release.download_and_attest(pin, output)
    assert len(calls) == 1
    assert not (output / "stack-manifest.json").exists()
