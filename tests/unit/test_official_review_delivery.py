from __future__ import annotations

import hashlib
import io
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import official_review_crypto as crypto  # noqa: E402
import official_review_delivery as delivery  # noqa: E402


def fixture_archive(*, link: bool = False, extra: bool = False) -> bytes:
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as output:
        for name in ["age/age", "age/age-keygen"]:
            entry = tarfile.TarInfo(name)
            value = b"unit-fixture-not-an-executable"
            entry.size = len(value)
            if link and name == "age/age":
                entry.type, entry.linkname = tarfile.SYMTYPE, "/not-a-tool"
                entry.size = 0
                output.addfile(entry)
            else:
                output.addfile(entry, io.BytesIO(value))
        if extra:
            entry = tarfile.TarInfo("../escape")
            entry.size = 4
            output.addfile(entry, io.BytesIO(b"unit"))
    return archive.getvalue()


def fixture_manifest(value: bytes) -> dict:
    return {
        "schema": "elevenid.review-encryption-tool/v1",
        "version": "v1.3.2",
        "repository": "https://github.com/FiloSottile/age",
        "assets": {
            "linux-amd64": {"name": "age-v1.3.2-linux-amd64.tar.gz", "sha256": hashlib.sha256(value).hexdigest()}
        },
    }


def test_installer_uses_only_pinned_whitelisted_members_and_preserves_changed_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = fixture_archive(extra=True)
    monkeypatch.setattr(crypto.urllib.request, "urlopen", lambda *_args, **_kwargs: io.BytesIO(archive))
    manifest = fixture_manifest(archive)
    target = tmp_path / "tools"
    first = crypto.install(manifest, "linux-amd64", target)
    assert set(first["binaries"]) == {"age", "age-keygen"}
    assert not (tmp_path / "escape").exists()
    assert crypto.install(manifest, "linux-amd64", target) == first
    (target / "age").write_bytes(b"changed-local-tool")
    with pytest.raises(ValueError, match="preserving"):
        crypto.install(manifest, "linux-amd64", target)
    assert (target / "age").read_bytes() == b"changed-local-tool"


def test_installer_rejects_modified_cache_and_archive_links(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive = fixture_archive(link=True)
    monkeypatch.setattr(crypto.urllib.request, "urlopen", lambda *_args, **_kwargs: io.BytesIO(archive))
    with pytest.raises(ValueError, match="regular"):
        crypto.install(fixture_manifest(archive), "linux-amd64", tmp_path / "linked")
    archive = fixture_archive()
    manifest = fixture_manifest(archive)
    target = tmp_path / "cached"
    crypto.install(manifest, "linux-amd64", target)
    before = (target / "age").read_bytes()
    (target / "age-v1.3.2-linux-amd64.tar.gz").write_bytes(archive + b"changed")
    with pytest.raises(ValueError, match="pinned digest"):
        crypto.install(manifest, "linux-amd64", target)
    assert (target / "age").read_bytes() == before


@pytest.mark.parametrize("change", [{"version": "latest"}, {"repository": "https://other.example/age"}])
def test_mutable_or_foreign_tool_origins_are_rejected_before_download(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: dict[str, str]
) -> None:
    manifest = fixture_manifest(fixture_archive()) | change
    monkeypatch.setattr(crypto.urllib.request, "urlopen", lambda *_args, **_kwargs: pytest.fail("must not download"))
    with pytest.raises(ValueError, match="manifest is invalid"):
        crypto.install(manifest, "linux-amd64", tmp_path / "tools")


@pytest.mark.parametrize("name", ["../escape", "/absolute", "a/../escape", "a\\escape", "C:/escape"])
def test_decrypted_archive_paths_never_escape_into_the_filesystem(name: str) -> None:
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as output:
        entry = tarfile.TarInfo(name)
        entry.size = 4
        output.addfile(entry, io.BytesIO(b"unit"))
    with pytest.raises(ValueError, match="unsafe path"):
        delivery.unpack(archive.getvalue())


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, "duplicate"])
def test_decrypted_links_and_duplicate_members_are_rejected(kind: bytes | str) -> None:
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as output:
        if kind == "duplicate":
            output.addfile(tarfile.TarInfo("manifest.json"))
            output.addfile(tarfile.TarInfo("manifest.json"))
        else:
            entry = tarfile.TarInfo("manifest.json")
            entry.type, entry.linkname = kind, "other"
            output.addfile(entry)
    with pytest.raises(ValueError, match="invalid or duplicate"):
        delivery.unpack(archive.getvalue())


def test_imported_local_or_foreign_packets_cannot_claim_official_run_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    summary = {"lane": "haip"}
    for key in ["GITHUB_ACTIONS", "GITHUB_REPOSITORY", "GITHUB_REF", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"]:
        monkeypatch.delenv(key, raising=False)
    assert delivery.delivery_scope(summary, "haip-17-1", 1) == "LOCAL_DEVELOPER_FEEDBACK"
    for key, value in {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": "ElevenID/marty-ui",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_RUN_ID": "17",
        "GITHUB_RUN_ATTEMPT": "1",
    }.items():
        monkeypatch.setenv(key, value)
    assert delivery.delivery_scope(summary, "haip-17-1", 1) == "OFFICIAL_RUN_REVIEW_ONLY"
    assert delivery.delivery_scope(summary, "haip-18-1", 1) == "LOCAL_DEVELOPER_FEEDBACK"
    native = {**summary, "local_runtime_binding": {"runId": "haip-17-1", "releaseQualified": False}}
    assert delivery.delivery_scope(native, "haip-17-1", 1) == "LOCAL_DEVELOPER_FEEDBACK"
    monkeypatch.setenv("GITHUB_REPOSITORY", "other/repository")
    assert delivery.delivery_scope(summary, "haip-17-1", 1) == "LOCAL_DEVELOPER_FEEDBACK"
