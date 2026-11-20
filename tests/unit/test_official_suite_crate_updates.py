from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import tarfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "official_suite_crate_updates", ROOT / "scripts/official_suite_updates.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load official-suite updater")
updates = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(updates)


ABSENT = object()


def crate_fixture(
    monkeypatch: pytest.MonkeyPatch,
    *,
    manifest_name: str = "selected-crate",
    commit: Any = "a" * 40,
    duplicate: bool = False,
    dirty: Any = ABSENT,
) -> tuple[dict, dict, dict]:
    component = {
        "name": "selected-crate",
        "release": "v1.0.0",
        "commit": "b" * 40,
        "crate_checksum": "c" * 64,
        "repository": "https://github.com/example/project.git",
    }
    manifest = f'[package]\nname="{manifest_name}"\nversion="1.2.3"\nrepository="https://github.com/example/project"\n'
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as archive:
        vcs = {"sha1": commit}
        if dirty is not ABSENT:
            vcs["dirty"] = dirty
        files = [
            ("Cargo.toml", manifest.encode()),
            (".cargo_vcs_info.json", json.dumps({"git": vcs}).encode()),
        ]
        if duplicate:
            files.append(files[-1])
        for name, content in files:
            entry = tarfile.TarInfo("selected-crate-1.2.3/" + name)
            entry.size = len(content)
            archive.addfile(entry, io.BytesIO(content))
    archive_bytes = raw.getvalue()
    version = {
        "num": "1.2.3",
        "yanked": False,
        "checksum": hashlib.sha256(archive_bytes).hexdigest(),
        "repository": "https://github.com/example/project",
    }
    payload = {"crate": {"name": "selected-crate", "max_stable_version": "1.2.3"}, "versions": [version]}
    responses = {"archive": archive_bytes}

    def fetch(url: str, _maximum: int) -> bytes:
        if url == "https://crates.io/api/v1/crates/selected-crate":
            return json.dumps(payload).encode()
        assert url == "https://static.crates.io/crates/selected-crate/selected-crate-1.2.3.crate"
        return responses["archive"]

    monkeypatch.setattr(updates, "_registry_bytes", fetch)
    return component, payload, responses


def test_published_crate_is_bound_to_checksum_package_and_vcs_not_monorepo_release(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    component, payload, _ = crate_fixture(monkeypatch)
    monkeypatch.setattr(updates, "latest_github_release", lambda *_: pytest.fail("repository release used for crate"))
    result = updates._released_crate(component)
    assert result == {
        "pinned_release": "v1.0.0",
        "latest_release": "v1.2.3",
        "pinned_commit": "b" * 40,
        "latest_commit": "a" * 40,
        "pinned_checksum": "c" * 64,
        "latest_checksum": payload["versions"][0]["checksum"],
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("yanked", True),
        ("repository", None),
        ("repository", "https://example.test/fork"),
        ("checksum", "g" * 64),
        ("checksum", "0" * 64),
    ],
)
def test_untrusted_registry_identity_is_refused(field: str, value: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    component, payload, _ = crate_fixture(monkeypatch)
    payload["versions"][0][field] = value
    with pytest.raises(RuntimeError):
        updates._released_crate(component)


@pytest.mark.parametrize("change", ["name", "prerelease", "duplicate", "missing"])
def test_ambiguous_or_nonstable_registry_selection_is_refused(change: str, monkeypatch: pytest.MonkeyPatch) -> None:
    component, payload, _ = crate_fixture(monkeypatch)
    if change == "name":
        payload["crate"]["name"] = "different-crate"
    elif change == "prerelease":
        payload["crate"]["max_stable_version"] = "1.2.3-rc.1"
    elif change == "duplicate":
        payload["versions"] *= 2
    else:
        payload["versions"] = []
    with pytest.raises(RuntimeError):
        updates._released_crate(component)


@pytest.mark.parametrize("commit", [None, "0" * 40, "z" * 40, "a" * 39, {}])
def test_crate_source_commit_is_required(commit: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    component, _, _ = crate_fixture(monkeypatch, commit=commit)
    with pytest.raises(RuntimeError, match="source commit"):
        updates._released_crate(component)


@pytest.mark.parametrize("case", ["package", "duplicate", "tamper", "uncompressed"])
def test_archive_identity_and_resource_bounds_are_enforced(case: str, monkeypatch: pytest.MonkeyPatch) -> None:
    component, _, responses = crate_fixture(
        monkeypatch, manifest_name="wrong" if case == "package" else "selected-crate", duplicate=case == "duplicate"
    )
    if case == "tamper":
        responses["archive"] += b"altered"
    elif case == "uncompressed":
        monkeypatch.setattr(updates, "MAX_CRATE_CONTENTS", 16)
    with pytest.raises(RuntimeError):
        updates._released_crate(component)


def test_registry_download_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    class Response(io.BytesIO):
        pass

    monkeypatch.setattr(
        updates.urllib.request,
        "build_opener",
        lambda *_args: SimpleNamespace(open=lambda *_args, **_kwargs: Response(b"12345")),
    )
    with pytest.raises(RuntimeError, match="bound"):
        updates._registry_bytes("https://crates.io/api/v1/crates/selected-crate", 4)


def test_checksum_only_drift_is_visible() -> None:
    assert updates.has_drift({"upstreams": {"crate": {"pinned_checksum": "a" * 64, "latest_checksum": "b" * 64}}})


@pytest.mark.parametrize("dirty", [True, 0, None, "false", {}])
def test_dirty_or_invalid_vcs_metadata_is_refused(dirty: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    component, _, _ = crate_fixture(monkeypatch, dirty=dirty)
    with pytest.raises(RuntimeError, match="provenance"):
        updates._released_crate(component)


def test_explicit_clean_vcs_metadata_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    component, _, _ = crate_fixture(monkeypatch, dirty=False)
    assert updates._released_crate(component)["latest_commit"] == "a" * 40


@pytest.mark.parametrize(
    "url",
    [
        "http://crates.io/path",
        "https://example.test/path",
        "https://crates.io@evil.test/path",
        "https://crates.io:443/path",
        "file:///tmp/crate",
    ],
)
def test_registry_origin_refused_before_network(url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(updates.urllib.request, "build_opener", lambda *_: pytest.fail("network opener constructed"))
    with pytest.raises(RuntimeError, match="origin"):
        updates._registry_bytes(url, 4)


@pytest.mark.parametrize("url", ["http://static.crates.io/path", "https://example.test/path", "https://crates.io/path"])
def test_registry_redirect_refused_before_following(url: str) -> None:
    handler = updates._RegistryRedirect("static.crates.io")
    request = updates.urllib.request.Request("https://static.crates.io/original")
    with pytest.raises(RuntimeError, match="origin"):
        handler.redirect_request(request, None, 302, "Found", {}, url)


def test_registry_same_origin_redirect_is_retained() -> None:
    handler = updates._RegistryRedirect("static.crates.io")
    request = updates.urllib.request.Request("https://static.crates.io/original")
    redirected = handler.redirect_request(request, None, 302, "Found", {}, "https://static.crates.io/next")
    assert redirected.full_url == "https://static.crates.io/next"
