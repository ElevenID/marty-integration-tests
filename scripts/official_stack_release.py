#!/usr/bin/env python3
"""Resolve and verify the exact Marty stack release used by official suites."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PIN = ROOT / "conformance" / "stack-under-test.json"
PIN_SCHEMA = "elevenid.official-stack-pin/v1"
STACK_SCHEMA = "marty.stack/v1"
REPOSITORY = "ElevenID/marty-ui"
ASSET = "stack-manifest.json"
SEMVER_TAG = re.compile(r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_NAME = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
OCI_URI = re.compile(r"^[a-z0-9.-]+/[a-z0-9._/-]+$")


def file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def load_pin(path: Path = DEFAULT_PIN) -> dict[str, str | None]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != PIN_SCHEMA:
        raise ValueError(f"stack pin must use {PIN_SCHEMA}")
    if data.get("repository") != REPOSITORY:
        raise ValueError(f"stack pin repository must be {REPOSITORY}")
    if data.get("manifest_asset") != ASSET:
        raise ValueError(f"stack pin manifest_asset must be {ASSET}")
    if not SEMVER_TAG.fullmatch(str(data.get("release_tag", ""))):
        raise ValueError("stack pin release_tag must be a v-prefixed SemVer tag")
    state = data.get("state")
    if state not in {"ready", "awaiting_release"}:
        raise ValueError("stack pin state must be ready or awaiting_release")
    digest = data.get("manifest_sha256")
    if state == "ready" and (not isinstance(digest, str) or not SHA256.fullmatch(digest)):
        raise ValueError("ready stack pin manifest_sha256 must be sha256:<64 lowercase hex>")
    if state == "awaiting_release" and digest is not None:
        raise ValueError("awaiting-release stack pin must not invent a manifest digest")
    return {
        "schema": str(data["schema"]),
        "state": str(state),
        "repository": str(data["repository"]),
        "release_tag": str(data["release_tag"]),
        "manifest_asset": str(data["manifest_asset"]),
        "manifest_sha256": digest,
    }


def resolve_pin(
    pin: dict[str, str | None],
    *,
    release_tag: str | None = None,
    manifest_sha256: str | None = None,
) -> dict[str, str]:
    """Apply an intentional manual override only when tag and digest travel together."""
    supplied = (bool(release_tag), bool(manifest_sha256))
    if supplied[0] != supplied[1]:
        raise ValueError("manual stack override requires both release tag and manifest sha256")
    if not supplied[0]:
        if pin["state"] != "ready":
            raise ValueError(
                f"stack pin is awaiting the signed {pin['release_tag']} release and reviewed manifest sha256"
            )
        return {key: str(value) for key, value in pin.items()}
    if not SEMVER_TAG.fullmatch(release_tag or ""):
        raise ValueError("manual release tag must be a v-prefixed SemVer tag")
    if not SHA256.fullmatch(manifest_sha256 or ""):
        raise ValueError("manual manifest digest must be sha256:<64 lowercase hex>")
    result = dict(pin)
    result["state"] = "ready"
    result["release_tag"] = release_tag or ""
    result["manifest_sha256"] = manifest_sha256 or ""
    return {key: str(value) for key, value in result.items()}


def validate_stack_manifest(path: Path, pin: dict[str, str]) -> dict[str, object]:
    actual_digest = file_sha256(path)
    if actual_digest != pin["manifest_sha256"]:
        raise ValueError(f"stack manifest digest mismatch: got {actual_digest}, expected {pin['manifest_sha256']}")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("schema") != STACK_SCHEMA:
        raise ValueError(f"released stack manifest must use {STACK_SCHEMA}")
    expected_release = f"marty-ui@{pin['release_tag'][1:]}"
    if manifest.get("release") != expected_release:
        raise ValueError(f"released stack is {manifest.get('release')!r}; expected {expected_release!r}")
    components = manifest.get("components")
    if not isinstance(components, list) or not components:
        raise ValueError("released stack manifest contains no components")

    names: set[str] = set()
    images: list[dict[str, str]] = []
    marty_components: list[dict] = []
    for component in components:
        if not isinstance(component, dict):
            raise ValueError("every stack component must be an object")
        name = component.get("name")
        repository = component.get("repository")
        commit = component.get("commit")
        if not isinstance(name, str) or not name or name in names:
            raise ValueError("stack component names must be non-empty and unique")
        names.add(name)
        if not isinstance(repository, str) or not REPOSITORY_NAME.fullmatch(repository):
            raise ValueError(f"{name}: repository must be owner/name")
        if not isinstance(commit, str) or not COMMIT.fullmatch(commit):
            raise ValueError(f"{name}: commit must be a full lowercase SHA")
        if name == "marty-ui":
            marty_components.append(component)
        artifacts = component.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            raise ValueError(f"{name}: at least one artifact is required")
        for artifact in artifacts:
            if not isinstance(artifact, dict) or artifact.get("type") != "oci":
                continue
            uri = artifact.get("uri")
            digest = artifact.get("digest")
            if not isinstance(uri, str) or not OCI_URI.fullmatch(uri) or "@" in uri:
                raise ValueError(f"{name}: OCI URI must be an immutable registry path without tag or digest")
            if not isinstance(digest, str) or not SHA256.fullmatch(digest):
                raise ValueError(f"{name}: OCI artifact must have a sha256 digest")
            images.append(
                {
                    "component": name,
                    "repository": repository,
                    "reference": f"{uri}@{digest}",
                }
            )
    if len(marty_components) != 1 or marty_components[0].get("repository") != REPOSITORY:
        raise ValueError("released stack must contain exactly one ElevenID/marty-ui component")
    if not images:
        raise ValueError("released stack manifest contains no OCI artifacts")
    return {
        "schema": "elevenid.official-stack-material/v1",
        "repository": pin["repository"],
        "release_tag": pin["release_tag"],
        "manifest_asset": pin["manifest_asset"],
        "manifest_path": str(path.resolve()),
        "manifest_sha256": actual_digest,
        "stack_release": expected_release,
        "marty_commit": str(marty_components[0]["commit"]),
        "images": images,
    }


def require_gh() -> str:
    executable = shutil.which("gh")
    if not executable:
        raise ValueError("GitHub CLI is required to download and attest the released stack manifest")
    return executable


def download_and_attest(pin: dict[str, str], output_dir: Path) -> Path:
    gh = require_gh()
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / pin["manifest_asset"]
    if manifest_path.exists():
        raise FileExistsError(f"refusing to reuse an existing stack manifest: {manifest_path}")
    subprocess.run(
        [
            gh,
            "release",
            "download",
            pin["release_tag"],
            "--repo",
            pin["repository"],
            "--pattern",
            pin["manifest_asset"],
            "--dir",
            str(output_dir),
        ],
        check=True,
    )
    if not manifest_path.is_file():
        raise ValueError("GitHub release download did not produce stack-manifest.json")
    # Verify the independent expected hash before asking GitHub to validate its
    # signed build provenance. A mutable release asset cannot silently replace
    # the reviewed stack-under-test pin.
    actual = file_sha256(manifest_path)
    if actual != pin["manifest_sha256"]:
        manifest_path.unlink(missing_ok=True)
        raise ValueError(f"downloaded stack manifest digest is {actual}; expected {pin['manifest_sha256']}")
    subprocess.run(
        [gh, "attestation", "verify", str(manifest_path), "--repo", pin["repository"]],
        check=True,
    )
    return manifest_path


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate-pin")
    validate.add_argument("--pin", type=Path, default=DEFAULT_PIN)
    materialize = commands.add_parser("materialize")
    materialize.add_argument("--pin", type=Path, default=DEFAULT_PIN)
    materialize.add_argument("--release-tag")
    materialize.add_argument("--manifest-sha256")
    materialize.add_argument("--output-dir", type=Path, required=True)
    materialize.add_argument("--metadata-output", type=Path, required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    pin = load_pin(args.pin.resolve())
    if args.command == "validate-pin":
        print(json.dumps(pin, indent=2, sort_keys=True))
        return 0
    resolved = resolve_pin(
        pin,
        release_tag=args.release_tag,
        manifest_sha256=args.manifest_sha256,
    )
    manifest_path = download_and_attest(resolved, args.output_dir.resolve())
    metadata = validate_stack_manifest(manifest_path, resolved)
    metadata_output = args.metadata_output.resolve()
    metadata_output.parent.mkdir(parents=True, exist_ok=True)
    metadata_output.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(metadata, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError, subprocess.CalledProcessError) as exc:
        print(f"Official stack release error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
