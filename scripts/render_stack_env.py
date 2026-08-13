#!/usr/bin/env python3
"""Render digest-only Compose inputs from a marty.stack/v1 manifest."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).parent))
from docker_context import docker_command

DIGEST = re.compile(r"sha256:[0-9a-f]{64}$")
FORBIDDEN = ("square", "subscription", "billing", "product-catalog", "product_catalog")
REQUIRED_IMAGES = {
    "MARTY_UI_IMAGE": "ui",
    "MARTY_SERVICES_IMAGE": "services",
    "MARTY_MIGRATIONS_IMAGE": "migrations",
    "MARTY_ISSUANCE_IMAGE": "marty-credentials-issuance",
}
REQUIRED_PYTHON_ARTIFACTS = {
    "MARTY_RS": ("marty-core-python", "python", "ElevenID/marty-core"),
    "MARTY_VERIFICATION": ("marty-verification-python", "python", "ElevenID/marty-core"),
    "MARTY_ISO18013": ("marty-iso18013-python", "python", "ElevenID/marty-core"),
    "MARTY_COMMON": ("marty-common", "python", "ElevenID/Marty"),
}
RELEASE_SEGMENT = re.compile(r"[0-9A-Za-z._+-]+$")
WHEEL_SEGMENT = re.compile(r"[0-9A-Za-z._+-]+\.whl$")


def load_manifest(path: Path) -> dict:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("schema") != "marty.stack/v1":
        raise ValueError("manifest schema must be marty.stack/v1")
    serialized = json.dumps(manifest).lower()
    for marker in FORBIDDEN:
        if marker in serialized:
            raise ValueError(f"forbidden commerce marker in manifest: {marker}")
    return manifest


def image_map(manifest: dict) -> dict[str, str]:
    images: list[str] = []
    for component in manifest.get("components", []):
        for artifact in component.get("artifacts", []):
            if artifact.get("type") != "oci":
                continue
            uri = artifact.get("uri", "")
            digest = artifact.get("digest", "")
            if not DIGEST.fullmatch(digest):
                raise ValueError(f"invalid OCI digest for {uri}")
            if ":" in uri.rsplit("/", 1)[-1]:
                raise ValueError(f"OCI URI must not contain a mutable tag: {uri}")
            images.append(f"{uri}@{digest}")

    rendered: dict[str, str] = {}
    for variable, repository in REQUIRED_IMAGES.items():
        matches = [
            image
            for image in images
            if image.split("@", 1)[0].rstrip("/").rsplit("/", 1)[-1] == repository
        ]
        if len(matches) != 1:
            raise ValueError(
                f"expected exactly one image with repository name {repository}, "
                f"found {len(matches)}"
            )
        rendered[variable] = matches[0]
    return rendered


def python_artifact_map(manifest: dict) -> dict[str, str]:
    """Render immutable wheel inputs required when Compose builds local adapters."""
    rendered: dict[str, str] = {}
    components = manifest.get("components", [])
    if not isinstance(components, list):
        raise ValueError("stack manifest components must be a list")
    for variable, (component_name, artifact_type, repository) in REQUIRED_PYTHON_ARTIFACTS.items():
        matches = [
            artifact
            for component in components
            if isinstance(component, dict)
            and component.get("name") == component_name
            and component.get("repository") == repository
            for artifact in (component.get("artifacts") if isinstance(component.get("artifacts"), list) else [])
            if isinstance(artifact, dict) and artifact.get("type") == artifact_type
        ]
        if len(matches) != 1:
            raise ValueError(
                f"expected exactly one {artifact_type} artifact for {component_name} from "
                f"{repository}, found {len(matches)}"
            )
        artifact = matches[0]
        uri = artifact.get("uri")
        digest = artifact.get("digest")
        if not isinstance(uri, str) or not immutable_wheel_uri(uri, repository):
            raise ValueError(f"{component_name} must use an immutable GitHub release wheel")
        if not DIGEST.fullmatch(digest if isinstance(digest, str) else ""):
            raise ValueError(f"{component_name} must use an immutable GitHub release artifact")
        rendered[f"{variable}_URI"] = uri
        rendered[f"{variable}_DIGEST"] = digest
    return rendered


def immutable_wheel_uri(uri: str, repository: str) -> bool:
    """Accept one unambiguous wheel URL from the component's governed repository."""
    try:
        parsed = urlsplit(uri)
    except ValueError:
        return False
    if (
        parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        return False
    prefix = f"/{repository}/releases/download/"
    if not parsed.path.startswith(prefix):
        return False
    remainder = parsed.path.removeprefix(prefix)
    parts = remainder.split("/")
    return len(parts) == 2 and bool(RELEASE_SEGMENT.fullmatch(parts[0])) and bool(WHEEL_SEGMENT.fullmatch(parts[1]))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path(".env.stack"))
    parser.add_argument("--pull", action="store_true")
    parser.add_argument("--previous-manifest", type=Path)
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)
    images = image_map(manifest)
    artifacts = python_artifact_map(manifest)
    base = json.loads(Path("config/base-images.json").read_text(encoding="utf-8"))
    images["POSTGRES_IMAGE"] = base["postgres"]
    images["REDIS_IMAGE"] = base["redis"]
    for value in images.values():
        if "@sha256:" not in value:
            raise ValueError(f"image is not pinned by digest: {value}")

    args.output.write_text(
        "\n".join(f"{key}={value}" for key, value in sorted({**images, **artifacts}.items())) + "\n",
        encoding="utf-8",
    )

    if args.previous_manifest:
        previous = image_map(load_manifest(args.previous_manifest))
        if set(previous) != set(image_map(manifest)):
            raise ValueError("upgrade/rollback manifests do not expose the same image roles")
        print("Validated upgrade and rollback image roles.")

    if args.pull:
        for image in images.values():
            subprocess.run(docker_command(["pull", image]), check=True)
    print(f"Rendered {len(images)} immutable images to {args.output}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
