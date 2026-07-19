#!/usr/bin/env python3
"""Render digest-only Compose inputs from a marty.stack/v1 manifest."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path(".env.stack"))
    parser.add_argument("--pull", action="store_true")
    parser.add_argument("--previous-manifest", type=Path)
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)
    images = image_map(manifest)
    base = json.loads(Path("config/base-images.json").read_text(encoding="utf-8"))
    images["POSTGRES_IMAGE"] = base["postgres"]
    images["REDIS_IMAGE"] = base["redis"]
    for value in images.values():
        if "@sha256:" not in value:
            raise ValueError(f"image is not pinned by digest: {value}")

    args.output.write_text(
        "\n".join(f"{key}={images[key]}" for key in sorted(images)) + "\n",
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
