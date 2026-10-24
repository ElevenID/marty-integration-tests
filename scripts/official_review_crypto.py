#!/usr/bin/env python3
"""Install the digest-pinned standard age encryptor without any private identity."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import platform
import re
import stat
import tarfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_ARCHIVE = 64 * 1024 * 1024


def read_regular(path: Path, maximum: int = MAX_ARCHIVE) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError("review input must be a bounded regular file")
    with path.open("rb") as source:
        value = source.read(maximum + 1)
    if len(value) > maximum:
        raise ValueError("review input exceeds its size limit")
    return value


def asset(manifest: dict, target: str) -> dict:
    if (
        manifest.get("schema") != "elevenid.review-encryption-tool/v1"
        or manifest.get("repository") != "https://github.com/FiloSottile/age"
        or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", manifest.get("version", ""))
    ):
        raise ValueError("review encryptor manifest is invalid")
    selected = manifest["assets"][target]
    suffix = ".zip" if target == "windows-amd64" else ".tar.gz"
    if selected.get("name") != f"age-{manifest['version']}-{target}{suffix}" or not re.fullmatch(
        r"[0-9a-f]{64}", selected.get("sha256", "")
    ):
        raise ValueError("review encryptor asset is not pinned")
    return selected


def binary_members(archive: bytes, target: str) -> dict[str, bytes]:
    names = ["age.exe", "age-keygen.exe"] if target == "windows-amd64" else ["age", "age-keygen"]
    result = {}
    if target == "windows-amd64":
        with zipfile.ZipFile(io.BytesIO(archive)) as source:
            for name in names:
                member = source.getinfo("age/" + name)
                if member.is_dir() or stat.S_ISLNK(member.external_attr >> 16) or member.file_size > MAX_ARCHIVE:
                    raise ValueError("review encryptor archive member is not a bounded regular file")
                result[name] = source.read(member)
    else:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as source:
            for name in names:
                member = source.getmember("age/" + name)
                if not member.isfile() or member.size > MAX_ARCHIVE:
                    raise ValueError("review encryptor archive member is not a bounded regular file")
                stream = source.extractfile(member)
                if stream is None:
                    raise ValueError("review encryptor archive member is missing")
                result[name] = stream.read(MAX_ARCHIVE + 1)
    if any(not value or len(value) > MAX_ARCHIVE for value in result.values()):
        raise ValueError("review encryptor binary size is invalid")
    return result


def install(manifest: dict, target: str, destination: Path) -> dict:
    selected = asset(manifest, target)
    if destination.is_symlink():
        raise ValueError("review encryptor destination must not be a symlink")
    destination.mkdir(parents=True, exist_ok=True)
    cache = destination / selected["name"]
    if cache.exists() or cache.is_symlink():
        archive = read_regular(cache)
    else:
        url = f"{manifest['repository']}/releases/download/{manifest['version']}/{selected['name']}"
        with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 - fixed official HTTPS origin
            archive = response.read(MAX_ARCHIVE + 1)
    if len(archive) > MAX_ARCHIVE or hashlib.sha256(archive).hexdigest() != selected["sha256"]:
        raise ValueError("review encryptor archive differs from its pinned digest")
    members = binary_members(archive, target)
    if not cache.exists():
        with cache.open("xb") as output:
            output.write(archive)
    hashes = {}
    for name, value in members.items():
        path = destination / name
        if path.exists() or path.is_symlink():
            if read_regular(path) != value:
                raise ValueError("existing review encryptor was changed; preserving it")
        else:
            with path.open("xb") as output:
                output.write(value)
        path.chmod(0o755)
        hashes[name] = hashlib.sha256(value).hexdigest()
    receipt = {
        "schema": "elevenid.review-encryptor-install/v1",
        "version": manifest["version"],
        "target": target,
        "archive_sha256": selected["sha256"],
        "binaries": hashes,
    }
    path = destination / "install-receipt.json"
    if path.exists() or path.is_symlink():
        if json.loads(read_regular(path)) != receipt:
            raise ValueError("existing review encryptor custody differs; preserving it")
    else:
        with path.open("x", encoding="utf-8") as output:
            json.dump(receipt, output, indent=2, sort_keys=True)
            output.write("\n")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "conformance/review-encryption-tool.json")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    machine = platform.machine().lower()
    target = {"linux": "linux-amd64", "windows": "windows-amd64"}.get(platform.system().lower())
    if machine not in {"amd64", "x86_64"} or target is None:
        parser.error("review encryptor supports only the pinned amd64 platforms")
    try:
        receipt = install(json.loads(read_regular(args.manifest)), target, args.output)
    except (OSError, ValueError, KeyError, tarfile.TarError, zipfile.BadZipFile):
        print("Review encryptor installation failed its origin/digest/custody checks.")
        return 1
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
