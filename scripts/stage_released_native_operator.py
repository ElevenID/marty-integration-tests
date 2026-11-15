#!/usr/bin/env python3
"""Stage the signed, source-matched operator for a pinned published stack."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import runpy
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

from official_stack_release import load_pin, resolve_pin

OPERATOR = "marty-deploy-linux-amd64"
INVENTORY = "installer-inventory.json"
WORKFLOW = ".github/workflows/cd.yml"
MAXIMUM_OPERATOR_BYTES = 512 * 1024 * 1024


def file_digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def build_identity(binary: Path) -> str:
    return subprocess.run(
        [str(binary), "--build-identity"], capture_output=True, text=True, check=True, timeout=10,
    ).stdout.strip()


def stage(
    pin: dict[str, str], checkout: Path, output: Path, *, gh: Path, cosign: Path,
    probe: Callable[[Path], str] = build_identity,
) -> dict[str, str]:
    """Authenticate both published subjects before executing the native probe.

    The inventory's producer fields are not trusted until its own signature and
    provenance have been checked against the independently reviewed stack pin.
    The same producer must then authenticate the exact inventoried operator.
    """
    checkout = checkout.resolve(strict=True)
    output = output.parent.resolve(strict=True) / output.name
    if pin["marty_commit"] != pin["marty_checkout_commit"]:
        raise ValueError("released operator requires its exact source checkout")
    actual = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True, timeout=10,
    ).stdout.strip()
    if actual != pin["marty_commit"] or output.is_relative_to(checkout):
        raise ValueError("released operator source or output root is invalid")
    verifier_path = checkout / "scripts/verify_installer_provenance.py"
    expected_verifier = subprocess.run(
        ["git", "-C", str(checkout), "show", f"{actual}:scripts/verify_installer_provenance.py"],
        capture_output=True, check=True, timeout=10,
    ).stdout
    # Python consumes universal newlines; Windows Git checkouts may use CRLF.
    if (verifier_path.is_symlink()
            or verifier_path.read_bytes().replace(b"\r\n", b"\n") != expected_verifier.replace(b"\r\n", b"\n")):
        raise ValueError("released operator verifier differs from the pinned source")
    verifier = runpy.run_path(str(verifier_path))["verify_subject"]
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    command = [str(gh), "release", "download", pin["release_tag"], "--repo", pin["repository"],
               "--dir", str(output)]
    for name in (INVENTORY, OPERATOR):
        for suffix in ("", ".provenance.jsonl", ".sigstore.json"):
            command.extend(("--pattern", name + suffix))
    subprocess.run(command, check=True, timeout=180)
    for path in output.iterdir():
        if path.is_symlink() or not path.is_file():
            raise ValueError("released operator download contains an unexpected entry")
        path.chmod(0o600)
    inventory_path = output / INVENTORY
    if inventory_path.stat().st_size > 64 * 1024:
        raise ValueError("released installer inventory is oversized")
    inventory_digest = file_digest(inventory_path)
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    if (
        inventory.get("schema") != "elevenid.installer-inventory/v1"
        or inventory.get("repository") != pin["repository"]
        or inventory.get("platform") != "linux/amd64"
        or inventory.get("source_sha") != pin["marty_commit"]
        or inventory.get("release_tag") != pin["release_tag"]
        or type(inventory.get("build_run_id")) is not int
        or inventory["build_run_id"] <= 0
        or type(inventory.get("build_run_attempt")) is not int
        or inventory["build_run_attempt"] <= 0
    ):
        raise ValueError("released installer inventory does not match the reviewed platform")
    identity = {
        "gh": gh, "cosign": cosign, "workflow": WORKFLOW, "source_sha": pin["marty_commit"],
        "run_id": inventory["build_run_id"], "run_attempt": inventory["build_run_attempt"],
    }
    verifier(inventory_path, output / (INVENTORY + ".provenance.jsonl"),
             signature_bundle=output / (INVENTORY + ".sigstore.json"), **identity)
    entries = inventory.get("artifacts")
    matches = [item for item in entries if isinstance(item, dict) and item.get("name") == OPERATOR] \
        if isinstance(entries, list) else []
    if len(matches) != 1:
        raise ValueError("released installer inventory has no unique native operator")
    entry = matches[0]
    if (
        type(entry.get("size")) is not int or not 0 < entry["size"] <= MAXIMUM_OPERATOR_BYTES
        or not isinstance(entry.get("sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
    ):
        raise ValueError("released native operator inventory entry is invalid")
    binary = output / OPERATOR

    def unchanged() -> bool:
        return (not binary.is_symlink() and not inventory_path.is_symlink()
                and binary.stat().st_size == entry["size"] and file_digest(binary) == entry["sha256"]
                and file_digest(inventory_path) == inventory_digest)

    if not unchanged():
        raise ValueError("released native operator differs from the authenticated inventory")
    verifier(binary, output / (OPERATOR + ".provenance.jsonl"),
             signature_bundle=output / (OPERATOR + ".sigstore.json"), **identity)
    binary.chmod(0o700)
    if not unchanged() or probe(binary) != f"{pin['marty_commit']}:{pin['release_tag']}" or not unchanged():
        raise ValueError("released native operator build identity or bytes changed")
    return {
        "MARTY_DEPLOY_BIN": str(binary), "MARTY_DEPLOY_BIN_SHA256": entry["sha256"],
        "MARTY_DEPLOY_SOURCE_SHA": pin["marty_commit"], "MARTY_DEPLOY_RELEASE_TAG": pin["release_tag"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pin", type=Path, required=True)
    parser.add_argument("--marty-ui", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--github-env", type=Path, required=True)
    args = parser.parse_args()
    gh, cosign = shutil.which("gh"), shutil.which("cosign")
    if not gh or not cosign:
        raise ValueError("published native staging requires gh and cosign")
    if any(os.environ.get(name) for name in (
        "MARTY_DEPLOY_BIN", "MARTY_DEPLOY_BIN_SHA256", "MARTY_DEPLOY_SOURCE_SHA", "MARTY_DEPLOY_RELEASE_TAG",
    )):
        raise ValueError("published native staging refuses an existing operator selection")
    values = stage(resolve_pin(load_pin(args.pin)), args.marty_ui, args.output,
                   gh=Path(gh), cosign=Path(cosign))
    if any("\n" in value or "\r" in value for value in values.values()):
        raise ValueError("published native environment contains an invalid value")
    with args.github_env.open("a", encoding="utf-8") as stream:
        stream.write("".join(f"{key}={value}\n" for key, value in values.items()))
    print("Staged signed, source-matched published native operator.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
