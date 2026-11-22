#!/usr/bin/env python3
"""Verify the offline CLI release lookup pin or restore it from a local CLI checkout."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
MODULE = SCRIPTS / "release_lookup.py"
PIN = SCRIPTS / "release_lookup.source.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-repo", type=Path, help="Restore the pin using this local marty-cli checkout")
    args = parser.parse_args()

    pin = json.loads(PIN.read_text(encoding="utf-8"))
    revision = pin["revision"]
    if pin["repository"] != "ElevenID/marty-cli" or re.fullmatch(r"[a-f0-9]{40}", revision) is None:
        parser.exit(1, "Expected an immutable marty-cli source revision.\n")

    if args.source_repo is None:
        source = MODULE.read_bytes()
    else:
        source = subprocess.check_output(
            ["git", "-C", str(args.source_repo), "show", f"{revision}:scripts/release_lookup.py"],
        )
    if hashlib.sha256(source).hexdigest() != pin["sha256"]:
        parser.exit(1, "Release lookup bytes do not match the recorded SHA-256.\n")
    if args.source_repo is not None:
        MODULE.write_bytes(source)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
