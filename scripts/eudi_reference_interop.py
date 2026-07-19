#!/usr/bin/env python3
"""Validate immutable inputs for EUDI reference-wallet interoperability."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "conformance" / "eudi-reference-interop.json"
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST_IMAGE = re.compile(r"^ghcr\.io/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$")


def load_manifest(path: Path = MANIFEST) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != "elevenid.eudi-reference-interop/v1":
        raise ValueError("unsupported EUDI interop manifest schema")
    components = data.get("components", {})
    for name in ("wallet_tester", "verifier_endpoint", "wallet_kit"):
        component = components.get(name, {})
        if not component.get("repository", "").startswith("https://github.com/eu-digital-identity-wallet/"):
            raise ValueError(f"{name} must point to an official EUDI repository")
        if not SHA.fullmatch(component.get("commit", "")):
            raise ValueError(f"{name} must pin a full commit SHA")
        image = component.get("image")
        if image is not None and not DIGEST_IMAGE.fullmatch(image):
            raise ValueError(f"{name} image must be pinned by sha256 digest")
    coverage = data.get("coverage", {})
    if not {"sd_jwt_vc", "mso_mdoc"} <= set(coverage.get("issuance", [])):
        raise ValueError("EUDI issuance coverage must include SD-JWT VC and mdoc")
    if not {"sd_jwt_vc", "mso_mdoc"} <= set(coverage.get("presentation", [])):
        raise ValueError("EUDI presentation coverage must include SD-JWT VC and mdoc")
    if "replayed_response" not in coverage.get("negative", []):
        raise ValueError("EUDI coverage must include replay rejection")
    return data


if __name__ == "__main__":
    try:
        manifest = load_manifest()
        print("EUDI reference interop manifest is valid:", manifest["components"]["wallet_tester"]["commit"])
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"EUDI reference interop setup error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
