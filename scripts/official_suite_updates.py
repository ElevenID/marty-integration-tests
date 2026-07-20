#!/usr/bin/env python3
"""Detect official interoperability-suite drift without changing test pins.

The resulting review record is deliberately separate from the pinned manifests:
an automated PR makes a new upstream revision visible, while a maintainer must
still review compatibility, image digests, and test results before changing a
pin used by release evidence.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "conformance" / "upstream-review.json"


def git_head(repository: str, ref: str = "HEAD") -> str:
    output = subprocess.check_output(["git", "ls-remote", repository, ref], text=True)
    sha = output.split()[0] if output.split() else ""
    if len(sha) != 40:
        raise RuntimeError(f"no full commit SHA returned for {repository} {ref}")
    return sha


def latest_oidf_release() -> str:
    request = urllib.request.Request(
        "https://gitlab.com/api/v4/projects/openid%2Fconformance-suite/releases/permalink/latest",
        headers={"Accept": "application/json", "User-Agent": "ElevenID-Official-Suite-Updates"},
    )
    # B310: the request URL above is a fixed official GitLab HTTPS endpoint.
    with urllib.request.urlopen(request, timeout=20) as response:  # nosec B310
        payload: object = json.load(response)
    if not isinstance(payload, dict):
        raise RuntimeError("OIDF latest-release response is not a JSON object")
    value = payload.get("tag_name")
    if not isinstance(value, str):
        raise RuntimeError("OIDF latest-release response has no string tag_name")
    if not value.startswith("release-v"):
        raise RuntimeError("OIDF latest-release response has no release-v tag")
    return value


def load_json(relative: str) -> dict[str, Any]:
    value: object = json.loads((ROOT / relative).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"{relative} must contain a JSON object")
    return cast(dict[str, Any], value)


def observe() -> dict:
    oidf = load_json("conformance/oidf-runner.json")["official_runner"]
    w3c = load_json("conformance/w3c-vc-data-model-v2.json")["official_suite"]
    eudi = load_json("conformance/eudi-reference-interop.json")["components"]
    upstreams = {
        "oidf": {
            "pinned_release": oidf["release"],
            "latest_release": latest_oidf_release(),
        },
        "w3c_vc_data_model_v2": {
            "pinned_commit": w3c["commit"],
            "latest_commit": git_head(w3c["repository"], "refs/heads/main"),
        },
        "eudi_wallet_tester": {
            "pinned_commit": eudi["wallet_tester"]["commit"],
            "latest_commit": git_head(eudi["wallet_tester"]["repository"], "refs/heads/main"),
        },
        "eudi_verifier_endpoint": {
            "pinned_commit": eudi["verifier_endpoint"]["commit"],
            "latest_commit": git_head(eudi["verifier_endpoint"]["repository"], "refs/heads/main"),
        },
    }
    for name, library in eudi["wallet_kit"]["libraries"].items():
        upstreams[f"eudi_wallet_kit_{name}"] = {
            "pinned_commit": library["commit"],
            "latest_commit": git_head(library["repository"], "refs/heads/main"),
        }
    return {
        "schema": "elevenid.official-suite-upstream-review/v1",
        "upstreams": upstreams,
    }


def has_drift(observation: dict) -> bool:
    values = observation["upstreams"].values()
    return any(
        entry.get("pinned_release") != entry.get("latest_release")
        or entry.get("pinned_commit") != entry.get("latest_commit")
        for entry in values
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    observation = observe()
    drift = has_drift(observation)
    if args.write and drift:
        observation["observed_at"] = datetime.now(UTC).isoformat()
        RECORD.write_text(json.dumps(observation, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(observation, indent=2, sort_keys=True))
    return 3 if drift else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f"Official suite update check failed: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
