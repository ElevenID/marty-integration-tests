#!/usr/bin/env python3
"""Exercise a digest-pinned released Rust verifier with fresh KMS/wallet input."""

from __future__ import annotations

import argparse
import json
import subprocess

from credentials_verifier_artifact import (
    _run_positive_oid4vp_gate,
    positive_oid4vp_public_input,
)


def rejected(image: str, public_input: dict) -> bool:
    result = subprocess.run(
        ["docker", "run", "--rm", "-i", "--network", "none", image,
         "/usr/local/bin/marty-verifier-positive-gate"],
        input=json.dumps(public_input), capture_output=True, text=True,
        timeout=120, check=False,
    )
    return result.returncode != 0 and not result.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    evidence = _run_positive_oid4vp_gate(args.image)
    public_input = positive_oid4vp_public_input()
    parts = public_input["presentation"].split("~")
    jwt = parts[0].split(".")
    if len(jwt) != 3 or not jwt[2]:
        raise ValueError("remote issuer JWT shape changed")
    jwt[2] = ("A" if jwt[2][0] != "A" else "B") + jwt[2][1:]
    parts[0] = ".".join(jwt)
    tampered = dict(public_input, presentation="~".join(parts))
    if not rejected(args.image, tampered):
        raise ValueError("released verifier accepted a tampered issuer signature")
    private = dict(public_input, issuer_public_jwk=dict(public_input["issuer_public_jwk"], d="forbidden"))
    if not rejected(args.image, private):
        raise ValueError("released verifier accepted a private issuer JWK member")
    print(json.dumps({"status": evidence["status"], "decision": evidence["decision"],
                      "checks": len(evidence["checks"]),
                      "tampered_issuer_signature": "rejected",
                      "private_issuer_jwk": "rejected"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
