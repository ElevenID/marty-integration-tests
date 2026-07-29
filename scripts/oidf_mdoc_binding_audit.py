#!/usr/bin/env python3
"""Compare OIDF-generated mdoc bindings with privacy-safe Marty diagnostics.

The official suite export is read as evidence and is never modified. Output
contains hashes and booleans only; credential bytes and request values remain
inside the disposable runner workspace.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

HEX = r"[0-9a-f]{64}"
FLOW_BINDING = re.compile(
    rf"OID4VP mdoc binding flow_instance_sha256=(?P<flow>{HEX}) "
    rf"transcript_sha256=(?P<transcript>{HEX}) "
    rf"client_id_sha256=(?P<client_id>{HEX}) nonce_sha256=(?P<nonce>{HEX}) "
    rf"response_uri_sha256=(?P<response_uri>{HEX}) "
    rf"response_key_thumbprint_sha256=(?P<response_key>{HEX}|none) "
    rf"presentation_sha256=(?P<presentation>{HEX})"
)
POLICY_BINDING = re.compile(
    rf"mDoc verification binding transcript_sha256=(?P<transcript>{HEX}) "
    rf"device_response_sha256=(?P<device_response>{HEX}) "
    r"issuer_signature_valid=(?P<issuer_signature>True|False) "
    r"issuer_trusted=(?P<issuer_trusted>True|False) "
    r"device_authentication_valid=(?P<device_authentication>True|False)"
)
FLOW_PATH = re.compile(r"/v1/flows/instances/([^/]+)/submit$")
FIELDS = (
    "transcript",
    "client_id",
    "nonce",
    "response_uri",
    "response_key",
    "presentation",
    "device_response",
)


def digest(value: bytes | str) -> str:
    data = value if isinstance(value, bytes) else value.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def decode_b64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _official_presentation(records: list[dict[str, Any]], name: str) -> str:
    for record in records:
        value = record.get("vp_token")
        if not isinstance(value, dict) or len(value) != 1:
            continue
        presentations = next(iter(value.values()))
        if (
            isinstance(presentations, list)
            and len(presentations) == 1
            and isinstance(presentations[0], str)
            and presentations[0]
        ):
            return presentations[0]
    raise ValueError(f"{name} has no one-query/one-presentation mdoc response")


def _official_modules(export_dir: Path) -> list[dict[str, Any]]:
    exports = sorted(export_dir.glob("*.zip"))
    if len(exports) != 1:
        raise ValueError(f"expected exactly one official OIDF export, found {len(exports)}")
    modules: list[dict[str, Any]] = []
    with zipfile.ZipFile(exports[0]) as archive:
        for name in sorted(archive.namelist()):
            if not name.endswith(".json") or not name.startswith("test-log-"):
                continue
            payload = json.loads(archive.read(name))
            records = payload.get("results", [])
            transcript_record = next(
                (
                    record
                    for record in records
                    if isinstance(record, dict)
                    and isinstance(record.get("session_transcript_b64"), str)
                    and isinstance(record.get("session_transcript_input"), dict)
                ),
                None,
            )
            if transcript_record is None:
                continue
            inputs = transcript_record["session_transcript_input"]
            client_id = inputs.get("client_id")
            nonce = inputs.get("nonce")
            response_uri = inputs.get("response_uri")
            if not all(isinstance(value, str) and value for value in (client_id, nonce, response_uri)):
                raise ValueError(f"{name} has an incomplete official session transcript input")
            match = FLOW_PATH.search(urlparse(response_uri).path)
            if match is None:
                raise ValueError(f"{name} response URI does not identify a Marty flow")
            thumbprint = inputs.get("jwkThumbprint_b64")
            response_key = (
                "none"
                if thumbprint in {None, "<null>"}
                else digest(decode_b64(thumbprint))
                if isinstance(thumbprint, str)
                else None
            )
            if response_key is None:
                raise ValueError(f"{name} has an invalid response-key thumbprint")
            test_info = payload.get("testInfo", {})
            test_name = test_info.get("testName")
            if not isinstance(test_name, str) or not test_name:
                raise ValueError(f"{name} has no official test name")
            presentation = _official_presentation(records, name)
            modules.append(
                {
                    "test_name": test_name,
                    "flow": digest(match.group(1)),
                    "transcript": digest(decode_b64(transcript_record["session_transcript_b64"])),
                    "client_id": digest(client_id),
                    "nonce": digest(nonce),
                    "response_uri": digest(response_uri),
                    "response_key": response_key,
                    "presentation": digest(presentation),
                    "device_response": digest(decode_b64(presentation)),
                }
            )
    if not modules:
        raise ValueError("official OIDF export contains no mdoc session transcripts")
    return modules


def _runtime_bindings(
    compose_log: Path,
) -> tuple[dict[str, dict[str, str]], set[tuple[str, str]]]:
    text = compose_log.read_text(encoding="utf-8", errors="replace")
    flows: dict[str, dict[str, str]] = {}
    for match in FLOW_BINDING.finditer(text):
        values = match.groupdict()
        flow = values.pop("flow")
        previous = flows.get(flow)
        if previous is not None and previous != values:
            raise ValueError("one Marty flow emitted conflicting mdoc binding diagnostics")
        flows[flow] = values
    policy_presentations = {
        (match.group("transcript"), match.group("device_response"))
        for match in POLICY_BINDING.finditer(text)
    }
    return flows, policy_presentations


def audit(export_dir: Path, compose_log: Path) -> dict[str, Any]:
    official_modules = _official_modules(export_dir)
    runtime_flows, policy_presentations = _runtime_bindings(compose_log)
    modules: list[dict[str, Any]] = []
    for official in official_modules:
        runtime = runtime_flows.get(official["flow"])
        negative = "invalid-session-transcript" in official["test_name"]
        if runtime is None:
            matches = dict.fromkeys(FIELDS, False)
            forwarded = False
            status = "runtime-binding-unavailable"
        else:
            matches = {
                field: official[field] == runtime[field]
                for field in FIELDS
                if field != "device_response"
            }
            forwarded = (
                runtime["transcript"],
                official["device_response"],
            ) in policy_presentations
            matches["device_response"] = forwarded
            binding_matches = all(matches.values())
            expected = not negative
            status = (
                "expected-binding-observed"
                if binding_matches == expected and forwarded
                else "unexpected-binding-observed"
            )
        modules.append(
            {
                "test_name": official["test_name"],
                "expectation": (
                    "reject-mismatched-session-transcript"
                    if negative
                    else "accept-matching-session-transcript"
                ),
                "binding_matches": matches,
                "product_transcript_forwarded": forwarded,
                "status": status,
            }
        )
    return {
        "schema": "elevenid.oidf-mdoc-binding-audit/v1",
        "source_policy": "unmodified",
        "modules": modules,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--export-dir", type=Path, required=True)
    result.add_argument("--compose-log", type=Path, required=True)
    result.add_argument("--output", type=Path, required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    report = audit(args.export_dir, args.compose_log)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print("--- OIDF mdoc binding audit (redacted) ---")
    for module in report["modules"]:
        mismatches = ",".join(
            field for field, matched in module["binding_matches"].items() if not matched
        )
        print(
            f"{module['test_name']}: status={module['status']} "
            f"mismatches={mismatches or 'none'}"
        )
    print("--- end OIDF mdoc binding audit ---")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
