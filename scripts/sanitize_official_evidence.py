#!/usr/bin/env python3
"""Create a public-safe summary of private official-suite run evidence."""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ElementTree
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

SCHEMA = "elevenid.sanitized-official-interop/v1"
LANES = {"oid4vp-final", "haip", "w3c-v2", "eudi"}
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SENSITIVE_KEY = re.compile(
    r"(?:^|_)(?:authorization|cookie|password|secret|session|signing_jwk|private_key|access_token|refresh_token)(?:$|_)",
    re.IGNORECASE,
)
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)?\b")
SECRET_MARKERS = ("-----BEGIN PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----", "sessionId=")


def _safe_string(value: str) -> tuple[str, int]:
    if any(marker in value for marker in SECRET_MARKERS) or JWT.search(value):
        return "[REDACTED]", 1
    if value.startswith(("http://", "https://")):
        parsed = urlsplit(value)
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            return urlunsplit((parsed.scheme, parsed.hostname or "", parsed.path, "", "")), 1
    if Path(value).is_absolute():
        return Path(value).name, 1
    return value, 0


def sanitize(value: object, *, key: str = "") -> tuple[object, int]:
    if key and SENSITIVE_KEY.search(key):
        return "[REDACTED]", 1
    if isinstance(value, dict):
        result: dict[str, object] = {}
        redactions = 0
        for child_key, child_value in value.items():
            clean, count = sanitize(child_value, key=str(child_key))
            result[str(child_key)] = clean
            redactions += count
        return result, redactions
    if isinstance(value, list):
        result_list: list[object] = []
        redactions = 0
        for item in value:
            clean, count = sanitize(item)
            result_list.append(clean)
            redactions += count
        return result_list, redactions
    if isinstance(value, str):
        return _safe_string(value)
    return value, 0


def junit_summary(path: Path) -> dict[str, int]:
    root = ElementTree.parse(path).getroot()
    totals = dict.fromkeys(("tests", "failures", "errors", "skipped"), 0)
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    for suite in suites:
        for name in totals:
            totals[name] += int(suite.attrib.get(name, "0"))
    return totals


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def build_summary(
    input_dir: Path,
    *,
    lane: str,
    harness_commit: str,
    exit_code: int,
    stack_metadata: Path | None = None,
    material_report: Path | None = None,
) -> dict[str, object]:
    if lane not in LANES:
        raise ValueError(f"unknown official interoperability lane: {lane}")
    if not COMMIT.fullmatch(harness_commit):
        raise ValueError("harness commit must be a full lowercase SHA")

    redactions = 0
    stack: object | None = None
    if stack_metadata and stack_metadata.is_file():
        stack, count = sanitize(load_json(stack_metadata))
        redactions += count
    material: object | None = None
    if material_report and material_report.is_file():
        material, count = sanitize(load_json(material_report))
        redactions += count

    evidence: list[dict[str, object]] = []
    junit: list[dict[str, object]] = []
    if input_dir.is_dir():
        for path in sorted(input_dir.rglob("evidence.json")):
            clean, count = sanitize(load_json(path))
            redactions += count
            evidence.append({"source": path.relative_to(input_dir).as_posix(), "evidence": clean})
        for path in sorted(input_dir.rglob("*.xml")):
            try:
                counts = junit_summary(path)
            except (ElementTree.ParseError, ValueError):
                continue
            junit.append({"source": path.relative_to(input_dir).as_posix(), **counts})

    return {
        "schema": SCHEMA,
        "lane": lane,
        "harness_commit": harness_commit,
        "result": {"exit_code": exit_code, "passed": exit_code == 0},
        "stack": stack,
        "material": material,
        "official_evidence": evidence,
        "junit": junit,
        "redactions": redactions,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--input", type=Path, required=True)
    result.add_argument("--output", type=Path, required=True)
    result.add_argument("--lane", choices=sorted(LANES), required=True)
    result.add_argument("--harness-commit", required=True)
    result.add_argument("--exit-code", type=int, required=True)
    result.add_argument("--stack-metadata", type=Path)
    result.add_argument("--material-report", type=Path)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    summary = build_summary(
        args.input.resolve(),
        lane=args.lane,
        harness_commit=args.harness_commit,
        exit_code=args.exit_code,
        stack_metadata=args.stack_metadata.resolve() if args.stack_metadata else None,
        material_report=args.material_report.resolve() if args.material_report else None,
    )
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    destination = output / "summary.json"
    destination.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(destination)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError, ElementTree.ParseError) as exc:
        print(f"Official evidence sanitization error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
