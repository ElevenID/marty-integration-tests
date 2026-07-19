#!/usr/bin/env python3
"""Validate and execute the pinned W3C VC Data Model v2 suite boundary."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "conformance" / "w3c-vc-data-model-v2.json"
SHA = re.compile(r"^[0-9a-f]{40}$")


def load_manifest(path: Path = MANIFEST) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != "elevenid.official-vc-suite/v1":
        raise ValueError("unsupported W3C VC suite manifest schema")
    suite = data.get("official_suite", {})
    if suite.get("repository") != "https://github.com/w3c/vc-data-model-2.0-test-suite.git":
        raise ValueError("W3C VC suite must use the official repository")
    if not SHA.fullmatch(suite.get("commit", "")):
        raise ValueError("W3C VC suite commit must be a full lowercase SHA")
    for exclusion in data.get("exclusions", []):
        if not {"capability", "reason", "owner", "review_date"} <= exclusion.keys():
            raise ValueError("every W3C exclusion needs capability, reason, owner, and review_date")
    return data


def revision(path: Path) -> str:
    return subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()


def validate_checkout(path: Path, manifest: dict) -> None:
    if not (path / "package.json").is_file():
        raise ValueError("W3C VC suite package.json is missing")
    actual = revision(path)
    expected = manifest["official_suite"]["commit"]
    if actual != expected:
        raise ValueError(f"W3C VC suite is {actual}; expected pinned {expected}")


def write_local_config(path: Path, adapter_base_url: str) -> None:
    base = adapter_base_url.rstrip("/")
    if not base.startswith(("http://", "https://")):
        raise ValueError("adapter URL must be absolute http(s)")
    path.write_text(
        "module.exports = {\n"
        "  settings: { enableInteropTests: false, testAllImplementations: false },\n"
        "  implementations: [{\n"
        "    name: 'ElevenID', implementation: 'Marty VC API test adapter',\n"
        # Marty issues and verifies JWT VCs as the VC Data Model v2 JOSE
        # enveloping-proof representation.  The official runner uses this
        # capability tag to inspect the nested JWT payload rather than
        # assuming an embedded JSON-LD Data Integrity proof.
        f"    issuers: [{{ id: '{base}/issuer', endpoint: '{base}/credentials/issue', tags: ['vc2.0', 'EnvelopingProof'], supports: {{ vc: ['2.0'], proof: ['JOSE'] }} }}],\n"
        f"    verifiers: [{{ id: 'marty-vc-verifier', endpoint: '{base}/credentials/verify', tags: ['vc2.0', 'EnvelopingProof'], supports: {{ vc: ['2.0'] }} }}],\n"
        f"    vpVerifiers: [{{ id: 'marty-vp-verifier', endpoint: '{base}/presentations/verify', tags: ['vc2.0', 'EnvelopingProof'], supports: {{ vc: ['2.0'] }} }}]\n"
        "  }]\n};\n",
        encoding="utf-8",
    )


def file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def npm_command() -> str:
    """Return the executable npm launcher on the current platform."""
    return "npm.cmd" if os.name == "nt" else "npm"


def w3c_test_command(suite: Path) -> list[str]:
    """Return the upstream Mocha command with absolute reporter paths."""
    mocha = suite / "node_modules" / "mocha" / "bin" / "mocha.js"
    if not mocha.is_file():
        raise RuntimeError("W3C suite dependencies are missing the Mocha entry point")
    node = shutil.which("node.exe") or shutil.which("node")
    if not node:
        raise RuntimeError("Node is required to run the W3C suite")
    options = (
        f"abstract={(suite / 'abstract.hbs').as_posix()},reportDir={(suite / 'reports').as_posix()},"
        f"respec={(suite / 'respecConfig.json').as_posix()},suiteLog={(suite / 'suite.log').as_posix()},"
        f"templateData={(suite / 'reports' / 'index.json').as_posix()},title=VC v2.0 Interoperability Report"
    )
    return [node, str(mocha), "tests/", "--reporter", "@digitalbazaar/mocha-w3c-interop-reporter", "--reporter-options", options, "--timeout", "15000", "--preserve-symlinks"]


def report_has_executed_cases(path: Path) -> bool:
    """Return whether the W3C reporter recorded at least one matrix case.

    The upstream runner exits successfully when no implementation matches its
    issuer-led selectors.  That is a useful discovery state, but it is not an
    interoperability pass and must fail this harness.
    """
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return any(
        matrix.get("rows") and matrix.get("columns")
        for matrix in report.get("matrices", [])
        if isinstance(matrix, dict)
    )


def write_evidence(output: Path, manifest: dict, suite: Path, adapter_url: str, result: int) -> None:
    artifacts = [
        {"path": str(path.relative_to(output)).replace("\\", "/"), "sha256": file_sha256(path)}
        for path in sorted(output.rglob("*"))
        if path.is_file() and path.name != "evidence.json"
    ]
    evidence = {
        "schema": "elevenid.official-interop-evidence/v1",
        "official_suite": manifest["official_suite"],
        "suite_checkout": {"path": str(suite), "commit": revision(suite)},
        "marty": {"commit": os.environ.get("MARTY_COMMIT", "unrecorded"), "adapter_url": adapter_url},
        "exclusions": manifest["exclusions"],
        "result": {"exit_code": result, "passed": result == 0},
        "artifacts": artifacts,
    }
    (output / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_suite(suite: Path, adapter_url: str, output: Path, *, install: bool) -> int:
    """Run the official W3C test command against the real test-only adapter.

    The upstream checkout is pinned before invoking its own ``npm test``
    command. Install is explicit because the upstream suite has no lockfile;
    any generated package lock is included in the result artifact set.
    """
    manifest = load_manifest()
    validate_checkout(suite, manifest)
    write_local_config(suite / "localConfig.cjs", adapter_url)
    if install:
        install_result = subprocess.run([npm_command(), "install", "--package-lock-only", "--ignore-scripts"], cwd=suite, check=False).returncode
        if install_result:
            return install_result
        install_result = subprocess.run([npm_command(), "ci", "--ignore-scripts"], cwd=suite, check=False).returncode
        if install_result:
            return install_result
    output.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(suite / "reports", ignore_errors=True)
    (suite / "reports").mkdir(parents=True, exist_ok=True)
    (suite / "suite.log").unlink(missing_ok=True)
    result = subprocess.run(w3c_test_command(suite), cwd=suite, check=False).returncode
    report = suite / "reports" / "index.json"
    if result == 0 and not report_has_executed_cases(report):
        print("W3C VC suite produced no executed matrix cases; refusing to report a pass.", file=sys.stderr)
        result = 1
    for source in (suite / "reports", suite / "suite.log", suite / "package-lock.json"):
        if source.is_file():
            target = output / source.name
            target.write_bytes(source.read_bytes())
        elif source.is_dir():
            for path in source.rglob("*"):
                if path.is_file():
                    target = output / "reports" / path.relative_to(source)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(path.read_bytes())
    write_evidence(output, manifest, suite, adapter_url, result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate")
    run = sub.add_parser("write-local-config")
    run.add_argument("--adapter-url", required=True)
    run.add_argument("--output", type=Path, required=True)
    execute = sub.add_parser("run")
    execute.add_argument("--suite", type=Path, required=True)
    execute.add_argument("--adapter-url", required=True)
    execute.add_argument("--output-dir", type=Path, required=True)
    execute.add_argument("--install", action="store_true", help="generate the upstream lockfile and install its dependencies")
    args = parser.parse_args()
    manifest = load_manifest()
    if args.command == "validate":
        print(f"W3C VC v2 suite manifest is valid: {manifest['official_suite']['commit']}")
        return 0
    if args.command == "run":
        return run_suite(args.suite.resolve(), args.adapter_url, args.output_dir.resolve(), install=args.install)
    write_local_config(args.output, args.adapter_url)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f"W3C VC conformance setup error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
