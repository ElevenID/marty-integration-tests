#!/usr/bin/env python3
"""Validate and execute the pinned W3C VC Data Model v2 suite boundary."""

from __future__ import annotations

import argparse
import base64
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from hashlib import sha256, sha512
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "conformance" / "w3c-vc-data-model-v2.json"
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SRI_SHA512 = re.compile(r"^sha512-[A-Za-z0-9+/]+={0,2}$")
REQUIRED_EVIDENCE_CAPABILITIES = frozenset({"issuer", "vc_verifier", "vp_verifier"})


def load_manifest(path: Path = MANIFEST) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("W3C VC suite manifest must be a JSON object")
    if data.get("schema") != "elevenid.official-vc-suite/v1":
        raise ValueError("unsupported W3C VC suite manifest schema")
    suite = data.get("official_suite", {})
    if suite.get("repository") != "https://github.com/w3c/vc-data-model-2.0-test-suite.git":
        raise ValueError("W3C VC suite must use the official repository")
    if not SHA.fullmatch(suite.get("commit", "")):
        raise ValueError("W3C VC suite commit must be a full lowercase SHA")
    if suite.get("node") != "24":
        raise ValueError("W3C VC suite must run on Node 24")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", suite.get("npm", "")):
        raise ValueError("W3C VC suite must pin an exact npm version")
    npm_tarball = f"https://registry.npmjs.org/npm/-/npm-{suite['npm']}.tgz"
    if suite.get("npm_tarball") != npm_tarball:
        raise ValueError("W3C VC suite npm tarball must match the pinned npm version")
    if not SRI_SHA512.fullmatch(suite.get("npm_integrity", "")):
        raise ValueError("W3C VC suite must pin the npm tarball SHA-512 integrity")
    if not DIGEST.fullmatch(suite.get("package_lock_sha256", "")):
        raise ValueError("W3C VC suite must pin the generated package-lock digest")
    evidence = data.get("evidence")
    if not isinstance(evidence, dict):
        raise ValueError("W3C VC suite must define evidence requirements")
    if not isinstance(evidence.get("implementation_column"), str) or not evidence["implementation_column"]:
        raise ValueError("W3C VC evidence must name its implementation column")
    requirements = evidence.get("required_capabilities")
    if not isinstance(requirements, dict) or set(requirements) != REQUIRED_EVIDENCE_CAPABILITIES:
        raise ValueError("W3C VC evidence must require issuer, vc_verifier, and vp_verifier")
    for capability, markers in requirements.items():
        if (
            not isinstance(markers, list)
            or not markers
            or not all(isinstance(marker, str) and marker for marker in markers)
        ):
            raise ValueError(f"W3C VC evidence capability {capability} must have non-empty row markers")
    for exclusion in data.get("exclusions", []):
        if not {"capability", "reason", "owner", "review_date"} <= exclusion.keys():
            raise ValueError("every W3C exclusion needs capability, reason, owner, and review_date")
    return cast(dict[str, Any], data)


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
        f"    issuers: [{{ id: '{base}/issuer',\n"
        f"      endpoint: '{base}/credentials/issue', tags: ['vc2.0', 'EnvelopingProof'],\n"
        "      supports: { vc: ['2.0'], proof: ['JOSE'] } }],\n"
        "    verifiers: [{ id: 'marty-vc-verifier',\n"
        f"      endpoint: '{base}/credentials/verify', tags: ['vc2.0', 'EnvelopingProof'],\n"
        "      supports: { vc: ['2.0'] } }],\n"
        "    vpVerifiers: [{ id: 'marty-vp-verifier',\n"
        f"      endpoint: '{base}/presentations/verify', tags: ['vc2.0', 'EnvelopingProof'],\n"
        "      supports: { vc: ['2.0'] } }]\n"
        "  }]\n};\n",
        encoding="utf-8",
    )


def file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def package_lock_sha256(path: Path) -> str:
    """Hash an npm-generated lockfile independently of the runner's newline mode.

    The pinned W3C suite has no committed lockfile.  npm generates identical
    JSON with CRLF on Windows and LF on GitHub's Linux runners, so using the
    raw file digest made an otherwise reviewed dependency graph appear to
    drift across platforms.  Canonical LF bytes preserve a strict graph pin
    without making the official lane operating-system dependent.
    """
    payload = path.read_bytes().replace(b"\r\n", b"\n")
    return f"sha256:{sha256(payload).hexdigest()}"


def stack_manifest_metadata(path: Path) -> dict:
    """Validate and record the immutable deployment tested by the W3C suite."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("schema") != "marty.stack/v1":
        raise ValueError("stack manifest must use marty.stack/v1")
    images: list[dict[str, str]] = []
    for component in raw.get("components", []):
        if not isinstance(component, dict):
            continue
        for artifact in component.get("artifacts", []):
            if not isinstance(artifact, dict) or artifact.get("type") != "oci":
                continue
            uri, digest = artifact.get("uri"), artifact.get("digest")
            if not isinstance(uri, str) or not isinstance(digest, str) or not DIGEST.fullmatch(digest):
                raise ValueError("every OCI stack artifact must have an immutable sha256 digest")
            images.append({"component": str(component.get("name", "unknown")), "uri": uri, "digest": digest})
    if not images:
        raise ValueError("stack manifest contains no immutable OCI artifacts")
    return {"path": str(path), "sha256": file_sha256(path), "release": raw.get("release"), "images": images}


def node_command() -> str:
    """Return the Node launcher used for the verified private npm runtime."""
    return shutil.which("node.exe") or shutil.which("node") or "node"


def npm_command() -> list[str]:
    """Return the verified npm CLI, falling back only for local validation."""
    configured = os.environ.get("W3C_NPM_CLI", "").strip()
    if configured:
        cli = Path(configured)
        if not cli.is_absolute() or not cli.is_file():
            raise ValueError("W3C_NPM_CLI must be an existing absolute npm-cli.js path")
        return [node_command(), str(cli)]
    return ["npm.cmd" if os.name == "nt" else "npm"]


def npm_version() -> str:
    return subprocess.check_output([*npm_command(), "--version"], text=True).strip()


def bootstrap_npm(output: Path, manifest: dict) -> Path:
    """Download, verify, and unpack the exact npm runtime used by the W3C lane."""
    if output.exists():
        raise ValueError("npm runtime output already exists")
    suite = manifest["official_suite"]
    request = urllib.request.Request(
        suite["npm_tarball"],
        headers={"Accept": "application/octet-stream", "User-Agent": "ElevenID-W3C-Interop"},
    )
    # B310: load_manifest restricts this URL to the exact HTTPS npm registry path.
    with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310
        payload = response.read()
    actual_integrity = "sha512-" + base64.b64encode(sha512(payload).digest()).decode("ascii")
    if actual_integrity != suite["npm_integrity"]:
        raise ValueError(f"npm tarball integrity is {actual_integrity}; expected {suite['npm_integrity']}")
    output.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
        archive.extractall(output, filter="data")
    cli = (output / "package" / "bin" / "npm-cli.js").resolve()
    if not cli.is_file():
        raise ValueError("verified npm tarball contains no package/bin/npm-cli.js")
    return cli


def install_dependencies(suite: Path, manifest: dict) -> int:
    """Install only the dependency graph reviewed for the pinned suite commit."""
    expected_version = manifest["official_suite"]["npm"]
    actual_version = npm_version()
    if actual_version != expected_version:
        raise ValueError(f"W3C suite requires npm {expected_version}; found {actual_version}")
    lock = suite / "package-lock.json"
    lock.unlink(missing_ok=True)
    result = subprocess.run(
        [*npm_command(), "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"],
        cwd=suite,
        check=False,
    ).returncode
    if result:
        return result
    actual_digest = package_lock_sha256(lock)
    expected_digest = manifest["official_suite"]["package_lock_sha256"]
    if actual_digest != expected_digest:
        raise ValueError(f"generated W3C package lock is {actual_digest}; expected {expected_digest}")
    return subprocess.run(
        [*npm_command(), "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
        cwd=suite,
        check=False,
    ).returncode


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
    return [
        node,
        str(mocha),
        "tests/",
        "--reporter",
        "@digitalbazaar/mocha-w3c-interop-reporter",
        "--reporter-options",
        options,
        "--timeout",
        "15000",
        "--preserve-symlinks",
    ]


def executed_capabilities_from_report(report: object, manifest: dict[str, Any]) -> set[str]:
    """Return Marty roles proven by passed official normative matrix rows.

    The required row fragments live beside the immutable suite pin so an
    upstream wording change is reviewed with that pin.  No total case count is
    fixed: the official suite may add cases without weakening this role guard.
    """
    if not isinstance(report, dict):
        return set()
    evidence = manifest["evidence"]
    implementation = evidence["implementation_column"]
    requirements = evidence["required_capabilities"]
    executed: set[str] = set()
    matrices = report.get("matrices")
    if not isinstance(matrices, list):
        return executed
    for matrix in matrices:
        if not isinstance(matrix, dict) or not isinstance(matrix.get("rows"), list):
            continue
        for row in matrix["rows"]:
            if not isinstance(row, dict) or not isinstance(row.get("id"), str):
                continue
            cells = row.get("cells")
            if not isinstance(cells, list):
                continue
            passed = any(
                isinstance(cell, dict)
                and cell.get("state") == "passed"
                and isinstance(cell.get("cell"), dict)
                and cell["cell"].get("columnId") == implementation
                for cell in cells
            )
            if not passed:
                continue
            row_id = row["id"].casefold()
            for capability, markers in requirements.items():
                if any(marker.casefold() in row_id for marker in markers):
                    executed.add(capability)
    return executed


def report_executed_capabilities(path: Path, manifest: dict[str, Any]) -> set[str]:
    """Load a W3C report and return its role-complete execution evidence."""
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    return executed_capabilities_from_report(report, manifest)


def write_evidence(
    output: Path,
    manifest: dict,
    suite: Path,
    adapter_url: str,
    result: int,
    stack_manifest: Path,
) -> None:
    executed_capabilities = report_executed_capabilities(output / "reports" / "index.json", manifest)
    artifacts = [
        {"path": str(path.relative_to(output)).replace("\\", "/"), "sha256": file_sha256(path)}
        for path in sorted(output.rglob("*"))
        if path.is_file() and path.name != "evidence.json"
    ]
    evidence = {
        "schema": "elevenid.official-interop-evidence/v1",
        "official_suite": manifest["official_suite"],
        "suite_checkout": {"path": str(suite), "commit": revision(suite)},
        "marty": {
            "commit": os.environ.get("MARTY_COMMIT", "unrecorded"),
            "adapter_url": adapter_url,
            "stack_manifest": stack_manifest_metadata(stack_manifest),
        },
        "exclusions": manifest["exclusions"],
        "result": {
            "exit_code": result,
            "passed": result == 0 and executed_capabilities >= REQUIRED_EVIDENCE_CAPABILITIES,
            "required_capabilities": sorted(REQUIRED_EVIDENCE_CAPABILITIES),
            "executed_capabilities": sorted(executed_capabilities),
        },
        "artifacts": artifacts,
    }
    (output / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_suite(suite: Path, adapter_url: str, output: Path, stack_manifest: Path, *, install: bool) -> int:
    """Run the official W3C test command against the real test-only adapter.

    The upstream checkout is pinned before invoking its own ``npm test``
    command. Install is explicit because the upstream suite has no lockfile;
    the generated package lock must match the reviewed digest and is included
    in the result artifact set.
    """
    manifest = load_manifest()
    validate_checkout(suite, manifest)
    stack_manifest_metadata(stack_manifest)
    write_local_config(suite / "localConfig.cjs", adapter_url)
    if install:
        install_result = install_dependencies(suite, manifest)
        if install_result:
            return install_result
    output.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(suite / "reports", ignore_errors=True)
    (suite / "reports").mkdir(parents=True, exist_ok=True)
    (suite / "suite.log").unlink(missing_ok=True)
    result = subprocess.run(w3c_test_command(suite), cwd=suite, check=False).returncode
    report = suite / "reports" / "index.json"
    executed_capabilities = report_executed_capabilities(report, manifest)
    missing_capabilities = REQUIRED_EVIDENCE_CAPABILITIES - executed_capabilities
    if result == 0 and missing_capabilities:
        missing = ", ".join(sorted(missing_capabilities))
        print(f"W3C VC suite did not prove required Marty capabilities: {missing}.", file=sys.stderr)
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
    write_evidence(output, manifest, suite, adapter_url, result, stack_manifest)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate")
    bootstrap = sub.add_parser("bootstrap-npm")
    bootstrap.add_argument("--output", type=Path, required=True)
    run = sub.add_parser("write-local-config")
    run.add_argument("--adapter-url", required=True)
    run.add_argument("--output", type=Path, required=True)
    execute = sub.add_parser("run")
    execute.add_argument("--suite", type=Path, required=True)
    execute.add_argument("--adapter-url", required=True)
    execute.add_argument("--output-dir", type=Path, required=True)
    execute.add_argument(
        "--stack-manifest",
        type=Path,
        required=True,
        help="attested marty.stack/v1 manifest for the deployment under test",
    )
    execute.add_argument(
        "--install", action="store_true", help="generate the upstream lockfile and install its dependencies"
    )
    args = parser.parse_args()
    manifest = load_manifest()
    if args.command == "validate":
        print(f"W3C VC v2 suite manifest is valid: {manifest['official_suite']['commit']}")
        return 0
    if args.command == "run":
        return run_suite(
            args.suite.resolve(),
            args.adapter_url,
            args.output_dir.resolve(),
            args.stack_manifest.resolve(),
            install=args.install,
        )
    if args.command == "bootstrap-npm":
        print(bootstrap_npm(args.output.resolve(), manifest))
        return 0
    write_local_config(args.output, args.adapter_url)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, tarfile.TarError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f"W3C VC conformance setup error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
