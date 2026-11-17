#!/usr/bin/env python3
"""Detect official-suite and independent interoperability drift without changing pins.

The resulting review record is deliberately separate from the pinned manifests:
an automated PR makes a new upstream revision visible, while a maintainer must
still review compatibility, image digests, and test results before changing a
pin used by release evidence.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
import tomllib
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "conformance" / "upstream-review.json"
GIT_TIMEOUT_SECONDS = 30
MAX_CRATE_ARCHIVE = 4 * 1024 * 1024
MAX_CRATE_CONTENTS = 16 * 1024 * 1024


def _git_refs(repository: str, *refs: str) -> dict[str, str]:
    """Read only the requested refs, rejecting malformed or ambiguous output."""
    try:
        output = subprocess.check_output(
            ["git", "ls-remote", "--", repository, *refs],
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"git ls-remote timed out after {GIT_TIMEOUT_SECONDS}s for {repository}") from exc
    candidates: dict[str, str] = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) != 2:
            raise RuntimeError(f"malformed git ls-remote output for {repository}")
        sha, ref = fields
        if ref not in refs or ref in candidates:
            raise RuntimeError(f"unexpected or duplicate remote ref for {repository}: {ref}")
        if re.fullmatch(r"[0-9a-f]{40}", sha) is None or sha == "0" * 40:
            raise RuntimeError(f"invalid remote object ID for {repository} {ref}")
        candidates[ref] = sha
    return candidates


def git_head(repository: str, ref: str = "HEAD") -> str:
    sha = _git_refs(repository, ref).get(ref)
    if sha is None:
        raise RuntimeError(f"no full commit SHA returned for {repository} {ref}")
    return sha


def git_tag_commit(repository: str, tag: str) -> str:
    """Resolve a release tag to the commit it identifies.

    Annotated tags report both the tag object and its peeled commit.  Prefer
    the peeled value and fall back to the direct value for lightweight tags.
    """
    ref = f"refs/tags/{tag}"
    candidates = _git_refs(repository, ref, f"{ref}^{{}}")
    if ref not in candidates:
        raise RuntimeError(f"no full commit SHA returned for {repository} {tag}")
    return candidates.get(f"{ref}^{{}}", candidates[ref])


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


def latest_github_release(repository: str) -> str:
    """Return the latest published release tag for an official GitHub repository."""
    parsed = urlparse(repository)
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        raise RuntimeError(f"interoperability repository is not on GitHub: {repository}")
    path = parsed.path.removesuffix(".git").strip("/")
    parts = path.split("/")
    if len(parts) != 2 or not all(parts):
        raise RuntimeError(f"official GitHub repository URL is invalid: {repository}")
    request = urllib.request.Request(
        f"https://api.github.com/repos/{parts[0]}/{parts[1]}/releases/latest",
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "ElevenID-Official-Suite-Updates",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    # B310: the URL is constrained above to GitHub's fixed HTTPS API origin.
    with urllib.request.urlopen(request, timeout=20) as response:  # nosec B310
        payload: object = json.load(response)
    if not isinstance(payload, dict):
        raise RuntimeError("GitHub latest-release response is not a JSON object")
    value = payload.get("tag_name")
    if not isinstance(value, str) or not value:
        raise RuntimeError("GitHub latest-release response has no string tag_name")
    return value


def load_json(relative: str) -> dict[str, Any]:
    value: object = json.loads((ROOT / relative).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"{relative} must contain a JSON object")
    return cast(dict[str, Any], value)


def _registry_origin(url: str) -> str:
    parsed = urlparse(url)
    if (
        parsed.scheme != "https"
        or parsed.netloc not in {"crates.io", "static.crates.io"}
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError("crate registry URL is outside the fixed HTTPS origins")
    return parsed.netloc


class _RegistryRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, origin: str) -> None:
        super().__init__()
        self.origin = origin

    def redirect_request(
        self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> urllib.request.Request | None:
        if _registry_origin(newurl) != self.origin:
            raise RuntimeError("crate registry redirect changes origin")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _registry_bytes(url: str, maximum: int) -> bytes:
    origin = _registry_origin(url)
    request = urllib.request.Request(url, headers={"User-Agent": "ElevenID-Official-Suite-Updates"})
    # URLs are constructed only from the fixed registry origins and validated
    # package/version components below; no manifest-provided URL is followed.
    opener = urllib.request.build_opener(_RegistryRedirect(origin))
    with opener.open(request, timeout=20) as response:  # nosec B310
        raw = response.read(maximum + 1)
    if not isinstance(raw, bytes) or len(raw) > maximum:
        raise RuntimeError("crate registry response exceeds its bound")
    return raw


def _released_crate(component: dict[str, Any]) -> dict[str, str]:
    """Observe the selected published crate, not an unrelated monorepo release.

    The registry checksum identifies the archive and its package metadata.
    Cargo VCS metadata is the publisher's clean-source claim, not an attestation
    or proof of archive-to-commit equivalence. Adoption still requires review.
    A coordinated repository release is not a crate release tag.
    """
    name = component["name"]
    if not isinstance(name, str) or re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", name) is None:
        raise RuntimeError("invalid registry crate name")
    payload = json.loads(_registry_bytes(f"https://crates.io/api/v1/crates/{name}", MAX_CRATE_ARCHIVE))
    if not isinstance(payload, dict) or not isinstance(payload.get("crate"), dict):
        raise RuntimeError("invalid registry crate metadata")
    package = payload["crate"]
    version = package.get("max_stable_version")
    if (
        package.get("name") != name
        or not isinstance(version, str)
        or re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version) is None
    ):
        raise RuntimeError("registry did not identify the requested stable crate")
    versions = payload.get("versions")
    if not isinstance(versions, list):
        raise RuntimeError("registry crate versions are missing")
    matching = [v for v in versions if isinstance(v, dict) and v.get("num") == version]
    if len(matching) != 1:
        raise RuntimeError("registry stable crate version is ambiguous")
    selected = matching[0]
    checksum = selected.get("checksum")
    repository = component["repository"].removesuffix(".git").rstrip("/")
    selected_repository = selected.get("repository")
    if (
        selected.get("yanked") is not False
        or not isinstance(selected_repository, str)
        or selected_repository.removesuffix(".git").rstrip("/") != repository
        or not isinstance(checksum, str)
        or re.fullmatch(r"[0-9a-f]{64}", checksum) is None
    ):
        raise RuntimeError("registry crate checksum, custody or publication is invalid")
    raw = _registry_bytes(f"https://static.crates.io/crates/{name}/{name}-{version}.crate", MAX_CRATE_ARCHIVE)
    if hashlib.sha256(raw).hexdigest() != checksum:
        raise RuntimeError("published crate checksum mismatch")
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
        contents = compressed.read(MAX_CRATE_CONTENTS + 1)
    if len(contents) > MAX_CRATE_CONTENTS:
        raise RuntimeError("uncompressed crate exceeds its bound")
    prefix = f"{name}-{version}/"
    with tarfile.open(fileobj=io.BytesIO(contents), mode="r:") as archive:
        members = archive.getmembers()
        if len(members) > 4096:
            raise RuntimeError("crate archive contains too many entries")

        def metadata(path: str) -> bytes:
            matches = [member for member in members if member.name == prefix + path]
            if len(matches) != 1 or not matches[0].isfile() or not 0 < matches[0].size <= 256 * 1024:
                raise RuntimeError("crate source metadata is absent, ambiguous or unsafe")
            stream = archive.extractfile(matches[0])
            if stream is None:
                raise RuntimeError("crate source metadata cannot be read")
            return stream.read()

        manifest = tomllib.loads(metadata("Cargo.toml").decode("utf-8"))
        identity = manifest.get("package", {})
        vcs = json.loads(metadata(".cargo_vcs_info.json"))
    identity_repository = identity.get("repository") if isinstance(identity, dict) else None
    if (
        not isinstance(identity, dict)
        or identity.get("name") != name
        or identity.get("version") != version
        or not isinstance(identity_repository, str)
        or identity_repository.removesuffix(".git").rstrip("/") != repository
    ):
        raise RuntimeError("published crate identity does not match registry metadata")
    git = vcs.get("git") if isinstance(vcs, dict) else None
    commit = git.get("sha1") if isinstance(git, dict) else None
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None or commit == "0" * 40:
        raise RuntimeError("published crate has no valid source commit")
    if not isinstance(git, dict) or git.get("dirty", False) is not False:
        raise RuntimeError("published crate has dirty or invalid source provenance")
    return {
        "pinned_release": component["release"],
        "latest_release": f"v{version}",
        "pinned_commit": component["commit"],
        "latest_commit": commit,
        "pinned_checksum": component["crate_checksum"],
        "latest_checksum": checksum,
    }


def observe() -> dict:
    oidf = load_json("conformance/oidf-runner.json")["official_runner"]
    w3c_manifest = load_json("conformance/w3c-vc-data-model-v2.json")
    w3c = w3c_manifest["official_suite"]
    eudi = load_json("conformance/eudi-reference-interop.json")["components"]
    didcomm = load_json("conformance/didcomm-interoperability.json")["independent_implementation"]
    latest_oidf = latest_oidf_release()
    upstreams = {
        "oidf": {
            "pinned_release": oidf["release"],
            "latest_release": latest_oidf,
            "pinned_commit": oidf["commit"],
            "latest_commit": git_tag_commit(oidf["repository"], latest_oidf),
        },
        "w3c_vc_data_model_v2": {
            "pinned_commit": w3c["commit"],
            "latest_commit": git_head(w3c["repository"], "refs/heads/main"),
        },
        "didcomm_independent_implementation": _released_crate(didcomm),
        "eudi_verifier_endpoint": _released_upstream(eudi["verifier_endpoint"]),
    }
    for name, library in eudi["wallet_kit"]["libraries"].items():
        upstreams[f"eudi_wallet_kit_{name}"] = _released_upstream(library)
    return {
        "schema": "elevenid.official-suite-upstream-review/v1",
        "upstreams": upstreams,
    }


def _released_upstream(component: dict[str, Any]) -> dict[str, str]:
    """Compare a release pin with the latest tag, never an unreleased head."""
    latest_release = latest_github_release(component["repository"])
    return {
        "pinned_release": component["release"],
        "latest_release": latest_release,
        "pinned_commit": component["commit"],
        "latest_commit": git_tag_commit(component["repository"], latest_release),
    }


def has_drift(observation: dict) -> bool:
    values = observation["upstreams"].values()
    return any(
        entry.get("pinned_release") != entry.get("latest_release")
        or entry.get("pinned_commit") != entry.get("latest_commit")
        or entry.get("pinned_checksum") != entry.get("latest_checksum")
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
    except (OSError, RuntimeError, subprocess.CalledProcessError, ValueError, tarfile.TarError) as exc:
        print(f"Official suite update check failed: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
