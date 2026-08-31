#!/usr/bin/env python3
"""Fail closed unless a release tag resolves into protected main history."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Callable
from typing import Any
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

API_ROOT = "https://api.github.com"
API_VERSION = "2026-03-10"
PROTECTED_BRANCH = "main"
_COMMIT_SHA = re.compile(r"[0-9a-f]{40}")


class ReleaseLineageError(RuntimeError):
    """The release tag's protected-main lineage could not be established safely."""


def _validate_sha(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _COMMIT_SHA.fullmatch(value) is None:
        raise ReleaseLineageError(f"{label} response is malformed")
    return value


def _repository_root(repository: str) -> str:
    parts = repository.split("/")
    if len(parts) != 2 or not all(parts):
        raise ReleaseLineageError("repository must use OWNER/REPO format")
    owner, name = parts
    return f"{API_ROOT}/repos/{quote(owner, safe='')}/{quote(name, safe='')}"


def _load_object(
    url: str,
    token: str,
    *,
    label: str,
    opener: Callable[..., Any],
) -> dict[str, Any]:
    request = Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": API_VERSION,
        },
        method="GET",
    )
    try:
        with opener(request, timeout=30) as response:
            payload = json.load(response)
    except HTTPError as error:
        raise ReleaseLineageError(f"{label} lookup failed with HTTP {error.code}") from error
    except (OSError, UnicodeError, ValueError) as error:
        raise ReleaseLineageError(f"{label} lookup returned an invalid response") from error
    if not isinstance(payload, dict):
        raise ReleaseLineageError(f"{label} response is malformed")
    return payload


def _object_target(payload: dict[str, Any], *, label: str) -> tuple[str, str]:
    target = payload.get("object")
    if not isinstance(target, dict) or not isinstance(target.get("type"), str):
        raise ReleaseLineageError(f"{label} response is malformed")
    return target["type"], _validate_sha(target.get("sha"), label=label)


def _resolve_tag_commit(
    repository_root: str,
    tag: str,
    expected_commit: str,
    token: str,
    *,
    opener: Callable[..., Any],
) -> str:
    encoded_tag = quote(tag, safe="")
    tag_ref = _load_object(
        f"{repository_root}/git/ref/tags/{encoded_tag}",
        token,
        label="tag ref",
        opener=opener,
    )
    if tag_ref.get("ref") != f"refs/tags/{tag}":
        raise ReleaseLineageError("tag ref response does not match the requested tag")
    object_type, object_sha = _object_target(tag_ref, label="tag ref")

    if object_type == "commit":
        resolved_commit = object_sha
    elif object_type == "tag":
        annotated_tag = _load_object(
            f"{repository_root}/git/tags/{object_sha}",
            token,
            label="annotated tag",
            opener=opener,
        )
        if annotated_tag.get("sha") != object_sha or annotated_tag.get("tag") != tag:
            raise ReleaseLineageError("annotated tag response does not match the requested tag")
        target_type, resolved_commit = _object_target(annotated_tag, label="annotated tag")
        if target_type != "commit":
            raise ReleaseLineageError("annotated tag has an unsupported target type")
    else:
        raise ReleaseLineageError("tag ref has an unsupported target type")

    if resolved_commit != expected_commit:
        label = "annotated tag" if object_type == "tag" else "tag ref"
        raise ReleaseLineageError(f"{label} does not resolve to the workflow event commit")
    return resolved_commit


def _capture_protected_main(
    repository_root: str,
    token: str,
    *,
    opener: Callable[..., Any],
) -> str:
    branch = _load_object(
        f"{repository_root}/branches/{PROTECTED_BRANCH}",
        token,
        label="protected main",
        opener=opener,
    )
    commit = branch.get("commit")
    if branch.get("name") != PROTECTED_BRANCH or not isinstance(commit, dict):
        raise ReleaseLineageError("protected main response is malformed")
    if branch.get("protected") is not True:
        raise ReleaseLineageError("main is not protected")
    return _validate_sha(commit.get("sha"), label="protected main")


def _require_main_ancestor(
    repository_root: str,
    tagged_commit: str,
    captured_main: str,
    token: str,
    *,
    opener: Callable[..., Any],
) -> None:
    comparison = _load_object(
        f"{repository_root}/compare/{tagged_commit}...{captured_main}",
        token,
        label="comparison",
        opener=opener,
    )
    base = comparison.get("base_commit")
    merge_base = comparison.get("merge_base_commit")
    status = comparison.get("status")
    ahead_by = comparison.get("ahead_by")
    behind_by = comparison.get("behind_by")
    if (
        not isinstance(base, dict)
        or not isinstance(merge_base, dict)
        or not isinstance(status, str)
        or type(ahead_by) is not int
        or type(behind_by) is not int
        or ahead_by < 0
        or behind_by < 0
    ):
        raise ReleaseLineageError("comparison response is malformed")
    base_sha = _validate_sha(base.get("sha"), label="comparison")
    merge_base_sha = _validate_sha(merge_base.get("sha"), label="comparison")
    valid_counts = (status == "identical" and ahead_by == 0) or (status == "ahead" and ahead_by > 0)
    if base_sha != tagged_commit or merge_base_sha != tagged_commit or behind_by != 0 or not valid_counts:
        raise ReleaseLineageError("release tag commit is not an ancestor of protected main")


def ensure_release_lineage(
    repository: str,
    tag: str,
    expected_commit: str,
    token: str,
    *,
    opener: Callable[..., Any] = urlopen,
) -> str:
    """Return one captured protected-main SHA after proving tag ancestry."""
    repository_root = _repository_root(repository)
    if not tag:
        raise ReleaseLineageError("tag must be non-empty")
    if _COMMIT_SHA.fullmatch(expected_commit) is None:
        raise ReleaseLineageError("expected commit is invalid")
    if not token:
        raise ReleaseLineageError("GH_TOKEN is required")

    tagged_commit = _resolve_tag_commit(
        repository_root,
        tag,
        expected_commit,
        token,
        opener=opener,
    )
    captured_main = _capture_protected_main(repository_root, token, opener=opener)
    _require_main_ancestor(repository_root, tagged_commit, captured_main, token, opener=opener)
    return captured_main


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args(argv)
    try:
        ensure_release_lineage(
            args.repository,
            args.tag,
            args.expected_commit,
            os.environ.get("GH_TOKEN", ""),
        )
    except ReleaseLineageError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    print("Release tag is bound to protected main.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
