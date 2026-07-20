#!/usr/bin/env python3
"""Fail closed when a release tag already has a draft or published release."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable
from typing import Any
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

API_VERSION = "2026-03-10"


class ReleaseLookupError(RuntimeError):
    """The release state could not be established safely."""


class ReleaseAlreadyExistsError(RuntimeError):
    """A draft or published release already owns the requested tag."""


def release_url(repository: str, tag: str) -> str:
    parts = repository.split("/")
    if len(parts) != 2 or not all(parts) or not tag:
        raise ReleaseLookupError("repository must use OWNER/REPO format and tag must be non-empty")
    owner, name = parts
    encoded_owner = quote(owner, safe="")
    encoded_name = quote(name, safe="")
    encoded_tag = quote(tag, safe="")
    return f"https://api.github.com/repos/{encoded_owner}/{encoded_name}/releases/tags/{encoded_tag}"


def load_release(
    repository: str,
    tag: str,
    token: str,
    *,
    opener: Callable[..., Any] = urlopen,
) -> dict[str, Any] | None:
    if not token:
        raise ReleaseLookupError("GH_TOKEN is required")
    request = Request(
        release_url(repository, tag),
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": API_VERSION,
        },
    )
    try:
        with opener(request, timeout=30) as response:
            payload = json.load(response)
    except HTTPError as error:
        if error.code == 404:
            return None
        raise ReleaseLookupError(f"GitHub release lookup failed with HTTP {error.code}") from error
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise ReleaseLookupError("GitHub release lookup returned an invalid response") from error
    if not isinstance(payload, dict):
        raise ReleaseLookupError("GitHub release lookup returned an invalid response")
    return payload


def ensure_release_absent(
    repository: str,
    tag: str,
    token: str,
    *,
    opener: Callable[..., Any] = urlopen,
) -> None:
    release = load_release(repository, tag, token, opener=opener)
    if release is None:
        return
    if release.get("tag_name") != tag or not isinstance(release.get("draft"), bool):
        raise ReleaseLookupError("GitHub release response did not match the requested tag")
    state = "draft" if release["draft"] else "published"
    raise ReleaseAlreadyExistsError(
        f"Release {tag} already exists as a {state}; refusing to rebuild or overwrite it. "
        "Inspect and explicitly remove an incomplete draft before retrying."
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args(argv)
    try:
        ensure_release_absent(args.repository, args.tag, os.environ.get("GH_TOKEN", ""))
    except (ReleaseAlreadyExistsError, ReleaseLookupError) as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    print(f"No existing GitHub release owns {args.tag}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
