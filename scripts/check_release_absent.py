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


def actions_write_context(repository: str) -> None:
    """Validate the trusted workflow context, not a user-only role field.

    The two source-controlled workflows declare contents:write for these jobs.
    GitHub installation tokens need not expose repository.permissions.push.
    The preflight exercises actual draft visibility with that token class.
    """
    prefix = repository + "/.github/workflows/"
    release = (
        os.environ.get("GITHUB_JOB") in {"verify-source", "release"}
        and os.environ.get("GITHUB_EVENT_NAME") == "push"
        and os.environ.get("GITHUB_REF", "").startswith("refs/tags/")
        and os.environ.get("GITHUB_WORKFLOW_REF") == prefix + "release.yml@" + os.environ["GITHUB_REF"]
    )
    preflight = (
        os.environ.get("GITHUB_JOB") == "release-lookup-probe"
        and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and os.environ.get("GITHUB_REF") == "refs/heads/main"
        and os.environ.get("GITHUB_WORKFLOW_REF") == prefix + "release-preflight.yml@refs/heads/main"
    )
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("GITHUB_REPOSITORY") != repository
        or not (release or preflight)
    ):
        raise ReleaseLookupError("Actions write-token mode requires the trusted release workflow context")


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
    actions_write_token: bool = False,
) -> dict[str, Any] | None:
    if not token:
        raise ReleaseLookupError("GH_TOKEN is required")
    if actions_write_token:
        actions_write_context(repository)
    tagged_url = release_url(repository, tag)
    repository_url = tagged_url.split("/releases/tags/", 1)[0]

    def get(url: str) -> Any:
        request = Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": API_VERSION,
            },
        )
        with opener(request, timeout=30) as response:
            return json.load(response)

    try:
        try:
            payload = get(tagged_url)
        except HTTPError as error:
            if error.code != 404:
                raise
            # Tag lookup is documented for published releases. Drafts require
            # a paginated listing and an identity able to see draft releases.
            if not actions_write_token:
                identity = get(repository_url)
                permissions = identity.get("permissions") if isinstance(identity, dict) else None
                if not isinstance(permissions, dict) or permissions.get("push") is not True:
                    raise ReleaseLookupError("Push visibility is required to exclude draft releases") from None
            for page in range(1, 101):
                items = get(f"{repository_url}/releases?per_page=100&page={page}")
                if not isinstance(items, list) or len(items) > 100:
                    raise ReleaseLookupError("GitHub release listing is invalid") from None
                for item in items:
                    if (
                        not isinstance(item, dict)
                        or not isinstance(item.get("tag_name"), str)
                        or not isinstance(item.get("draft"), bool)
                    ):
                        raise ReleaseLookupError("GitHub release listing is invalid") from None
                    if item["tag_name"] == tag:
                        return item
                if len(items) < 100:
                    return None
            raise ReleaseLookupError("GitHub release listing exceeded the lookup bound") from None
    except HTTPError as error:
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
    actions_write_token: bool = False,
) -> None:
    release = load_release(repository, tag, token, opener=opener, actions_write_token=actions_write_token)
    if release is None:
        return
    if release.get("tag_name") != tag or not isinstance(release.get("draft"), bool):
        raise ReleaseLookupError("GitHub release response did not match the requested tag")
    state = "draft" if release["draft"] else "published"
    raise ReleaseAlreadyExistsError(
        f"Release {tag} already exists as a {state}; refusing to rebuild or overwrite it. "
        "Publish corrections under a new version; this workflow does not modify existing releases."
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument(
        "--actions-write-token", action="store_true", help="trusted release job whose workflow declares contents:write"
    )
    args = parser.parse_args(argv)
    try:
        ensure_release_absent(
            args.repository, args.tag, os.environ.get("GH_TOKEN", ""), actions_write_token=args.actions_write_token
        )
    except (ReleaseAlreadyExistsError, ReleaseLookupError) as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    print(f"No existing GitHub release owns {args.tag}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
