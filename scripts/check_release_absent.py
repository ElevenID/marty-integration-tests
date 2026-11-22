#!/usr/bin/env python3
"""Fail closed when a release tag already has a draft or published release."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable
from typing import Any
from urllib.request import urlopen

import release_lookup
from release_lookup import (
    API_VERSION as API_VERSION,
    ReleaseAlreadyExistsError as ReleaseAlreadyExistsError,
    ReleaseLookupError as ReleaseLookupError,
    release_url as release_url,
)


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


def load_release(
    repository: str,
    tag: str,
    token: str,
    *,
    opener: Callable[..., Any] = urlopen,
    actions_write_token: bool = False,
) -> dict[str, Any] | None:
    return release_lookup.load_release(
        repository,
        tag,
        token,
        opener=opener,
        authorize_actions_write=actions_write_context if actions_write_token else None,
    )


def ensure_release_absent(
    repository: str,
    tag: str,
    token: str,
    *,
    opener: Callable[..., Any] = urlopen,
    actions_write_token: bool = False,
) -> None:
    release_lookup.ensure_release_absent(
        repository,
        tag,
        token,
        opener=opener,
        authorize_actions_write=actions_write_context if actions_write_token else None,
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
