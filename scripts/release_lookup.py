"""Shared GitHub release lookup and draft visibility rules."""

from __future__ import annotations

import json
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
    authorize_actions_write: Callable[[str], None] | None = None,
) -> dict[str, Any] | None:
    if not token:
        raise ReleaseLookupError("GH_TOKEN is required")
    if authorize_actions_write is not None:
        authorize_actions_write(repository)
    tagged_url = release_url(repository, tag)
    repository_url = tagged_url.split("/releases/tags/", 1)[0]

    def get(url: str) -> Any:
        request = Request(url, headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": API_VERSION,
        })
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
            if authorize_actions_write is None:
                identity = get(repository_url)
                permissions = identity.get("permissions") if isinstance(identity, dict) else None
                if not isinstance(permissions, dict) or permissions.get("push") is not True:
                    raise ReleaseLookupError("Push visibility is required to exclude draft releases")
            for page in range(1, 101):
                items = get(f"{repository_url}/releases?per_page=100&page={page}")
                if not isinstance(items, list) or len(items) > 100:
                    raise ReleaseLookupError("GitHub release listing is invalid")
                for item in items:
                    if (not isinstance(item, dict) or not isinstance(item.get("tag_name"), str)
                            or not isinstance(item.get("draft"), bool)):
                        raise ReleaseLookupError("GitHub release listing is invalid")
                    if item["tag_name"] == tag:
                        return item
                if len(items) < 100:
                    return None
            raise ReleaseLookupError("GitHub release listing exceeded the lookup bound")
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
    authorize_actions_write: Callable[[str], None] | None = None,
) -> None:
    release = load_release(repository, tag, token, opener=opener,
                           authorize_actions_write=authorize_actions_write)
    if release is None:
        return
    if release.get("tag_name") != tag or not isinstance(release.get("draft"), bool):
        raise ReleaseLookupError("GitHub release response did not match the requested tag")
    state = "draft" if release["draft"] else "published"
    raise ReleaseAlreadyExistsError(
        f"Release {tag} already exists as a {state}; refusing to rebuild or overwrite it. "
        "Publish corrections under a new version; this workflow does not modify existing releases."
    )
