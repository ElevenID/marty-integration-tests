#!/usr/bin/env python3
"""Exercise Actions draft visibility with one owned draft on an existing tag."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen
from uuid import uuid4

from check_release_absent import (
    API_VERSION,
    ReleaseAlreadyExistsError,
    actions_write_context,
    ensure_release_absent,
    load_release,
    release_url,
)


def exercise(
    repository: str,
    tag: str,
    commit: str,
    tag_ref: str,
    token: str,
    output: Path,
    *,
    opener: Callable[..., Any] = urlopen,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    actions_write_context(repository)
    if os.environ.get("GITHUB_JOB") != "release-lookup-probe":
        raise ValueError("Draft fixture is restricted to the manual preflight job")
    if (
        not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", tag)
        or any(not re.fullmatch(r"[a-f0-9]{40}", value) for value in (commit, tag_ref))
        or not output.is_absolute()
        or output.exists()
        or output.is_symlink()
        or not token
    ):
        raise ValueError("Preflight inputs or fresh receipt path are invalid")
    base = release_url(repository, tag).split("/releases/tags/", 1)[0]
    marker = "Owned release-lookup fixture " + uuid4().hex
    record: dict[str, Any] = {
        "schema": "marty.release-lookup-preflight/v1",
        "repository": repository,
        "fixture_tag": tag,
        "tag_ref": tag_ref,
        "tag_commit": commit,
        "draft_target_commitish": "main",
        "source_sha": os.environ.get("GITHUB_SHA"),
        "fixture_id": None,
        "owner_nonce": marker,
        "draft_refused": False,
        "owned_draft_removed": False,
        "tag_unchanged": False,
        "stage": "initial",
        "lookup_observations": [],
    }
    failure: Exception | None = None

    def save(*, initial: bool = False) -> None:
        if output.is_symlink():
            raise ValueError("Preflight receipt changed ownership")
        with output.open("x" if initial else "r+", encoding="utf-8") as stream:
            if not initial:
                if json.load(stream).get("owner_nonce") != marker:
                    raise ValueError("Preflight receipt changed ownership")
                stream.seek(0)
            stream.write(json.dumps(record, indent=2) + "\n")
            stream.truncate()

    def api(method: str, path: str, value: Any = None, *, missing: bool = False) -> Any:
        request = Request(
            base + path,
            method=method,
            data=json.dumps(value).encode() if value is not None else None,
            headers={
                "Authorization": "Bearer " + token,
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": API_VERSION,
            },
        )
        try:
            with opener(request, timeout=30) as response:
                return json.load(response) if method != "DELETE" else None
        except HTTPError as error:
            if missing and error.code == 404:
                return None
            raise RuntimeError("Draft preflight API request failed") from error

    ref_path = "/git/ref/tags/" + quote(tag, safe="")
    if api("GET", ref_path).get("object", {}).get("sha") != tag_ref:
        raise ValueError("Fixture tag differs from the frozen existing ref")
    record["result"] = "running"
    save(initial=True)
    try:
        record["stage"] = "initial_absence"
        ensure_release_absent(repository, tag, token, opener=opener, actions_write_token=True)
        record["stage"] = "create_owned_draft"
        created = api(
            "POST",
            "/releases",
            {
                # The existing tag is authoritative; target_commitish is ignored
                # for it. Keep the default branch selector so no workflow scope
                # is needed to target an older workflow-bearing commit.
                "tag_name": tag,
                "target_commitish": "main",
                "draft": True,
                "prerelease": True,
                "name": "Temporary release lookup preflight",
                "body": marker,
            },
        )
        identity = created.get("id")
        if type(identity) is not int or identity <= 0:
            raise ValueError("Fixture creation did not return an owned release identity")
        record["fixture_id"] = identity
        save()
        record["created_tag"] = created.get("tag_name")
        record["created_draft"] = created.get("draft")
        record["stage"] = "observe_owned_draft"
        # Only an absent lookup is retried, with a fixed 18-second wait bound.
        # This does not relax the production guard or accept another draft.
        for attempt in range(10):
            observed = load_release(repository, tag, token, opener=opener, actions_write_token=True)
            record["lookup_observations"].append(
                None
                if observed is None
                else {
                    "id": observed.get("id"),
                    "tag_name": observed.get("tag_name"),
                    "draft": observed.get("draft"),
                }
            )
            save()
            if observed is not None:
                break
            if attempt < 9:
                sleeper(2)
        if not isinstance(observed, dict) or observed.get("id") != identity or observed.get("draft") is not True:
            raise ValueError("Actions lookup did not identify the exact owned draft")
        record["stage"] = "refuse_owned_draft"
        try:
            ensure_release_absent(repository, tag, token, opener=opener, actions_write_token=True)
        except ReleaseAlreadyExistsError:
            record["draft_refused"] = True
        else:
            raise ValueError("Actions lookup failed to see its owned draft")
    except Exception as error:  # noqa: BLE001 - Unexpected probe failures must still clean owned state.
        failure = error
        record["failure_stage"] = record["stage"]
        record["failure_type"] = type(error).__name__
    finally:
        try:
            if record["fixture_id"] is not None:
                path = "/releases/" + str(record["fixture_id"])
                live = api("GET", path, missing=True)
                if live is not None:
                    if (
                        live.get("id") != record["fixture_id"]
                        or live.get("tag_name") != tag
                        or live.get("draft") is not True
                        or live.get("assets") != []
                        or live.get("body") != marker
                        or live.get("target_commitish") != "main"
                    ):
                        raise ValueError("Draft changed ownership, state or contents; preserving it")
                    api("DELETE", path)
                if api("GET", path, missing=True) is not None:
                    raise ValueError("Owned fixture draft remains after cleanup")
                record["owned_draft_removed"] = True
            record["tag_unchanged"] = api("GET", ref_path).get("object", {}).get("sha") == tag_ref
            if not record["tag_unchanged"]:
                raise ValueError("Existing fixture tag changed during preflight")
        except Exception as error:  # noqa: BLE001 - Preserve failed ownership/cleanup as unqualified evidence.
            failure = error
            record["cleanup_failure_type"] = type(error).__name__
        finally:
            if failure is not None and "failure_stage" not in record:
                record["failure_stage"] = "cleanup"
                record["failure_type"] = type(failure).__name__
            record["result"] = "passed" if failure is None else "failed"
            save()
    if failure is not None:
        raise RuntimeError("Release lookup preflight failed; inspect the owned receipt") from failure
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-tag", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        tag = "refs/tags/" + args.fixture_tag
        # No Git writes: the manual workflow fetches and authenticates main/tags.
        tag_ref = subprocess.check_output(["git", "rev-parse", "--verify", tag], text=True).strip()
        commit = subprocess.check_output(["git", "rev-parse", "--verify", tag + "^{commit}"], text=True).strip()
        subprocess.run(["git", "merge-base", "--is-ancestor", commit, "origin/main"], check=True)
        exercise(
            os.environ["GITHUB_REPOSITORY"],
            args.fixture_tag,
            commit,
            tag_ref,
            os.environ.get("GH_TOKEN", ""),
            args.output,
        )
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print("Release lookup preflight failed: " + type(error).__name__)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
