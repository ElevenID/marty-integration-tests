from __future__ import annotations

import importlib.util
import io
import json
from collections.abc import Callable
from email.message import Message
from pathlib import Path
from typing import Any, cast
from urllib.error import HTTPError

import pytest

SCRIPT = Path(__file__).parents[2] / "scripts" / "check_release_lineage.py"
SPEC = importlib.util.spec_from_file_location("check_release_lineage", SCRIPT)
assert SPEC is not None
assert SPEC.loader is not None
lineage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lineage)

REPOSITORY = "ElevenID/marty-integration-tests"
TAG = "v1.2.79"
TAG_COMMIT = "1" * 40
MAIN_COMMIT = "2" * 40
TAG_OBJECT = "3" * 40
OTHER_COMMIT = "4" * 40
MERGE_BASE = "5" * 40
API_ROOT = "https://api.github.com/repos/ElevenID/marty-integration-tests"
REF_URL = f"{API_ROOT}/git/ref/tags/{TAG}"
TAG_URL = f"{API_ROOT}/git/tags/{TAG_OBJECT}"
MAIN_URL = f"{API_ROOT}/branches/main"


class Response(io.BytesIO):
    def __enter__(self) -> Response:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def response(payload: object) -> Response:
    return Response(json.dumps(payload).encode())


class Api:
    def __init__(self, responses: dict[str, object | BaseException]) -> None:
        self.responses = responses
        self.urls: list[str] = []

    def __call__(self, request: Any, *, timeout: int) -> Response:
        assert timeout == 30
        assert request.method == "GET"
        assert request.get_header("Accept") == "application/vnd.github+json"
        assert request.get_header("Authorization") == "Bearer token"
        assert request.get_header("X-github-api-version") == "2026-03-10"
        self.urls.append(request.full_url)
        if request.full_url not in self.responses:
            raise AssertionError(f"unexpected API request: {request.full_url}")
        result = self.responses[request.full_url]
        if isinstance(result, BaseException):
            raise result
        return response(result)


def tag_ref(*, object_type: str = "commit", sha: str = TAG_COMMIT, ref: str | None = None) -> dict[str, Any]:
    return {
        "ref": ref or f"refs/tags/{TAG}",
        "object": {"type": object_type, "sha": sha},
    }


def annotated_tag(
    *,
    tag: str = TAG,
    target_type: str = "commit",
    target_sha: str = TAG_COMMIT,
    sha: str = TAG_OBJECT,
) -> dict[str, Any]:
    return {
        "sha": sha,
        "tag": tag,
        "object": {"type": target_type, "sha": target_sha},
    }


def protected_main(*, protected: bool = True, sha: str = MAIN_COMMIT, name: str = "main") -> dict[str, Any]:
    return {"name": name, "protected": protected, "commit": {"sha": sha}}


def comparison(
    *,
    status: str = "ahead",
    base_sha: str = TAG_COMMIT,
    merge_base_sha: str = TAG_COMMIT,
    ahead_by: int = 1,
    behind_by: int = 0,
) -> dict[str, Any]:
    return {
        "status": status,
        "ahead_by": ahead_by,
        "behind_by": behind_by,
        "base_commit": {"sha": base_sha},
        "merge_base_commit": {"sha": merge_base_sha},
    }


def compare_url(main_sha: str = MAIN_COMMIT, tag_sha: str = TAG_COMMIT) -> str:
    return f"{API_ROOT}/compare/{tag_sha}...{main_sha}"


def lightweight_api(
    *,
    ref_payload: object | None = None,
    main_payload: object | None = None,
    compare_payload: object | None = None,
) -> Api:
    return Api(
        {
            REF_URL: tag_ref() if ref_payload is None else ref_payload,
            MAIN_URL: protected_main() if main_payload is None else main_payload,
            compare_url(): comparison() if compare_payload is None else compare_payload,
        }
    )


def ensure(api: Callable[..., Any]) -> str:
    return cast(str, lineage.ensure_release_lineage(REPOSITORY, TAG, TAG_COMMIT, "token", opener=api))


def test_exact_protected_main_head_is_accepted() -> None:
    api = lightweight_api(
        main_payload=protected_main(sha=TAG_COMMIT),
        compare_payload=comparison(status="identical", ahead_by=0),
    )
    api.responses[compare_url(TAG_COMMIT)] = api.responses.pop(compare_url())

    assert ensure(api) == TAG_COMMIT
    assert api.urls == [REF_URL, MAIN_URL, compare_url(TAG_COMMIT)]


def test_older_protected_main_ancestor_is_accepted_using_the_captured_main_sha() -> None:
    api = lightweight_api()

    assert ensure(api) == MAIN_COMMIT
    assert api.urls == [REF_URL, MAIN_URL, compare_url()]
    assert all("...main" not in url for url in api.urls)


def test_one_annotated_tag_is_peeled_to_the_event_commit() -> None:
    api = Api(
        {
            REF_URL: tag_ref(object_type="tag", sha=TAG_OBJECT),
            TAG_URL: annotated_tag(),
            MAIN_URL: protected_main(),
            compare_url(): comparison(),
        }
    )

    assert ensure(api) == MAIN_COMMIT
    assert api.urls == [REF_URL, TAG_URL, MAIN_URL, compare_url()]


@pytest.mark.parametrize(
    "ref_payload",
    [
        tag_ref(sha=OTHER_COMMIT),
        tag_ref(ref="refs/tags/v9.9.9"),
    ],
)
def test_moved_or_mismatched_tag_ref_is_rejected(ref_payload: dict[str, Any]) -> None:
    api = lightweight_api(ref_payload=ref_payload)

    with pytest.raises(lineage.ReleaseLineageError, match="tag ref"):
        ensure(api)


@pytest.mark.parametrize(
    "tag_payload",
    [
        annotated_tag(tag="v9.9.9"),
        annotated_tag(target_sha=OTHER_COMMIT),
        annotated_tag(sha=OTHER_COMMIT),
    ],
)
def test_mismatched_annotated_tag_is_rejected(tag_payload: dict[str, Any]) -> None:
    api = Api(
        {
            REF_URL: tag_ref(object_type="tag", sha=TAG_OBJECT),
            TAG_URL: tag_payload,
        }
    )

    with pytest.raises(lineage.ReleaseLineageError, match="annotated tag"):
        ensure(api)


@pytest.mark.parametrize(
    ("ref_payload", "tag_payload"),
    [
        (tag_ref(object_type="tree"), None),
        (tag_ref(object_type="tag", sha=TAG_OBJECT), annotated_tag(target_type="tag")),
    ],
)
def test_unsupported_tag_targets_are_rejected(
    ref_payload: dict[str, Any],
    tag_payload: dict[str, Any] | None,
) -> None:
    responses: dict[str, object] = {REF_URL: ref_payload}
    if tag_payload is not None:
        responses[TAG_URL] = tag_payload
    api = Api(responses)

    with pytest.raises(lineage.ReleaseLineageError, match="unsupported"):
        ensure(api)


def test_unprotected_main_is_rejected() -> None:
    api = lightweight_api(main_payload=protected_main(protected=False))

    with pytest.raises(lineage.ReleaseLineageError, match="not protected"):
        ensure(api)


@pytest.mark.parametrize(
    "compare_payload",
    [
        comparison(status="behind", merge_base_sha=MAIN_COMMIT, ahead_by=0, behind_by=1),
        comparison(status="diverged", merge_base_sha=MERGE_BASE, ahead_by=2, behind_by=1),
        comparison(status="diverged", merge_base_sha=MERGE_BASE, ahead_by=1, behind_by=3),
        comparison(base_sha=OTHER_COMMIT),
        comparison(merge_base_sha=MERGE_BASE),
    ],
    ids=["descendant", "diverged", "side-branch", "wrong-base", "wrong-merge-base"],
)
def test_commit_outside_protected_main_history_is_rejected(compare_payload: dict[str, Any]) -> None:
    api = lightweight_api(compare_payload=compare_payload)

    with pytest.raises(lineage.ReleaseLineageError, match="ancestor"):
        ensure(api)


@pytest.mark.parametrize(
    ("responses", "error"),
    [
        ({REF_URL: []}, "tag ref"),
        ({REF_URL: {"ref": f"refs/tags/{TAG}"}}, "tag ref"),
        ({REF_URL: tag_ref(), MAIN_URL: {"name": "main", "protected": True}}, "protected main"),
        (
            {
                REF_URL: tag_ref(),
                MAIN_URL: protected_main(),
                compare_url(): {"status": "ahead", "behind_by": 0},
            },
            "comparison",
        ),
        (
            {
                REF_URL: tag_ref(),
                MAIN_URL: protected_main(),
                compare_url(): comparison() | {"ahead_by": "1"},
            },
            "comparison",
        ),
    ],
    ids=["non-object", "missing-ref-object", "missing-main-commit", "missing-comparison", "wrong-count-type"],
)
def test_malformed_api_responses_fail_closed(responses: dict[str, object], error: str) -> None:
    api = Api(responses)

    with pytest.raises(lineage.ReleaseLineageError, match=error):
        ensure(api)


def test_http_error_fails_closed_without_echoing_response_values() -> None:
    api = Api({REF_URL: HTTPError(REF_URL, 503, "secret-response-value", Message(), None)})

    with pytest.raises(lineage.ReleaseLineageError, match="HTTP 503") as caught:
        ensure(api)
    assert "secret-response-value" not in str(caught.value)


def test_missing_token_fails_closed_before_any_request() -> None:
    api = Api({})

    with pytest.raises(lineage.ReleaseLineageError, match="GH_TOKEN is required"):
        lineage.ensure_release_lineage(REPOSITORY, TAG, TAG_COMMIT, "", opener=api)
    assert api.urls == []


@pytest.mark.parametrize(
    ("repository", "tag", "commit"),
    [
        ("missing-owner", TAG, TAG_COMMIT),
        (REPOSITORY, "", TAG_COMMIT),
        (REPOSITORY, TAG, "not-a-commit"),
    ],
)
def test_invalid_inputs_fail_before_any_request(repository: str, tag: str, commit: str) -> None:
    api = Api({})

    with pytest.raises(lineage.ReleaseLineageError, match="invalid|OWNER/REPO|non-empty"):
        lineage.ensure_release_lineage(repository, tag, commit, "token", opener=api)
    assert api.urls == []
