from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request

import pytest

SCRIPT = Path(__file__).parents[2] / "scripts" / "check_release_absent.py"
SPEC = importlib.util.spec_from_file_location("check_release_absent", SCRIPT)
assert SPEC is not None
assert SPEC.loader is not None
release_check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_check)


class Response(io.BytesIO):
    def __enter__(self) -> Response:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def response(payload: object) -> Response:
    return Response(json.dumps(payload).encode())


def test_tag_404_requires_visible_complete_draft_scan() -> None:
    visited: list[str] = []

    def missing(request: Request, *, timeout: int) -> Response:
        assert timeout == 30
        visited.append(request.full_url)
        if "/releases/tags/" in request.full_url:
            raise HTTPError(request.full_url, 404, "Not Found", {}, None)
        if "/releases?" in request.full_url:
            return response([])
        return response({"permissions": {"push": True}})

    release_check.ensure_release_absent("ElevenID/marty-integration-tests", "v1.1.3", "token", opener=missing)
    assert len(visited) == 3
    assert visited[-1].endswith("/releases?per_page=100&page=1")


@pytest.mark.parametrize(("draft", "state"), [(True, "draft"), (False, "published")])
def test_existing_release_fails_closed(draft: bool, state: str) -> None:
    with pytest.raises(release_check.ReleaseAlreadyExistsError, match=state):
        release_check.ensure_release_absent(
            "ElevenID/marty-integration-tests",
            "v1.1.3",
            "token",
            opener=lambda *_args, **_kwargs: response({"tag_name": "v1.1.3", "draft": draft}),
        )


def test_lookup_failure_is_not_treated_as_absence() -> None:
    def unavailable(request: object, *, timeout: int) -> object:
        assert timeout == 30
        raise HTTPError(str(request), 503, "Unavailable", {}, None)

    with pytest.raises(release_check.ReleaseLookupError, match="HTTP 503"):
        release_check.ensure_release_absent("ElevenID/marty-integration-tests", "v1.1.3", "token", opener=unavailable)


@pytest.mark.parametrize("permissions", [{}, {"push": False}, {"push": "true"}])
def test_hidden_draft_visibility_cannot_be_called_absence(permissions: dict[str, Any]) -> None:
    def opener(request: Request, *, timeout: int) -> Response:
        assert timeout == 30
        if "/releases/tags/" in request.full_url:
            raise HTTPError(request.full_url, 404, "Not Found", {}, None)
        return response({"permissions": permissions})

    with pytest.raises(release_check.ReleaseLookupError, match="visibility"):
        release_check.ensure_release_absent("ElevenID/marty-integration-tests", "v1.1.3", "token", opener=opener)


def test_draft_on_later_page_refuses_publication() -> None:
    def opener(request: Request, *, timeout: int) -> Response:
        assert timeout == 30
        if "/releases/tags/" in request.full_url:
            raise HTTPError(request.full_url, 404, "Not Found", {}, None)
        if request.full_url.endswith("page=1"):
            return response([{"tag_name": "v9.9.9", "draft": False}] * 100)
        if request.full_url.endswith("page=2"):
            return response([{"tag_name": "v1.1.3", "draft": True}])
        return response({"permissions": {"push": True}})

    with pytest.raises(release_check.ReleaseAlreadyExistsError, match="draft"):
        release_check.ensure_release_absent("ElevenID/marty-integration-tests", "v1.1.3", "token", opener=opener)


@pytest.mark.parametrize("listing", [{}, [{"tag_name": "v1.1.3"}], [{"tag_name": "v1.1.3", "draft": "false"}]])
def test_malformed_history_fails_closed(listing: Any) -> None:
    def opener(request: Request, *, timeout: int) -> Response:
        assert timeout == 30
        if "/releases/tags/" in request.full_url:
            raise HTTPError(request.full_url, 404, "Not Found", {}, None)
        if "/releases?" in request.full_url:
            return response(listing)
        return response({"permissions": {"push": True}})

    with pytest.raises(release_check.ReleaseLookupError, match="listing"):
        release_check.ensure_release_absent("ElevenID/marty-integration-tests", "v1.1.3", "token", opener=opener)


def test_exhausting_listing_bound_does_not_prove_absence() -> None:
    def opener(request: Request, *, timeout: int) -> Response:
        assert timeout == 30
        if "/releases/tags/" in request.full_url:
            raise HTTPError(request.full_url, 404, "Not Found", {}, None)
        if "/releases?" in request.full_url:
            return response([{"tag_name": "v9.9.9", "draft": False}] * 100)
        return response({"permissions": {"push": True}})

    with pytest.raises(release_check.ReleaseLookupError, match="bound"):
        release_check.ensure_release_absent("ElevenID/marty-integration-tests", "v1.1.3", "token", opener=opener)
