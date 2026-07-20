from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
from urllib.error import HTTPError

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


def test_only_a_404_proves_the_release_is_absent() -> None:
    def missing(request: object, *, timeout: int) -> object:
        assert timeout == 30
        raise HTTPError(str(request), 404, "Not Found", {}, None)

    release_check.ensure_release_absent("ElevenID/marty-integration-tests", "v1.1.3", "token", opener=missing)


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
