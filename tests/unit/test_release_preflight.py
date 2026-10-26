"""The actual release API sequence's context, visibility and ownership gates."""

from __future__ import annotations

import copy
import importlib.util
import io
import json
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request

import pytest

SCRIPTS = Path(__file__).parents[2] / "scripts"
REPOSITORY = "ElevenID/marty-integration-tests"
TAG = "v1.2.91"


def load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / (name + ".py"))
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


guard = load("check_release_absent")
probe = load("probe_release_lookup")


@pytest.fixture(autouse=True)
def trusted_context(monkeypatch: pytest.MonkeyPatch) -> None:
    context = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_JOB": "release-lookup-probe",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_WORKFLOW_REF": REPOSITORY + "/.github/workflows/release-preflight.yml@refs/heads/main",
        "GITHUB_SHA": "b" * 40,
    }
    for field, value in context.items():
        monkeypatch.setenv(field, value)


class DraftAPI:
    def __init__(
        self,
        *,
        hidden: bool = False,
        changed: bool = False,
        preexisting: bool = False,
        delay: int = 0,
        lost_response: bool = False,
    ) -> None:
        self.hidden, self.changed, self.lost_response = hidden, changed, lost_response
        self.delay, self.observations = delay, 0
        self.created = self.deleted = 0
        self.draft: dict[str, Any] | None = (
            {"id": 99, "tag_name": TAG, "draft": True, "body": "user-owned"} if preexisting else None
        )

    def __call__(self, request: Request, *, timeout: int) -> io.BytesIO:
        assert timeout == 30
        path, method = urlsplit(request.full_url).path, request.get_method()
        if "/git/ref/tags/" in path:
            value = {"object": {"sha": "a" * 40}}
        elif "/releases/tags/" in path:
            raise HTTPError(request.full_url, 404, "Not Found", {}, None)
        elif method == "POST" and path.endswith("/releases"):
            assert self.draft is None
            value = json.loads(request.data)
            assert value["draft"] is True
            assert value["prerelease"] is True
            assert value["tag_name"] == TAG
            self.created += 1
            self.draft = {**value, "id": 101, "assets": []}
            if self.lost_response:
                raise HTTPError(request.full_url, 503, "Unknown creation result", {}, None)
            value = self.draft
        elif method == "GET" and path.endswith("/releases"):
            if self.created:
                self.observations += 1
            unavailable = self.created and (self.hidden or self.observations <= self.delay)
            value = [self.draft] if self.draft and not unavailable else []
        elif path.endswith("/releases/101"):
            if self.draft is None:
                raise HTTPError(request.full_url, 404, "Not Found", {}, None)
            if method == "DELETE":
                assert self.draft["draft"] is True
                self.deleted += 1
                self.draft = None
                return io.BytesIO(b"")
            if self.changed:
                self.draft["assets"] = [{"id": 7}]
            value = self.draft
        else:
            raise AssertionError("Unexpected API operation: " + method + " " + path)
        return io.BytesIO(json.dumps(value).encode())


def exercise(api: Callable[..., Any], path: Path, waits: list[float]) -> dict[str, Any]:
    return probe.exercise(REPOSITORY, TAG, "a" * 40, "a" * 40, "fixture-token", path, opener=api, sleeper=waits.append)


@pytest.mark.parametrize("job", ["verify-source", "release"])
def test_tag_jobs_accept_their_declared_installation_token(job: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_JOB", job)
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("GITHUB_REF", "refs/tags/" + TAG)
    monkeypatch.setenv("GITHUB_WORKFLOW_REF", REPOSITORY + "/.github/workflows/release.yml@refs/tags/" + TAG)
    guard.ensure_release_absent(REPOSITORY, TAG, "fixture-token", actions_write_token=True, opener=DraftAPI())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("GITHUB_ACTIONS", "false"),
        ("GITHUB_JOB", "foreign"),
        ("GITHUB_REPOSITORY", "foreign/repository"),
        ("GITHUB_REF", "refs/heads/feature"),
        ("GITHUB_EVENT_NAME", "pull_request"),
    ],
)
def test_untrusted_actions_context_is_rejected(field: str, value: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(field, value)
    with pytest.raises(guard.ReleaseLookupError, match="trusted"):
        guard.ensure_release_absent(REPOSITORY, TAG, "fixture-token", actions_write_token=True, opener=DraftAPI())


def test_delayed_exact_owned_draft_is_refused_and_removed(tmp_path: Path) -> None:
    api, waits = DraftAPI(delay=2), []
    path = tmp_path / "receipt.json"
    record = exercise(api, path, waits)
    assert waits == [2, 2]
    assert record["lookup_observations"][:2] == [None, None]
    assert record["lookup_observations"][2]["id"] == record["fixture_id"]
    assert record["result"] == "passed"
    assert all(record[k] for k in ("draft_refused", "owned_draft_removed", "tag_unchanged"))
    assert (api.created, api.deleted) == (1, 1)
    assert "fixture-token" not in path.read_text()


def test_permanently_hidden_draft_fails_but_cleans_its_fixture(tmp_path: Path) -> None:
    api, waits = DraftAPI(hidden=True), []
    path = tmp_path / "receipt.json"
    with pytest.raises(RuntimeError, match="preflight failed"):
        exercise(api, path, waits)
    record = json.loads(path.read_text())
    assert waits == [2] * 9
    assert record["lookup_observations"] == [None] * 10
    assert not record["draft_refused"]
    assert record["owned_draft_removed"]
    assert record["failure_stage"] == "observe_owned_draft"
    assert record["failure_type"] == "ValueError"
    assert (api.created, api.deleted) == (1, 1)


@pytest.mark.parametrize("denied", [False, True])
def test_foreign_identity_and_lookup_errors_fail_without_waiting(tmp_path: Path, denied: bool) -> None:
    api, waits = DraftAPI(), []
    path = tmp_path / "receipt.json"

    def opener(request: Request, *, timeout: int) -> io.BytesIO:
        if request.get_method() == "GET" and "/releases?" in request.full_url and api.created:
            if denied:
                raise HTTPError(request.full_url, 403, "Forbidden", {}, None)
            return io.BytesIO(json.dumps([{"id": 999, "tag_name": TAG, "draft": True}]).encode())
        return api(request, timeout=timeout)

    with pytest.raises(RuntimeError, match="preflight failed"):
        exercise(opener, path, waits)
    assert not waits
    assert (api.created, api.deleted) == (1, 1)
    record = json.loads(path.read_text())
    assert not record["draft_refused"]
    assert record["failure_stage"] == "observe_owned_draft"


@pytest.mark.parametrize("options", [{"changed": True}, {"preexisting": True}])
def test_changed_and_preexisting_drafts_are_preserved(tmp_path: Path, options: dict[str, bool]) -> None:
    api = DraftAPI(**options)
    original = copy.deepcopy(api.draft)
    path = tmp_path / "receipt.json"
    with pytest.raises(RuntimeError, match="preflight failed"):
        exercise(api, path, [])
    assert api.deleted == 0
    if original is not None:
        assert api.created == 0
        assert api.draft == original
    assert json.loads(path.read_text())["result"] == "failed"


def test_unknown_creation_result_preserves_nonce_for_recovery_without_blind_delete(tmp_path: Path) -> None:
    api, path = DraftAPI(lost_response=True), tmp_path / "receipt.json"
    with pytest.raises(RuntimeError, match="preflight failed"):
        exercise(api, path, [])
    record = json.loads(path.read_text())
    assert record["fixture_id"] is None
    assert not record["owned_draft_removed"]
    assert record["result"] == "failed"
    assert record["failure_stage"] == "create_owned_draft"
    assert api.draft is not None
    assert api.draft["body"] == record["owner_nonce"]
    assert api.created == 1
    assert api.deleted == 0
