from __future__ import annotations

import importlib.util
import json
import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "official_suite_update_boundaries", ROOT / "scripts/official_suite_updates.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load official-suite update helper")
updates = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(updates)
BRANCH = "automation/official-suite-updates"


@pytest.mark.parametrize("sha", ["a" * 39, "a" * 41, "z" * 40, "0" * 40, "-" * 40])
@pytest.mark.parametrize("kind", ["head", "tag"])
def test_remote_object_ids_are_validated(sha: str, kind: str, monkeypatch: pytest.MonkeyPatch) -> None:
    ref = "refs/heads/main" if kind == "head" else "refs/tags/v1"
    monkeypatch.setattr(updates.subprocess, "check_output", lambda *_args, **_kwargs: f"{sha}\t{ref}\n")
    with pytest.raises(RuntimeError):
        if kind == "head":
            updates.git_head("https://example.test/repository.git", ref)
        else:
            updates.git_tag_commit("https://example.test/repository.git", "v1")


@pytest.mark.parametrize(
    "output",
    [
        "",
        f"{'a' * 40}\trefs/heads/other\n",
        f"{'a' * 40}\trefs/heads/main\n{'a' * 40}\trefs/heads/main\n",
        f"{'a' * 40}\trefs/heads/main\n{'b' * 40}\trefs/heads/main\n",
        f"{'a' * 40}\n",
        f"{'a' * 40}\trefs/heads/main extra\n",
    ],
)
def test_head_resolution_rejects_missing_or_ambiguous_output(output: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(updates.subprocess, "check_output", lambda *_args, **_kwargs: output)
    with pytest.raises(RuntimeError):
        updates.git_head("https://example.test/repository.git", "refs/heads/main")


@pytest.mark.parametrize(
    "output",
    [
        "",
        f"{'a' * 40}\trefs/tags/v1^{{}}\n",
        f"{'a' * 40}\trefs/tags/v1\n{'b' * 40}\trefs/tags/v1\n",
        f"{'a' * 40}\trefs/tags/v1\n{'b' * 40}\trefs/tags/v2\n",
        f"{'a' * 40}\trefs/tags/v1\ninvalid line here\n",
        f"{'z' * 40}\trefs/tags/v1\n{'b' * 40}\trefs/tags/v1^{{}}\n",
        f"{'a' * 40}\trefs/tags/v1\n{'0' * 40}\trefs/tags/v1^{{}}\n",
    ],
)
def test_tag_resolution_rejects_incomplete_or_malformed_output(output: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(updates.subprocess, "check_output", lambda *_args, **_kwargs: output)
    with pytest.raises(RuntimeError):
        updates.git_tag_commit("https://example.test/repository.git", "v1")


@pytest.mark.parametrize("kind", ["head", "tag"])
def test_git_requests_are_bounded_and_separate_options(kind: str, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}
    ref = "refs/heads/main" if kind == "head" else "refs/tags/v1"

    def check_output(args: list[str], **kwargs: object) -> str:
        captured["args"] = args
        captured.update(kwargs)
        return f"{'a' * 40}\t{ref}\n"

    monkeypatch.setattr(updates.subprocess, "check_output", check_output)
    repository = "https://example.test/repository.git"
    if kind == "head":
        assert updates.git_head(repository, ref) == "a" * 40
    else:
        assert updates.git_tag_commit(repository, "v1") == "a" * 40
    expected_refs = [ref] if kind == "head" else [ref, f"{ref}^{{}}"]
    assert captured == {
        "args": ["git", "ls-remote", "--", repository, *expected_refs],
        "text": True,
        "timeout": 30,
    }


@pytest.mark.parametrize("kind", ["head", "tag"])
def test_git_timeout_is_a_controlled_failure(kind: str, monkeypatch: pytest.MonkeyPatch) -> None:
    def timeout(*_args: object, **_kwargs: object) -> str:
        raise subprocess.TimeoutExpired("git ls-remote", 30)

    monkeypatch.setattr(updates.subprocess, "check_output", timeout)
    with pytest.raises(RuntimeError, match="timed out after 30s"):
        if kind == "head":
            updates.git_head("https://example.test/repository.git")
        else:
            updates.git_tag_commit("https://example.test/repository.git", "v1")


def test_failed_observation_preserves_the_existing_record(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    record = tmp_path / "upstream-review.json"
    original = b'{"reviewed": "preserve this evidence"}\n'
    record.write_bytes(original)
    monkeypatch.setattr(updates, "RECORD", record)
    monkeypatch.setattr(updates.sys, "argv", ["official_suite_updates.py", "--write"])

    def failed_observation() -> dict:
        raise RuntimeError("upstream observation failed")

    monkeypatch.setattr(updates, "observe", failed_observation)
    with pytest.raises(RuntimeError, match="observation failed"):
        updates.main()
    assert record.read_bytes() == original


def _git(cwd: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=cwd, text=True, stderr=subprocess.PIPE, timeout=15).strip()


def _repository(tmp_path: Path) -> tuple[Path, Path, str]:
    remote = tmp_path / "remote.git"
    work = tmp_path / "work"
    work.mkdir()
    _git(tmp_path, "init", "--bare", str(remote))
    _git(work, "init", "-b", "main")
    _git(work, "config", "user.name", "Regression Test")
    _git(work, "config", "user.email", "regression@example.invalid")
    (work / "README.md").write_text("preserved main\n", encoding="utf-8")
    _git(work, "add", "README.md")
    _git(work, "commit", "-m", "Initial main")
    head = _git(work, "rev-parse", "HEAD")
    _git(work, "remote", "add", "origin", str(remote))
    _git(work, "push", "origin", "main")
    (work / "conformance").mkdir()
    (work / "conformance/upstream-review.json").write_text('{"new": "observation"}\n', encoding="utf-8")
    return work, remote, head


def _feature_branch(work: Path) -> str:
    _git(work, "checkout", "-b", BRANCH)
    (work / "preserved-feature.txt").write_text("human-reviewed migration work\n", encoding="utf-8")
    _git(work, "add", "preserved-feature.txt")
    _git(work, "commit", "-m", "Preserve migration implementation")
    head = _git(work, "rev-parse", "HEAD")
    _git(work, "push", "origin", BRANCH)
    _git(work, "checkout", "main")
    return head


def test_real_git_resolves_head_and_both_tag_types(tmp_path: Path) -> None:
    work, remote, head = _repository(tmp_path)
    _git(work, "tag", "lightweight")
    _git(work, "tag", "-a", "annotated", "-m", "Annotated release")
    _git(work, "push", "origin", "--tags")
    assert updates.git_head(str(remote), "refs/heads/main") == head
    assert updates.git_tag_commit(str(remote), "lightweight") == head
    assert updates.git_tag_commit(str(remote), "annotated") == head
    assert _git(work, "rev-parse", "annotated") != head
    with pytest.raises(RuntimeError):
        updates.git_tag_commit(str(remote), "missing")


def _run_publication(
    work: Path,
    tmp_path: Path,
    *,
    open_pr: str = "",
    gh_failure: bool = False,
    git_failure: str = "",
    race_head: str = "",
    is_draft: bool = True,
) -> tuple[subprocess.CompletedProcess[str], str]:
    """Execute the actual workflow shell against real Git; stub only GitHub PR calls."""
    workflow = yaml.safe_load((ROOT / ".github/workflows/official-suite-updates.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["review-upstream-drift"]["steps"]
    script = next(step["run"] for step in steps if step.get("name") == "Open review PR")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "github-calls"
    gh = bin_dir / "gh"
    gh.write_text(
        '#!/bin/sh\n'
        'printf "%s\\n" "$*" >> "$CALLS"\n'
        'if [ "$1 $2" = "pr list" ]; then\n'
        '  if [ "$GH_FAILURE" = "1" ]; then exit 17; fi\n'
        '  case "$*" in\n'
        '    *"select(.isDraft)"*) if [ "$IS_DRAFT" != "1" ]; then exit 0; fi ;;\n'
        '  esac\n'
        '  printf "%s\\n" "$OPEN_PR"\n'
        'fi\n',
        encoding="utf-8",
    )
    gh.chmod(0o755)
    real_git = shutil.which("git")
    if real_git is None:
        raise RuntimeError("Git is required for the publication regression")
    git_wrapper = bin_dir / "git"
    git_wrapper.write_text(
        '#!/bin/sh\n'
        'if [ "$1" = "$GIT_FAILURE" ]; then exit 19; fi\n'
        'if [ "$1" = "push" ] && [ -n "$RACE_HEAD" ]; then\n'
        f'  {shlex.quote(real_git)} --git-dir="$REMOTE" update-ref "refs/heads/{BRANCH}" "$RACE_HEAD" || exit $?\n'
        'fi\n'
        f'exec {shlex.quote(real_git)} "$@"\n',
        encoding="utf-8",
    )
    git_wrapper.chmod(0o755)
    env = dict(os.environ)
    env.update(
        PATH=f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        CALLS=str(calls),
        OPEN_PR=open_pr,
        GH_FAILURE="1" if gh_failure else "0",
        GIT_FAILURE=git_failure,
        RACE_HEAD=race_head,
        REMOTE=str(tmp_path / "remote.git"),
        IS_DRAFT="1" if is_draft else "0",
        GIT_TERMINAL_PROMPT="0",
    )
    completed = subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script],
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    return completed, calls.read_text(encoding="utf-8") if calls.exists() else ""


@pytest.mark.parametrize("is_draft", [True, False])
def test_open_review_preserves_branch_and_description(tmp_path: Path, is_draft: bool) -> None:
    work, remote, _base = _repository(tmp_path)
    head = _feature_branch(work)
    result, calls = _run_publication(work, tmp_path, open_pr="490", is_draft=is_draft)
    assert result.returncode == 0, result.stderr
    assert _git(remote, "rev-parse", f"refs/heads/{BRANCH}") == head
    assert _git(work, "branch", "--show-current") == "main"
    assert "pr create" not in calls
    assert "pr edit" not in calls
    assert "Preserving open review PR #490" in result.stdout


def test_orphan_review_branch_is_not_replaced(tmp_path: Path) -> None:
    work, remote, _base = _repository(tmp_path)
    head = _feature_branch(work)
    result, calls = _run_publication(work, tmp_path)
    assert result.returncode != 0
    assert _git(remote, "rev-parse", f"refs/heads/{BRANCH}") == head
    assert "pr create" not in calls
    assert "pr edit" not in calls
    assert "already exists" in result.stdout


def test_missing_branch_creates_one_draft_from_the_observation(tmp_path: Path) -> None:
    work, remote, head = _repository(tmp_path)
    result, calls = _run_publication(work, tmp_path)
    assert result.returncode == 0, result.stderr
    published = _git(remote, "rev-parse", f"refs/heads/{BRANCH}")
    assert _git(remote, "rev-parse", f"{published}^") == head
    assert _git(remote, "diff", "--name-only", head, published) == "conformance/upstream-review.json"
    assert json.loads(_git(remote, "show", f"{published}:conformance/upstream-review.json")) == {"new": "observation"}
    assert calls.count("pr create --draft") == 1
    assert "pr edit" not in calls


def test_pr_lookup_failure_does_not_push(tmp_path: Path) -> None:
    work, remote, _head = _repository(tmp_path)
    result, calls = _run_publication(work, tmp_path, gh_failure=True)
    assert result.returncode == 17
    assert _git(remote, "for-each-ref", "--format=%(refname)", f"refs/heads/{BRANCH}") == ""
    assert "pr create" not in calls


def test_remote_lookup_error_is_not_treated_as_absence(tmp_path: Path) -> None:
    work, remote, _head = _repository(tmp_path)
    result, calls = _run_publication(work, tmp_path, git_failure="ls-remote")
    assert result.returncode == 19
    assert _git(remote, "for-each-ref", "--format=%(refname)", f"refs/heads/{BRANCH}") == ""
    assert "pr create" not in calls


def test_concurrently_created_branch_is_not_overwritten(tmp_path: Path) -> None:
    work, remote, head = _repository(tmp_path)
    result, calls = _run_publication(work, tmp_path, race_head=head)
    assert result.returncode != 0
    assert _git(remote, "rev-parse", f"refs/heads/{BRANCH}") == head
    assert "pr create" not in calls


def test_failed_push_never_creates_a_pr(tmp_path: Path) -> None:
    work, remote, _head = _repository(tmp_path)
    result, calls = _run_publication(work, tmp_path, git_failure="push")
    assert result.returncode == 19
    assert _git(remote, "for-each-ref", "--format=%(refname)", f"refs/heads/{BRANCH}") == ""
    assert "pr create" not in calls
