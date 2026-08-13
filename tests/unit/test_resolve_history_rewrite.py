from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "resolve_history_rewrite", ROOT / "scripts" / "resolve_history_rewrite.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load history rewrite resolver")
resolver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(resolver)

OLD = "1" * 40
NEW = "2" * 40
REPOSITORY = "ElevenID/marty-ui"


def write_map(path: Path, mapping: dict[str, str] | None = None) -> Path:
    path.write_text(
        json.dumps(
            {
                "schema": resolver.SCHEMA,
                "repositories": {REPOSITORY: {"old_to_new": mapping or {}}},
            }
        ),
        encoding="utf-8",
    )
    return path


def test_empty_reviewed_map_preserves_commit(tmp_path: Path) -> None:
    assert resolver.resolve_commit(REPOSITORY, OLD, write_map(tmp_path / "map.json")) == OLD


def test_reviewed_mapping_translates_old_commit(tmp_path: Path) -> None:
    assert resolver.resolve_commit(REPOSITORY, OLD, write_map(tmp_path / "map.json", {OLD: NEW})) == NEW


def test_default_map_declares_rewritten_repositories_and_is_initially_noop() -> None:
    mappings = resolver.load_rewrite_map(resolver.DEFAULT_MAP)
    assert set(mappings) == {"ElevenID/marty-ui", "ElevenID/marty-microservices-framework"}
    assert mappings["ElevenID/marty-ui"] == {}
    assert mappings["ElevenID/marty-microservices-framework"] == {}


def test_reviewed_stack_checkout_matches_rewrite_map() -> None:
    pin = json.loads((ROOT / "conformance" / "stack-under-test.json").read_text(encoding="utf-8"))
    assert resolver.resolve_commit(pin["repository"], pin["marty_commit"]) == pin["marty_checkout_commit"]


@pytest.mark.parametrize("commit", ["", "A" * 40, "a" * 39, "not-a-commit"])
def test_rejects_noncanonical_commit(commit: str, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="full lowercase"):
        resolver.resolve_commit(REPOSITORY, commit, write_map(tmp_path / "map.json"))


def test_rejects_undeclared_repository(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not declared"):
        resolver.resolve_commit("ElevenID/other", OLD, write_map(tmp_path / "map.json"))


def test_rejects_invalid_mapped_commit(tmp_path: Path) -> None:
    path = write_map(tmp_path / "map.json", {OLD: "invalid"})
    with pytest.raises(ValueError, match="invalid new commit"):
        resolver.resolve_commit(REPOSITORY, OLD, path)
