#!/usr/bin/env python3
"""Translate an immutable commit pin after an approved repository rewrite."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MAP = ROOT / "conformance" / "history-rewrite-map.json"
SCHEMA = "elevenid.history-rewrite-map/v1"
COMMIT = re.compile(r"^[0-9a-f]{40}$")


def load_rewrite_map(path: Path) -> dict[str, dict[str, str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise ValueError(f"history rewrite map schema must be {SCHEMA}")
    repositories = data.get("repositories")
    if not isinstance(repositories, dict) or not repositories:
        raise ValueError("history rewrite map must declare repositories")

    result: dict[str, dict[str, str]] = {}
    for repository, definition in repositories.items():
        if not isinstance(repository, str) or not repository:
            raise ValueError("history rewrite map contains an invalid repository name")
        if not isinstance(definition, dict):
            raise ValueError(f"history rewrite entry for {repository} must be an object")
        mapping = definition.get("old_to_new")
        if not isinstance(mapping, dict):
            raise ValueError(f"history rewrite entry for {repository} must contain old_to_new")
        for old_commit, new_commit in mapping.items():
            if not isinstance(old_commit, str) or not COMMIT.fullmatch(old_commit):
                raise ValueError(f"history rewrite map contains an invalid old commit for {repository}")
            if not isinstance(new_commit, str) or not COMMIT.fullmatch(new_commit):
                raise ValueError(f"history rewrite map contains an invalid new commit for {repository}")
        result[repository] = mapping
    return result


def resolve_commit(repository: str, commit: str, map_path: Path = DEFAULT_MAP) -> str:
    if not COMMIT.fullmatch(commit):
        raise ValueError("commit must be a full lowercase 40-character SHA-1")
    mappings = load_rewrite_map(map_path)
    if repository not in mappings:
        raise ValueError(f"repository is not declared in history rewrite map: {repository}")
    return mappings[repository].get(commit, commit)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--repository", required=True)
    result.add_argument("--commit", required=True)
    result.add_argument("--map", dest="map_path", type=Path, default=DEFAULT_MAP)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    print(resolve_commit(args.repository, args.commit, args.map_path))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"History rewrite resolution error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
