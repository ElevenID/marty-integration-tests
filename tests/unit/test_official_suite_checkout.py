from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "official_suite_checkout", ROOT / "scripts" / "official_suite_checkout.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load official suite checkout helper")
checkout = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checkout)


def test_all_suite_sources_are_exact_and_allowlisted() -> None:
    oidf_repository, oidf_commit = checkout.pinned_source("oidf")
    w3c_repository, w3c_commit = checkout.pinned_source("w3c")
    assert oidf_repository == "https://gitlab.com/openid/conformance-suite.git"
    assert w3c_repository == "https://github.com/w3c/vc-data-model-2.0-test-suite.git"
    assert len(oidf_commit) == len(w3c_commit) == 40


def test_checkout_refuses_to_reuse_nonempty_directory(tmp_path: Path) -> None:
    (tmp_path / "existing").write_text("do not replace", encoding="utf-8")
    with pytest.raises(FileExistsError, match="non-empty"):
        checkout.checkout("w3c", tmp_path)
