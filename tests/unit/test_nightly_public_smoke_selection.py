"""Keep the candidate nightly public-stack smoke set small and explicit."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

TESTS_DIR = Path(__file__).parents[1]
PUBLIC_STACK_DIR = TESTS_DIR / "oss_stack"

EXPECTED_CASE_IDS = {
    "tests/oss_stack/test_public_stack.py::test_gateway_is_healthy",
    "tests/oss_stack/test_public_stack.py::test_required_public_services_are_healthy",
    "tests/oss_stack/test_public_stack.py::test_oid4vci_metadata_is_available",
    "tests/oss_stack/test_public_stack.py::test_ui_is_served",
    "tests/oss_stack/test_positive_credential_issuance.py::test_application_offer_redeems_to_issued_credential",
}


def _marked_case_ids(stack_dir: Path, tests_dir: Path) -> set[str]:
    # Ask pytest which cases -m will actually select. Static decorator inspection
    # misses module/class marks, aliases, and marks added during collection.
    result = subprocess.run(  # noqa: S603 - fixed interpreter and arguments; no shell
        [
            sys.executable,
            "-m",
            "pytest",
            str(stack_dir.relative_to(tests_dir.parent).as_posix()),
            "-m",
            "nightly_public_smoke",
            "--collect-only",
            "-q",
            "-o",
            "addopts=",
        ],
        cwd=tests_dir.parent,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return {line.strip() for line in result.stdout.splitlines() if line.startswith("tests/") and "::" in line}


def test_candidate_nightly_smoke_case_ids_are_explicit() -> None:
    selected = _marked_case_ids(PUBLIC_STACK_DIR, TESTS_DIR)
    assert selected == EXPECTED_CASE_IDS


def test_candidate_nightly_smoke_guard_sees_new_test_files(tmp_path: Path) -> None:
    stack_dir = tmp_path / "tests" / "oss_stack"
    stack_dir.mkdir(parents=True)
    (stack_dir / "test_new_journey.py").write_text(
        "import pytest\n\n"
        "@pytest.mark.nightly_public_smoke\n"
        "def test_unreviewed_case():\n"
        "    pass\n",
        encoding="utf-8",
    )

    assert _marked_case_ids(stack_dir, tmp_path / "tests") == {
        "tests/oss_stack/test_new_journey.py::test_unreviewed_case"
    }


def test_candidate_nightly_smoke_guard_sees_module_markers(tmp_path: Path) -> None:
    stack_dir = tmp_path / "tests" / "oss_stack"
    stack_dir.mkdir(parents=True)
    (stack_dir / "test_module_mark.py").write_text(
        "import pytest\n"
        "pytestmark = pytest.mark.nightly_public_smoke\n\n"
        "def test_unreviewed_case():\n"
        "    pass\n",
        encoding="utf-8",
    )

    assert _marked_case_ids(stack_dir, tmp_path / "tests") == {
        "tests/oss_stack/test_module_mark.py::test_unreviewed_case"
    }
