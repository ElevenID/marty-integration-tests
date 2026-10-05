"""Keep the candidate nightly public-stack smoke set small and explicit."""

from __future__ import annotations

import ast
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
    selected = set()
    for path in sorted(stack_dir.rglob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        selected.update(
            f"tests/{path.relative_to(tests_dir).as_posix()}::{node.name}"
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and any(
                isinstance(decorator, ast.Attribute)
                and isinstance(decorator.value, ast.Attribute)
                and isinstance(decorator.value.value, ast.Name)
                and decorator.value.value.id == "pytest"
                and decorator.value.attr == "mark"
                and decorator.attr == "nightly_public_smoke"
                for decorator in node.decorator_list
            )
        )
    return selected


def test_candidate_nightly_smoke_case_ids_are_explicit() -> None:
    selected = _marked_case_ids(PUBLIC_STACK_DIR, TESTS_DIR)
    assert selected == EXPECTED_CASE_IDS


def test_candidate_nightly_smoke_guard_sees_new_test_files(tmp_path: Path) -> None:
    stack_dir = tmp_path / "oss_stack"
    stack_dir.mkdir()
    (stack_dir / "test_new_journey.py").write_text(
        "@pytest.mark.nightly_public_smoke\n"
        "def test_unreviewed_case():\n"
        "    pass\n",
        encoding="utf-8",
    )

    assert _marked_case_ids(stack_dir, tmp_path) == {
        "tests/oss_stack/test_new_journey.py::test_unreviewed_case"
    }
