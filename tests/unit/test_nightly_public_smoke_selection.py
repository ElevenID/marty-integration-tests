"""Keep the candidate nightly public-stack smoke set small and explicit."""

from __future__ import annotations

import ast
from pathlib import Path

PUBLIC_STACK = Path(__file__).parents[1] / "oss_stack" / "test_public_stack.py"
POSITIVE_ISSUANCE = Path(__file__).parents[1] / "oss_stack" / "test_positive_credential_issuance.py"

EXPECTED_CASE_IDS = {
    "tests/oss_stack/test_public_stack.py::test_gateway_is_healthy",
    "tests/oss_stack/test_public_stack.py::test_required_public_services_are_healthy",
    "tests/oss_stack/test_public_stack.py::test_oid4vci_metadata_is_available",
    "tests/oss_stack/test_public_stack.py::test_ui_is_served",
    "tests/oss_stack/test_positive_credential_issuance.py::test_application_offer_redeems_to_issued_credential",
}


def test_candidate_nightly_smoke_case_ids_are_explicit() -> None:
    selected = set()
    for path in (PUBLIC_STACK, POSITIVE_ISSUANCE):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        selected.update(
            f"tests/oss_stack/{path.name}::{node.name}"
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
    assert selected == EXPECTED_CASE_IDS
