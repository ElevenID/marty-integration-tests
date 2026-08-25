"""Prevent the retired Python MMF runtime from returning to this test suite."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOTS = (
    ROOT / ".github",
    ROOT / "config",
    ROOT / "requirements",
    ROOT / "scripts",
    ROOT / "services",
    ROOT / "tests",
    ROOT / "tools",
)
ROOT_INPUTS = (
    ROOT / "Dockerfile.integration-tests",
    ROOT / "docker-compose.yml",
    ROOT / "docker-compose.rust-revocation.yml",
    ROOT / "pyproject.toml",
)
TEXT_SUFFIXES = {".json", ".py", ".toml", ".yaml", ".yml"}

# Assemble these fragments so the policy test does not report its own source.
RETIRED_PYTHON_MMF_FRAGMENTS = (
    "marty" + "-msf",
    "marty" + "_msf",
    "from " + "mmf",
    "import " + "mmf",
)


def _runtime_and_test_inputs() -> list[Path]:
    inputs = list(ROOT_INPUTS)
    for source_root in SOURCE_ROOTS:
        inputs.extend(
            path
            for path in source_root.rglob("*")
            if path.is_file()
            and (path.suffix in TEXT_SUFFIXES or path.name.startswith("Dockerfile"))
            and "__pycache__" not in path.parts
        )
    return sorted(inputs)


def test_runtime_and_test_inputs_do_not_depend_on_python_mmf() -> None:
    violations: list[str] = []

    for path in _runtime_and_test_inputs():
        source = path.read_text(encoding="utf-8").lower()
        for fragment in RETIRED_PYTHON_MMF_FRAGMENTS:
            if fragment in source:
                violations.append(f"{path.relative_to(ROOT)}: {fragment}")

    assert not violations, (
        "Retired Python MMF dependency found; use the canonical Rust crates "
        "and language-neutral behavior contracts:\n" + "\n".join(violations)
    )
