"""Prevent owned product regressions from masquerading as official evidence."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OWNED_INTEGRATION = ROOT / "tests" / "integration"
FORBIDDEN_CLAIMS = (
    "oidf-mirrored",
    "expected to fail until",
)
FORBIDDEN_POSITIVE_FIXTURES = (
    "dummy-vc-jwt-string",
    "falls back to a dummy signature",
    "dummy signature",
)


def _owned_protocol_sources() -> list[Path]:
    return sorted(OWNED_INTEGRATION.glob("test_*conformance.py"))


def test_owned_protocol_regressions_do_not_claim_official_provenance() -> None:
    violations: list[str] = []
    for path in _owned_protocol_sources():
        content = path.read_text(encoding="utf-8").lower()
        for marker in FORBIDDEN_CLAIMS:
            if marker in content:
                violations.append(f"{path.relative_to(ROOT)}: {marker}")
    assert not violations, "owned tests make misleading official claims: " + ", ".join(violations)


def test_owned_protocol_regressions_do_not_use_dummy_positive_evidence() -> None:
    violations: list[str] = []
    for path in _owned_protocol_sources():
        content = path.read_text(encoding="utf-8").lower()
        for marker in FORBIDDEN_POSITIVE_FIXTURES:
            if marker in content:
                violations.append(f"{path.relative_to(ROOT)}: {marker}")
    assert not violations, "owned tests contain dummy positive evidence: " + ", ".join(violations)


def test_local_conformance_target_is_explicitly_owned_and_non_official() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    recipe = makefile.split("conformance-local:", maxsplit=1)[1].split(
        "conformance-oidf-validate:", maxsplit=1
    )[0]
    assert "ElevenID-owned" in recipe
    assert "not imported OIDF tests" in recipe
    assert "test_oid4vci_issuer_conformance.py" in recipe
    assert "test_oid4vp_verifier_conformance.py" not in recipe
    assert "test_siop_v2_conformance.py" not in recipe
