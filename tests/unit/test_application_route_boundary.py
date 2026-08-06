"""Prevent first-party integration tests from reviving retired application APIs."""

from pathlib import Path

INTEGRATION_ROOT = Path(__file__).parents[1] / "integration"

# These routes predate the applicant/reviewer public boundary.  The current
# browser-facing contract is rooted at /v1/me and /v1/reviewer.  Passport
# application routes are a separate product surface and are intentionally not
# matched by these exact fragments.
RETIRED_FRAGMENTS = (
    '"/v1/applications',
    'f"/v1/applications',
    '"/v1/applicants/',
    'f"/v1/applicants/',
    "APPLICANT_SERVICE_URL",
    "gateway_client.create_application(",
    "gateway_client.get_application(",
    "gateway_client.list_applications(",
    "gateway_client.submit_evidence(",
    "gateway_client.approve_application(",
    "gateway_client.reject_application(",
)


def test_first_party_integration_tests_use_current_application_boundary() -> None:
    violations: list[str] = []

    for path in sorted(INTEGRATION_ROOT.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        for fragment in RETIRED_FRAGMENTS:
            if fragment in source:
                relative = path.relative_to(INTEGRATION_ROOT)
                violations.append(f"{relative}: {fragment}")

    assert not violations, (
        "Retired generic or internal application routes found. Use the "
        "authenticated /v1/me or /v1/reviewer public boundary:\n" + "\n".join(violations)
    )
