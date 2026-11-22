"""Credential issuance cases exercised by both gateway wallets."""

import pytest

# Claims common to identity-type credentials
_ID_CLAIMS = {
    "given_name": "Integration",
    "family_name": "Test",
    "date_of_birth": "1990-01-01",
}
# Same but adds document_number (passport, visa, DTC)
_DOC_CLAIMS = {**_ID_CLAIMS, "document_number": "ITG-TEST-001"}

# (template_id, credential_config_id, claims, human_label)
CREDENTIAL_TYPE_CASES = [
    pytest.param(
        "40000000-0000-0000-0000-000000000001",
        "passport",
        _DOC_CLAIMS,
        "passport",
        id="passport",
    ),
    pytest.param(
        "40000000-0000-0000-0000-000000000002",
        "org.iso.18013.5.1.mDL",
        _ID_CLAIMS,
        "drivers_license",
        id="drivers_license",
    ),
    pytest.param(
        "40000000-0000-0000-0000-000000000005",
        "access_badge",
        _ID_CLAIMS,
        "access_badge",
        id="access_badge",
    ),
    pytest.param(
        "40000000-0000-0000-0000-000000000007",
        "open_badge",
        _ID_CLAIMS,
        "open_badge",
        id="open_badge",
    ),
]
