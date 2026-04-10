"""
ICAO Passport Compliance Profile Conformance Tests

Validates that the ICAO_PASSPORT compliance profile (passport.json) correctly
defines all required elements per ICAO Doc 9303 and integrates with the
personalization bureau flow.

These tests run entirely offline (no running services) — they validate the
profile JSON structure and data constraints.
"""

import json
from pathlib import Path

import pytest


PROFILE_PATH = Path(__file__).resolve().parents[4] / "marty-protocol" / "compliance-profiles" / "icao" / "passport.json"


@pytest.fixture(scope="module")
def profile():
    """Load the ICAO_PASSPORT compliance profile."""
    if not PROFILE_PATH.exists():
        pytest.skip(f"Profile not found at {PROFILE_PATH}")
    with open(PROFILE_PATH) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Structural validation
# ---------------------------------------------------------------------------

class TestProfileStructure:

    def test_has_required_top_level_keys(self, profile):
        required = {
            "id", "name", "compliance_code", "version",
            "credential_format", "issuance_protocol",
            "required_claims", "key_requirements",
        }
        assert required.issubset(profile.keys())

    def test_compliance_code(self, profile):
        assert profile["compliance_code"] == "ICAO_PASSPORT"

    def test_credential_format_is_physical(self, profile):
        assert profile["credential_format"] == "PHYSICAL"

    def test_issuance_protocol(self, profile):
        assert profile["issuance_protocol"] == "PHYSICAL_DOCUMENT"

    def test_version_is_semver(self, profile):
        parts = profile["version"].split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)

    def test_is_system_profile(self, profile):
        assert profile.get("is_system") is True

    def test_immutable(self, profile):
        assert profile.get("immutable") is True


# ---------------------------------------------------------------------------
# Required claims — ICAO data groups
# ---------------------------------------------------------------------------

class TestRequiredClaims:

    def test_dg1_required(self, profile):
        """DG1 (MRZ) is mandatory per ICAO 9303 Part 10."""
        claims = {c["name"]: c for c in profile["required_claims"]}
        assert "data_group_1" in claims
        assert claims["data_group_1"]["required"] is True

    def test_dg2_required(self, profile):
        """DG2 (facial image) is mandatory."""
        claims = {c["name"]: c for c in profile["required_claims"]}
        assert "data_group_2" in claims
        assert claims["data_group_2"]["required"] is True

    def test_sod_required(self, profile):
        """EF.SOD (Document Security Object) is mandatory."""
        claims = {c["name"]: c for c in profile["required_claims"]}
        assert "sod" in claims
        assert claims["sod"]["required"] is True

    def test_biometric_dgs_are_optional(self, profile):
        """DG3 (fingerprints) and DG7 (iris) require EAC and are optional."""
        claims = {c["name"]: c for c in profile["required_claims"]}
        for dg in ("data_group_3", "data_group_7"):
            if dg in claims:
                assert claims[dg]["required"] is False

    def test_namespace_is_icao(self, profile):
        for claim in profile["required_claims"]:
            assert claim["namespace"] == "com.icao.passport"


# ---------------------------------------------------------------------------
# PKI / Key requirements
# ---------------------------------------------------------------------------

class TestKeyRequirements:

    def test_csca_required(self, profile):
        assert profile["key_requirements"]["csca_required"] is True

    def test_dsc_required(self, profile):
        assert profile["key_requirements"]["dsc_required"] is True

    def test_hsm_mode(self, profile):
        assert "HSM" in profile["key_requirements"]["key_modes"]

    def test_min_key_size(self, profile):
        assert profile["key_requirements"]["min_key_size_bits"] >= 256


class TestPKIHierarchy:

    def test_root_is_csca(self, profile):
        assert profile["pki_hierarchy"]["root"] == "CSCA"

    def test_leaf_is_dsc(self, profile):
        assert profile["pki_hierarchy"]["leaf"] == "DSC"

    def test_max_chain_depth(self, profile):
        assert profile["pki_hierarchy"]["max_chain_depth"] <= 3


# ---------------------------------------------------------------------------
# Physical production
# ---------------------------------------------------------------------------

class TestPhysicalProduction:

    def test_required(self, profile):
        assert profile["physical_production"]["required"] is True

    def test_booklet_type_td3(self, profile):
        assert "TD3" in profile["physical_production"]["booklet_types"]

    def test_chip_standard(self, profile):
        assert "14443" in profile["physical_production"]["chip_standard"]

    def test_bac_required(self, profile):
        bac = profile["physical_production"]["access_control"]["bac"]
        assert bac["required"] is True

    def test_eac_required_for_biometrics(self, profile):
        eac = profile["physical_production"]["access_control"]["eac"]
        assert "DG3" in eac["required_for"]
        assert "DG7" in eac["required_for"]

    def test_personalization_steps_order(self, profile):
        steps = profile["physical_production"]["personalization_steps"]
        assert len(steps) >= 6
        # Chip encoding must come before quality assurance
        encode_idx = steps.index("encode_chip_data_groups")
        qa_idx = steps.index("quality_assurance_read_back")
        assert encode_idx < qa_idx
        # SOD must be written after encoding
        sod_idx = steps.index("write_ef_sod")
        assert sod_idx > encode_idx

    def test_data_group_encoding_is_der(self, profile):
        assert "DER" in profile["physical_production"]["data_group_encoding"]


# ---------------------------------------------------------------------------
# API surface
# ---------------------------------------------------------------------------

class TestAPISurface:

    def test_has_application_endpoint(self, profile):
        rels = [api["rel"] for api in profile["api_surface"]]
        assert "passport-application" in rels

    def test_has_sod_generation_endpoint(self, profile):
        rels = [api["rel"] for api in profile["api_surface"]]
        assert "passport-generate-sod" in rels

    def test_has_personalization_endpoint(self, profile):
        rels = [api["rel"] for api in profile["api_surface"]]
        assert "passport-submit-personalization" in rels

    def test_has_status_endpoint(self, profile):
        rels = [api["rel"] for api in profile["api_surface"]]
        assert "passport-production-status" in rels

    def test_has_activation_endpoint(self, profile):
        rels = [api["rel"] for api in profile["api_surface"]]
        assert "passport-activate" in rels

    def test_all_endpoints_require_auth(self, profile):
        for api in profile["api_surface"]:
            assert api["auth_required"] is True


# ---------------------------------------------------------------------------
# Revocation and trust
# ---------------------------------------------------------------------------

class TestRevocation:

    def test_revocation_required(self, profile):
        assert profile["revocation_required"] is True

    def test_crl_supported(self, profile):
        assert "CRL" in profile["revocation_methods"]

    def test_no_skip_revocation(self, profile):
        assert profile["allow_skip_revocation"] is False


class TestVettingRequirements:

    def test_assurance_level(self, profile):
        assert profile["vetting_requirements"]["assurance_level"] in ("IAL2", "IAL3")

    def test_document_type(self, profile):
        assert profile["vetting_requirements"]["document_type"] == "PASSPORT"

    def test_required_checks(self, profile):
        checks = profile["vetting_requirements"]["required_checks"]
        assert "IDENTITY_VERIFICATION" in checks
        assert "BIOMETRIC_ENROLLMENT" in checks
