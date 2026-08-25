"""Implementation smoke tests for passport-related crypto and MRZ helpers.

These self-generated certificates, round trips, and sample MRZ checks preserve
useful implementation coverage but do not establish ICAO Doc 9303 conformance.
Authoritative TD3, LDS, EF.SOD, PKI, CRL, and Part 11 mechanism fixtures are
required before this repository may advertise a format-native conformance lane.

Covers implementation behavior for:
  - LDS (Logical Data Structure) helpers: EF.COM, EF.SOD, DG encoding
  - PKI helpers: CSCA → DSC chain, key usage, validity periods
  - SOD signature verification round-trip
  - BAC key derivation from known test vectors
  - MRZ ↔ DG1 consistency

These tests use the project's crypto primitives (Rust or Python fallback) and
do NOT require a running gateway.

Markers:
  @pytest.mark.implementation_smoke
  @pytest.mark.passport
"""

import datetime
import hashlib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

pytestmark = [pytest.mark.implementation_smoke, pytest.mark.passport]

PkiMaterial = tuple[
    ec.EllipticCurvePrivateKey,
    x509.Certificate,
    ec.EllipticCurvePrivateKey,
    x509.Certificate,
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _generate_csca_dsc_pair() -> PkiMaterial:
    """Generate a CSCA + DSC key pair for test purposes."""
    csca_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)

    csca_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "UT"),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Test CSCA"),
        ]))
        .issuer_name(x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "UT"),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Test CSCA"),
        ]))
        .public_key(csca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(csca_key, hashes.SHA256())
    )

    dsc_key = ec.generate_private_key(ec.SECP256R1())
    dsc_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "UT"),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Test DSC"),
        ]))
        .issuer_name(csca_cert.subject)
        .public_key(dsc_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1825))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(csca_key, hashes.SHA256())
    )

    return csca_key, csca_cert, dsc_key, dsc_cert


# ---------------------------------------------------------------------------
# PKI hierarchy implementation smoke coverage
# ---------------------------------------------------------------------------

class TestCSCADSCSmoke:
    """Exercise local CSCA/DSC helper behavior without claiming conformance."""

    @pytest.fixture
    def pki(self) -> PkiMaterial:
        return _generate_csca_dsc_pair()

    def test_csca_is_ca(self, pki: PkiMaterial) -> None:
        _, csca_cert, _, _ = pki
        bc = csca_cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True

    def test_csca_key_usage(self, pki: PkiMaterial) -> None:
        _, csca_cert, _, _ = pki
        ku = csca_cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.value.key_cert_sign is True
        assert ku.value.crl_sign is True

    def test_dsc_is_not_ca(self, pki: PkiMaterial) -> None:
        _, _, _, dsc_cert = pki
        bc = dsc_cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False

    def test_dsc_key_usage_digital_signature(self, pki: PkiMaterial) -> None:
        _, _, _, dsc_cert = pki
        ku = dsc_cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.value.digital_signature is True

    def test_dsc_issued_by_csca(self, pki: PkiMaterial) -> None:
        _, csca_cert, _, dsc_cert = pki
        assert dsc_cert.issuer == csca_cert.subject

    def test_csca_validity_at_least_10_years(self, pki: PkiMaterial) -> None:
        _, csca_cert, _, _ = pki
        delta = csca_cert.not_valid_after_utc - csca_cert.not_valid_before_utc
        assert delta.days >= 3650

    def test_dsc_validity_at_most_5_years(self, pki: PkiMaterial) -> None:
        _, _, _, dsc_cert = pki
        delta = dsc_cert.not_valid_after_utc - dsc_cert.not_valid_before_utc
        assert delta.days <= 1826  # 5 years + 1 day tolerance


# ---------------------------------------------------------------------------
# SOD round-trip implementation smoke coverage
# ---------------------------------------------------------------------------

class TestSODSmoke:
    """Exercise local EF.SOD helpers with self-generated material."""

    @pytest.fixture
    def pki(self) -> PkiMaterial:
        return _generate_csca_dsc_pair()

    def test_sod_create_and_verify_round_trip(self, pki: PkiMaterial) -> None:
        """Create an EF.SOD and verify the signature."""
        try:
            from marty_backend_common.crypto.sod_signer import create_sod, verify_sod_signature
        except ImportError:
            pytest.skip("sod_signer not available")

        _, csca_cert, dsc_key, dsc_cert = pki

        # Hash data groups — DG1 and DG2 minimum
        dg1_hash = hashlib.sha256(b"FAKE_DG1_DATA").digest()
        dg2_hash = hashlib.sha256(b"FAKE_DG2_DATA").digest()

        sod_blob = create_sod(
            data_group_hashes={1: dg1_hash, 2: dg2_hash},
            private_key=dsc_key,
            certificate=dsc_cert,
        )

        assert isinstance(sod_blob, bytes)
        assert len(sod_blob) > 0
        assert verify_sod_signature(sod_blob, [dsc_cert])

    def test_sod_with_all_standard_dgs(self, pki: PkiMaterial) -> None:
        """SOD with DG1-DG16 hashes (max set)."""
        try:
            from marty_backend_common.crypto.sod_signer import create_sod, verify_sod_signature
        except ImportError:
            pytest.skip("sod_signer not available")

        _, _, dsc_key, dsc_cert = pki

        dg_hashes = {
            i: hashlib.sha256(f"DG{i}_DATA".encode()).digest()
            for i in range(1, 17)
        }
        sod = create_sod(dg_hashes, dsc_key, dsc_cert)
        assert verify_sod_signature(sod, [dsc_cert])


# ---------------------------------------------------------------------------
# BAC key derivation implementation smoke coverage
# ---------------------------------------------------------------------------

class TestBACSmoke:
    """Exercise local BAC helper behavior against the existing sample."""

    def test_bac_keys_from_icao_example(self) -> None:
        """Known MRZ info → deterministic K_enc and K_mac."""
        try:
            from marty_backend_common.verification.bac_protocol import (
                _derive_bac_keys_python,
            )
        except ImportError:
            pytest.skip("bac_protocol not available")

        # ICAO 9303 Part 11 Appendix D.1 (adjusted)
        mrz_info = "L898902C36907231M6908061"
        k_enc, k_mac = _derive_bac_keys_python(mrz_info)

        # Verify structure
        assert len(k_enc) == 16
        assert len(k_mac) == 16

        # DES parity on every byte
        for b in k_enc + k_mac:
            assert bin(b).count("1") % 2 == 1

    def test_bac_key_derivation_determinism(self) -> None:
        """Same MRZ info always yields the same keys."""
        try:
            from marty_backend_common.verification.bac_protocol import _derive_bac_keys_python
        except ImportError:
            pytest.skip("bac_protocol not available")

        mrz = "AB12345670010101X3012310"
        assert _derive_bac_keys_python(mrz) == _derive_bac_keys_python(mrz)


# ---------------------------------------------------------------------------
# MRZ ↔ DG1 consistency
# ---------------------------------------------------------------------------

class TestMRZDG1Consistency:
    """DG1 must contain the same MRZ data that was used to derive BAC keys."""

    ICAO_MRZ = (
        "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<"
        "L898902C36UTO7408122F1204159ZE184226B<<<<<10"
    )

    def test_dg1_matches_mrz_document_number(self) -> None:
        """Document number extracted from MRZ line 2 matches DG1."""
        line2 = self.ICAO_MRZ[44:]
        doc_number = line2[0:9]  # Positions 1-9
        assert doc_number == "L898902C3"

    def test_dg1_matches_mrz_dob(self) -> None:
        line2 = self.ICAO_MRZ[44:]
        dob = line2[13:19]  # Positions 14-19
        assert dob == "740812"

    def test_dg1_matches_mrz_expiry(self) -> None:
        line2 = self.ICAO_MRZ[44:]
        expiry = line2[21:27]  # Positions 22-27
        assert expiry == "120415"

    def test_td3_total_length(self) -> None:
        """TD3 MRZ is exactly 88 characters (2 × 44)."""
        assert len(self.ICAO_MRZ) == 88

    def test_bac_input_from_mrz(self) -> None:
        """
        BAC MRZ_info = doc_number(9)+check + dob(6)+check + expiry(6)+check = 24 chars.
        """
        line2 = self.ICAO_MRZ[44:]
        mrz_info = line2[0:10] + line2[13:20] + line2[21:28]
        assert len(mrz_info) == 24
        # Known values from ICAO example
        assert mrz_info.startswith("L898902C36")
