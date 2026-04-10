"""Unit tests for OID4VCI proof JWT audience selection (Bug #4).

The OID4VCI spec requires the proof JWT ``aud`` claim to match the
credential issuer URL the wallet is interacting with.  When the platform
uses organisation-scoped issuer URLs (e.g. ``.../org/{id}``), the
credential offer carries the full URL, but the issuer metadata may
advertise a shorter base URL.

The fix: prefer ``credential_offer.credential_issuer`` over
``issuer_metadata.credential_issuer`` when building the proof JWT.

These tests validate the audience-selection logic in isolation.
"""

import pytest


class _FakeWalletState:
    """Minimal stand-in for OID4VCIWalletClient's relevant attributes."""

    def __init__(
        self,
        issuer_base_url: str,
        credential_offer: dict | None = None,
        issuer_metadata: dict | None = None,
    ):
        self.issuer_base_url = issuer_base_url
        self.credential_offer = credential_offer
        self.issuer_metadata = issuer_metadata

    def determine_audience(self) -> str:
        """Replicate the audience-selection logic from request_credential()."""
        audience = self.issuer_base_url
        if self.credential_offer:
            audience = self.credential_offer.get("credential_issuer", audience)
        elif self.issuer_metadata:
            audience = self.issuer_metadata.get("credential_issuer", audience)
        return audience


class TestProofJwtAudienceSelection:
    """Bug #4: Proof JWT audience must prefer the offer URL."""

    BASE = "https://gateway.example.com"
    OFFER_URL = "https://gateway.example.com/org/abc-123"
    META_URL = "https://gateway.example.com"

    def test_offer_takes_precedence_over_metadata(self) -> None:
        """When both offer and metadata are present, offer wins."""
        state = _FakeWalletState(
            issuer_base_url=self.BASE,
            credential_offer={"credential_issuer": self.OFFER_URL},
            issuer_metadata={"credential_issuer": self.META_URL},
        )
        assert state.determine_audience() == self.OFFER_URL

    def test_offer_takes_precedence_over_base(self) -> None:
        """Offer URL should override the base URL."""
        state = _FakeWalletState(
            issuer_base_url=self.BASE,
            credential_offer={"credential_issuer": self.OFFER_URL},
        )
        assert state.determine_audience() == self.OFFER_URL

    def test_metadata_used_when_no_offer(self) -> None:
        """Fall back to metadata when no offer is available."""
        meta_url = "https://other.example.com/issuer"
        state = _FakeWalletState(
            issuer_base_url=self.BASE,
            issuer_metadata={"credential_issuer": meta_url},
        )
        assert state.determine_audience() == meta_url

    def test_base_url_used_when_nothing_else(self) -> None:
        """If neither offer nor metadata is set, use the base URL."""
        state = _FakeWalletState(issuer_base_url=self.BASE)
        assert state.determine_audience() == self.BASE

    def test_offer_missing_credential_issuer_falls_to_base(self) -> None:
        """If the offer dict exists but lacks the key, fall back to base."""
        state = _FakeWalletState(
            issuer_base_url=self.BASE,
            credential_offer={"grants": {}},
        )
        assert state.determine_audience() == self.BASE

    def test_buggy_order_would_prefer_metadata(self) -> None:
        """Demonstrate the bug: if we checked metadata first (old code),
        the shorter URL would be returned even when offer has the full URL."""
        # Simulating the OLD buggy logic: metadata checked first
        state = _FakeWalletState(
            issuer_base_url=self.BASE,
            credential_offer={"credential_issuer": self.OFFER_URL},
            issuer_metadata={"credential_issuer": self.META_URL},
        )

        # Buggy: check metadata first  
        buggy_audience = self.BASE
        if state.issuer_metadata:
            buggy_audience = state.issuer_metadata.get("credential_issuer", buggy_audience)
        elif state.credential_offer:
            buggy_audience = state.credential_offer.get("credential_issuer", buggy_audience)

        # Buggy gives us the shorter metadata URL
        assert buggy_audience == self.META_URL
        # Fixed gives us the full org-scoped URL
        assert state.determine_audience() == self.OFFER_URL
        # They differ — proving the bug matters
        assert buggy_audience != state.determine_audience()
