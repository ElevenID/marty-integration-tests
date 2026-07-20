"""Ensure the EUDI suite has a disposable official-wallet-kit driver."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_eudi_wallet_harness_is_opt_in_and_reachable_from_runner() -> None:
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

    assert "eudi-wallet-harness:" in compose
    assert "profiles: [eudi]" in compose
    assert "./services/eudi-wallet-harness" in compose
    assert "EUDI_WALLET_KIT_HOST_PORT:-29090" in compose


def test_eudi_conformance_uses_tls_public_services() -> None:
    guide = (ROOT / "conformance" / "README.md").read_text(encoding="utf-8")

    assert "eudi_reference_interop.py run" in guide
    assert '--eudi-material "conformance/eudi-material/$OFFICIAL_SUITE_RUN_ID"' in guide
    assert "loads the generated CA, exact endpoints" in guide
    assert "Explicit endpoint" in guide
    assert "must exactly match" in guide
