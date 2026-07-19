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

    assert "--wallet-tester-url https://marty-oidf.test:25051" in guide
    assert "--verifier-url https://marty-oidf.test:28091" in guide
    assert "--wallet-kit-url http://localhost:29090" in guide
