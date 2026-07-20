"""Guard the production boundary of the standalone EUDI reference runner."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def service_block(compose: str, service: str, next_service: str) -> str:
    return compose.split(f"  {service}:\n", 1)[1].split(f"\n  {next_service}:\n", 1)[0]


def test_eudi_reference_wallets_only_reach_marty_through_the_tls_bridge() -> None:
    compose = (ROOT / "conformance" / "eudi-reference.compose.yml").read_text(encoding="utf-8")

    wallet_tester = service_block(compose, "eudi-wallet-tester", "eudi-wallet-tester-tls")
    wallet_kit = service_block(compose, "eudi-wallet-kit", "networks")
    assert "networks: [default, marty_oidf_bridge]" in wallet_tester
    assert "networks: [default, marty_oidf_bridge]" in wallet_kit
    assert "marty-network" not in wallet_tester
    assert "marty-network" not in wallet_kit

    bridge = compose.split("networks:\n", 1)[1]
    assert "marty_oidf_bridge:" in bridge
    assert "external: true" in bridge
    assert "${OIDF_MARTY_BRIDGE_NETWORK" in bridge
