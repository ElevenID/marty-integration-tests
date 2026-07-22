"""Guard the production boundary of the standalone EUDI reference runner."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def service_block(compose: str, service: str, next_service: str) -> str:
    next_header = f"\n{next_service}:\n" if next_service == "networks" else f"\n  {next_service}:\n"
    return compose.split(f"  {service}:\n", 1)[1].split(next_header, 1)[0]


def test_eudi_reference_wallets_only_reach_marty_through_the_tls_bridge() -> None:
    compose = (ROOT / "conformance" / "eudi-reference.compose.yml").read_text(encoding="utf-8")

    port_bridge = service_block(compose, "eudi-marty-public-port-bridge", "eudi-wallet-tester")
    wallet_tester = service_block(compose, "eudi-wallet-tester", "eudi-wallet-tester-tls")
    wallet_kit = service_block(compose, "eudi-wallet-kit", "networks")
    assert "networks: [default, marty_public_url]" in wallet_tester
    assert "networks: [default, marty_public_url]" in wallet_kit
    assert "marty_oidf_bridge" not in wallet_tester
    assert "marty_oidf_bridge" not in wallet_kit
    assert "marty-network" not in wallet_tester
    assert "marty-network" not in wallet_kit

    assert "docker.io/alpine/socat:1.8.0.3@sha256:" in port_bridge
    assert "TCP-LISTEN:${OIDF_TLS_HOST_PORT" in port_bridge
    assert "TCP:oidf-tls-proxy:443" in port_bridge
    assert "${OIDF_CONFORMANCE_BRIDGE_ALIAS" in port_bridge
    assert "marty_public_url:" in port_bridge
    assert "marty_oidf_bridge: {}" in port_bridge

    bridge = compose.split("networks:\n", 1)[1]
    assert "marty_public_url:" in bridge
    assert "internal: true" in bridge
    assert "marty_oidf_bridge:" in bridge
    assert "external: true" in bridge
    assert "${OIDF_MARTY_BRIDGE_NETWORK" in bridge


def test_eudi_reference_services_use_real_ca_and_access_certificate_contracts() -> None:
    compose = (ROOT / "conformance" / "eudi-reference.compose.yml").read_text(encoding="utf-8")
    verifier = service_block(compose, "eudi-verifier", "eudi-verifier-tls")
    wallet_kit = service_block(compose, "eudi-wallet-kit", "networks")

    assert "REQUESTS_CA_BUNDLE: /certs/root-ca.pem" in compose
    assert "service_url: ${EUDI_WALLET_TESTER_PUBLIC_URL" in compose
    assert "HTTPS origin without a trailing slash}/" in compose
    assert "VERIFIER_DEFAULTHTTPRESPONSEMODE" in compose
    assert "VERIFIER_DEFEAULTHTTPRESPONSEMODE" not in compose
    assert "VERIFIER_ACCESS_CERTIFICATE_SIGNING_ALGORITHM" in compose
    assert "VERIFIER_CLIENTIDPREFIX" in compose
    assert "VERIFIER_ORIGINALCLIENTID" in compose
    assert "-Djavax.net.ssl.trustStoreType=JKS" in compose
    assert "${EUDI_OID4VP_TRUST_ANCHOR_FILE:?" in compose
    assert ":/oid4vp-trust/anchors.pem:ro" in compose
    assert compose.count("healthcheck:") >= 3
    assert "urllib.request.urlopen('http://127.0.0.1:5000/'" in compose
    assert compose.count('["CMD", "nginx", "-t"]') == 2
    assert compose.count("${EUDI_CONFORMANCE_CONFIG_ROOT:-./eudi-reference}") == 2
    assert "mem_limit: 1g" in verifier
    assert 'JAVA_TOOL_OPTIONS: "-XX:ActiveProcessorCount=2 -Xss512k"' in verifier
    assert "mem_limit: 768m" in wallet_kit


def test_wallet_harness_has_no_trust_all_tls_path() -> None:
    service = (
        ROOT / "services" / "eudi-wallet-harness" / "src" / "main" / "kotlin" / "com" / "elevenid" / "marty" / "wallet"
    )
    sources = "\n".join(
        (service / name).read_text(encoding="utf-8")
        for name in ("WalletIssuanceService.kt", "WalletPresentationService.kt")
    )
    assert "trustAllManager" not in sources
    assert "X509TrustManager" not in sources
    assert "_create_unverified_context" not in sources
    assert "PKIXParameters" in sources
    assert "EUDI_OID4VP_TRUST_ANCHOR_FILE" in sources
