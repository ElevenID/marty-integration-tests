"""Release contracts for the artifact-only public stack."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_migrations_never_seed_an_internal_public_origin() -> None:
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    migrations = compose.split("  migrations:\n", 1)[1].split("\n  auth-service:\n", 1)[0]

    assert "PUBLIC_API_URL: ${ISSUER_BASE_URL:-https://oss-ci.elevenid.dev}" in migrations
    assert "PUBLIC_API_URL: ${ISSUER_BASE_URL:-http://gateway:8000}" not in migrations


def test_oid4vci_services_share_one_external_https_issuer_identifier() -> None:
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    issuance = compose.split("  issuance-service:\n", 1)[1].split(
        "\n  compliance-profile-service:\n", 1
    )[0]
    gateway = compose.split("  gateway:\n", 1)[1].split("\n  ui:\n", 1)[0]
    public_issuer = "ISSUER_BASE_URL: ${ISSUER_BASE_URL:-https://oss-ci.elevenid.dev}"

    assert public_issuer in issuance
    assert public_issuer in gateway
    assert "ISSUER_BASE_URL: ${ISSUER_BASE_URL:-http://gateway:8000}" not in compose
