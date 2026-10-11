"""Explicit opt-in business journey for a fresh public self-host installation.

The file is intentionally not named test_*. Ordinary OSS smoke selection does
not collect it. Run this exact path only against disposable, digest-pinned
installation state. Missing fixture inputs fail before any service mutation.
"""

from __future__ import annotations

import os
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import pytest

from tests.integration.gateway.helpers.auth_helper import AuthHelper
from tests.integration.gateway.helpers.gateway_client import GatewayClient
from tests.integration.gateway.helpers.marty_wallet_client import MartyHeadlessWalletClient
from tests.integration.gateway.helpers.test_data import TestDataBuilder


def required_inputs() -> dict[str, str]:
    names = (
        "SELFHOST_GATEWAY_URL", "SELFHOST_KEYCLOAK_URL",
        "SELFHOST_PUBLIC_DOMAIN",
        "SELFHOST_TEST_USERNAME", "SELFHOST_TEST_PASSWORD",
        "SELFHOST_ORG_ID", "SELFHOST_ISSUER_DID", "SELFHOST_VERIFIER_DID",
    )
    values = {name: os.environ.get(name, "").strip() for name in names}
    missing = sorted(name for name, value in values.items() if not value)
    if missing:
        raise ValueError("self-host journey fixture missing: " + ", ".join(missing))
    gateway = urlsplit(values["SELFHOST_GATEWAY_URL"])
    keycloak = urlsplit(values["SELFHOST_KEYCLOAK_URL"])
    if (gateway.scheme not in {"http", "https"} or not gateway.hostname
            or keycloak.scheme not in {"http", "https"} or not keycloak.hostname
            or gateway.username or gateway.password or keycloak.username or keycloak.password):
        raise ValueError("self-host fixture URLs are invalid")
    try:
        canonical_org_id = str(UUID(values["SELFHOST_ORG_ID"]))
    except ValueError as error:
        raise ValueError("self-host organization ID is not canonical") from error
    if canonical_org_id != values["SELFHOST_ORG_ID"]:
        raise ValueError("self-host organization ID is not canonical")
    if not values["SELFHOST_ISSUER_DID"].startswith("did:"):
        raise ValueError("self-host issuer public DID is invalid")
    if not values["SELFHOST_VERIFIER_DID"].startswith("did:"):
        raise ValueError("self-host verifier public DID is invalid")
    return values


@pytest.mark.asyncio
async def test_clean_install_issue_present_verify() -> None:
    """Use public gateway routes, real PKCE login, and an in-memory wallet."""
    fixture = required_inputs()
    gateway_url = fixture["SELFHOST_GATEWAY_URL"].rstrip("/")
    helper = AuthHelper(
        auth_service_url=gateway_url,
        keycloak_local_url=fixture["SELFHOST_KEYCLOAK_URL"],
        gateway_external_host=fixture["SELFHOST_PUBLIC_DOMAIN"],
    )
    session_id = await helper.get_session_id(
        fixture["SELFHOST_TEST_USERNAME"], fixture["SELFHOST_TEST_PASSWORD"])
    assert session_id, "public PKCE login returned no gateway session"
    organization_id = fixture["SELFHOST_ORG_ID"]
    issuer_did = fixture["SELFHOST_ISSUER_DID"]
    verifier_did = fixture["SELFHOST_VERIFIER_DID"]
    unique = uuid4().hex[:10]
    async with GatewayClient(base_url=gateway_url) as gateway:
        gateway.set_session(session_id)
        assert (await gateway.health_check()).get("status") == "healthy"
        organizations = await gateway.list_organizations()
        assert any(item.get("id") == organization_id for item in organizations), (
            "PKCE principal cannot access the migration-seeded organization")
        compliance = await gateway.create_compliance_profile(
            organization_id=organization_id, name=f"Self-host check {unique}",
            compliance_code="MDL_SD_JWT", credential_format="sd_jwt_vc",
            frameworks=["aamva"],
        )
        revocation = await gateway.create_revocation_profile(
            organization_id=organization_id, name=f"Self-host status {unique}",
            revocation_mechanism=["STATUS_LIST_2021"],
        )
        revocation = await gateway.activate_revocation_profile(str(revocation["id"]))
        template_data = TestDataBuilder.sd_jwt_mdl_template(
            organization_id=organization_id, issuer_did=issuer_did,
            compliance_profile_id=str(compliance["id"]),
            revocation_profile_id=str(revocation["id"]),
            name=f"Self-host credential {unique}",
        )
        template = await gateway.create_credential_template(**template_data)
        template = await gateway.activate_credential_template(str(template["id"]))
        policy_data = TestDataBuilder.presentation_policy_age_verification(
            organization_id=organization_id,
            credential_template_id=str(template["id"]),
            name=f"Self-host age check {unique}",
        )
        policy = await gateway.create_presentation_policy(**policy_data)
        policy = await gateway.activate_presentation_policy(str(policy["id"]))
        async with MartyHeadlessWalletClient(gateway_url=gateway_url) as wallet:
            await wallet.create_wallet(f"selfhost-{unique}")
            holder_did = (await wallet.create_did(method="jwk"))["did"]
            claims = TestDataBuilder.mdl_claims()
            claims["date_of_birth"] = "1990-05-15"
            issuance = await gateway.issue_credential(
                organization_id=organization_id,
                credential_template_id=str(template["id"]),
                subject_did=holder_did, claims=claims,
            )
            offer = issuance.get("credential_offer_uri")
            assert isinstance(offer, str)
            assert offer.startswith("openid-credential-offer://")
            await wallet.accept_credential_offer(offer_url=offer, did=holder_did)
            credentials = await wallet.list_credentials()
            assert len(credentials) == 1
            assert credentials[0].get("credential")
            flow = await gateway.start_verification_flow(
                presentation_policy_id=str(policy["id"]),
                organization_id=organization_id, issuer_did=verifier_did,
            )
            assert flow.get("instance_id")
            assert flow.get("request_uri")
            await wallet.present_credential(
                presentation_request_url=flow["request_uri"],
                credential_ids=[credentials[0]["id"]], did=holder_did,
            )
            decision = await gateway.get_verification_decision(flow["instance_id"])
            assert decision.get("decision") == "allow", "public verifier did not accept the wallet presentation"
        assert (await gateway.health_check()).get("status") == "healthy"
