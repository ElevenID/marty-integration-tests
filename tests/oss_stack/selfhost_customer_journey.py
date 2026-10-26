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
    validate_public_inputs(values)
    keycloak = urlsplit(values["SELFHOST_KEYCLOAK_URL"])
    if (keycloak.scheme not in {"http", "https"} or not keycloak.hostname
            or keycloak.username or keycloak.password):
        raise ValueError("self-host fixture URLs are invalid")
    return values


def validate_public_inputs(values: dict[str, str]) -> None:
    gateway = urlsplit(values["SELFHOST_GATEWAY_URL"])
    if (gateway.scheme not in {"http", "https"} or not gateway.hostname
            or gateway.username or gateway.password):
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
    async with GatewayClient(base_url=gateway_url) as gateway:
        gateway.set_session(session_id)
        await exercise_customer_journey(fixture, gateway)


async def exercise_customer_journey(
    fixture: dict[str, str], gateway: GatewayClient, *,
    consumer: GatewayClient | None = None,
) -> None:
    """Share the same real credential assertions across operator and machine clients."""
    gateway_url = fixture["SELFHOST_GATEWAY_URL"].rstrip("/")
    organization_id = fixture["SELFHOST_ORG_ID"]
    issuer_did = fixture["SELFHOST_ISSUER_DID"]
    verifier_did = fixture["SELFHOST_VERIFIER_DID"]
    unique = uuid4().hex[:10]
    assert (await gateway.health_check()).get("status") == "healthy"
    organizations = await gateway.list_organizations()
    assert any(item.get("id") == organization_id for item in organizations), (
        "Authenticated principal cannot access the migration-seeded organization")
    identity_response = await gateway.client.get(
        "/v1/signing-keys/issuer-identities",
        params={"organization_id": organization_id},
    )
    identity_response.raise_for_status()
    identities = identity_response.json()
    active = identities.get("identities")
    assert isinstance(active, list), "public active issuer profiles are unavailable"
    assert any(item.get("issuer_did") == issuer_did and item.get("status") == "active"
               for item in active), "credential issuer DID is not an active managed profile"
    assert any(item.get("issuer_did") == verifier_did and item.get("status") == "active"
               for item in active), "verifier DID is not an active managed profile"
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
    entities = await gateway.list_issuer_entities(organization_id)
    issuer_entity = next((item for item in entities if item.get("issuer_id") == issuer_did), None)
    if issuer_entity is None:
        issuer_entity = await gateway.create_issuer_entity(
            organization_id=organization_id, issuer_id=issuer_did,
            display_name=f"Self-host issuer {unique}",
            description="Disposable public-route trust evidence",
        )
    trust_profile = await gateway.create_trust_profile(
        organization_id=organization_id, name=f"Self-host trust {unique}",
        supported_formats=["SD_JWT_VC"],
        revocation_profile_id=str(revocation["id"]),
        revocation_policy={"check_mode": "HARD_FAIL"},
    )
    await gateway.add_trust_profile_issuer(
        str(trust_profile["id"]), str(issuer_entity["id"]), trust_level=100)
    trust_profile = await gateway.activate_trust_profile(str(trust_profile["id"]))
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
    policy = await gateway.create_presentation_policy(
        **policy_data, trust_profile_id=str(trust_profile["id"]))
    policy = await gateway.activate_presentation_policy(str(policy["id"]))
    runtime = consumer or gateway
    async with MartyHeadlessWalletClient(gateway_url=gateway_url) as wallet:
        await wallet.create_wallet(f"selfhost-{unique}")
        holder_did = (await wallet.create_did(method="jwk"))["did"]
        claims = TestDataBuilder.mdl_claims()
        claims["date_of_birth"] = "1990-05-15"
        issuance = await runtime.issue_credential(
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
        flow = await runtime.start_verification_flow(
            presentation_policy_id=str(policy["id"]),
            trust_profile_id=str(trust_profile["id"]),
            organization_id=organization_id, issuer_did=verifier_did,
        )
        assert flow.get("instance_id")
        assert flow.get("request_uri")
        await wallet.present_credential(
            presentation_request_url=flow["request_uri"],
            credential_ids=[credentials[0]["id"]], did=holder_did,
        )
        decision = await runtime.get_verification_decision(flow["instance_id"])
        assert decision.get("decision") == "allow", "public verifier did not accept the wallet presentation"
        assert decision.get("result") == "passed", "accepted presentation did not pass verification"
        assert any(
            item.get("revocation_checked") is True
            for item in decision.get("credential_results", [])
        ), "accepted presentation omitted revocation evidence"
        assert issuance.get("id"), "issuance response omitted lifecycle identity"
        await runtime.revoke_credential(
            issuance_id=str(issuance["id"]),
            reason="Disposable self-host negative control",
            organization_id=organization_id,
        )
        status = await runtime.get_revocation_status(
            str(issuance["id"]), organization_id=organization_id)
        assert status.get("revoked") is True or str(status.get("status", "")).lower() == "revoked"
        revoked_flow = await runtime.start_verification_flow(
            presentation_policy_id=str(policy["id"]),
            trust_profile_id=str(trust_profile["id"]),
            organization_id=organization_id, issuer_did=verifier_did,
        )
        await wallet.present_credential(
            presentation_request_url=revoked_flow["request_uri"],
            credential_ids=[credentials[0]["id"]], did=holder_did,
        )
        denied = await runtime.get_verification_decision(revoked_flow["instance_id"])
        assert denied.get("decision") == "deny", "revoked credential was not denied"
        assert denied.get("result") == "failed", "revoked verification did not fail closed"
        assert "revok" in str(denied.get("decision_reason", "")).lower(), (
            "denial did not identify revocation as its reason"
        )
        assert "credential_revoked" in denied.get("error_codes", []), (
            "denial omitted the credential_revoked error code"
        )
        denied_credentials = denied.get("credential_results", [])
        assert any(item.get("revocation_checked") is True for item in denied_credentials), (
            "denial omitted a revocation check"
        )
        assert any(item.get("not_revoked") is False for item in denied_credentials), (
            "denial did not identify the credential as revoked"
        )
        assert any(item.get("satisfied") is False for item in denied_credentials), (
            "denial omitted failed credential satisfaction"
        )
    assert (await gateway.health_check()).get("status") == "healthy"
