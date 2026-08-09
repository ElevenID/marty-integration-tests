#!/usr/bin/env python3
"""Create disposable official-suite fixtures through Marty's public API."""

from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import stat
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).parent))
from oidf_marty_public_login import authenticated_json_request
from oidf_marty_start_verification import gateway_session_id, https_url

from tests.integration.gateway.helpers.mdoc_test_certificate import (
    create_disposable_issuer_certificate_chain,
)

DEFAULT_ORGANIZATION = "00000000-0000-0000-0000-000000000001"
RUN_ID = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
CREDENTIAL_CONFIGURATION_ID = re.compile(r"^[A-Za-z0-9_.:#-]{1,192}$")
OFFICIAL_OIDF_ISSUER_DOMAIN = "localhost.emobix.co.uk"
OFFICIAL_MDOC_SIGNER_CERTIFICATE = re.compile(
    r"val\s+documentSignerCert\s*=\s*X509Cert\.fromPem\(\s*"
    r'"""(?P<certificate>-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)"""',
    re.DOTALL,
)


def compliance_profile_payload(
    organization_id: str,
    *,
    w3c: bool,
    run_id: str,
    oid4vci: bool = False,
    mdoc: bool = False,
) -> dict[str, object]:
    """Build the public API resource a credential template must reference.

    The production credential-template API deliberately accepts only a profile
    identifier.  Creating the profile through its own public endpoint avoids
    relying on the older, removed inline-profile shape and exercises the same
    lifecycle a real integrator uses.
    """
    if w3c:
        return {
            "organization_id": organization_id,
            "name": f"Official W3C VC Data Model v2 {run_id}",
            "compliance_code": "W3C_VC",
            "credential_format": "jwt_vc",
            "frameworks": ["w3c_vc"],
            "system_profile": False,
        }
    if mdoc:
        return {
            "organization_id": organization_id,
            "name": f"Official OID4VP ISO mDL {run_id}",
            "compliance_code": "AAMVA_MDL",
            # Marty resources use the protocol enum. `mso_mdoc` is emitted only
            # by the OID4VC adapter at the external metadata/wire boundary.
            "credential_format": "MDOC",
            "frameworks": ["aamva", "iso_18013_5", "oid4vp"],
            "system_profile": False,
        }
    protocol_name = "OID4VCI" if oid4vci else "OID4VP"
    return {
        "organization_id": organization_id,
        "name": f"Official {protocol_name} SD-JWT {run_id}",
        "compliance_code": f"{protocol_name}_FINAL",
        "credential_format": "sd_jwt_vc",
        "frameworks": [protocol_name.lower()],
        "system_profile": False,
    }


def issuer_identity_payload(
    organization_id: str,
    *,
    gateway_url: str,
    w3c: bool,
    algorithm: str,
    key_purpose: str = "vc_jwt_issuer",
    credential_format: str | None = None,
    key_attestation_trust_anchor_pem: str | None = None,
) -> dict[str, Any]:
    """Request a DID identity while leaving all custody selection to Marty."""
    domain = urlparse(gateway_url).hostname
    if not domain:
        raise ValueError("gateway URL has no hostname for the disposable issuer DID")
    result: dict[str, Any] = {
        "organization_id": organization_id,
        "issuer_did": f"did:web:{domain}:orgs:{organization_id}",
        "key_purpose": key_purpose,
        "credential_format": credential_format or ("JSON_LD" if w3c else "SD_JWT_VC"),
        "algorithm": algorithm,
    }
    if key_attestation_trust_anchor_pem is not None:
        result["key_attestation_policy"] = {
            "mode": "required",
            "trusted_root_certificates_pem": [key_attestation_trust_anchor_pem],
            "allowed_algorithms": ["ES256"],
            "required_key_storage": [],
            "required_user_authentication": [],
            "max_age_seconds": 300,
            "require_nonce": True,
            # The official OIDF issuer test emits no optional status claim.
            # This lane tests trusted attester signatures and proof binding;
            # EUDI status-list validation remains a separate production lane.
            "status_validation": "disabled",
        }
    return result


def key_attestation_trust_anchor(path: Path) -> str:
    """Load one CA certificate used only to trust the official test wallet."""
    pem = path.resolve().read_text(encoding="ascii")
    certificate = x509.load_pem_x509_certificate(pem.encode("ascii"))
    try:
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("OIDF key-attestation trust anchor has no CA constraint") from exc
    if not constraints.ca:
        raise ValueError("OIDF key-attestation trust anchor is not a CA certificate")
    return pem


def eudi_compliance_profile_payload(organization_id: str, *, run_id: str) -> dict[str, object]:
    """Build the shared EUDI SD-JWT compliance profile for disposable fixtures."""
    return {
        "organization_id": organization_id,
        "name": f"Official EUDI SD-JWT {run_id}",
        "compliance_code": "EUDI_PID",
        "credential_format": "sd_jwt_vc",
        "frameworks": ["eudi"],
        "system_profile": False,
    }


def eudi_template_payload(
    organization_id: str,
    compliance_profile_id: str,
    issuer_did: str,
    revocation_profile_id: str,
    *,
    credential_type: str,
    gateway_url: str,
    run_id: str,
) -> dict[str, object]:
    """Build one production-shaped EUDI SD-JWT credential template.

    The public template binds only the issuer DID. The gateway resolves its
    authorized profile and custody service inside the organization boundary.
    """
    if credential_type not in {"Passport", "MobileDrivingLicense", "OpenBadge"}:
        raise ValueError("unsupported EUDI fixture credential type")
    gateway_origin = gateway_url.rstrip("/")
    properties: dict[str, object] = {
        "given_name": {"type": "string"},
        "family_name": {"type": "string"},
        "date_of_birth": {"type": "string", "format": "full-date"},
        "test_id": {"type": "string"},
        "source": {"type": "string"},
        "wallet_profile": {"type": "string"},
    }
    claims = [
        {"name": "given_name", "display_name": "Given Name", "required": True},
        {"name": "family_name", "display_name": "Family Name", "required": True},
        {"name": "date_of_birth", "display_name": "Date of Birth", "required": True},
    ]
    if credential_type == "Passport":
        properties["document_number"] = {"type": "string"}
        claims.append({"name": "document_number", "display_name": "Document Number", "required": False})
    return {
        "organization_id": organization_id,
        "name": f"Official EUDI {credential_type} {run_id}",
        "credential_type": credential_type,
        "vct": f"{gateway_origin}/credentials/{credential_type}",
        "supported_formats": ["sd_jwt_vc"],
        "credential_payload_format": "w3c_vcdm_v2_sd_jwt",
        "compliance_profile_id": compliance_profile_id,
        "issuer_did": issuer_did,
        "revocation_profile_id": revocation_profile_id,
        "schema_uri": {
            "type": "object",
            "properties": properties,
            "required": ["given_name", "family_name", "date_of_birth"],
        },
        "claims": claims,
    }


def revocation_profile_payload(
    organization_id: str,
    *,
    w3c: bool,
    run_id: str,
    label: str | None = None,
    mdoc: bool = False,
) -> dict[str, object]:
    """Build a disposable, standards-shaped revocation dependency.

    Credential templates are intentionally not issuable until an active
    revocation policy is bound to them.  The official-suite fixtures must use
    that same lifecycle, rather than weakening the production issuance guard.
    """
    profile_label = label or ("W3C VC Data Model v2" if w3c else "OID4VP SD-JWT")
    return {
        "organization_id": organization_id,
        "name": f"Official {profile_label} revocation {run_id}",
        "description": "Disposable status-list dependency for official interoperability evidence",
        "revocation_mechanism": ["BITSTRING_STATUS_LIST"],
        "mechanism_priority": ["BITSTRING_STATUS_LIST"],
        "check_mode": "ALWAYS",
        "supported_formats": (["JSON_LD"] if w3c else ["MDOC"] if mdoc else ["SD_JWT_VC"]),
    }


def template_payload(
    organization_id: str,
    compliance_profile_id: str,
    issuer_did: str,
    revocation_profile_id: str,
    *,
    w3c: bool,
    run_id: str,
    presentation: bool = False,
    mdoc: bool = False,
) -> dict[str, object]:
    if w3c:
        # Issuance and presentation verification intentionally use separate
        # templates, but both declare the native Data Integrity representation.
        # This keeps each policy role explicit without reconstructing a JOSE
        # envelope around a credential that Marty actually signs as JSON-LD.
        return {
            "organization_id": organization_id,
            "name": (
                f"Official W3C VC v2 Data Integrity verifier {run_id}"
                if presentation
                else f"Official W3C VC v2 Data Integrity issuer {run_id}"
            ),
            "credential_type": "VerifiableId",
            "vct": "https://credentials.marty.dev/VerifiableId",
            "supported_formats": ["ldp_vc"],
            "credential_payload_format": "ldp_vc",
            "compliance_profile_id": compliance_profile_id,
            "issuer_did": issuer_did,
            "revocation_profile_id": revocation_profile_id,
            "schema_uri": {
                "type": "object",
                "properties": {
                    "givenName": {"type": "string"},
                    "familyName": {"type": "string"},
                    "birthDate": {"type": "string", "format": "full-date"},
                    "documentNumber": {"type": "string"},
                },
                "required": ["givenName", "familyName", "birthDate", "documentNumber"],
            },
            "claims": [
                {"name": "givenName", "display_name": "Given Name", "required": True},
                {"name": "familyName", "display_name": "Family Name", "required": True},
                {"name": "birthDate", "display_name": "Birth Date", "required": True},
                {"name": "documentNumber", "display_name": "Document Number", "required": True},
            ],
        }
    if mdoc:
        # This is an actual ISO 18013-5 mDL template.  The official OIDF
        # verifier generates the mdoc credential; Marty contributes the
        # public policy and request object that must demand this format.
        return {
            "organization_id": organization_id,
            "name": f"Official OID4VP ISO mDL verifier {run_id}",
            "credential_type": "org.iso.18013.5.1.mDL",
            "doctype": "org.iso.18013.5.1.mDL",
            "supported_formats": ["MDOC"],
            "credential_payload_format": "MDOC",
            "compliance_profile_id": compliance_profile_id,
            "issuer_did": issuer_did,
            "revocation_profile_id": revocation_profile_id,
            "schema_uri": {
                "namespaces": {
                    "org.iso.18013.5.1": {
                        "family_name": {"type": "string"},
                        "given_name": {"type": "string"},
                        "birth_date": {"type": "string", "format": "full-date"},
                    }
                }
            },
            "claims": [
                {
                    "name": "family_name",
                    "display_name": "Family Name",
                    "required": True,
                    "namespace": "org.iso.18013.5.1",
                },
                {
                    "name": "given_name",
                    "display_name": "Given Name",
                    "required": True,
                    "namespace": "org.iso.18013.5.1",
                },
                {
                    "name": "birth_date",
                    "display_name": "Birth Date",
                    "required": True,
                    "namespace": "org.iso.18013.5.1",
                },
            ],
        }
    return {
        "organization_id": organization_id,
        "name": f"Official OID4VP SD-JWT {run_id}",
        "credential_type": "PID",
        "vct": "urn:eudi:pid:1",
        "supported_formats": ["sd_jwt_vc"],
        "credential_payload_format": "w3c_vcdm_v2_sd_jwt",
        "compliance_profile_id": compliance_profile_id,
        "issuer_did": issuer_did,
        "revocation_profile_id": revocation_profile_id,
        "schema_uri": {
            "type": "object",
            "properties": {
                "family_name": {"type": "string"},
                "given_name": {"type": "string"},
                "birthdate": {"type": "string", "format": "full-date"},
            },
            "required": ["family_name", "given_name", "birthdate"],
        },
        "claims": [
            {"name": "family_name", "display_name": "Family Name", "required": True},
            {"name": "given_name", "display_name": "Given Name", "required": True},
            {"name": "birthdate", "display_name": "Birth Date", "required": True},
        ],
    }


def browser_credential_template_payload(
    organization_id: str,
    compliance_profile_id: str,
    issuer_did: str,
    revocation_profile_id: str,
    *,
    gateway_url: str,
    run_id: str,
) -> dict[str, object]:
    """Build a disposable DID-bound credential for the real applicant UI."""
    return {
        "organization_id": organization_id,
        "name": f"Official Browser Member Credential {run_id}",
        "description": (
            "Disposable credential used to prove the released applicant UI "
            "reaches Marty's public DID-first issuance boundary"
        ),
        "credential_type": "MemberCredential",
        "vct": f"{gateway_url.rstrip('/')}/credentials/OfficialBrowserMemberCredential",
        "supported_formats": ["sd_jwt_vc"],
        "credential_payload_format": "w3c_vcdm_v2_sd_jwt",
        "compliance_profile_id": compliance_profile_id,
        "issuer_did": issuer_did,
        "revocation_profile_id": revocation_profile_id,
        "schema_uri": {
            "type": "object",
            "properties": {
                "email": {"type": "string", "format": "email"},
                "given_name": {"type": "string"},
                "family_name": {"type": "string"},
                "member_id": {"type": "string"},
                "organization_id": {"type": "string"},
                "role": {"type": "string"},
            },
            "required": ["email"],
        },
        "claims": [
            {"name": "email", "display_name": "Email", "required": True},
            {"name": "given_name", "display_name": "Given Name", "required": False},
            {"name": "family_name", "display_name": "Family Name", "required": False},
            {"name": "member_id", "display_name": "Member ID", "required": False},
            {
                "name": "organization_id",
                "display_name": "Organization ID",
                "required": False,
            },
            {"name": "role", "display_name": "Role", "required": False},
        ],
    }


def browser_application_template_payload(
    organization_id: str,
    credential_template_id: str,
    *,
    run_id: str,
) -> dict[str, object]:
    """Build the public applicant workflow linked to the disposable credential."""
    return {
        "organization_id": organization_id,
        "name": f"Official Browser Member Application {run_id}",
        "description": "One-click application through the released applicant UI",
        "credential_template_id": credential_template_id,
        "form_fields": [
            {
                "field_id": "email",
                "label": "Email",
                "field_type": "EMAIL",
                "required": True,
                "claim_mapping": "email",
            }
        ],
        "claim_collection_rules": [
            {
                "claim_name": "email",
                "source": "FORM_FIELD",
                "source_config": {"field_id": "email"},
            }
        ],
        "approval_strategy": "AUTO",
        "application_validity_days": 1,
    }


def browser_issuance_flow_payload(
    organization_id: str,
    credential_template_id: str,
    *,
    run_id: str,
) -> dict[str, object]:
    """Build the normal application-approved OID4VCI extension flow."""
    return {
        "organization_id": organization_id,
        "name": f"Official Browser Issuance {run_id}",
        "description": "Disposable released-browser OID4VCI issuance flow",
        "flow_type": "custom",
        "approval_strategy": "AUTO",
        "credential_template_id": credential_template_id,
        "trigger": {
            "trigger_type": "WEBHOOK",
            "config": {"event_type": "APPLICATION_APPROVED"},
        },
        "extension": {
            "extension_uri": "urn:elevenid:official-browser-issuance",
            "extension_version": "1.0.0",
            "extends_flow_type": "oid4vci_pre_authorized",
            "entry_step_id": "create_offer",
            "steps": [
                {
                    "step_id": "create_offer",
                    "action": "create_offer",
                    "config": {},
                }
            ],
            "transitions": [],
            "config": {},
        },
    }


def bootstrap_browser_issuance(
    gateway_url: str,
    session_id: str,
    *,
    organization_id: str,
    issuer_did: str,
    revocation_profile_id: str,
    run_id: str,
    request: Callable[..., object],
) -> dict[str, str]:
    """Create the disposable product-path resources separately from OIDF."""
    compliance = request(
        gateway_url,
        session_id,
        "/v1/compliance-profiles",
        method="POST",
        json_body=compliance_profile_payload(
            organization_id,
            w3c=False,
            run_id=f"browser-{run_id}",
            oid4vci=True,
        ),
    )
    compliance_profile_id = response_id(
        compliance,
        "browser issuance compliance profile",
    )
    credential = request(
        gateway_url,
        session_id,
        "/v1/credential-templates",
        method="POST",
        json_body=browser_credential_template_payload(
            organization_id,
            compliance_profile_id,
            issuer_did,
            revocation_profile_id,
            gateway_url=gateway_url,
            run_id=run_id,
        ),
    )
    credential_template_id = response_id(
        credential,
        "browser issuance credential template",
    )
    activated_credential = request(
        gateway_url,
        session_id,
        f"/v1/credential-templates/{credential_template_id}/activate",
        method="POST",
    )
    if response_id(activated_credential, "activated browser credential template") != credential_template_id:
        raise RuntimeError("activated browser credential template id changed unexpectedly")

    application = request(
        gateway_url,
        session_id,
        "/v1/application-templates",
        method="POST",
        json_body=browser_application_template_payload(
            organization_id,
            credential_template_id,
            run_id=run_id,
        ),
    )
    application_template_id = response_id(
        application,
        "browser issuance application template",
    )
    activated_application = request(
        gateway_url,
        session_id,
        f"/v1/application-templates/{application_template_id}/activate",
        method="POST",
    )
    if response_id(activated_application, "activated browser application template") != application_template_id:
        raise RuntimeError("activated browser application template id changed unexpectedly")

    flow = request(
        gateway_url,
        session_id,
        "/v1/flows/definitions",
        method="POST",
        json_body=browser_issuance_flow_payload(
            organization_id,
            credential_template_id,
            run_id=run_id,
        ),
    )
    flow_id = response_id(flow, "browser issuance flow")
    activated_flow = request(
        gateway_url,
        session_id,
        f"/v1/flows/definitions/{flow_id}/activate",
        method="POST",
    )
    if response_id(activated_flow, "activated browser issuance flow") != flow_id:
        raise RuntimeError("activated browser issuance flow id changed unexpectedly")

    return {
        "browser_credential_template_id": credential_template_id,
        "browser_application_template_id": application_template_id,
        "browser_flow_id": flow_id,
    }


def policy_payload(
    organization_id: str,
    template_id: str,
    *,
    w3c: bool,
    run_id: str,
    presentation: bool = True,
    mdoc: bool = False,
) -> dict[str, object]:
    # The W3C verifier suite supplies standards-conforming generic credentials,
    # not Marty's product-specific identity schema. Marty's policy schema still
    # requires at least one requested-claim entry, so use credentialSubject.id as
    # an optional structural claim. This preserves cryptographic and holder-
    # binding validation without inventing a claim that VCDM v2 does not require.
    claims = (
        (("id", False),)
        if w3c
        else tuple(
            (claim, True)
            for claim in (
                ("family_name", "given_name", "birth_date") if mdoc else ("given_name", "family_name", "birthdate")
            )
        )
    )
    if not w3c and not presentation:
        raise ValueError("OID4VP fixtures require a presentation policy")
    label = (
        f"W3C VC v2 {'presentation' if presentation else 'credential'}"
        if w3c
        else "OID4VP ISO mDL"
        if mdoc
        else "OID4VP SD-JWT"
    )
    holder_binding: dict[str, object] = {"required": presentation}
    if presentation:
        holder_binding.update(
            {
                "binding_methods": ["DEVICE_KEY"],
                "proof_profiles": ["MDOC_DEVICE_AUTHENTICATION" if mdoc else "OID4VP_VERIFIABLE_PRESENTATION"],
                "proof_freshness": {
                    "challenge_required": True,
                    "audience_binding_required": True,
                    "replay_detection_required": True,
                },
            }
        )
    return {
        "organization_id": organization_id,
        "name": f"Official {label} {run_id}",
        "purpose": f"Disposable {label} official-suite verification",
        # OIDF and W3C Data Integrity presentations are holder bound. A JWT VC
        # verified outside a presentation is not: requiring a VP challenge on
        # that path would reject a valid credential before signature checks.
        # Send the complete public holder-binding contract. The service used
        # these same fail-closed defaults for older stored policies, but public
        # callers must now state the proof and freshness requirements
        # explicitly so policy intent cannot be inferred differently by a
        # generated client or another service.
        "holder_binding": holder_binding,
        "credential_requirements": [
            {
                "credential_template_id": template_id,
                "display_name": label,
                "credential_payload_format": ("w3c_vcdm_v2_di" if w3c else "MDOC" if mdoc else "w3c_vcdm_v2_sd_jwt"),
                "requested_claims": [
                    {
                        "claim_name": claim,
                        "display_name": claim,
                        "required": required,
                    }
                    for claim, required in claims
                ],
            }
        ],
    }


def official_signer_public_jwk(config_path: Path) -> dict[str, str]:
    """Extract only the public P-256 members from the private runner config."""
    raw: object = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("official runner config must be a JSON object")
    credential = raw.get("credential")
    signing_jwk = credential.get("signing_jwk") if isinstance(credential, dict) else None
    if not isinstance(signing_jwk, dict):
        raise ValueError("official runner config has no credential signing JWK")
    if signing_jwk.get("kty") != "EC" or signing_jwk.get("crv") != "P-256":
        raise ValueError("official runner credential signing JWK must use EC P-256")
    if any(not isinstance(signing_jwk.get(name), str) or not signing_jwk[name] for name in ("x", "y")):
        raise ValueError("official runner credential signing JWK has no complete public key")
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": signing_jwk["x"],
        "y": signing_jwk["y"],
    }


def official_mdoc_trust_anchor(
    runner_source: Path,
    *,
    now: datetime | None = None,
) -> str:
    """Read the mock mdoc issuer certificate from the exact OIDF runner source.

    The verifier plan's mdoc wallet does not use ``credential.signing_jwk``.
    It provisions a separate document signer in ``TestAppUtils`` and includes
    that public certificate in IssuerAuth. Reading it from the checked-out,
    commit-pinned runner keeps the Trust Profile aligned when the official
    runner rotates its disposable certificate.
    """
    candidates = sorted(
        runner_source.glob(
            "src/main/kotlin/**/TestAppUtils.kt",
        )
    )
    matches: list[str] = []
    for source in candidates:
        match = OFFICIAL_MDOC_SIGNER_CERTIFICATE.search(source.read_text(encoding="utf-8"))
        if match is not None:
            certificate = "\n".join(line.strip() for line in match.group("certificate").strip().splitlines())
            certificate += "\n"
            # Reject malformed or substituted PEM before sending public trust
            # administration data to Marty.
            ssl.PEM_cert_to_DER_cert(certificate)
            matches.append(certificate)
    if len(matches) != 1:
        raise ValueError("exact OIDF runner source must expose exactly one documentSignerCert mdoc trust anchor")
    certificate_pem = matches[0]
    certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
    checked_at = now or datetime.now(UTC)
    if checked_at.tzinfo is None:
        raise ValueError("OIDF mdoc certificate validation time must be timezone-aware")
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
    if checked_at < not_before:
        raise ValueError(
            "official OIDF mdoc documentSignerCert is not valid yet: "
            f"not_before={not_before.isoformat()} sha256={fingerprint}"
        )
    if checked_at >= not_after:
        raise ValueError(
            "official OIDF mdoc documentSignerCert has expired: "
            f"not_after={not_after.isoformat()} sha256={fingerprint}; "
            "do not bypass certificate validation or modify the imported suite"
        )
    return certificate_pem


def trust_profile_payload(
    organization_id: str,
    public_jwk: dict[str, str] | None,
    *,
    run_id: str,
    mdoc_trust_anchor_pem: str | None = None,
) -> dict[str, object]:
    if mdoc_trust_anchor_pem is not None:
        if public_jwk is not None:
            raise ValueError("mdoc trust must use the runner document certificate, not its SD-JWT JWK")
        ssl.PEM_cert_to_DER_cert(mdoc_trust_anchor_pem)
        return {
            "organization_id": organization_id,
            "name": f"Official OIDF mdoc signer {run_id}",
            "description": (
                "Exact OIDF fixture certificate pinned so the unchanged suite reaches "
                "Marty's production certificate-profile validation"
            ),
            "profile_type": "CUSTOM",
            "supported_formats": ["MDOC"],
            "allowed_algorithms": ["ES256"],
            "trust_sources": [
                {
                    "source_type": "PINNED_ISSUER",
                    "certificate_pem": mdoc_trust_anchor_pem,
                    "description": (
                        "Public test certificate extracted from the exact commit-pinned OIDF conformance runner; "
                        "pinning does not bypass ISO document-signer certificate validation"
                    ),
                }
            ],
            "auto_generated": True,
        }
    if public_jwk is None:
        raise ValueError("OIDF SD-JWT trust requires the runner public signing JWK")
    return {
        "organization_id": organization_id,
        "name": f"Official OIDF signer {run_id}",
        "description": "Disposable trust anchor for the pinned official OIDF runner credential signer",
        "profile_type": "CUSTOM",
        "supported_formats": ["SD_JWT_VC"],
        "allowed_algorithms": ["ES256"],
        "allowed_issuers": [OFFICIAL_OIDF_ISSUER_DOMAIN],
        "system_issuer_overrides": {
            OFFICIAL_OIDF_ISSUER_DOMAIN: {"public_jwk": public_jwk},
        },
        "auto_generated": True,
    }


def mdoc_issuer_entity_payload(
    organization_id: str,
    certificate_pem: str,
    *,
    run_id: str,
) -> dict[str, object]:
    """Build the governed lifecycle record for the exact pinned mdoc signer."""
    certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
    certificate_sha256 = certificate.fingerprint(hashes.SHA256()).hex()
    return {
        "organization_id": organization_id,
        "issuer_id": f"x509-sha256:{certificate_sha256}",
        "issuer_type": "GOVERNMENT",
        "display_name": f"Official OIDF mdoc signer {run_id}",
        "description": (
            "Disposable lifecycle record for the exact document signer in the "
            "commit-pinned unmodified OIDF runner"
        ),
        "compliance_status": "COMPLIANT",
        "valid_from": certificate.not_valid_before_utc.isoformat(),
        "valid_until": certificate.not_valid_after_utc.isoformat(),
        "metadata": {
            "source": "official-oidf-commit-pinned-document-signer",
            "certificate_sha256": certificate_sha256,
        },
    }


def response_id(value: object, resource: str) -> str:
    if not isinstance(value, dict):
        raise RuntimeError(f"public API returned a non-object for {resource}")
    identifier = value.get("id")
    if not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier):
        raise RuntimeError(f"public API returned an invalid {resource} id")
    return identifier


def create_disposable_vc_api_key(
    gateway_url: str,
    session_id: str,
    *,
    organization_id: str,
    run_id: str,
    request: Callable[..., object],
) -> tuple[str, str]:
    """Create the least-privilege key used by the official W3C client."""
    created = request(
        gateway_url,
        session_id,
        f"/v1/api-keys?{urlencode({'organization_id': organization_id})}",
        method="POST",
        json_body={
            "name": f"Official W3C VC API {run_id}",
            "description": "Disposable key for one official VCDM v2 suite run",
            "scopes": ["credentials:issue", "credentials:read"],
            "is_test": True,
        },
    )
    key_id = response_id(created, "W3C VC API key")
    raw_key = created.get("key") if isinstance(created, dict) else None
    scopes = created.get("scopes") if isinstance(created, dict) else None
    if (
        not isinstance(raw_key, str)
        or not raw_key.startswith("mk_test_")
        or not isinstance(scopes, list)
        or len(scopes) != 2
        or set(scopes) != {"credentials:issue", "credentials:read"}
    ):
        raise RuntimeError("public API did not return the expected least-privilege test key")
    return key_id, raw_key


def oid4vci_configuration_id(
    metadata: object,
    *,
    expected_format: str,
    expected_vct: str,
) -> str:
    """Resolve the unique public configuration advertised for the fixture."""
    if not isinstance(metadata, dict):
        raise RuntimeError("public OID4VCI metadata is not an object")
    configurations = metadata.get("credential_configurations_supported")
    if not isinstance(configurations, dict):
        raise RuntimeError("public OID4VCI metadata has no credential_configurations_supported")
    matches = [
        config_id
        for config_id, configuration in configurations.items()
        if (
            isinstance(config_id, str)
            and CREDENTIAL_CONFIGURATION_ID.fullmatch(config_id)
            and isinstance(configuration, dict)
            and configuration.get("format") == expected_format
            and configuration.get("vct") == expected_vct
        )
    ]
    if len(matches) != 1:
        raise RuntimeError("public OID4VCI metadata did not advertise exactly one matching credential configuration")
    return matches[0]


def issuer_identity_response(value: object) -> dict[str, object]:
    """Validate the provider-neutral public issuer-identity response."""
    if not isinstance(value, dict):
        raise RuntimeError("public API returned a non-object for issuer identity")
    identity = value.get("identity", value)
    if not isinstance(identity, dict) or not str(identity.get("issuer_did") or "").startswith("did:"):
        raise RuntimeError("public API returned an invalid issuer identity")
    forbidden = {"issuer_profile_id", "signing_service_id", "signing_key_reference", "kms_provider", "key_name"}
    leaked = forbidden.intersection(identity)
    if leaked:
        raise RuntimeError(f"public issuer identity leaked private selectors: {sorted(leaked)}")
    return identity


def resolve_issuer_identity_public_jwk(
    gateway_url: str,
    session_id: str,
    *,
    organization_id: str,
    issuer_did: str,
    key_purpose: str,
    credential_format: str,
    algorithm: str,
    request: Callable[..., object],
    attempts: int = 10,
) -> dict[str, object]:
    """Resolve one public DID key from the complete provider-neutral tuple."""
    path = "/v1/signing-keys/issuer-identities/resolve"
    body = {
        "organization_id": organization_id,
        "issuer_did": issuer_did,
        "key_purpose": key_purpose,
        "credential_format": credential_format,
        "algorithm": algorithm,
    }
    for attempt in range(attempts):
        try:
            resolved = request(
                gateway_url,
                session_id,
                path,
                method="POST",
                json_body=body,
            )
        except RuntimeError as exc:
            if "HTTP 404" not in str(exc) or attempt + 1 == attempts:
                raise
            time.sleep(1)
            continue
        identity = resolved.get("identity") if isinstance(resolved, dict) else None
        public_jwk = resolved.get("public_jwk") if isinstance(resolved, dict) else None
        if not isinstance(identity, dict) or identity.get("issuer_did") != issuer_did:
            raise RuntimeError("public identity resolution changed the requested issuer DID")
        if not isinstance(public_jwk, dict) or not public_jwk.get("kty"):
            raise RuntimeError("public identity resolution returned no usable public JWK")
        return public_jwk
    raise AssertionError("issuer identity visibility retry exhausted unexpectedly")


def bootstrap_eudi(
    gateway_url: str,
    session_id: str,
    *,
    organization_id: str,
    run_id: str,
    key_attestation_trust_anchor_pem: str,
    request: Callable[..., object],
) -> dict[str, Any]:
    """Create EUDI fixtures while keeping custody details behind the profile.

    This function performs profile administration through the public API. Its
    returned runner contract contains only organization, issuer identity, and
    template identifiers; custody-service and key references never cross into
    the issuance request path.
    """

    def provision_identity(
        label: str,
        key_purpose: str,
        *,
        attach_certificate: bool = False,
        trust_wallet_attester: bool = False,
    ) -> str:
        credential_format = "SD_JWT_VC"
        payload = issuer_identity_payload(
            organization_id,
            gateway_url=gateway_url,
            w3c=False,
            algorithm="ES256",
            key_purpose=key_purpose,
            credential_format=credential_format,
            key_attestation_trust_anchor_pem=(key_attestation_trust_anchor_pem if trust_wallet_attester else None),
        )
        created = request(
            gateway_url,
            session_id,
            "/v1/signing-keys/issuer-identities",
            method="POST",
            json_body=payload,
        )
        identity = issuer_identity_response(created)
        if identity.get("issuer_did") != payload["issuer_did"]:
            raise RuntimeError("issuer identity response changed the requested DID")
        if attach_certificate:
            public_jwk = resolve_issuer_identity_public_jwk(
                gateway_url,
                session_id,
                organization_id=organization_id,
                issuer_did=str(payload["issuer_did"]),
                key_purpose=key_purpose,
                credential_format=credential_format,
                algorithm="ES256",
                request=request,
            )
            certificate = create_disposable_issuer_certificate_chain(
                public_jwk,
                organization_id=organization_id,
                profile_label=label,
            )
            attached = request(
                gateway_url,
                session_id,
                "/v1/signing-keys/issuer-identities/certificate",
                method="PUT",
                json_body={
                    "organization_id": organization_id,
                    "issuer_did": payload["issuer_did"],
                    "key_purpose": key_purpose,
                    "credential_format": credential_format,
                    "algorithm": "ES256",
                    "cert_pem": certificate.leaf_pem,
                    "cert_chain_pem": certificate.chain_pem,
                },
            )
            if (
                not isinstance(attached, dict)
                or attached.get("issuer_did") != payload["issuer_did"]
                or attached.get("credential_format") != credential_format
            ):
                raise RuntimeError("issuer identity certificate attachment was not confirmed")
        return str(payload["issuer_did"])

    issuer_did = provision_identity(
        "EUDI SD-JWT",
        "vc_jwt_issuer",
        attach_certificate=True,
        trust_wallet_attester=True,
    )
    request_issuer_did = provision_identity(
        "EUDI OID4VP request",
        "oid4vp_request_signing",
    )
    request_issuer_public_jwk = resolve_issuer_identity_public_jwk(
        gateway_url,
        session_id,
        organization_id=organization_id,
        issuer_did=request_issuer_did,
        key_purpose="oid4vp_request_signing",
        credential_format="SD_JWT_VC",
        algorithm="ES256",
        request=request,
    )

    created_compliance = request(
        gateway_url,
        session_id,
        "/v1/compliance-profiles",
        method="POST",
        json_body=eudi_compliance_profile_payload(organization_id, run_id=run_id),
    )
    compliance_profile_id = response_id(created_compliance, "EUDI compliance profile")
    created_revocation = request(
        gateway_url,
        session_id,
        "/v1/revocation-profiles",
        method="POST",
        json_body=revocation_profile_payload(
            organization_id,
            w3c=False,
            run_id=run_id,
            label="EUDI SD-JWT",
        ),
    )
    revocation_profile_id = response_id(created_revocation, "EUDI revocation profile")
    activated_revocation = request(
        gateway_url,
        session_id,
        f"/v1/revocation-profiles/{revocation_profile_id}/activate",
        method="POST",
    )
    if response_id(activated_revocation, "activated EUDI revocation profile") != revocation_profile_id:
        raise RuntimeError("activated EUDI revocation profile id changed unexpectedly")

    result = {
        "organization_id": organization_id,
        "eudi_issuer_did": issuer_did,
        "eudi_request_issuer_did": request_issuer_did,
        "eudi_request_issuer_public_jwk": request_issuer_public_jwk,
        "eudi_compliance_profile_id": compliance_profile_id,
        "eudi_revocation_profile_id": revocation_profile_id,
    }
    for name, credential_type in (
        ("passport", "Passport"),
        ("mdl", "MobileDrivingLicense"),
        ("open_badge", "OpenBadge"),
    ):
        created_template = request(
            gateway_url,
            session_id,
            "/v1/credential-templates",
            method="POST",
            json_body=eudi_template_payload(
                organization_id,
                compliance_profile_id,
                issuer_did,
                revocation_profile_id,
                credential_type=credential_type,
                gateway_url=gateway_url,
                run_id=run_id,
            ),
        )
        result[f"eudi_{name}_template_id"] = response_id(
            created_template,
            f"EUDI {name} credential template",
        )
    return result


def bootstrap(
    gateway_url: str,
    session_id: str,
    *,
    organization_id: str,
    run_id: str,
    mode: str,
    oidf_signer_public_jwk: dict[str, str] | None = None,
    oidf_mdoc_trust_anchor_pem: str | None = None,
    oidf_key_attestation_trust_anchor_pem: str | None = None,
    request: Callable[..., object] = authenticated_json_request,
) -> dict[str, Any]:
    if not RUN_ID.fullmatch(run_id):
        raise ValueError("run id must use lowercase letters, digits, and internal hyphens")
    if not IDENTIFIER.fullmatch(organization_id):
        raise ValueError("organization id contains unsupported characters")
    if mode in {"oid4vp", "all"} and oidf_signer_public_jwk is None:
        raise ValueError("OID4VP fixture bootstrap requires the official runner public signing JWK")
    if mode == "oid4vp-mdoc" and oidf_mdoc_trust_anchor_pem is None:
        raise ValueError("OID4VP mdoc fixture bootstrap requires the official runner document certificate")
    if mode in {"oid4vci", "eudi"} and oidf_key_attestation_trust_anchor_pem is None:
        raise ValueError(f"{mode} fixture bootstrap requires a key-attestation trust anchor")
    if mode == "eudi":
        return bootstrap_eudi(
            gateway_url,
            session_id,
            organization_id=organization_id,
            run_id=run_id,
            key_attestation_trust_anchor_pem=oidf_key_attestation_trust_anchor_pem,
            request=request,
        )
    result = {"organization_id": organization_id}
    targets = (False, True) if mode == "all" else (mode == "w3c",)
    for w3c in targets:
        oid4vci = mode == "oid4vci"
        mdoc = mode == "oid4vp-mdoc"
        prefix = "w3c" if w3c else ("oid4vci" if oid4vci else "oid4vp_mdoc" if mdoc else "oid4vp")
        profile_payload = issuer_identity_payload(
            organization_id,
            gateway_url=gateway_url,
            w3c=w3c,
            algorithm="EdDSA" if w3c else "ES256",
            key_purpose="mdoc_dsc" if mdoc else "vc_jwt_issuer",
            credential_format="JSON_LD" if w3c else "MDOC" if mdoc else "SD_JWT_VC",
            key_attestation_trust_anchor_pem=(oidf_key_attestation_trust_anchor_pem if oid4vci else None),
        )
        created_issuer_identity = request(
            gateway_url,
            session_id,
            "/v1/signing-keys/issuer-identities",
            method="POST",
            json_body=profile_payload,
        )
        issuer_identity_response(created_issuer_identity)
        request_profile_payload: dict[str, Any] | None = None
        request_issuer_public_jwk: dict[str, str] | None = None
        if not w3c and not oid4vci:
            request_profile_payload = issuer_identity_payload(
                organization_id,
                gateway_url=gateway_url,
                w3c=False,
                algorithm="ES256",
                key_purpose="oid4vp_request_signing",
                credential_format="MDOC" if mdoc else "SD_JWT_VC",
            )
            created_request_identity = request(
                gateway_url,
                session_id,
                "/v1/signing-keys/issuer-identities",
                method="POST",
                json_body=request_profile_payload,
            )
            issuer_identity_response(created_request_identity)
            request_issuer_public_jwk = resolve_issuer_identity_public_jwk(
                gateway_url,
                session_id,
                organization_id=organization_id,
                issuer_did=request_profile_payload["issuer_did"],
                key_purpose="oid4vp_request_signing",
                credential_format="MDOC" if mdoc else "SD_JWT_VC",
                algorithm="ES256",
                request=request,
            )
        created_compliance_profile = request(
            gateway_url,
            session_id,
            "/v1/compliance-profiles",
            method="POST",
            json_body=compliance_profile_payload(
                organization_id,
                w3c=w3c,
                run_id=run_id,
                oid4vci=oid4vci,
                mdoc=mdoc,
            ),
        )
        compliance_profile_id = response_id(
            created_compliance_profile,
            f"{prefix} compliance profile",
        )
        created_revocation_profile = request(
            gateway_url,
            session_id,
            "/v1/revocation-profiles",
            method="POST",
            json_body=revocation_profile_payload(
                organization_id,
                w3c=w3c,
                run_id=run_id,
                mdoc=mdoc,
            ),
        )
        revocation_profile_id = response_id(
            created_revocation_profile,
            f"{prefix} revocation profile",
        )
        activated_revocation_profile = request(
            gateway_url,
            session_id,
            f"/v1/revocation-profiles/{revocation_profile_id}/activate",
            method="POST",
        )
        activated_revocation_profile_id = response_id(
            activated_revocation_profile,
            f"activated {prefix} revocation profile",
        )
        if activated_revocation_profile_id != revocation_profile_id:
            raise RuntimeError(f"activated {prefix} revocation profile id changed unexpectedly")
        created_template_payload = template_payload(
            organization_id,
            compliance_profile_id,
            profile_payload["issuer_did"],
            revocation_profile_id,
            w3c=w3c,
            run_id=run_id,
            mdoc=mdoc,
        )
        created_template = request(
            gateway_url,
            session_id,
            "/v1/credential-templates",
            method="POST",
            json_body=created_template_payload,
        )
        template_id = response_id(created_template, f"{prefix} credential template")
        credential_configuration_id: str | None = None
        if oid4vci:
            activated_template = request(
                gateway_url,
                session_id,
                f"/v1/credential-templates/{template_id}/activate",
                method="POST",
            )
            if (
                response_id(
                    activated_template,
                    "activated OID4VCI credential template",
                )
                != template_id
            ):
                raise RuntimeError("activated OID4VCI credential template id changed unexpectedly")
            issuer_metadata = request(
                gateway_url,
                session_id,
                (f"/org/{organization_id}/.well-known/openid-credential-issuer"),
                method="GET",
            )
            credential_configuration_id = oid4vci_configuration_id(
                issuer_metadata,
                expected_format="dc+sd-jwt",
                expected_vct=str(created_template_payload["vct"]),
            )
        presentation_template_id = template_id
        if w3c:
            created_presentation_template = request(
                gateway_url,
                session_id,
                "/v1/credential-templates",
                method="POST",
                json_body=template_payload(
                    organization_id,
                    compliance_profile_id,
                    profile_payload["issuer_did"],
                    revocation_profile_id,
                    w3c=True,
                    run_id=run_id,
                    presentation=True,
                ),
            )
            presentation_template_id = response_id(
                created_presentation_template,
                f"{prefix} presentation template",
            )
        policy_roles = ("credential", "presentation") if w3c else (() if oid4vci else ("presentation",))
        policy_ids: dict[str, str] = {}
        for role in policy_roles:
            created_policy = request(
                gateway_url,
                session_id,
                "/v1/presentation-policies",
                method="POST",
                json_body=policy_payload(
                    organization_id,
                    presentation_template_id if role == "presentation" else template_id,
                    w3c=w3c,
                    run_id=run_id,
                    presentation=role == "presentation",
                    mdoc=mdoc,
                ),
            )
            policy_id = response_id(created_policy, f"{prefix} {role} policy")
            activated = request(
                gateway_url,
                session_id,
                f"/v1/presentation-policies/{policy_id}/activate",
                method="POST",
            )
            activated_id = response_id(activated, f"activated {prefix} {role} policy")
            if activated_id != policy_id:
                raise RuntimeError(f"activated {prefix} {role} policy id changed unexpectedly")
            policy_ids[role] = policy_id
        result[f"{prefix}_template_id"] = template_id
        if w3c:
            result["w3c_presentation_template_id"] = presentation_template_id
            result["w3c_credential_policy_id"] = policy_ids["credential"]
            result["w3c_presentation_policy_id"] = policy_ids["presentation"]
        elif not oid4vci:
            result[f"{prefix}_policy_id"] = policy_ids["presentation"]
        result[f"{prefix}_compliance_profile_id"] = compliance_profile_id
        if w3c:
            result["w3c_issuer_did"] = profile_payload["issuer_did"]
        elif oid4vci:
            result["oid4vci_issuer_did"] = profile_payload["issuer_did"]
            assert credential_configuration_id is not None
            # OID4VCI credential-configuration identifiers are the keys of
            # credential_configurations_supported, not Marty's internal
            # credential-template resource UUIDs.  Keep both identities so
            # public issuance can address the template while the official
            # runner selects the advertised protocol configuration.
            result["oid4vci_credential_configuration_id"] = credential_configuration_id
        else:
            assert request_profile_payload is not None
            assert request_issuer_public_jwk is not None
            result[f"{prefix}_issuer_did"] = request_profile_payload["issuer_did"]
            result[f"{prefix}_request_issuer_public_jwk"] = request_issuer_public_jwk
        result[f"{prefix}_revocation_profile_id"] = revocation_profile_id
        if not w3c and not oid4vci:
            created_trust_profile = request(
                gateway_url,
                session_id,
                "/v1/trust-profiles",
                method="POST",
                json_body=trust_profile_payload(
                    organization_id,
                    None if mdoc else oidf_signer_public_jwk,
                    run_id=run_id,
                    mdoc_trust_anchor_pem=(oidf_mdoc_trust_anchor_pem if mdoc else None),
                ),
            )
            trust_profile_id = response_id(created_trust_profile, "OID4VP trust profile")
            if mdoc:
                assert oidf_mdoc_trust_anchor_pem is not None
                issuer_payload = mdoc_issuer_entity_payload(
                    organization_id,
                    oidf_mdoc_trust_anchor_pem,
                    run_id=run_id,
                )
                created_issuer = request(
                    gateway_url,
                    session_id,
                    "/v1/issuer-entities",
                    method="POST",
                    json_body=issuer_payload,
                )
                issuer_entity_id = response_id(
                    created_issuer,
                    "OID4VP mdoc issuer entity",
                )
                linked_issuer = request(
                    gateway_url,
                    session_id,
                    f"/v1/trust-profiles/{trust_profile_id}/issuers",
                    method="POST",
                    json_body={
                        "issuer_id": issuer_entity_id,
                        "trust_level": 100,
                        "relationship_status": "TRUSTED",
                        "cascade_revocation_policy": "AUTO_CASCADE",
                        "metadata": {
                            "source": "official-oidf-commit-pinned-document-signer"
                        },
                    },
                )
                response_id(linked_issuer, "OID4VP mdoc issuer relationship")
                result[f"{prefix}_status_issuer_id"] = issuer_payload["issuer_id"]
            activated_trust_profile = request(
                gateway_url,
                session_id,
                f"/v1/trust-profiles/{trust_profile_id}/activate",
                method="POST",
            )
            activated_trust_profile_id = response_id(
                activated_trust_profile,
                "activated OID4VP trust profile",
            )
            if activated_trust_profile_id != trust_profile_id:
                raise RuntimeError("activated OID4VP trust profile id changed unexpectedly")
            result[f"{prefix}_trust_profile_id"] = trust_profile_id
            if mode == "oid4vp":
                result.update(
                    bootstrap_browser_issuance(
                        gateway_url,
                        session_id,
                        organization_id=organization_id,
                        issuer_did=profile_payload["issuer_did"],
                        revocation_profile_id=revocation_profile_id,
                        run_id=run_id,
                        request=request,
                    )
                )
        if w3c:
            api_key_id, api_key = create_disposable_vc_api_key(
                gateway_url,
                session_id,
                organization_id=organization_id,
                run_id=run_id,
                request=request,
            )
            result["w3c_api_key_id"] = api_key_id
            result["w3c_api_key"] = api_key
    return result


def write_private_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "--mode",
        choices=("oid4vci", "oid4vp", "oid4vp-mdoc", "w3c", "eudi", "all"),
        required=True,
    )
    result.add_argument("--gateway-url", default=os.environ.get("OIDF_MARTY_GATEWAY_URL"))
    result.add_argument(
        "--organization-id", default=os.environ.get("MARTY_CONFORMANCE_ORGANIZATION_ID", DEFAULT_ORGANIZATION)
    )
    result.add_argument("--run-id", default=os.environ.get("OFFICIAL_SUITE_RUN_ID"), required=False)
    result.add_argument("--oidf-runner-config", type=Path)
    result.add_argument("--oidf-runner-source", type=Path)
    result.add_argument("--oidf-key-attestation-trust-anchor", type=Path)
    result.add_argument("--output", type=Path, required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if not args.gateway_url:
        raise ValueError("--gateway-url or OIDF_MARTY_GATEWAY_URL is required")
    if not args.run_id:
        raise ValueError("--run-id or OFFICIAL_SUITE_RUN_ID is required")
    needs_oidf_signer = args.mode in {"oid4vp", "all"}
    if needs_oidf_signer and args.oidf_runner_config is None:
        raise ValueError("--oidf-runner-config is required for OID4VP fixture bootstrap")
    if args.mode == "oid4vp-mdoc" and args.oidf_runner_source is None:
        raise ValueError("--oidf-runner-source is required for OID4VP mdoc fixture bootstrap")
    if args.mode in {"oid4vci", "eudi"} and args.oidf_key_attestation_trust_anchor is None:
        raise ValueError("--oidf-key-attestation-trust-anchor is required for OID4VCI and EUDI fixture bootstrap")
    gateway = https_url(args.gateway_url, "gateway URL")
    signer_public_jwk = (
        official_signer_public_jwk(args.oidf_runner_config)
        if args.oidf_runner_config is not None and needs_oidf_signer
        else None
    )
    mdoc_trust_anchor_pem = (
        official_mdoc_trust_anchor(args.oidf_runner_source)
        if args.oidf_runner_source is not None and args.mode == "oid4vp-mdoc"
        else None
    )
    key_attestation_trust_anchor_pem = (
        key_attestation_trust_anchor(args.oidf_key_attestation_trust_anchor)
        if args.oidf_key_attestation_trust_anchor is not None and args.mode in {"oid4vci", "eudi"}
        else None
    )
    fixtures = bootstrap(
        gateway,
        gateway_session_id(),
        organization_id=args.organization_id,
        run_id=args.run_id,
        mode=args.mode,
        oidf_signer_public_jwk=signer_public_jwk,
        oidf_mdoc_trust_anchor_pem=mdoc_trust_anchor_pem,
        oidf_key_attestation_trust_anchor_pem=key_attestation_trust_anchor_pem,
    )
    write_private_json(args.output.resolve(), fixtures)
    # The file contains identifiers and public signing material only, but keep
    # stdout free of values so it remains safe if fixture metadata grows.
    print(f"Created {args.mode} official-suite fixtures through the public gateway.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"Official fixture bootstrap error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
