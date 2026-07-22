#!/usr/bin/env python3
"""Create disposable official-suite fixtures through Marty's public API."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlencode, urlparse

sys.path.insert(0, str(Path(__file__).parent))
from oidf_marty_public_login import authenticated_json_request
from oidf_marty_start_verification import gateway_session_id, https_url

DEFAULT_ORGANIZATION = "00000000-0000-0000-0000-000000000001"
RUN_ID = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
OFFICIAL_OIDF_ISSUER_DOMAIN = "localhost.emobix.co.uk"


def compliance_profile_payload(organization_id: str, *, w3c: bool, run_id: str) -> dict[str, object]:
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
    return {
        "organization_id": organization_id,
        "name": f"Official OID4VP SD-JWT {run_id}",
        "compliance_code": "OID4VP_FINAL",
        "credential_format": "sd_jwt_vc",
        "frameworks": ["openid4vp"],
        "system_profile": False,
    }


def signing_service_request_payload(
    *,
    w3c: bool,
    key_purpose: str = "vc_jwt_issuer",
) -> dict[str, str]:
    """Request the configured production signer for one profile purpose."""
    payload = {
        "key_purpose": key_purpose,
        "algorithm": "ES256",
    }
    if key_purpose == "vc_jwt_issuer":
        payload["credential_format"] = "jwt_vc_json" if w3c else "dc+sd-jwt"
    elif key_purpose == "mdoc_dsc":
        payload["credential_format"] = "mso_mdoc"
    return payload


def issuer_profile_payload(
    organization_id: str,
    signing_service: dict[str, object],
    *,
    gateway_url: str,
    w3c: bool,
    run_id: str,
    label: str | None = None,
    key_purpose: str = "vc_jwt_issuer",
) -> dict[str, str]:
    """Provision an issuer profile whose private key remains in managed custody.

    The service and key references are profile-administration inputs only. The
    conformance runners never receive them: issuance selects the resulting
    issuer profile, and the profile's DID is the signing identity.
    """
    service_id = signing_service.get("id")
    key_reference = signing_service.get("key_reference")
    if not isinstance(service_id, str) or not IDENTIFIER.fullmatch(service_id):
        raise RuntimeError("public signing-service resolution returned an invalid service id")
    if not isinstance(key_reference, str) or not key_reference:
        raise RuntimeError("public signing-service resolution returned no KMS key reference")
    domain = urlparse(gateway_url).hostname
    if not domain:
        raise ValueError("gateway URL has no hostname for the disposable issuer DID")
    profile_label = label or ("W3C VC Data Model v2" if w3c else "OID4VP SD-JWT")
    return {
        "name": f"Official {profile_label} issuer {run_id}",
        "issuer_did": f"did:web:{domain}:orgs:{organization_id}",
        "signing_service_id": service_id,
        "signing_key_reference": key_reference,
        "key_purpose": key_purpose,
        "status": "active",
    }


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
    issuer_profile_id: str,
    revocation_profile_id: str,
    *,
    credential_type: str,
    gateway_url: str,
    run_id: str,
) -> dict[str, object]:
    """Build one production-shaped EUDI SD-JWT credential template.

    The template binds the issuer profile. It intentionally contains no KMS
    service or key reference, so issuance can only sign as the profile's DID.
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
        "issuer_profile_id": issuer_profile_id,
        "revocation_profile_id": revocation_profile_id,
        "schema_uri": {
            "type": "object",
            "properties": properties,
            "required": ["given_name", "family_name", "date_of_birth"],
        },
        "claims": claims,
        "auto_generate_artifacts": True,
    }


def revocation_profile_payload(
    organization_id: str,
    *,
    w3c: bool,
    run_id: str,
    label: str | None = None,
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
        "supported_formats": ["VC_JWT"] if w3c else ["SD_JWT_VC"],
    }


def template_payload(
    organization_id: str,
    compliance_profile_id: str,
    issuer_profile_id: str,
    revocation_profile_id: str,
    *,
    w3c: bool,
    run_id: str,
) -> dict[str, object]:
    if w3c:
        return {
            "organization_id": organization_id,
            "name": f"Official W3C VC v2 {run_id}",
            "credential_type": "VerifiableId",
            "vct": "https://credentials.marty.dev/VerifiableId",
            "supported_formats": ["jwt_vc"],
            "credential_payload_format": "w3c_vcdm_v2_jwt_vc",
            "compliance_profile_id": compliance_profile_id,
            "issuer_profile_id": issuer_profile_id,
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
            "auto_generate_artifacts": True,
        }
    return {
        "organization_id": organization_id,
        "name": f"Official OID4VP SD-JWT {run_id}",
        "credential_type": "PID",
        "vct": "urn:eudi:pid:1",
        "supported_formats": ["sd_jwt_vc"],
        "credential_payload_format": "w3c_vcdm_v2_sd_jwt",
        "compliance_profile_id": compliance_profile_id,
        "issuer_profile_id": issuer_profile_id,
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
        "auto_generate_artifacts": True,
    }


def policy_payload(
    organization_id: str,
    template_id: str,
    *,
    w3c: bool,
    run_id: str,
    presentation: bool = True,
) -> dict[str, object]:
    # The W3C verifier suite supplies standards-conforming generic credentials,
    # not Marty's product-specific identity schema. Marty's policy schema still
    # requires at least one requested-claim entry, so use credentialSubject.id as
    # an optional structural claim. This preserves cryptographic and holder-
    # binding validation without inventing a claim that VCDM v2 does not require.
    claims = (("id", False),) if w3c else tuple((claim, True) for claim in ("given_name", "family_name", "birthdate"))
    if not w3c and not presentation:
        raise ValueError("OID4VP fixtures require a presentation policy")
    label = f"W3C VC v2 {'presentation' if presentation else 'credential'}" if w3c else "OID4VP SD-JWT"
    return {
        "organization_id": organization_id,
        "name": f"Official {label} {run_id}",
        "purpose": f"Disposable {label} official-suite verification",
        # OIDF and W3C Data Integrity presentations are holder bound. A JWT VC
        # verified outside a presentation is not: requiring a VP challenge on
        # that path would reject a valid credential before signature checks.
        "holder_binding": {"required": presentation},
        "credential_requirements": [
            {
                "credential_template_id": template_id,
                "display_name": label,
                "credential_payload_format": (
                    "w3c_vcdm_v2_di" if w3c and presentation else "w3c_vcdm_v2_jwt_vc" if w3c else "w3c_vcdm_v2_sd_jwt"
                ),
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


def trust_profile_payload(
    organization_id: str,
    public_jwk: dict[str, str],
    *,
    run_id: str,
) -> dict[str, object]:
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


def response_id(value: object, resource: str) -> str:
    if not isinstance(value, dict):
        raise RuntimeError(f"public API returned a non-object for {resource}")
    identifier = value.get("id")
    if not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier):
        raise RuntimeError(f"public API returned an invalid {resource} id")
    return identifier


def issuer_profile_response_id(value: object) -> str:
    """Extract the profile object returned by the public issuer-profile API."""
    if not isinstance(value, dict):
        raise RuntimeError("public API returned a non-object for issuer profile")
    return response_id(value.get("profile", value), "issuer profile")


def resolve_signing_service(
    gateway_url: str,
    session_id: str,
    *,
    organization_id: str,
    w3c: bool,
    key_purpose: str = "vc_jwt_issuer",
    request: Callable[..., object],
) -> dict[str, object]:
    """Resolve a KMS signing service through the gateway, with global fallback.

    The fallback is still a public gateway call.  It supports stacks that
    register a shared managed service while retaining the issuer profile in
    the disposable test organization.
    """
    failure: RuntimeError | None = None
    for candidate_organization in (organization_id, None):
        query = (
            f"?{urlencode({'organization_id': candidate_organization})}" if candidate_organization is not None else ""
        )
        try:
            resolved = request(
                gateway_url,
                session_id,
                f"/v1/signing-keys/config/resolve{query}",
                method="POST",
                json_body=signing_service_request_payload(
                    w3c=w3c,
                    key_purpose=key_purpose,
                ),
            )
        except RuntimeError as exc:
            failure = exc
            continue
        if isinstance(resolved, dict) and isinstance(resolved.get("service"), dict):
            return resolved["service"]
        raise RuntimeError("public signing-service resolution returned no service object")
    raise RuntimeError(f"no public KMS signing service is available: {failure}")


def bootstrap_eudi(
    gateway_url: str,
    session_id: str,
    *,
    organization_id: str,
    run_id: str,
    request: Callable[..., object],
) -> dict[str, str]:
    """Create EUDI fixtures while keeping custody details behind the profile.

    This function performs profile administration through the public API. Its
    returned runner contract contains only organization, issuer identity, and
    template identifiers; KMS service and key references never cross into the
    issuance request path.
    """
    def provision_profile(label: str, key_purpose: str) -> tuple[str, str]:
        custody_service = resolve_signing_service(
            gateway_url,
            session_id,
            organization_id=organization_id,
            w3c=False,
            key_purpose=key_purpose,
            request=request,
        )
        payload = issuer_profile_payload(
            organization_id,
            custody_service,
            gateway_url=gateway_url,
            w3c=False,
            run_id=run_id,
            label=label,
            key_purpose=key_purpose,
        )
        created = request(
            gateway_url,
            session_id,
            f"/v1/signing-keys/issuer-profiles?{urlencode({'organization_id': organization_id})}",
            method="POST",
            json_body=payload,
        )
        return issuer_profile_response_id(created), payload["issuer_did"]

    issuer_profile_id, issuer_did = provision_profile("EUDI SD-JWT", "vc_jwt_issuer")
    request_profile_id, request_issuer_did = provision_profile(
        "EUDI OID4VP request",
        "oid4vp_request_signing",
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
        "eudi_issuer_profile_id": issuer_profile_id,
        "eudi_issuer_did": issuer_did,
        "eudi_request_issuer_profile_id": request_profile_id,
        "eudi_request_issuer_did": request_issuer_did,
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
                issuer_profile_id,
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
    request: Callable[..., object] = authenticated_json_request,
) -> dict[str, str]:
    if not RUN_ID.fullmatch(run_id):
        raise ValueError("run id must use lowercase letters, digits, and internal hyphens")
    if not IDENTIFIER.fullmatch(organization_id):
        raise ValueError("organization id contains unsupported characters")
    if mode in {"oid4vp", "all"} and oidf_signer_public_jwk is None:
        raise ValueError("OID4VP fixture bootstrap requires the official runner public signing JWK")
    if mode == "eudi":
        return bootstrap_eudi(
            gateway_url,
            session_id,
            organization_id=organization_id,
            run_id=run_id,
            request=request,
        )
    result = {"organization_id": organization_id}
    targets = (False, True) if mode == "all" else (mode == "w3c",)
    for w3c in targets:
        prefix = "w3c" if w3c else "oid4vp"
        signing_service = resolve_signing_service(
            gateway_url,
            session_id,
            organization_id=organization_id,
            w3c=w3c,
            request=request,
        )
        profile_payload = issuer_profile_payload(
            organization_id,
            signing_service,
            gateway_url=gateway_url,
            w3c=w3c,
            run_id=run_id,
        )
        created_issuer_profile = request(
            gateway_url,
            session_id,
            f"/v1/signing-keys/issuer-profiles?{urlencode({'organization_id': organization_id})}",
            method="POST",
            json_body=profile_payload,
        )
        credential_issuer_profile_id = issuer_profile_response_id(created_issuer_profile)
        request_profile_payload: dict[str, str] | None = None
        request_issuer_profile_id: str | None = None
        if not w3c:
            request_signing_service = resolve_signing_service(
                gateway_url,
                session_id,
                organization_id=organization_id,
                w3c=False,
                key_purpose="oid4vp_request_signing",
                request=request,
            )
            request_profile_payload = issuer_profile_payload(
                organization_id,
                request_signing_service,
                gateway_url=gateway_url,
                w3c=False,
                run_id=run_id,
                label="OID4VP Request Object",
                key_purpose="oid4vp_request_signing",
            )
            created_request_profile = request(
                gateway_url,
                session_id,
                f"/v1/signing-keys/issuer-profiles?{urlencode({'organization_id': organization_id})}",
                method="POST",
                json_body=request_profile_payload,
            )
            request_issuer_profile_id = issuer_profile_response_id(created_request_profile)
        created_compliance_profile = request(
            gateway_url,
            session_id,
            "/v1/compliance-profiles",
            method="POST",
            json_body=compliance_profile_payload(organization_id, w3c=w3c, run_id=run_id),
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
        created_template = request(
            gateway_url,
            session_id,
            "/v1/credential-templates",
            method="POST",
            json_body=template_payload(
                organization_id,
                compliance_profile_id,
                credential_issuer_profile_id,
                revocation_profile_id,
                w3c=w3c,
                run_id=run_id,
            ),
        )
        template_id = response_id(created_template, f"{prefix} credential template")
        policy_roles = ("credential", "presentation") if w3c else ("presentation",)
        policy_ids: dict[str, str] = {}
        for role in policy_roles:
            created_policy = request(
                gateway_url,
                session_id,
                "/v1/presentation-policies",
                method="POST",
                json_body=policy_payload(
                    organization_id,
                    template_id,
                    w3c=w3c,
                    run_id=run_id,
                    presentation=role == "presentation",
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
            result["w3c_credential_policy_id"] = policy_ids["credential"]
            result["w3c_presentation_policy_id"] = policy_ids["presentation"]
        else:
            result["oid4vp_policy_id"] = policy_ids["presentation"]
        result[f"{prefix}_compliance_profile_id"] = compliance_profile_id
        if w3c:
            result["w3c_issuer_profile_id"] = credential_issuer_profile_id
            result["w3c_issuer_did"] = profile_payload["issuer_did"]
        else:
            assert request_profile_payload is not None
            assert request_issuer_profile_id is not None
            result["oid4vp_credential_issuer_profile_id"] = credential_issuer_profile_id
            result["oid4vp_issuer_profile_id"] = request_issuer_profile_id
            result["oid4vp_issuer_did"] = request_profile_payload["issuer_did"]
        result[f"{prefix}_revocation_profile_id"] = revocation_profile_id
        if not w3c:
            assert oidf_signer_public_jwk is not None
            created_trust_profile = request(
                gateway_url,
                session_id,
                "/v1/trust-profiles",
                method="POST",
                json_body=trust_profile_payload(
                    organization_id,
                    oidf_signer_public_jwk,
                    run_id=run_id,
                ),
            )
            trust_profile_id = response_id(created_trust_profile, "OID4VP trust profile")
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
            result["oid4vp_trust_profile_id"] = trust_profile_id
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
    result.add_argument("--mode", choices=("oid4vp", "w3c", "eudi", "all"), required=True)
    result.add_argument("--gateway-url", default=os.environ.get("OIDF_MARTY_GATEWAY_URL"))
    result.add_argument(
        "--organization-id", default=os.environ.get("MARTY_CONFORMANCE_ORGANIZATION_ID", DEFAULT_ORGANIZATION)
    )
    result.add_argument("--run-id", default=os.environ.get("OFFICIAL_SUITE_RUN_ID"), required=False)
    result.add_argument("--oidf-runner-config", type=Path)
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
    gateway = https_url(args.gateway_url, "gateway URL")
    signer_public_jwk = (
        official_signer_public_jwk(args.oidf_runner_config)
        if args.oidf_runner_config is not None and needs_oidf_signer
        else None
    )
    fixtures = bootstrap(
        gateway,
        gateway_session_id(),
        organization_id=args.organization_id,
        run_id=args.run_id,
        mode=args.mode,
        oidf_signer_public_jwk=signer_public_jwk,
    )
    write_private_json(args.output.resolve(), fixtures)
    # The file contains identifiers only, but keep stdout free of values so it
    # remains safe if future fixture metadata grows.
    print(f"Created {args.mode} official-suite fixtures through the public gateway.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"Official fixture bootstrap error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
