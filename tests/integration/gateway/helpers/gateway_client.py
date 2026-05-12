"""
Gateway API Client for Integration Tests

HTTP client wrapper for the Marty Gateway API that provides convenient methods
for all endpoints used by the UI. Handles authentication, error handling, and
response parsing.
"""

import base64
import json
import logging
import os
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import httpx

logger = logging.getLogger(__name__)


class GatewayClientError(Exception):
    """Base exception for gateway client errors"""
    pass


class GatewayClient:
    """HTTP client for Gateway API integration tests"""
    
    def __init__(self, base_url: Optional[str] = None, timeout: float = 90.0):
        """
        Initialize gateway client.
        
        Args:
            base_url: Gateway base URL (defaults to GATEWAY_URL env var or localhost:8000)
            timeout: Request timeout in seconds
        """
        self.base_url = base_url or os.getenv("GATEWAY_URL", "http://localhost:8000")
        self.timeout = timeout
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=timeout,
            follow_redirects=True,
        )
        self._auth_token: Optional[str] = None
        self._session_id: Optional[str] = None
        
    async def __aenter__(self):
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
        
    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()
        
    def set_session(self, session_id: str) -> None:
        """
        Set the gateway session cookie on this client.

        Call this (or ``authenticate``) before making requests to
        auth-protected endpoints.
        """
        self._session_id = session_id
        self.client.cookies.set("sessionId", session_id)
        logger.debug("Gateway client: session cookie set (%s...)", session_id[:8])

    async def authenticate(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> str:
        """
        Complete the Keycloak PKCE flow and store the resulting session cookie.

        Parameters
        ----------
        username:
            Keycloak username / email.  Falls back to ``TEST_USERNAME`` env var
            then ``admin@marty.demo``.
        password:
            Keycloak password.  Falls back to ``TEST_PASSWORD`` env var
            then ``MartyTest123!``.

        Returns
        -------
        str
            The ``sessionId`` cookie value.
        """
        from .auth_helper import AuthHelper

        helper = AuthHelper()
        session_id = await helper.get_session_id(username, password)
        self.set_session(session_id)
        logger.info("Gateway client: authenticated as %s", username or "default-test-user")
        return session_id

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with auth if available"""
        headers = {"Content-Type": "application/json"}
        if self._auth_token:
            headers["Authorization"] = f"Bearer {self._auth_token}"
        return headers
        
    async def _request(
        self,
        method: str,
        path: str,
        json: Optional[Dict] = None,
        params: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """
        Make HTTP request and handle errors.
        
        Args:
            method: HTTP method
            path: API path (e.g., "/v1/organizations")
            json: JSON body
            params: Query parameters
            
        Returns:
            Response JSON data
            
        Raises:
            GatewayClientError: On request failure
        """
        try:
            response = await self.client.request(
                method=method,
                url=path,
                json=json,
                params=params,
                headers=self._get_headers(),
            )
            response.raise_for_status()
            if response.status_code == 204 or not response.content:
                return {}

            try:
                return response.json()
            except ValueError:
                return {"text": response.text} if response.text else {}
        except httpx.HTTPStatusError as e:
            error_detail = e.response.text
            raise GatewayClientError(
                f"{method} {path} failed with {e.response.status_code}: {error_detail}"
            ) from e
        except httpx.RequestError as e:
            raise GatewayClientError(f"Request to {path} failed: {e}") from e
            
    # =============================================================================
    # Health & Status
    # =============================================================================
    
    async def health_check(self) -> Dict[str, Any]:
        """Check gateway health"""
        return await self._request("GET", "/health")
        
    async def check_services_health(self) -> Dict[str, Any]:
        """Check health of all backend services"""
        return await self._request("GET", "/health/services")
        
    # =============================================================================
    # Organization Management
    # =============================================================================
    
    async def create_organization(
        self,
        name: str,
        display_name: Optional[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Create a new organization.
        
        Args:
            name: Organization name (unique identifier)
            display_name: Human-readable display name
            
        Returns:
            Organization object with id, name, created_at, etc.
        """
        body = {"name": name, "display_name": display_name or name}
        body.update(kwargs)
        return await self._request(
            "POST",
            "/v1/organizations",
            json=body,
        )
        
    async def get_organization(self, org_id: str) -> Dict[str, Any]:
        """Get organization by ID"""
        return await self._request("GET", f"/v1/organizations/{org_id}")
        
    async def list_organizations(self) -> List[Dict[str, Any]]:
        """List all organizations"""
        return await self._request("GET", "/v1/organizations")

    async def update_organization(
        self,
        org_id: str,
        **updates,
    ) -> Dict[str, Any]:
        """Update an organization."""
        return await self._request(
            "PATCH",
            f"/v1/organizations/{org_id}",
            json=updates,
        )

    async def delete_organization(self, org_id: str) -> None:
        """Delete an organization."""
        await self._request("DELETE", f"/v1/organizations/{org_id}")
        
    # =============================================================================
    # Trust Profiles
    # =============================================================================
    
    async def create_trust_profile(
        self,
        organization_id: str,
        name: str,
        trusted_issuers: Optional[List[Dict]] = None,
        trust_sources: Optional[List[Dict]] = None,
        trust_frameworks: Optional[List[str]] = None,
        revocation_check_enabled: bool = True,
    ) -> Dict[str, Any]:
        """
        Create a trust profile.
        
        Args:
            organization_id: Organization ID
            name: Trust profile name
            trusted_issuers: List of trusted issuer configurations
            trust_sources: List of trust source configurations
            trust_frameworks: List of trust framework identifiers
            revocation_check_enabled: Whether to check revocation status
            
        Returns:
            Trust profile object
        """
        payload = {
            "organization_id": organization_id,
            "name": name,
            "trusted_issuers": trusted_issuers or [],
            "trust_frameworks": trust_frameworks or [],
            "revocation_check_enabled": revocation_check_enabled,
        }
        if trust_sources is not None:
            payload["trust_sources"] = trust_sources
        return await self._request(
            "POST",
            "/v1/trust-profiles",
            json=payload,
        )
        
    async def get_trust_profile(self, profile_id: str) -> Dict[str, Any]:
        """Get trust profile by ID"""
        return await self._request("GET", f"/v1/trust-profiles/{profile_id}")
        
    async def list_trust_profiles(self, organization_id: str) -> List[Dict[str, Any]]:
        """List trust profiles for an organization"""
        return await self._request(
            "GET",
            "/v1/trust-profiles",
            params={"organization_id": organization_id},
        )

    async def update_trust_profile(
        self,
        profile_id: str,
        **updates,
    ) -> Dict[str, Any]:
        """Update a trust profile."""
        return await self._request(
            "PATCH",
            f"/v1/trust-profiles/{profile_id}",
            json=updates,
        )

    async def delete_trust_profile(self, profile_id: str) -> None:
        """Delete a trust profile."""
        await self._request("DELETE", f"/v1/trust-profiles/{profile_id}")
        
    # =============================================================================
    # Credential Templates
    # =============================================================================
    
    async def create_credential_template(
        self,
        organization_id: str,
        name: str,
        credential_type: str,
        compliance_profile: Optional[Dict[str, Any]] = None,
        vct: str = "",
        supported_formats: Optional[List[str]] = None,
        schema: Optional[Dict] = None,
        claims: Optional[List[Dict]] = None,
        application_template_id: Optional[str] = None,
        trust_profile_id: Optional[str] = None,
        revocation_profile_id: Optional[str] = None,
        issuer_key_id: Optional[str] = None,
        issuer_key_algorithm: Optional[str] = None,
        issuer_certificate_chain_pem: Optional[str] = None,
        issuer_did: Optional[str] = None,
        auto_generate_artifacts: bool = True,
        zk_predicate_claims: Optional[List[str]] = None,
        credential_payload_format: Optional[str] = None,
        wallet_configs: Optional[List[Dict[str, str]]] = None,
        compliance_profile_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a credential template (master issuance configuration).
        
        Args:
            organization_id: Organization ID
            name: Template name
            credential_type: Type of credential (e.g., "org.iso.18013.5.1.mDL")
            compliance_profile: Embedded compliance profile configuration (required)
            vct: Verifiable Credential Type identifier (required)
            supported_formats: List of credential formats (mdoc, sd_jwt_vc, jwt_vc)
            schema: JSON schema for the credential
            claims: List of claim definitions
            application_template_id: Optional reference to Application Template
            trust_profile_id: Optional reference to Trust Profile
            revocation_profile_id: Optional reference to Revocation Profile
            issuer_key_id: Signing key reference
            issuer_key_algorithm: Signing algorithm (RS256, ES256, EdDSA)
            issuer_certificate_chain_pem: X.509 certificate chain (for mDoc)
            issuer_did: DID for issuer (for DID-based credentials)
            auto_generate_artifacts: Auto-generate missing artifacts in non-production
            credential_payload_format: Payload structure variant (e.g. 'w3c_vcdm_v2_sd_jwt',
                'ietf_sd_jwt', 'w3c_vcdm_v2_jwt_vc'). Server default: 'w3c_vcdm_v2_sd_jwt'.
            wallet_configs: Per-wallet deep-link configs, e.g.
                [{"wallet_id": "marty", "deep_link_scheme": "openid-credential-offer://"}]
            
        Returns:
            Credential template object
        """
        payload = {
            "organization_id": organization_id,
            "name": name,
            "credential_type": credential_type,
            "vct": vct,
            "supported_formats": supported_formats or ["sd_jwt_vc"],
            "claims": claims or [],
            "auto_generate_artifacts": auto_generate_artifacts,
        }
        
        if compliance_profile is not None:
            payload["compliance_profile"] = compliance_profile
        if compliance_profile_id:
            payload["compliance_profile_id"] = compliance_profile_id
        
        # Add optional fields
        if application_template_id:
            payload["application_template_id"] = application_template_id
        if trust_profile_id:
            payload["trust_profile_id"] = trust_profile_id
        if revocation_profile_id:
            payload["revocation_profile_id"] = revocation_profile_id
        if issuer_key_id:
            payload["issuer_key_id"] = issuer_key_id
        if issuer_key_algorithm:
            payload["issuer_key_algorithm"] = issuer_key_algorithm
        if issuer_certificate_chain_pem:
            payload["issuer_certificate_chain_pem"] = issuer_certificate_chain_pem
        if issuer_did:
            payload["issuer_did"] = issuer_did
        if schema:
            payload["schema_uri"] = schema
        if zk_predicate_claims:
            payload["zk_predicate_claims"] = zk_predicate_claims
        if credential_payload_format is not None:
            payload["credential_payload_format"] = credential_payload_format
        if wallet_configs is not None:
            payload["wallet_configs"] = wallet_configs

        return await self._request(
            "POST",
            "/v1/credential-templates",
            json=payload,
        )
        
    async def get_credential_template(self, template_id: str) -> Dict[str, Any]:
        """Get credential template by ID"""
        return await self._request("GET", f"/v1/credential-templates/{template_id}")
    
    async def validate_credential_template_artifacts(self, template_id: str) -> Dict[str, Any]:
        """Validate cryptographic artifacts for a credential template."""
        return await self._request(
            "POST",
            f"/v1/credential-templates/{template_id}/validate-artifacts",
        )
        
    async def list_credential_templates(
        self,
        organization_id: str,
    ) -> List[Dict[str, Any]]:
        """List credential templates for an organization"""
        return await self._request(
            "GET",
            "/v1/credential-templates",
            params={"organization_id": organization_id},
        )

    async def update_credential_template(
        self,
        template_id: str,
        **updates,
    ) -> Dict[str, Any]:
        """Update a credential template."""
        return await self._request(
            "PATCH",
            f"/v1/credential-templates/{template_id}",
            json=updates,
        )

    async def delete_credential_template(self, template_id: str) -> None:
        """Delete a credential template."""
        await self._request("DELETE", f"/v1/credential-templates/{template_id}")
    
    # =============================================================================
    # Compliance Profiles
    # =============================================================================
    
    async def create_compliance_profile(
        self,
        organization_id: str,
        name: str,
        compliance_code: Optional[str] = None,
        credential_format: str = "sd_jwt_vc",
        frameworks: Optional[List[str]] = None,
        trust_profile_constraints: Optional[Dict[str, Any]] = None,
        system_profile: bool = False,
    ) -> Dict[str, Any]:
        """
        Create a compliance profile.
        
        Args:
            organization_id: Organization ID
            name: Profile name
            compliance_code: Compliance code (AAMVA_MDL, ICAO_DTC, EUDI_PID, ENTERPRISE_VC)
            credential_format: Credential format (mso_mdoc, sd_jwt_vc, jwt_vc)
            frameworks: List of regulatory frameworks
            trust_profile_constraints: Trust profile constraint object
            system_profile: Whether this is a system-provided profile
            
        Returns:
            Compliance profile object
        """
        payload: Dict[str, Any] = {
            "organization_id": organization_id,
            "name": name,
            "compliance_code": compliance_code,
            "credential_format": credential_format,
            "frameworks": frameworks or [],
            "system_profile": system_profile,
        }
        if trust_profile_constraints is not None:
            payload["trust_profile_constraints"] = trust_profile_constraints
        return await self._request(
            "POST",
            "/v1/compliance-profiles",
            json=payload,
        )
    
    async def get_compliance_profile(self, profile_id: str) -> Dict[str, Any]:
        """Get compliance profile by ID"""
        return await self._request("GET", f"/v1/compliance-profiles/{profile_id}")
    
    async def list_compliance_profiles(
        self,
        organization_id: str,
    ) -> List[Dict[str, Any]]:
        """List compliance profiles for an organization"""
        return await self._request(
            "GET",
            "/v1/compliance-profiles",
            params={"organization_id": organization_id},
        )

    async def update_compliance_profile(
        self,
        profile_id: str,
        **updates,
    ) -> Dict[str, Any]:
        """Update a compliance profile."""
        return await self._request(
            "PATCH",
            f"/v1/compliance-profiles/{profile_id}",
            json=updates,
        )

    async def delete_compliance_profile(self, profile_id: str) -> None:
        """Delete a compliance profile."""
        await self._request("DELETE", f"/v1/compliance-profiles/{profile_id}")
        
    # =============================================================================
    # Presentation Policies
    # =============================================================================
    
    async def create_presentation_policy(
        self,
        organization_id: str,
        name: str,
        credential_requirements: List[Dict],
        purpose: Optional[str] = None,
        prefer_predicates: bool = False,
        fallback_policy: Optional[str] = None,
        supported_circuits: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Create a presentation policy.
        
        Args:
            organization_id: Organization ID
            name: Policy name
            credential_requirements: List of credential requirements
            purpose: Purpose of the verification
            prefer_predicates: Whether to prefer ZK predicate proofs
            fallback_policy: Optional fallback policy ID
            supported_circuits: Optional list of supported ZK circuits
            
        Returns:
            Presentation policy object
        """
        body: Dict[str, Any] = {
            "organization_id": organization_id,
            "name": name,
            "credential_requirements": credential_requirements,
            "purpose": purpose,
        }
        if prefer_predicates:
            body["prefer_predicates"] = True
        if fallback_policy:
            body["fallback_policy"] = fallback_policy
        if supported_circuits:
            body["supported_circuits"] = supported_circuits
        return await self._request(
            "POST",
            "/v1/presentation-policies",
            json=body,
        )
        
    async def get_presentation_policy(self, policy_id: str) -> Dict[str, Any]:
        """Get presentation policy by ID"""
        return await self._request("GET", f"/v1/presentation-policies/{policy_id}")
    
    async def activate_presentation_policy(self, policy_id: str) -> Dict[str, Any]:
        """Activate a presentation policy"""
        return await self._request("POST", f"/v1/presentation-policies/{policy_id}/activate")
        
    async def list_presentation_policies(
        self,
        organization_id: str,
    ) -> List[Dict[str, Any]]:
        """List presentation policies for an organization"""
        return await self._request(
            "GET",
            "/v1/presentation-policies",
            params={"organization_id": organization_id},
        )

    async def update_presentation_policy(
        self,
        policy_id: str,
        **updates,
    ) -> Dict[str, Any]:
        """Update a presentation policy."""
        return await self._request(
            "PATCH",
            f"/v1/presentation-policies/{policy_id}",
            json=updates,
        )

    async def delete_presentation_policy(self, policy_id: str) -> None:
        """Delete a presentation policy."""
        await self._request("DELETE", f"/v1/presentation-policies/{policy_id}")
        
    async def evaluate_presentation(
        self,
        policy_id: str,
        vp_token: str,
        nonce: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate a presentation against a policy (stateless verification).
        
        Args:
            policy_id: Presentation policy ID
            vp_token: VP token (JWT or other format)
            nonce: Optional nonce for freshness
            
        Returns:
            Evaluation result with decision, verified_claims, etc.
        """
        return await self._request(
            "POST",
            f"/v1/presentation-policies/{policy_id}/evaluate",
            json={"vp_token": vp_token, "nonce": nonce},
        )
        
    # =============================================================================
    # Application Templates & Applications
    # =============================================================================
    
    async def create_application_template(
        self,
        organization_id: str,
        name: str,
        credential_template_id: Optional[str] = None,
        evidence_requirements: Optional[List[str]] = None,
        form_fields: Optional[List[Dict]] = None,
        claim_collection_rules: Optional[List[Dict]] = None,
        approval_strategy: str = "auto",
        application_validity_days: int = 30,
        notifications: Optional[Dict] = None,
        ui_config: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """
        Create an application template (user-facing workflow definition).
        
        Args:
            organization_id: Organization ID
            name: Template name
            credential_template_id: Credential template ID for issuance
            evidence_requirements: List of required evidence types (e.g., ["identity_document", "portrait"])
            form_fields: Form field definitions for user data entry
            claim_collection_rules: How to collect claim values from applicant
            approval_strategy: How approvals are handled (auto, manual, rules_based)
            application_validity_days: How long applications remain valid
            notifications: Notification configuration
            ui_config: UI/UX customization
            
        Returns:
            Application template object
        """
        payload = {
            "organization_id": organization_id,
            "name": name,
            "evidence_requirements": evidence_requirements or ["identity_document", "portrait"],
            "form_fields": form_fields or [],
            "claim_collection_rules": claim_collection_rules or [],
            "approval_strategy": approval_strategy,
            "application_validity_days": application_validity_days,
        }
        
        if credential_template_id:
            payload["credential_template_id"] = credential_template_id
        
        if notifications:
            payload["notifications"] = notifications
        if ui_config:
            payload["ui_config"] = ui_config
        
        return await self._request(
            "POST",
            "/v1/application-templates",
            json=payload,
        )
        
    async def get_application_template(self, template_id: str) -> Dict[str, Any]:
        """Get application template by ID"""
        return await self._request("GET", f"/v1/application-templates/{template_id}")
        
    async def list_application_templates(
        self,
        organization_id: str,
    ) -> List[Dict[str, Any]]:
        """List application templates for an organization"""
        return await self._request(
            "GET",
            "/v1/application-templates",
            params={"organization_id": organization_id},
        )
        
    async def create_application(
        self,
        application_template_id: str,
        applicant_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Create an application.
        
        Args:
            application_template_id: Application template ID
            applicant_data: Applicant information (name, dob, etc.)
            
        Returns:
            Application object with status="pending"
        """
        return await self._request(
            "POST",
            "/v1/applications",
            json={
                "application_template_id": application_template_id,
                "applicant_data": applicant_data,
            },
        )
        
    async def get_application(self, application_id: str) -> Dict[str, Any]:
        """Get application by ID"""
        return await self._request("GET", f"/v1/applications/{application_id}")
        
    async def list_applications(
        self,
        organization_id: str,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List applications for an organization"""
        params = {"organization_id": organization_id}
        if status:
            params["status"] = status
        return await self._request("GET", "/v1/applications", params=params)
        
    async def submit_evidence(
        self,
        application_id: str,
        evidence: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Submit evidence for an application.
        
        Args:
            application_id: Application ID
            evidence: Evidence data (e.g., {"portrait": "base64..."})
            
        Returns:
            Updated application object
        """
        return await self._request(
            "POST",
            f"/v1/applications/{application_id}/submit-evidence",
            json=evidence,
        )
        
    async def approve_application(self, application_id: str, review_notes: str | None = None, reviewer_id: str | None = None) -> Dict[str, Any]:
        """Approve an application (triggers credential issuance)"""
        body = {}
        if review_notes:
            body["review_notes"] = review_notes
        if reviewer_id:
            body["reviewer_id"] = reviewer_id
        return await self._request("POST", f"/v1/applications/{application_id}/approve", json=body)
        
    async def reject_application(self, application_id: str, review_notes: str | None = None, reviewer_id: str | None = None) -> Dict[str, Any]:
        """Reject an application"""
        body = {
            "review_notes": review_notes or "Application rejected"
        }
        if reviewer_id:
            body["reviewer_id"] = reviewer_id
        return await self._request("POST", f"/v1/applications/{application_id}/reject", json=body)
        
    # =============================================================================
    # Credential Issuance
    # =============================================================================
    
    async def issue_credential(
        self,
        organization_id: str,
        credential_template_id: str,
        claims: Dict[str, Any],
        subject_did: Optional[str] = None,
        holder_did: Optional[str] = None,
        application_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Issue a credential directly (without application).
        
        Args:
            organization_id: Organization ID
            credential_template_id: Template ID
            claims: Credential claims
            subject_did: Optional subject DID
            holder_did: Optional holder DID (DIDComm v2 push delivery)
            application_id: Optional application ID
            
        Returns:
            Issuance object with credential data
        """
        payload: Dict[str, Any] = {
            "organization_id": organization_id,
            "credential_template_id": credential_template_id,
            "claims": claims,
            "subject_did": subject_did,
            "application_id": application_id,
        }
        if holder_did:
            payload["holder_did"] = holder_did
        return await self._request("POST", "/v1/issuance", json=payload)
        
    async def get_issuance(self, issuance_id: str) -> Dict[str, Any]:
        """Get issuance record by ID"""
        return await self._request("GET", f"/v1/issuance/{issuance_id}")
        
    async def list_issuances(
        self,
        organization_id: str,
    ) -> List[Dict[str, Any]]:
        """List issuance records for an organization"""
        return await self._request(
            "GET",
            "/v1/issuance",
            params={"organization_id": organization_id},
        )

    # =============================================================================
    # Canvas Integrations
    # =============================================================================

    async def create_canvas_connector(
        self,
        organization_id: str,
        canvas_account_id: str,
        credential_template_id: str,
        display_name: Optional[str] = None,
        canvas_base_url: Optional[str] = None,
        lti_client_id: Optional[str] = None,
        lti_deployment_id: Optional[str] = None,
        lti_issuer: Optional[str] = None,
        lti_jwks_url: Optional[str] = None,
        lti_jwks_json: Optional[Dict[str, Any]] = None,
        lti_openid_configuration: Optional[Dict[str, Any]] = None,
        enabled: bool = True,
    ) -> Dict[str, Any]:
        """Create a Canvas connector mapping for inbound credential events."""
        payload: Dict[str, Any] = {
            "organization_id": organization_id,
            "canvas_account_id": canvas_account_id,
            "credential_template_id": credential_template_id,
            "enabled": enabled,
        }
        if display_name is not None:
            payload["display_name"] = display_name
        if canvas_base_url is not None:
            payload["canvas_base_url"] = canvas_base_url
        if lti_client_id is not None:
            payload["lti_client_id"] = lti_client_id
        if lti_deployment_id is not None:
            payload["lti_deployment_id"] = lti_deployment_id
        if lti_issuer is not None:
            payload["lti_issuer"] = lti_issuer
        if lti_jwks_url is not None:
            payload["lti_jwks_url"] = lti_jwks_url
        if lti_jwks_json is not None:
            payload["lti_jwks_json"] = lti_jwks_json
        if lti_openid_configuration is not None:
            payload["lti_openid_configuration"] = lti_openid_configuration
        return await self._request("POST", "/v1/integrations/canvas/connectors", json=payload)

    async def list_canvas_connectors(self, organization_id: str) -> List[Dict[str, Any]]:
        """List Canvas connectors for an organization."""
        return await self._request(
            "GET",
            "/v1/integrations/canvas/connectors",
            params={"organization_id": organization_id},
        )

    async def get_canvas_connector(self, connector_id: str) -> Dict[str, Any]:
        """Get a Canvas connector by ID."""
        return await self._request("GET", f"/v1/integrations/canvas/connectors/{connector_id}")

    async def update_canvas_connector(self, connector_id: str, **updates) -> Dict[str, Any]:
        """Update a Canvas connector."""
        return await self._request("PUT", f"/v1/integrations/canvas/connectors/{connector_id}", json=updates)

    async def delete_canvas_connector(self, connector_id: str) -> None:
        """Delete a Canvas connector."""
        await self._request("DELETE", f"/v1/integrations/canvas/connectors/{connector_id}")

    async def probe_canvas_connector_sandbox(self, connector_id: str) -> Dict[str, Any]:
        """Fetch and persist Canvas sandbox metadata for a connector."""
        return await self._request(
            "POST",
            f"/v1/integrations/canvas/connectors/{connector_id}/sandbox-probe",
        )

    async def refresh_canvas_connector_jwks(self, connector_id: str) -> Dict[str, Any]:
        """Refresh and persist Canvas JWKS metadata for a connector."""
        return await self._request(
            "POST",
            f"/v1/integrations/canvas/connectors/{connector_id}/jwks-refresh",
        )

    async def launch_canvas_lti(
        self,
        connector_id: str,
        *,
        id_token: str,
        expected_nonce: Optional[str] = None,
        state: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Submit a public Canvas LTI launch to the gateway."""
        payload: Dict[str, Any] = {"id_token": id_token}
        if expected_nonce is not None:
            payload["expected_nonce"] = expected_nonce
        if state is not None:
            payload["state"] = state
        return await self._request(
            "POST",
            f"/v1/integrations/canvas/lti/launch/{connector_id}",
            json=payload,
        )

    async def initiate_canvas_lti_login(
        self,
        connector_id: str,
        *,
        login_hint: str,
        issuer: Optional[str] = None,
        target_link_uri: Optional[str] = None,
        lti_message_hint: Optional[str] = None,
        client_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Start Canvas LTI OIDC login and return the platform authorization redirect."""
        payload: Dict[str, Any] = {"login_hint": login_hint}
        if issuer is not None:
            payload["iss"] = issuer
        if target_link_uri is not None:
            payload["target_link_uri"] = target_link_uri
        if lti_message_hint is not None:
            payload["lti_message_hint"] = lti_message_hint
        if client_id is not None:
            payload["client_id"] = client_id

        try:
            response = await self.client.request(
                "POST",
                url=f"/v1/integrations/canvas/lti/login/{connector_id}",
                json=payload,
                headers=self._get_headers(),
                follow_redirects=False,
            )
            if response.status_code >= 400:
                response.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise GatewayClientError(
                f"POST /v1/integrations/canvas/lti/login/{connector_id} failed "
                f"with {e.response.status_code}: {e.response.text}"
            ) from e
        except httpx.RequestError as e:
            raise GatewayClientError(f"Request to Canvas LTI login failed: {e}") from e

        location = response.headers.get("location", "")
        if not location:
            raise GatewayClientError("Canvas LTI login did not return a Location header")

        params = parse_qs(urlparse(location).query)
        return {
            "authorization_url": location,
            "state": params.get("state", [""])[0],
            "nonce": params.get("nonce", [""])[0],
            "redirect_uri": params.get("redirect_uri", [""])[0],
        }

    async def didcomm_deliver(
        self,
        transaction_id: str,
        holder_did: str,
        universal_resolver_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Deliver a credential via DIDComm v2 push.

        Args:
            transaction_id: Issuance transaction ID
            holder_did: Holder's DID (must have a DIDComm service endpoint)
            universal_resolver_url: Optional Universal Resolver URL for unknown DID methods

        Returns:
            DIDComm delivery result with transaction_id, credential_id, status, etc.
        """
        payload: Dict[str, Any] = {
            "transaction_id": transaction_id,
            "holder_did": holder_did,
        }
        if universal_resolver_url:
            payload["universal_resolver_url"] = universal_resolver_url
        return await self._request("POST", "/v1/issuance/didcomm/deliver", json=payload)
        
    # =============================================================================
    # Verification Flows (Async Wallet Interaction)
    # =============================================================================
    
    async def start_verification_flow(
        self,
        presentation_policy_id: str,
        trust_profile_id: Optional[str] = None,
        expiry_minutes: int = 15,
    ) -> Dict[str, Any]:
        """
        Start a verification flow (creates QR code for wallet).
        
        Args:
            presentation_policy_id: Policy defining what to request
            trust_profile_id: Optional trust profile
            expiry_minutes: Request expiry time
            
        Returns:
            Flow instance with instance_id, request_uri, qr_code_data
        """
        return await self._request(
            "POST",
            "/v1/flows/verify",
            json={
                "presentation_policy_id": presentation_policy_id,
                "trust_profile_id": trust_profile_id,
                "expiry_minutes": expiry_minutes,
            },
        )
        
    async def get_verification_request(self, instance_id: str) -> Dict[str, Any]:
        """Get verification request object (wallet fetches this)"""
        # This endpoint returns a JWT (application/oauth-authz-req+jwt), not JSON
        # We need to decode it
        try:
            response = await self.client.get(
                f"/v1/flows/instances/{instance_id}/request",
                headers=self._get_headers(),
            )
            response.raise_for_status()
            
            # Check content type
            content_type = response.headers.get("content-type", "")
            if "jwt" in content_type or not content_type.startswith("application/json"):
                # It's a JWT - decode the payload (middle part)
                jwt_token = response.text
                # JWT format: header.payload.signature
                parts = jwt_token.split('.')
                if len(parts) == 3:
                    # Decode the payload (add padding if needed)
                    payload_b64 = parts[1]
                    # Add padding if needed
                    padding = 4 - len(payload_b64) % 4
                    if padding != 4:
                        payload_b64 += '=' * padding
                    payload_bytes = base64.urlsafe_b64decode(payload_b64)
                    decoded = json.loads(payload_bytes)
                    return decoded
                else:
                    raise GatewayClientError(f"Invalid JWT format: expected 3 parts, got {len(parts)}")
            else:
                # It's JSON
                return response.json()
        except httpx.HTTPStatusError as e:
            error_detail = e.response.text
            raise GatewayClientError(
                f"GET /v1/flows/instances/{instance_id}/request failed with {e.response.status_code}: {error_detail}"
            ) from e
        except httpx.RequestError as e:
            raise GatewayClientError(f"Request to /v1/flows/instances/{instance_id}/request failed: {e}") from e
        
    async def submit_verification(
        self,
        instance_id: str,
        vp_token: str,
    ) -> Dict[str, Any]:
        """
        Submit VP token to complete verification flow.
        
        Args:
            instance_id: Flow instance ID
            vp_token: VP token from wallet
            
        Returns:
            Verification result
        """
        return await self._request(
            "POST",
            f"/v1/flows/instances/{instance_id}/submit",
            json={"vp_token": vp_token},
        )
        
    async def get_verification_result(self, instance_id: str) -> Dict[str, Any]:
        """Get verification flow result"""
        return await self._request("GET", f"/v1/flows/instances/{instance_id}")
        
    # =============================================================================
    # Flow Definitions & Instances
    # =============================================================================
    
    async def create_flow_definition(
        self,
        organization_id: str,
        name: str,
        flow_type: Optional[str] = None,
        type: Optional[str] = None,
        steps: Optional[List[Dict]] = None,
        trust_profile_id: Optional[str] = None,
        credential_template_id: Optional[str] = None,
        presentation_policy_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a flow definition"""
        ft = flow_type or type or "issuance"
        return await self._request(
            "POST",
            "/v1/flows/definitions",
            json={
                "organization_id": organization_id,
                "name": name,
                "flow_type": ft,
                "steps": steps or [],
                "trust_profile_id": trust_profile_id,
                "credential_template_id": credential_template_id,
                "presentation_policy_id": presentation_policy_id,
            },
        )
        
    async def get_flow_definition(self, flow_def_id: str) -> Dict[str, Any]:
        """Get flow definition by ID"""
        return await self._request("GET", f"/v1/flows/definitions/{flow_def_id}")

    async def activate_flow_definition(self, flow_def_id: str) -> Dict[str, Any]:
        """Activate a flow definition"""
        return await self._request("POST", f"/v1/flows/definitions/{flow_def_id}/activate")
        
    async def list_flow_definitions(
        self,
        organization_id: str,
    ) -> List[Dict[str, Any]]:
        """List flow definitions for an organization"""
        return await self._request(
            "GET",
            "/v1/flows/definitions",
            params={"organization_id": organization_id},
        )

    async def update_flow_definition(
        self,
        flow_def_id: str,
        **updates,
    ) -> Dict[str, Any]:
        """Update a flow definition."""
        return await self._request(
            "PATCH",
            f"/v1/flows/definitions/{flow_def_id}",
            json=updates,
        )

    async def delete_flow_definition(self, flow_def_id: str) -> None:
        """Delete a flow definition."""
        await self._request("DELETE", f"/v1/flows/definitions/{flow_def_id}")
        
    async def start_flow_instance(
        self,
        flow_definition_id: str,
        subject_id: Optional[str] = None,
        initial_context: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """Start a flow instance"""
        return await self._request(
            "POST",
            "/v1/flows/instances",
            json={
                "flow_definition_id": flow_definition_id,
                "subject_id": subject_id,
                "initial_context": initial_context or {},
            },
        )
        
    async def get_flow_instance(self, instance_id: str) -> Dict[str, Any]:
        """Get flow instance by ID"""
        return await self._request("GET", f"/v1/flows/instances/{instance_id}")
    
    # =============================================================================
    # Deployment Profiles
    # =============================================================================
    
    async def create_deployment_profile(
        self,
        organization_id: str,
        name: str,
        site_id: str,
        network_mode: str = "online",
        key_access_mode: str = "key_vault",
        ux_config: Optional[Dict] = None,
        update_policy: Optional[Dict] = None,
        offline_cache_ttl_hours: int = 24,
        biometric_required: bool = False,
        audit_all_events: bool = True,
        default_presentation_policy_id: Optional[str] = None,
        trust_profile_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a deployment profile."""
        payload = {
            "organization_id": organization_id,
            "name": name,
            "site_id": site_id,
            "network_mode": network_mode,
            "key_access_mode": key_access_mode,
            "ux_config": ux_config or {},
            "update_policy": update_policy or {},
            "offline_cache_ttl_hours": offline_cache_ttl_hours,
            "biometric_required": biometric_required,
            "audit_all_events": audit_all_events,
            "default_presentation_policy_id": default_presentation_policy_id,
        }
        if trust_profile_id:
            payload["trust_profile_id"] = trust_profile_id
        return await self._request(
            "POST",
            "/v1/deployment-profiles",
            json=payload,
        )
    
    async def get_deployment_profile(self, profile_id: str) -> Dict[str, Any]:
        """Get deployment profile by ID."""
        return await self._request("GET", f"/v1/deployment-profiles/{profile_id}")
    
    async def list_deployment_profiles(
        self,
        organization_id: str,
    ) -> List[Dict[str, Any]]:
        """List deployment profiles for an organization."""
        return await self._request(
            "GET",
            "/v1/deployment-profiles",
            params={"organization_id": organization_id},
        )
    
    async def update_deployment_profile(
        self,
        profile_id: str,
        **updates,
    ) -> Dict[str, Any]:
        """Update a deployment profile."""
        return await self._request(
            "PUT",
            f"/v1/deployment-profiles/{profile_id}",
            json=updates,
        )
    
    async def delete_deployment_profile(self, profile_id: str) -> None:
        """Delete a deployment profile."""
        await self._request("DELETE", f"/v1/deployment-profiles/{profile_id}")
    
    async def activate_deployment_profile(self, profile_id: str) -> Dict[str, Any]:
        """Activate a deployment profile."""
        return await self._request(
            "POST",
            f"/v1/deployment-profiles/{profile_id}/activate",
        )
    
    async def generate_deployment_profile_api_key(self, profile_id: str) -> Dict[str, Any]:
        """Generate API key for deployment profile."""
        return await self._request(
            "POST",
            f"/v1/deployment-profiles/{profile_id}/generate-api-key",
        )
    
    # =============================================================================
    # Lanes (nested under Deployment Profiles)
    # =============================================================================
    
    async def create_lane(
        self,
        profile_id: Optional[str] = None,
        name: str = "",
        description: Optional[str] = None,
        location: Optional[str] = None,
        device_type: str = "kiosk",
        metadata: Optional[Dict] = None,
        deployment_profile_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a lane within a deployment profile."""
        pid = deployment_profile_id or profile_id
        return await self._request(
            "POST",
            f"/v1/deployment-profiles/{pid}/lanes",
            json={
                "name": name,
                "description": description,
                "location": location,
                "device_type": device_type,
                "metadata": metadata or {},
            },
        )
    
    async def get_lane(self, profile_id: str, lane_id: str) -> Dict[str, Any]:
        """Get lane by ID."""
        return await self._request(
            "GET",
            f"/v1/deployment-profiles/{profile_id}/lanes/{lane_id}",
        )
    
    async def list_lanes(self, profile_id: str) -> List[Dict[str, Any]]:
        """List lanes for a deployment profile."""
        return await self._request(
            "GET",
            f"/v1/deployment-profiles/{profile_id}/lanes",
        )
    
    async def update_lane(
        self,
        profile_id: str,
        lane_id: str,
        **updates,
    ) -> Dict[str, Any]:
        """Update a lane."""
        return await self._request(
            "PUT",
            f"/v1/deployment-profiles/{profile_id}/lanes/{lane_id}",
            json=updates,
        )
    
    async def delete_lane(self, profile_id: str, lane_id: str) -> None:
        """Delete a lane."""
        await self._request(
            "DELETE",
            f"/v1/deployment-profiles/{profile_id}/lanes/{lane_id}",
        )
    
    async def assign_device_to_lane(
        self,
        profile_id: str,
        lane_id: str,
        device_id: str,
        device_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Assign device to lane."""
        return await self._request(
            "POST",
            f"/v1/deployment-profiles/{profile_id}/lanes/{lane_id}/devices",
            json={
                "device_id": device_id,
                "device_name": device_name,
            },
        )

    # =============================================================================
    # Signing Keys
    # =============================================================================

    async def list_signing_keys(
        self,
        organization_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List signing keys for an organization scope."""
        params = {"organization_id": organization_id} if organization_id else None
        return await self._request("GET", "/v1/signing-keys", params=params)

    async def get_signing_key_config(
        self,
        organization_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get signing-key management config for an organization scope."""
        params = {"organization_id": organization_id} if organization_id else None
        return await self._request("GET", "/v1/signing-keys/config", params=params)

    async def update_signing_key_config(
        self,
        services: List[Dict[str, Any]],
        default_service_id: Optional[str] = None,
        organization_id: Optional[str] = None,
        format_defaults: Optional[Dict[str, str]] = None,
        type_defaults: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Update signing-key service registry configuration."""
        payload: Dict[str, Any] = {
            "services": services,
            "default_service_id": default_service_id,
        }
        if format_defaults is not None:
            payload["format_defaults"] = format_defaults
        if type_defaults is not None:
            payload["type_defaults"] = type_defaults

        params = {"organization_id": organization_id} if organization_id else None
        return await self._request("PATCH", "/v1/signing-keys/config", json=payload, params=params)

    async def resolve_signing_service(
        self,
        organization_id: Optional[str] = None,
        credential_format: Optional[str] = None,
        key_purpose: Optional[str] = None,
        algorithm: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Resolve the best signing service for a format, purpose, and algorithm."""
        payload: Dict[str, Any] = {}
        if credential_format is not None:
            payload["credential_format"] = credential_format
        if key_purpose is not None:
            payload["key_purpose"] = key_purpose
        if algorithm is not None:
            payload["algorithm"] = algorithm

        params = {"organization_id": organization_id} if organization_id else None
        return await self._request("POST", "/v1/signing-keys/config/resolve", json=payload, params=params)

    async def list_signing_key_purposes(self) -> Dict[str, Any]:
        """List valid signing-key purposes and constraints."""
        return await self._request("GET", "/v1/signing-keys/config/purposes")

    async def list_signing_key_service_capabilities(self) -> Dict[str, Any]:
        """List static provider capability metadata."""
        return await self._request("GET", "/v1/signing-keys/config/service-capabilities")

    async def create_issuer_profile(
        self,
        *,
        organization_id: str,
        name: str,
        issuer_did: str,
        signing_service_id: str,
        signing_key_reference: Optional[str] = None,
        key_purpose: str = "vc_jwt_issuer",
        status: str = "active",
    ) -> Dict[str, Any]:
        """Create or return an issuer profile bound to a signing service."""
        payload: Dict[str, Any] = {
            "name": name,
            "issuer_did": issuer_did,
            "signing_service_id": signing_service_id,
            "key_purpose": key_purpose,
            "status": status,
        }
        if signing_key_reference:
            payload["signing_key_reference"] = signing_key_reference
        response = await self._request(
            "POST",
            "/v1/signing-keys/issuer-profiles",
            json=payload,
            params={"organization_id": organization_id},
        )
        return response.get("profile", response)
    
    # =============================================================================
    # Revocation
    # =============================================================================

    async def create_revocation_profile(
        self,
        organization_id: str,
        name: str,
        revocation_mechanism: List[str],
        mechanism_priority: Optional[List[str]] = None,
        check_mode: str = "ALWAYS",
        cache_ttl_seconds: Optional[int] = None,
        offline_grace_seconds: Optional[int] = None,
        issuer_config: Optional[Dict[str, Any]] = None,
        status_list_url: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a revocation profile."""
        payload: Dict[str, Any] = {
            "organization_id": organization_id,
            "name": name,
            "revocation_mechanism": revocation_mechanism,
            "mechanism_priority": mechanism_priority or revocation_mechanism,
            "check_mode": check_mode,
            "issuer_config": issuer_config or {},
            "metadata": metadata or {},
        }
        if cache_ttl_seconds is not None:
            payload["cache_ttl_seconds"] = cache_ttl_seconds
        if offline_grace_seconds is not None:
            payload["offline_grace_seconds"] = offline_grace_seconds
        if status_list_url is not None:
            payload["status_list_url"] = status_list_url

        return await self._request(
            "POST",
            "/v1/revocation-profiles",
            json=payload,
        )

    async def get_revocation_profile(self, profile_id: str) -> Dict[str, Any]:
        """Get revocation profile by ID."""
        return await self._request(
            "GET",
            f"/v1/revocation-profiles/{profile_id}",
        )

    async def list_revocation_profiles(
        self,
        organization_id: str,
    ) -> List[Dict[str, Any]]:
        """List revocation profiles for an organization."""
        return await self._request(
            "GET",
            "/v1/revocation-profiles",
            params={"organization_id": organization_id},
        )

    async def update_revocation_profile(
        self,
        profile_id: str,
        **updates,
    ) -> Dict[str, Any]:
        """Update a revocation profile."""
        return await self._request(
            "PATCH",
            f"/v1/revocation-profiles/{profile_id}",
            json=updates,
        )

    async def delete_revocation_profile(self, profile_id: str) -> None:
        """Delete a revocation profile."""
        await self._request(
            "DELETE",
            f"/v1/revocation-profiles/{profile_id}",
        )
    
    async def revoke_credential(
        self,
        issuance_id: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Revoke a credential."""
        return await self._request(
            "POST",
            f"/v1/issuance/{issuance_id}/revoke",
            json={"reason": reason or "Test revocation"},
        )
    
    async def get_revocation_status(self, issuance_id: str) -> Dict[str, Any]:
        """Get revocation status for a credential."""
        return await self._request(
            "GET",
            f"/v1/issuance/{issuance_id}/revocation-status",
        )
