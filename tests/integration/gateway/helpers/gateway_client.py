"""
Gateway API Client for Integration Tests

HTTP client wrapper for the Marty Gateway API that provides convenient methods
for all endpoints used by the UI. Handles authentication, error handling, and
response parsing.
"""

import os
from typing import Any, Dict, List, Optional
from uuid import uuid4

import httpx


class GatewayClientError(Exception):
    """Base exception for gateway client errors"""
    pass


class GatewayClient:
    """HTTP client for Gateway API integration tests"""
    
    def __init__(self, base_url: Optional[str] = None, timeout: float = 30.0):
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
        
    async def __aenter__(self):
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
        
    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()
        
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
            return response.json()
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
    ) -> Dict[str, Any]:
        """
        Create a new organization.
        
        Args:
            name: Organization name (unique identifier)
            display_name: Human-readable display name
            
        Returns:
            Organization object with id, name, created_at, etc.
        """
        return await self._request(
            "POST",
            "/v1/organizations",
            json={"name": name, "display_name": display_name or name},
        )
        
    async def get_organization(self, org_id: str) -> Dict[str, Any]:
        """Get organization by ID"""
        return await self._request("GET", f"/v1/organizations/{org_id}")
        
    async def list_organizations(self) -> List[Dict[str, Any]]:
        """List all organizations"""
        return await self._request("GET", "/v1/organizations")
        
    # =============================================================================
    # Trust Profiles
    # =============================================================================
    
    async def create_trust_profile(
        self,
        organization_id: str,
        name: str,
        trusted_issuers: Optional[List[Dict]] = None,
        trust_frameworks: Optional[List[str]] = None,
        revocation_check_enabled: bool = True,
    ) -> Dict[str, Any]:
        """
        Create a trust profile.
        
        Args:
            organization_id: Organization ID
            name: Trust profile name
            trusted_issuers: List of trusted issuer configurations
            trust_frameworks: List of trust framework identifiers
            revocation_check_enabled: Whether to check revocation status
            
        Returns:
            Trust profile object
        """
        return await self._request(
            "POST",
            "/v1/trust-profiles",
            json={
                "organization_id": organization_id,
                "name": name,
                "trusted_issuers": trusted_issuers or [],
                "trust_frameworks": trust_frameworks or [],
                "revocation_check_enabled": revocation_check_enabled,
            },
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
        
    # =============================================================================
    # Credential Templates
    # =============================================================================
    
    async def create_credential_template(
        self,
        organization_id: str,
        name: str,
        credential_type: str,
        compliance_profile: Dict[str, Any],
        vct: str,
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
            
        Returns:
            Credential template object
        """
        payload = {
            "organization_id": organization_id,
            "name": name,
            "credential_type": credential_type,
            "compliance_profile": compliance_profile,
            "vct": vct,
            "supported_formats": supported_formats or ["sd_jwt_vc"],
            "claims": claims or [],
            "auto_generate_artifacts": auto_generate_artifacts,
        }
        
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
        trust_profile_constraints: Optional[List[str]] = None,
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
            trust_profile_constraints: List of trust profile IDs that can use this
            system_profile: Whether this is a system-provided profile
            
        Returns:
            Compliance profile object
        """
        return await self._request(
            "POST",
            "/v1/compliance-profiles",
            json={
                "organization_id": organization_id,
                "name": name,
                "compliance_code": compliance_code,
                "credential_format": credential_format,
                "frameworks": frameworks or [],
                "trust_profile_constraints": trust_profile_constraints or [],
                "system_profile": system_profile,
            },
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
        
    # =============================================================================
    # Presentation Policies
    # =============================================================================
    
    async def create_presentation_policy(
        self,
        organization_id: str,
        name: str,
        credential_requirements: List[Dict],
        purpose: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a presentation policy.
        
        Args:
            organization_id: Organization ID
            name: Policy name
            credential_requirements: List of credential requirements
            purpose: Purpose of the verification
            
        Returns:
            Presentation policy object
        """
        return await self._request(
            "POST",
            "/v1/presentation-policies",
            json={
                "organization_id": organization_id,
                "name": name,
                "credential_requirements": credential_requirements,
                "purpose": purpose,
            },
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
        application_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Issue a credential directly (without application).
        
        Args:
            organization_id: Organization ID
            credential_template_id: Template ID
            claims: Credential claims
            subject_did: Optional subject DID
            application_id: Optional application ID
            
        Returns:
            Issuance object with credential data
        """
        return await self._request(
            "POST",
            "/v1/issuance",
            json={
                "organization_id": organization_id,
                "credential_template_id": credential_template_id,
                "claims": claims,
                "subject_did": subject_did,
                "application_id": application_id,
            },
        )
        
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
        return await self._request(
            "GET",
            f"/v1/flows/instances/{instance_id}/request",
        )
        
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
        flow_type: str,
        steps: Optional[List[Dict]] = None,
        trust_profile_id: Optional[str] = None,
        credential_template_id: Optional[str] = None,
        presentation_policy_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a flow definition"""
        return await self._request(
            "POST",
            "/v1/flows/definitions",
            json={
                "organization_id": organization_id,
                "name": name,
                "flow_type": flow_type,
                "steps": steps or [],
                "trust_profile_id": trust_profile_id,
                "credential_template_id": credential_template_id,
                "presentation_policy_id": presentation_policy_id,
            },
        )
        
    async def get_flow_definition(self, flow_def_id: str) -> Dict[str, Any]:
        """Get flow definition by ID"""
        return await self._request("GET", f"/v1/flows/definitions/{flow_def_id}")
        
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
