"""
Test Data Builders for Gateway Integration Tests

Factory methods for creating consistent test data for various credential types,
application scenarios, and verification policies.
"""

from typing import Any, Dict, List, Optional
from uuid import uuid4
from datetime import datetime, timedelta


class TestDataBuilder:
    """Factory for creating test data"""
    
    # =============================================================================
    # Organization Data
    # =============================================================================
    
    @staticmethod
    def organization(
        name: Optional[str] = None,
        display_name: Optional[str] = None,
    ) -> Dict[str, str]:
        """Create organization data with unique name"""
        unique_suffix = str(uuid4())[:8]
        org_name = name or f"test-org-{unique_suffix}"
        return {
            "name": org_name,
            "display_name": display_name or f"Test Organization {unique_suffix}",
        }
        
    # =============================================================================
    # Trust Profile Data
    # =============================================================================
    
    @staticmethod
    def trust_profile(
        organization_id: str,
        name: Optional[str] = None,
        trusted_issuers: Optional[List[Dict]] = None,
    ) -> Dict[str, Any]:
        """Create trust profile data"""
        return {
            "organization_id": organization_id,
            "name": name or f"test-trust-profile-{str(uuid4())[:8]}",
            "trusted_issuers": trusted_issuers or [
                {
                    "issuer_id": "did:example:issuer123",
                    "name": "Test Issuer",
                    "trust_level": "high",
                }
            ],
            "trust_frameworks": ["eidas", "nist_800_63"],
            "revocation_check_enabled": True,
        }
    
    # =============================================================================
    # Compliance Profile Data
    # =============================================================================
    
    @staticmethod
    def compliance_profile(
        organization_id: str,
        name: Optional[str] = None,
        compliance_code: str = "AAMVA_MDL",
        credential_format: str = "mso_mdoc",
    ) -> Dict[str, Any]:
        """Create compliance profile data"""
        return {
            "organization_id": organization_id,
            "name": name or f"test-compliance-profile-{str(uuid4())[:8]}",
            "compliance_code": compliance_code,
            "credential_format": credential_format,
            "frameworks": ["aamva", "iso_18013_5"],
            "trust_profile_constraints": [],
            "system_profile": False,
        }
        
    # =============================================================================
    # Credential Template Data
    # =============================================================================
    
    @staticmethod
    def mdl_template(
        organization_id: str,
        name: Optional[str] = None,
        application_template_id: Optional[str] = None,
        compliance_profile_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create mobile driver's license (mDL) credential template.
        Follows org.iso.18013.5.1.mDL standard.
        
        Args:
            organization_id: Organization ID
            name: Template name
            application_template_id: Optional Application Template ID
            compliance_profile_id: Optional Compliance Profile ID
        """
        data = {
            "organization_id": organization_id,
            "name": name or "Mobile Driver's License",
            "credential_type": "org.iso.18013.5.1.mDL",
            "vct": "org.iso.18013.5.1.mDL",
            "supported_formats": ["mdoc"],
            "schema": {
                "namespaces": {
                    "org.iso.18013.5.1": {
                        "family_name": {"type": "string", "required": True},
                        "given_name": {"type": "string", "required": True},
                        "birth_date": {"type": "string", "format": "full-date", "required": True},
                        "issue_date": {"type": "string", "format": "full-date", "required": True},
                        "expiry_date": {"type": "string", "format": "full-date", "required": True},
                        "issuing_country": {"type": "string", "required": True},
                        "issuing_authority": {"type": "string", "required": True},
                        "document_number": {"type": "string", "required": True},
                        "portrait": {"type": "string", "format": "base64", "required": False},
                        "driving_privileges": {"type": "array", "required": True},
                        "un_distinguishing_sign": {"type": "string", "required": True},
                        "administrative_number": {"type": "string", "required": False},
                        "sex": {"type": "integer", "required": False},
                        "height": {"type": "integer", "required": False},
                        "weight": {"type": "integer", "required": False},
                        "eye_colour": {"type": "string", "required": False},
                        "hair_colour": {"type": "string", "required": False},
                        "birth_place": {"type": "string", "required": False},
                        "resident_address": {"type": "string", "required": False},
                        "portrait_capture_date": {"type": "string", "format": "full-date", "required": False},
                        "age_in_years": {"type": "integer", "required": False},
                        "age_birth_year": {"type": "integer", "required": False},
                        "age_over_18": {"type": "boolean", "required": False},
                        "age_over_21": {"type": "boolean", "required": False},
                        "issuing_jurisdiction": {"type": "string", "required": False},
                        "nationality": {"type": "string", "required": False},
                        "resident_city": {"type": "string", "required": False},
                        "resident_state": {"type": "string", "required": False},
                        "resident_postal_code": {"type": "string", "required": False},
                        "resident_country": {"type": "string", "required": False},
                    }
                }
            },
            "claims": [
                {"name": "family_name", "display_name": "Family Name", "required": True},
                {"name": "given_name", "display_name": "Given Name", "required": True},
                {"name": "birth_date", "display_name": "Birth Date", "required": True},
                {"name": "document_number", "display_name": "Document Number", "required": True},
                {"name": "driving_privileges", "display_name": "Driving Privileges", "required": True},
            ],
            "auto_generate_artifacts": True,
        }
        
        # Include compliance profile if not provided via ID
        if not compliance_profile_id:
            data["compliance_profile"] = {
                "name": "AAMVA mDL Compliance",
                "compliance_code": "AAMVA_MDL",
                "credential_format": "mdoc",
                "frameworks": ["aamva", "iso_18013_5"],
            }
        else:
            data["compliance_profile_id"] = compliance_profile_id
        
        if application_template_id:
            data["application_template_id"] = application_template_id
        
        return data
        
    @staticmethod
    def employee_badge_template(
        organization_id: str,
        name: Optional[str] = None,
        application_template_id: Optional[str] = None,
        wallet_configs: Optional[List[Dict]] = None,
    ) -> Dict[str, Any]:
        """Create employee badge credential template (W3C VCDM v2 SD-JWT payload)."""
        data = {
            "organization_id": organization_id,
            "name": name or "Employee Badge",
            "credential_type": "EmployeeBadge",
            "vct": "EmployeeBadge",
            "supported_formats": ["sd_jwt_vc"],
            "credential_payload_format": "w3c_vcdm_v2_sd_jwt",
            "wallet_configs": wallet_configs if wallet_configs is not None else [
                {"wallet_id": "marty", "deep_link_scheme": "openid-credential-offer://", "format_variant": "spruce-vc+sd-jwt"}
            ],
            "compliance_profile": {
                "name": "Enterprise VC Compliance",
                "compliance_code": "ENTERPRISE_VC",
                "credential_format": "sd_jwt_vc",
                "frameworks": ["enterprise"],
            },
            "schema": {
                "type": "object",
                "properties": {
                    "employeeId": {"type": "string"},
                    "givenName": {"type": "string"},
                    "familyName": {"type": "string"},
                    "jobTitle": {"type": "string"},
                    "department": {"type": "string"},
                    "email": {"type": "string", "format": "email"},
                    "photo": {"type": "string", "format": "base64"},
                },
                "required": ["employeeId", "givenName", "familyName", "department"],
            },
            "claims": [
                {"name": "employeeId", "display_name": "Employee ID", "required": True},
                {"name": "givenName", "display_name": "Given Name", "required": True},
                {"name": "familyName", "display_name": "Family Name", "required": True},
                {"name": "department", "display_name": "Department", "required": True},
            ],
            "auto_generate_artifacts": True,
        }
        
        if application_template_id:
            data["application_template_id"] = application_template_id
        
        return data
    
    # =============================================================================
    # Application Template Data
    # =============================================================================
    
    @staticmethod
    def jwt_vc_template(
        organization_id: str,
        name: Optional[str] = None,
        application_template_id: Optional[str] = None,
        wallet_configs: Optional[List[Dict]] = None,
    ) -> Dict[str, Any]:
        """
        Create a W3C JWT Verifiable Credential template (jwt_vc format) using
        the VCDM v1 payload structure (``issuanceDate`` / ``expirationDate``).

        Uses a generic VerifiableId credential type with flat key-value claims
        — the simplest shape that exercises the jwt_vc_json / VCDM v1 signing path.

        See also: ``jwt_vc_v2_template()`` for the VCDM v2 variant
        (``validFrom`` / ``validUntil``).
        """
        data = {
            "organization_id": organization_id,
            "name": name or "Verifiable ID",
            "credential_type": "VerifiableId",
            "vct": "VerifiableId",
            "supported_formats": ["jwt_vc"],
            # Explicit VCDM v1 format so the test is unambiguous even if the
            # server default changes in future.
            "credential_payload_format": "w3c_vcdm_v2_sd_jwt",  # falls into VCDM v1 branch
            "wallet_configs": wallet_configs if wallet_configs is not None else [
                {"wallet_id": "marty", "deep_link_scheme": "openid-credential-offer://", "format_variant": "spruce-vc+sd-jwt"}
            ],
            "compliance_profile": {
                "name": "W3C VC Compliance",
                "compliance_code": "W3C_VC",
                "credential_format": "jwt_vc",
                "frameworks": ["w3c_vc"],
            },
            "schema": {
                "type": "object",
                "properties": {
                    "givenName": {"type": "string"},
                    "familyName": {"type": "string"},
                    "birthDate": {"type": "string", "format": "full-date"},
                    "nationalityCode": {"type": "string"},
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

        if application_template_id:
            data["application_template_id"] = application_template_id

        return data

    @staticmethod
    def jwt_vc_v2_template(
        organization_id: str,
        name: Optional[str] = None,
        application_template_id: Optional[str] = None,
        wallet_configs: Optional[List[Dict]] = None,
    ) -> Dict[str, Any]:
        """
        Create a W3C JWT Verifiable Credential template (jwt_vc format) using
        the VCDM **v2** payload structure (``validFrom`` / ``validUntil``).

        Sets ``credential_payload_format = "w3c_vcdm_v2_jwt_vc"`` so the signing
        layer uses v2 timestamps and the v2 ``@context`` / ``type`` values.

        Use with :func:`jwt_vc_claims` to supply subject claim values.
        """
        data = {
            "organization_id": organization_id,
            "name": name or "Verifiable ID (VCDM v2)",
            "credential_type": "VerifiableId",
            "vct": "VerifiableId",
            "supported_formats": ["jwt_vc"],
            "credential_payload_format": "w3c_vcdm_v2_jwt_vc",
            "wallet_configs": wallet_configs if wallet_configs is not None else [
                {"wallet_id": "marty", "deep_link_scheme": "openid-credential-offer://", "format_variant": "spruce-vc+sd-jwt"}
            ],
            "compliance_profile": {
                "name": "W3C VC Compliance",
                "compliance_code": "W3C_VC",
                "credential_format": "jwt_vc",
                "frameworks": ["w3c_vc"],
            },
            "schema": {
                "type": "object",
                "properties": {
                    "givenName": {"type": "string"},
                    "familyName": {"type": "string"},
                    "birthDate": {"type": "string", "format": "full-date"},
                    "nationalityCode": {"type": "string"},
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

        if application_template_id:
            data["application_template_id"] = application_template_id

        return data

    @staticmethod
    def jwt_vc_claims(
        given_name: str = "Carol",
        family_name: str = "Chen",
        birth_date: str = "1988-03-22",
        document_number: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create claims for a VerifiableId (jwt_vc) credential."""
        return {
            "givenName": given_name,
            "familyName": family_name,
            "birthDate": birth_date,
            "nationalityCode": "US",
            "documentNumber": document_number or f"ID{str(uuid4())[:8].upper()}",
        }

    @staticmethod
    def zk_mdoc_template(
        organization_id: str,
        name: Optional[str] = None,
        zk_predicate_claims: Optional[List[str]] = None,
        application_template_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a ZK-enabled mDoc credential template (`zk_mdoc` format).

        Structurally identical to an mDL template but declares
        ``supported_formats: ["zk_mdoc"]`` and an explicit list of claims
        that support zero-knowledge predicate proofs (Longfellow/Ligero).

        ``zk_predicate_claims`` defaults to age and date fields that are
        typically used for ZK predicates (e.g. ``age_over_18``, ``birth_date``).
        """
        data = {
            "organization_id": organization_id,
            "name": name or "ZK Mobile Driver's License",
            "credential_type": "org.iso.18013.5.1.mDL",
            "vct": "org.iso.18013.5.1.mDL",
            "supported_formats": ["zk_mdoc"],
            "zk_predicate_claims": zk_predicate_claims or [
                "birth_date",
                "age_over_18",
                "age_over_21",
            ],
            "compliance_profile": {
                "name": "AAMVA ZK mDL Compliance",
                "compliance_code": "AAMVA_MDL",
                "credential_format": "zk_mdoc",
                "frameworks": ["aamva", "iso_18013_5"],
            },
            "schema": {
                "namespaces": {
                    "org.iso.18013.5.1": {
                        "family_name": {"type": "string", "required": True},
                        "given_name": {"type": "string", "required": True},
                        "birth_date": {"type": "string", "format": "full-date", "required": True},
                        "issue_date": {"type": "string", "format": "full-date", "required": True},
                        "expiry_date": {"type": "string", "format": "full-date", "required": True},
                        "issuing_country": {"type": "string", "required": True},
                        "issuing_authority": {"type": "string", "required": True},
                        "document_number": {"type": "string", "required": True},
                        "driving_privileges": {"type": "array", "required": True},
                        "un_distinguishing_sign": {"type": "string", "required": True},
                        "age_over_18": {"type": "boolean", "required": False},
                        "age_over_21": {"type": "boolean", "required": False},
                    }
                }
            },
            "claims": [
                {"name": "family_name", "display_name": "Family Name", "required": True},
                {"name": "given_name", "display_name": "Given Name", "required": True},
                {"name": "birth_date", "display_name": "Birth Date", "required": True},
                {"name": "document_number", "display_name": "Document Number", "required": True},
                {"name": "driving_privileges", "display_name": "Driving Privileges", "required": True},
                {"name": "age_over_18", "display_name": "Age Over 18", "required": False},
                {"name": "age_over_21", "display_name": "Age Over 21", "required": False},
            ],
            "auto_generate_artifacts": True,
        }

        if application_template_id:
            data["application_template_id"] = application_template_id

        return data

    @staticmethod
    def zk_mdoc_claims(
        given_name: str = "David",
        family_name: str = "Park",
        birth_date: str = "1991-08-14",
        document_number: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create claims for a ZK-enabled mDL credential (same structure as mdl_claims)."""
        issue_date = datetime.now()
        expiry_date = issue_date + timedelta(days=365 * 5)

        return {
            "family_name": family_name,
            "given_name": given_name,
            "birth_date": birth_date,
            "issue_date": issue_date.strftime("%Y-%m-%d"),
            "expiry_date": expiry_date.strftime("%Y-%m-%d"),
            "issuing_country": "US",
            "issuing_authority": "State DMV",
            "document_number": document_number or f"DL{str(uuid4())[:8].upper()}",
            "driving_privileges": [
                {
                    "vehicle_category_code": "C",
                    "issue_date": issue_date.strftime("%Y-%m-%d"),
                    "expiry_date": expiry_date.strftime("%Y-%m-%d"),
                }
            ],
            "un_distinguishing_sign": "USA",
            "age_over_18": True,
            "age_over_21": True,
        }

    @staticmethod
    def application_template(
        organization_id: str,
        name: Optional[str] = None,
        evidence_requirements: Optional[List[str]] = None,
        credential_template_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create application template data (user-facing workflow)"""
        return {
            "organization_id": organization_id,
            "name": name or f"test-application-template-{str(uuid4())[:8]}",
            "credential_template_id": credential_template_id or "",
            "evidence_requirements": evidence_requirements or ["drivers_license", "selfie"],
            "form_fields": [
                {
                    "name": "given_name",
                    "display_name": "First Name",
                    "field_type": "text",
                    "required": True,
                },
                {
                    "name": "family_name",
                    "display_name": "Last Name",
                    "field_type": "text",
                    "required": True,
                },
                {
                    "name": "birth_date",
                    "display_name": "Date of Birth",
                    "field_type": "date",
                    "required": True,
                },
            ],
            "claim_collection_rules": [
                {
                    "claim_name": "given_name",
                    "source": "form_field",
                    "source_field": "given_name",
                    "verification_required": False,
                },
                {
                    "claim_name": "family_name",
                    "source": "form_field",
                    "source_field": "family_name",
                    "verification_required": False,
                },
                {
                    "claim_name": "birth_date",
                    "source": "form_field",
                    "source_field": "birth_date",
                    "verification_required": True,
                    "verification_method": "document_scan",
                },
            ],
            "approval_strategy": "auto",
            "application_validity_days": 30,
        }
        
    # =============================================================================
    # Application Data
    # =============================================================================
    
    @staticmethod
    def mdl_application_data(
        given_name: str = "Alice",
        family_name: str = "Smith",
        birth_date: str = "1990-05-15",
    ) -> Dict[str, Any]:
        """Create mDL application data"""
        return {
            "given_name": given_name,
            "family_name": family_name,
            "birth_date": birth_date,
            "sex": 2,  # Female
            "height": 165,
            "weight": 60,
            "eye_colour": "brown",
            "hair_colour": "black",
            "resident_address": "123 Main St, Springfield, IL 62701, USA",
            "resident_city": "Springfield",
            "resident_state": "IL",
            "resident_postal_code": "62701",
            "resident_country": "USA",
            "nationality": "USA",
        }
        
    @staticmethod
    def mdl_claims(
        given_name: str = "Alice",
        family_name: str = "Smith",
        birth_date: str = "1990-05-15",
        document_number: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create mDL credential claims"""
        issue_date = datetime.now()
        expiry_date = issue_date + timedelta(days=365 * 5)  # 5 years
        
        return {
            "family_name": family_name,
            "given_name": given_name,
            "birth_date": birth_date,
            "issue_date": issue_date.strftime("%Y-%m-%d"),
            "expiry_date": expiry_date.strftime("%Y-%m-%d"),
            "issuing_country": "US",
            "issuing_authority": "State DMV",
            "document_number": document_number or f"DL{str(uuid4())[:8].upper()}",
            "driving_privileges": [
                {
                    "vehicle_category_code": "C",
                    "issue_date": issue_date.strftime("%Y-%m-%d"),
                    "expiry_date": expiry_date.strftime("%Y-%m-%d"),
                }
            ],
            "un_distinguishing_sign": "USA",
            "sex": 2,
            "height": 165,
            "weight": 60,
            "eye_colour": "brown",
            "age_over_18": True,
            "age_over_21": True,
        }
        
    @staticmethod
    def employee_badge_claims(
        employee_id: Optional[str] = None,
        given_name: str = "Bob",
        family_name: str = "Johnson",
    ) -> Dict[str, Any]:
        """Create employee badge credential claims"""
        return {
            "employeeId": employee_id or f"EMP{str(uuid4())[:6].upper()}",
            "givenName": given_name,
            "familyName": family_name,
            "jobTitle": "Software Engineer",
            "department": "Engineering",
            "email": f"{given_name.lower()}.{family_name.lower()}@example.com",
        }
        
    # =============================================================================
    # Presentation Policy Data
    # =============================================================================
    
    @staticmethod
    def presentation_policy_age_verification(
        organization_id: str,
        credential_template_id: str,
        min_age: int = 21,
        name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create presentation policy for age verification.
        Requests only age_over_21 claim from mDL.
        """
        return {
            "organization_id": organization_id,
            "name": name or f"Age Verification ({min_age}+)",
            "purpose": f"Verify holder is at least {min_age} years old",
            "credential_requirements": [
                {
                    "credential_template_id": credential_template_id,
                    "display_name": "Mobile Driver's License",
                    "requested_claims": [
                        {
                            "claim_name": f"age_over_{min_age}",
                            "display_name": f"Age Over {min_age}",
                            "required": True,
                        }
                    ],
                }
            ],
        }
        
    @staticmethod
    def presentation_policy_identity_verification(
        organization_id: str,
        credential_template_id: str,
        name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create presentation policy for full identity verification.
        Requests name, birth_date, portrait from mDL.
        """
        return {
            "organization_id": organization_id,
            "name": name or "Full Identity Verification",
            "purpose": "Verify holder's full identity",
            "credential_requirements": [
                {
                    "credential_template_id": credential_template_id,
                    "display_name": "Mobile Driver's License",
                    "requested_claims": [
                        {
                            "claim_name": "given_name",
                            "display_name": "Given Name",
                            "required": True,
                        },
                        {
                            "claim_name": "family_name",
                            "display_name": "Family Name",
                            "required": True,
                        },
                        {
                            "claim_name": "birth_date",
                            "display_name": "Birth Date",
                            "required": True,
                        },
                        {
                            "claim_name": "portrait",
                            "display_name": "Portrait",
                            "required": False,
                        },
                    ],
                }
            ],
        }
        
    @staticmethod
    def presentation_policy_employee_access(
        organization_id: str,
        credential_template_id: str,
        required_department: Optional[str] = None,
        name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create presentation policy for employee access verification.
        Requests employee badge with optional department constraint.
        """
        policy = {
            "organization_id": organization_id,
            "name": name or "Employee Access Verification",
            "purpose": "Verify employee credentials for access control",
            "credential_requirements": [
                {
                    "credential_template_id": credential_template_id,
                    "display_name": "Employee Badge",
                    "requested_claims": [
                        {"claim_name": "employeeId", "display_name": "Employee ID", "required": True},
                        {"claim_name": "givenName", "display_name": "Given Name", "required": True},
                        {"claim_name": "familyName", "display_name": "Family Name", "required": True},
                        {"claim_name": "department", "display_name": "Department", "required": True},
                    ],
                }
            ],
        }
        
        if required_department:
            policy["credential_requirements"][0]["claim_constraints"] = {
                "department": {"equals": required_department}
            }
            
        return policy
        
    # =============================================================================
    # Evidence Data
    # =============================================================================
    
    @staticmethod
    def portrait_evidence() -> Dict[str, Any]:
        """Create portrait evidence (base64 placeholder)"""
        # In real tests, this would be actual base64-encoded JPEG
        return {
            "evidence_type": "portrait",
            "evidence_data": {
                "portrait": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
            }
        }
        
    @staticmethod
    def identity_document_evidence() -> Dict[str, Any]:
        """Create identity document evidence"""
        return {
            "evidence_type": "identity_document",
            "evidence_data": {
                "identity_document_front": "base64_encoded_front_image",
                "identity_document_back": "base64_encoded_back_image",
            }
        }
    
    # =============================================================================
    # Deployment Profile Data
    # =============================================================================
    
    @staticmethod
    def deployment_profile(
        organization_id: str,
        name: Optional[str] = None,
        site_id: Optional[str] = None,
        default_presentation_policy_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create deployment profile data for runtime configuration."""
        return {
            "organization_id": organization_id,
            "name": name or f"test-deployment-profile-{str(uuid4())[:8]}",
            "site_id": site_id or f"site-{str(uuid4())[:6]}",
            "network_mode": "online",
            "key_access_mode": "key_vault",
            "ux_config": {
                "language": "en",
                "signage_text": "Please scan your credential",
                "operator_mode": False,
                "accessibility": True,
            },
            "update_policy": {
                "auto_update": True,
                "rollout_percentage": 100,
            },
            "offline_cache_ttl_hours": 24,
            "biometric_required": False,
            "audit_all_events": True,
            "default_presentation_policy_id": default_presentation_policy_id,
        }
    
    @staticmethod
    def lane(
        deployment_profile_id: str,
        name: Optional[str] = None,
        location: Optional[str] = None,
        device_type: str = "kiosk",
        organization_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create lane data (logical device grouping)."""
        return {
            "deployment_profile_id": deployment_profile_id,
            "name": name or f"Lane {str(uuid4())[:8]}",
            "description": "Test lane for verification",
            "location": location or "Terminal A, Gate 12",
            "device_type": device_type,
            "metadata": {
                "zone": "public",
                "operator_info": "Security Staff",
            },
        }
    
    # =============================================================================
    # ZK Predicate Presentation Policy Data
    # =============================================================================
    
    @staticmethod
    def presentation_policy_zk_age_verification(
        organization_id: str,
        credential_template_id: str,
        min_age: int = 21,
        name: Optional[str] = None,
        fallback_policy: str = "accept_raw",
    ) -> Dict[str, Any]:
        """Create presentation policy with ZK predicate for age verification.
        
        Requests a zero-knowledge range proof for age instead of raw birth_date.
        Follows the predicate_spec configuration from Digital_Identity_model.md.
        """
        return {
            "organization_id": organization_id,
            "name": name or f"ZK Age Verification ({min_age}+)",
            "purpose": f"Verify holder is at least {min_age} years old using ZK proof",
            "prefer_predicates": True,
            "fallback_policy": fallback_policy,
            "supported_circuits": [f"ligero_age_over_{min_age}", "bbs_range"],
            "credential_requirements": [
                {
                    "credential_template_id": credential_template_id,
                    "display_name": "Driver's License",
                    "requested_claims": [
                        {
                            "claim_name": "birth_date",
                            "display_name": "Birth Date",
                            "required": True,
                            "predicate_spec": {
                                "predicate_type": "range_proof",
                                "params": {
                                    "threshold": min_age,
                                    "comparison": "gte",
                                },
                                "supported_circuits": [f"ligero_age_over_{min_age}"],
                                "fallback_policy": fallback_policy,
                            },
                        }
                    ],
                }
            ],
        }
