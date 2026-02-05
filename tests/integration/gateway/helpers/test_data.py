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
    ) -> Dict[str, Any]:
        """Create employee badge credential template"""
        data = {
            "organization_id": organization_id,
            "name": name or "Employee Badge",
            "credential_type": "EmployeeBadge",
            "vct": "EmployeeBadge",
            "supported_formats": ["sd_jwt_vc"],
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
