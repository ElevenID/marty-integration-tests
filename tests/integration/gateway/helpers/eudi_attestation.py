"""Current EUDI wallet key-attestation policy for production-path fixtures."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from cryptography import x509


def required_eudi_key_attestation_policy() -> dict[str, Any]:
    """Load the disposable external-wallet root supplied by the lane."""
    configured = os.environ.get("EUDI_KEY_ATTESTATION_TRUST_ANCHOR_FILE", "").strip()
    if not configured:
        raise RuntimeError("EUDI key-attestation trust-anchor file is required")
    pem = Path(configured).resolve().read_text(encoding="ascii")
    certificate = x509.load_pem_x509_certificate(pem.encode("ascii"))
    try:
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound as exc:
        raise RuntimeError("EUDI key-attestation trust anchor has no CA constraint") from exc
    if not constraints.ca:
        raise RuntimeError("EUDI key-attestation trust anchor is not a CA certificate")
    return {
        "mode": "required",
        "trusted_root_certificates_pem": [pem],
        "allowed_algorithms": ["ES256"],
        "required_key_storage": [],
        "required_user_authentication": [],
        "max_age_seconds": 300,
        "require_nonce": True,
        "status_validation": "disabled",
    }
