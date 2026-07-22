"""Client for the EUDI Wallet Kit Test Harness.

Wraps HTTP calls to the Kotlin/JVM wallet harness service, which uses
the official EUDI Wallet Kit libraries (eudi-lib-jvm-openid4vci-kt,
eudi-lib-jvm-openid4vp-kt) internally.

When a test passes through this client, it proves that Marty's endpoints
are compatible with the same OID4VCI/OID4VP libraries used in the EUDI
Reference Wallet mobile application.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_SAFE_HARNESS_ERROR_CLASSES = {
    "CredentialOfferRequestException",
    "IllegalArgumentException",
    "JsonDecodingException",
    "SerializationException",
}
_SAFE_METADATA_FIELDS = {
    "credential_configurations_supported": "credential-configurations-supported",
    "credential_signing_alg_values_supported": "credential-signing-algorithms",
    "cryptographic_binding_methods_supported": "binding-methods",
    "proof_types_supported": "proof-types",
    "credential_definition": "credential-definition",
    "credential_metadata": "credential-metadata",
    "authorization_servers": "authorization-servers",
    "display": "display",
    "claims": "claims",
    "doctype": "doctype",
    "vct": "vct",
}


class EUDIWalletHarnessError(RuntimeError):
    """Public-safe failure from the local official-library facade."""


def _raise_for_status_safely(response: httpx.Response) -> None:
    """Raise without copying a response body, URL, or stack trace into JUnit."""
    if response.is_success:
        return

    error_class = "unclassified"
    diagnostic_text = ""
    try:
        body = response.json()
    except (ValueError, TypeError):
        body = None
    if isinstance(body, dict):
        candidate = str(body.get("error") or "")
        if candidate in _SAFE_HARNESS_ERROR_CLASSES:
            error_class = candidate
        diagnostic_text = "\n".join(
            str(body.get(key) or "") for key in ("message", "stackTrace")
        )

    field = next(
        (
            safe_name
            for wire_name, safe_name in _SAFE_METADATA_FIELDS.items()
            if wire_name.casefold() in diagnostic_text.casefold()
        ),
        None,
    )
    if error_class in {"JsonDecodingException", "SerializationException"}:
        code = "issuer-metadata-json-invalid"
        if field:
            code = f"{code}-{field}"
    else:
        code = f"wallet-harness-{error_class.casefold()}"
    raise EUDIWalletHarnessError(
        f"EUDI wallet harness HTTP {response.status_code}: {code}"
    )


class EUDIWalletKitClient:
    """HTTP client for the EUDI Wallet Kit test harness."""

    def __init__(self, base_url: str = "http://localhost:9090") -> None:
        self.base_url = base_url.rstrip("/")
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=60.0,
            follow_redirects=True,
        )

    async def close(self) -> None:
        await self.client.aclose()

    async def health(self) -> dict[str, Any]:
        """Check wallet harness health and library versions."""
        resp = await self.client.get("/health")
        _raise_for_status_safely(resp)
        return resp.json()

    async def resolve_offer(self, credential_offer_uri: str) -> dict[str, Any]:
        """Resolve a credential offer URI using the EUDI OID4VCI library.

        This validates that Marty's issuer metadata and credential offer
        structure are compatible with the EUDI Wallet Kit's strict parser.
        """
        resp = await self.client.post(
            "/issuance/resolve-offer",
            json={"credentialOfferUri": credential_offer_uri},
        )
        _raise_for_status_safely(resp)
        return resp.json()

    async def run_preauth_issuance(
        self,
        credential_offer_uri: str,
        tx_code: str | None = None,
    ) -> dict[str, Any]:
        """Run the full pre-authorized code issuance flow.

        The EUDI Wallet Kit library will:
        1. Fetch and validate Credential Issuer Metadata
        2. Fetch and validate OAuth2 Authorization Server metadata
        3. Exchange pre-authorized code for access token
        4. Generate P-256 proof-of-possession JWT
        5. Request credential from credential endpoint
        6. Return issued credential

        This exercises the complete OID4VCI spec surface that a real
        EUDI wallet would use.
        """
        body: dict[str, Any] = {"credentialOfferUri": credential_offer_uri}
        if tx_code is not None:
            body["txCode"] = tx_code

        resp = await self.client.post("/issuance/pre-auth", json=body)
        _raise_for_status_safely(resp)
        return resp.json()

    async def submit_presentation(
        self,
        authorization_request_uri: str,
        credential: str,
    ) -> dict[str, Any]:
        """Submit a credential presentation using the EUDI OID4VP library.

        The harness resolves the authorization request, builds a VP token
        with Key Binding JWT, and dispatches it to the verifier using the
        same EUDI library used in the Reference Wallet.
        """
        resp = await self.client.post(
            "/presentation/submit",
            json={
                "authorizationRequestUri": authorization_request_uri,
                "credential": credential,
            },
        )
        _raise_for_status_safely(resp)
        return resp.json()

    async def direct_post_presentation(
        self,
        response_uri: str,
        vp_token: str,
        presentation_submission: str | None = None,
        state: str | None = None,
    ) -> dict[str, Any]:
        """Direct-post a VP token to a verifier's response_uri.

        Bypasses the EUDI library's auth request resolution for compatibility
        tests that intentionally operate on an already-resolved request. This
        path is not counted as official-library OID4VP evidence. The harness
        sends an application/x-www-form-urlencoded POST per OID4VP.
        """
        body: dict[str, Any] = {
            "responseUri": response_uri,
            "vpToken": vp_token,
        }
        if presentation_submission is not None:
            body["presentationSubmission"] = presentation_submission
        if state is not None:
            body["state"] = state

        resp = await self.client.post("/presentation/direct-post", json=body)
        _raise_for_status_safely(resp)
        return resp.json()

    async def build_vp_token(
        self,
        credential: str,
        audience: str,
        nonce: str,
        credential_format: str = "dc+sd-jwt",
    ) -> str:
        """Build a VP token (SD-JWT with KB-JWT) without submitting it.

        Returns the compact VP token string.
        """
        resp = await self.client.post(
            "/presentation/build-vp-token",
            json={
                "credential": credential,
                "audience": audience,
                "nonce": nonce,
                "format": credential_format,
            },
        )
        _raise_for_status_safely(resp)
        return resp.json()["vpToken"]
