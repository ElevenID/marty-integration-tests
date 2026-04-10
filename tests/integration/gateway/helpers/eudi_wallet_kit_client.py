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
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger(__name__)


class EUDIWalletKitClient:
    """HTTP client for the EUDI Wallet Kit test harness."""

    def __init__(self, base_url: str = "http://localhost:9090"):
        self.base_url = base_url.rstrip("/")
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=60.0,
            follow_redirects=True,
        )

    async def close(self) -> None:
        await self.client.aclose()

    async def health(self) -> Dict[str, Any]:
        """Check wallet harness health and library versions."""
        resp = await self.client.get("/health")
        resp.raise_for_status()
        return resp.json()

    async def resolve_offer(self, credential_offer_uri: str) -> Dict[str, Any]:
        """Resolve a credential offer URI using the EUDI OID4VCI library.

        This validates that Marty's issuer metadata and credential offer
        structure are compatible with the EUDI Wallet Kit's strict parser.
        """
        resp = await self.client.post(
            "/issuance/resolve-offer",
            json={"credentialOfferUri": credential_offer_uri},
        )
        resp.raise_for_status()
        return resp.json()

    async def run_preauth_issuance(
        self,
        credential_offer_uri: str,
        tx_code: Optional[str] = None,
    ) -> Dict[str, Any]:
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
        body: Dict[str, Any] = {"credentialOfferUri": credential_offer_uri}
        if tx_code is not None:
            body["txCode"] = tx_code

        resp = await self.client.post("/issuance/pre-auth", json=body)
        resp.raise_for_status()
        return resp.json()

    async def submit_presentation(
        self,
        authorization_request_uri: str,
        credential: str,
    ) -> Dict[str, Any]:
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
        resp.raise_for_status()
        return resp.json()

    async def direct_post_presentation(
        self,
        response_uri: str,
        vp_token: str,
        presentation_submission: Optional[str] = None,
        state: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Direct-post a VP token to a verifier's response_uri.

        Bypasses the EUDI library's auth request resolution, useful when
        the verifier uses a client_id_scheme (e.g. DID) not natively
        supported by the EUDI library.  The harness sends an
        application/x-www-form-urlencoded POST per OID4VP spec.
        """
        body: Dict[str, Any] = {
            "responseUri": response_uri,
            "vpToken": vp_token,
        }
        if presentation_submission is not None:
            body["presentationSubmission"] = presentation_submission
        if state is not None:
            body["state"] = state

        resp = await self.client.post("/presentation/direct-post", json=body)
        resp.raise_for_status()
        return resp.json()

    async def build_vp_token(
        self,
        credential: str,
        audience: str,
        nonce: str,
        format: str = "dc+sd-jwt",
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
                "format": format,
            },
        )
        resp.raise_for_status()
        return resp.json()["vpToken"]
