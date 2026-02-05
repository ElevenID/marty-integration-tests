"""Walt.id Wallet API client for integration tests.

This client wraps the Walt.id Community Stack Wallet API to enable automated testing
of credential issuance and verification flows with a real wallet implementation.

Walt.id Wallet API (Community Stack) provides:
- OpenID4VCI (Draft 11, 13) credential issuance support
- OpenID4VP (Draft 14, 20) credential presentation support
- W3C VC (v1.1, v2.0), SD-JWT VC, ISO 18013-5 mDL support
- DID management (did:key, did:web, did:jwk)
- Key management with multiple algorithms
- REST API for headless operation

References:
- https://docs.walt.id/community-stack/wallet/getting-started
- https://github.com/walt-id/waltid-identity
- API Docs: http://localhost:7001/swagger
"""

from typing import Any, Dict, List, Optional
import httpx
import logging
import uuid

logger = logging.getLogger(__name__)


class WaltIdWalletClient:
    """Client for interacting with Walt.id Wallet API (Community Stack)."""

    def __init__(self, base_url: str = "http://localhost:7001"):
        """Initialize the Walt.id wallet client.

        Args:
            base_url: Base URL of the Walt.id Wallet API
        """
        self.base_url = base_url.rstrip("/")
        self.client = httpx.AsyncClient(base_url=self.base_url, timeout=30.0, follow_redirects=True)
        self.wallet_id: Optional[str] = None
        self.auth_token: Optional[str] = None
        self.account_id: Optional[str] = None

    async def __aenter__(self):
        """Async context manager entry."""
        await self.client.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.client.__aexit__(exc_type, exc_val, exc_tb)

    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()

    async def health(self) -> Dict[str, Any]:
        """Check wallet service health.

        Returns:
            Health status information

        Raises:
            httpx.HTTPError: If health check fails
        """
        # Walt.id wallet API health endpoint
        response = await self.client.get("/health")
        response.raise_for_status()
        # Health endpoint may return plain text or JSON
        try:
            return response.json()
        except:
            return {"status": response.text}

    async def create_wallet(self, name: str, email: Optional[str] = None, password: Optional[str] = None) -> Dict[str, Any]:
        """Create a new wallet account.

        Walt.id uses email/password authentication by default.
        This creates both an account and a wallet.

        Args:
            name: Wallet/account name
            email: Email for authentication (auto-generated if not provided)
            password: Password for authentication (auto-generated if not provided)

        Returns:
            Account and wallet creation response

        Raises:
            httpx.HTTPError: If wallet creation fails
        """
        # Generate credentials if not provided
        if not email:
            unique_id = uuid.uuid4().hex[:8]
            email = f"test-{unique_id}@example.com"
        if not password:
            password = f"TestPass{uuid.uuid4().hex[:12]}!"
        
        # Create account with email/password auth
        # Walt.id uses sealed class serialization - type discriminator required
        response = await self.client.post(
            "/wallet-api/auth/register",
            json={
                "type": "email",
                "name": name,
                "email": email,
                "password": password
            }
        )
        response.raise_for_status()
        # Registration returns simple success message
        
        logger.info(f"Registered account: {email}")
        
        # Login to get auth token
        login_response = await self.client.post(
            "/wallet-api/auth/login",
            json={
                "type": "email",
                "email": email,
                "password": password
            }
        )
        login_response.raise_for_status()
        login_data = login_response.json()
        
        # Store authentication token
        self.auth_token = login_data.get("token")
        self.account_id = login_data.get("id")
        
        # Set authorization header for future requests
        self.client.headers["Authorization"] = f"Bearer {self.auth_token}"
        
        # Get the wallet ID
        wallets_response = await self.client.get("/wallet-api/wallet/accounts/wallets")
        wallets_response.raise_for_status()
        wallets_data = wallets_response.json()
        
        if wallets_data.get("wallets"):
            self.wallet_id = wallets_data["wallets"][0]["id"]
            logger.info(f"Using wallet: {self.wallet_id}")
        
        return {
            "account_id": self.account_id,
            "wallet_id": self.wallet_id,
            "token": self.auth_token,
            "email": email,
        }

    async def create_did(
        self,
        method: str = "key",
        wallet_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create a new DID in the wallet.

        Args:
            method: DID method (e.g., "key", "web", "jwk")
            wallet_id: Wallet ID (uses stored wallet_id if not provided)

        Returns:
            DID creation response including the DID string

        Raises:
            httpx.HTTPError: If DID creation fails
        """
        wallet_id = wallet_id or self.wallet_id
        if not wallet_id:
            raise ValueError("No wallet_id provided or stored")

        # First generate a key
        key_response = await self.client.post(
            f"/wallet-api/wallet/{wallet_id}/keys/generate",
            json={"backend": "jwk", "keyType": "Ed25519"}
        )
        key_response.raise_for_status()
        # Key generation returns plaintext key ID, not JSON
        key_id = key_response.text
        
        # Create DID from the key
        response = await self.client.post(
            f"/wallet-api/wallet/{wallet_id}/dids/create/{method}",
            json={"keyId": key_id}
        )
        response.raise_for_status()
        # DID creation returns plaintext DID string, not JSON
        did = response.text
        logger.info(f"Created DID: {did}")
        return {"did": did, "keyId": key_id}

    async def list_dids(self, wallet_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all DIDs in the wallet.

        Args:
            wallet_id: Wallet ID (uses stored wallet_id if not provided)

        Returns:
            List of DID objects with did, alias, default, createdOn fields

        Raises:
            httpx.HTTPError: If listing fails
        """
        wallet_id = wallet_id or self.wallet_id
        if not wallet_id:
            raise ValueError("No wallet_id provided or stored")

        response = await self.client.get(f"/wallet-api/wallet/{wallet_id}/dids")
        response.raise_for_status()
        return response.json()

    async def accept_credential_offer(
        self,
        offer_url: str,
        wallet_id: Optional[str] = None,
        did: Optional[str] = None
    ) -> Dict[str, Any]:
        """Accept a credential offer via OpenID4VCI.

        Args:
            offer_url: The credential offer URL (openid-credential-offer://)
            wallet_id: Wallet ID (uses stored wallet_id if not provided)
            did: DID to use for credential (uses first DID if not provided)

        Returns:
            Credential acceptance response

        Raises:
            httpx.HTTPError: If credential acceptance fails
        """
        wallet_id = wallet_id or self.wallet_id
        if not wallet_id:
            raise ValueError("No wallet_id provided or stored")

        # Get a DID if not provided
        if not did:
            dids = await self.list_dids(wallet_id)
            if not dids:
                # Create a new DID if none exist
                did_result = await self.create_did(wallet_id=wallet_id)
                did = did_result.get("did")
            else:
                did = dids[0]

        logger.info(f"Accepting credential offer with DID: {did}")
        logger.info(f"Offer URL: {offer_url}")

        # Walt.id API endpoint for accepting credential offers
        response = await self.client.post(
            f"/wallet-api/wallet/{wallet_id}/exchange/useOfferRequest",
            params={"did": did},
            headers={"Content-Type": "text/plain"},
            content=offer_url
        )
        response.raise_for_status()
        
        # Response may be empty or contain accepted credentials
        try:
            result = response.json()
        except:
            result = {"status": "accepted", "content": response.text}
            
        logger.info(f"Credential offer accepted")
        return result

    async def list_credentials(
        self,
        wallet_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List all credentials in the wallet.

        Args:
            wallet_id: Wallet ID (uses stored wallet_id if not provided)

        Returns:
            List of credential objects

        Raises:
            httpx.HTTPError: If listing fails
        """
        wallet_id = wallet_id or self.wallet_id
        if not wallet_id:
            raise ValueError("No wallet_id provided or stored")

        response = await self.client.get(
            f"/wallet-api/wallet/{wallet_id}/credentials"
        )
        response.raise_for_status()
        return response.json()

    async def get_credential(
        self,
        credential_id: str,
        wallet_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get a specific credential by ID.

        Args:
            credential_id: Credential identifier
            wallet_id: Wallet ID (uses stored wallet_id if not provided)

        Returns:
            Credential object

        Raises:
            httpx.HTTPError: If credential not found
        """
        wallet_id = wallet_id or self.wallet_id
        if not wallet_id:
            raise ValueError("No wallet_id provided or stored")

        response = await self.client.get(
            f"/wallet-api/wallet/{wallet_id}/credentials/{credential_id}"
        )
        response.raise_for_status()
        return response.json()

    async def present_credential(
        self,
        presentation_request_url: str,
        credential_ids: List[str],
        wallet_id: Optional[str] = None,
        did: Optional[str] = None
    ) -> Dict[str, Any]:
        """Present credentials in response to a verification request (OpenID4VP).

        Args:
            presentation_request_url: The presentation request URL
            credential_ids: List of credential IDs to present
            wallet_id: Wallet ID (uses stored wallet_id if not provided)
            did: DID to use for presentation (uses first DID if not provided)

        Returns:
            Presentation response

        Raises:
            httpx.HTTPError: If presentation fails
        """
        wallet_id = wallet_id or self.wallet_id
        if not wallet_id:
            raise ValueError("No wallet_id provided or stored")

        # Get a DID if not provided
        if not did:
            dids = await self.list_dids(wallet_id)
            if dids:
                did = dids[0]

        logger.info(f"Presenting credentials: {credential_ids}")

        # Walt.ID's usePresentationRequest API requires:
        # - presentationRequest: the full presentation request URL
        # - selectedCredentials: list of credential IDs to present
        # - did: (optional) DID to use for signing the presentation
        response = await self.client.post(
            f"/wallet-api/wallet/{wallet_id}/exchange/usePresentationRequest",
            json={
                "presentationRequest": presentation_request_url,
                "selectedCredentials": credential_ids,  # Walt.ID expects this
                "did": did
            }
        )
        response.raise_for_status()
        result = response.json()
        logger.info(f"Credentials presented: {result}")
        return result

    async def resolve_credential_offer(
        self,
        offer_url: str,
        wallet_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Resolve a credential offer to see what's being offered.

        Args:
            offer_url: The credential offer URL
            wallet_id: Wallet ID (uses stored wallet_id if not provided)

        Returns:
            Credential offer details

        Raises:
            httpx.HTTPError: If resolution fails
        """
        wallet_id = wallet_id or self.wallet_id
        if not wallet_id:
            raise ValueError("No wallet_id provided or stored")

        # Walt.ID's resolveCredentialOffer expects offer URL in request body (not query param)
        # Per OID4VCI spec, offer can be:
        # 1. openid-credential-offer://?credential_offer=<json>
        # 2. openid-credential-offer://?credential_offer_uri=<url>
        # 3. Direct HTTP URL to offer endpoint
        logger.info(f"Resolving credential offer: {offer_url[:100]}...")
        
        response = await self.client.post(
            f"/wallet-api/wallet/{wallet_id}/exchange/resolveCredentialOffer",
            content=offer_url,  # Send as plain text body
            headers={"Content-Type": "text/plain"}
        )
        response.raise_for_status()
        return response.json()

    async def resolve_presentation_request(
        self,
        request_url: str,
        wallet_id: Optional[str] = None
    ) -> str:
        """Resolve a presentation request to see what's being requested.

        Walt.ID fetches the request from request_uri (if present), parses it,
        and returns a URL string with all parameters inline (including 
        presentation_definition as a query parameter).

        Args:
            request_url: The presentation request URL (e.g., openid4vp://authorize?request_uri=...)
            wallet_id: Wallet ID (uses stored wallet_id if not provided)

        Returns:
            A URL string with inline query parameters (e.g., openid4vp://...?presentation_definition={...}&client_id=...&response_uri=...)
            The presentation_definition parameter contains the full PresentationDefinition as a JSON string

        Raises:
            httpx.HTTPError: If resolution fails
        """
        wallet_id = wallet_id or self.wallet_id
        if not wallet_id:
            raise ValueError("No wallet_id provided or stored")

        response = await self.client.post(
            f"/wallet-api/wallet/{wallet_id}/exchange/resolvePresentationRequest",
            content=request_url,  # Send as plain text body
            headers={"Content-Type": "text/plain"}
        )
        response.raise_for_status()
        return response.text

    async def delete_credential(
        self,
        credential_id: str,
        wallet_id: Optional[str] = None
    ) -> None:
        """Delete a credential from the wallet.

        Args:
            credential_id: Credential identifier
            wallet_id: Wallet ID (uses stored wallet_id if not provided)

        Raises:
            httpx.HTTPError: If deletion fails
        """
        wallet_id = wallet_id or self.wallet_id
        if not wallet_id:
            raise ValueError("No wallet_id provided or stored")

        response = await self.client.delete(
            f"/wallet-api/wallet/{wallet_id}/credentials/{credential_id}"
        )
        response.raise_for_status()
        logger.info(f"Deleted credential: {credential_id}")

    async def delete_wallet(self, wallet_id: Optional[str] = None) -> None:
        """Delete a wallet.

        Args:
            wallet_id: Wallet ID (uses stored wallet_id if not provided)

        Raises:
            httpx.HTTPError: If deletion fails
        """
        wallet_id = wallet_id or self.wallet_id
        if not wallet_id:
            raise ValueError("No wallet_id provided or stored")

        try:
            response = await self.client.delete(f"/wallet-api/wallet/{wallet_id}")
            response.raise_for_status()
            logger.info(f"Deleted wallet: {wallet_id}")
        finally:
            # Always clear wallet_id if it matches the deleted one
            if wallet_id == self.wallet_id:
                self.wallet_id = None
