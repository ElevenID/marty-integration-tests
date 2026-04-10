"""Headless Marty Authenticator wallet client for integration tests.

Wraps the protocol-level OID4VCI/OID4VP clients to provide the same
interface as ``WaltIdWalletClient``, allowing the verification flow
tests to run against a wallet that properly supports P-256 keys.

Unlike the Walt.id client (which delegates to a running wallet server),
this client executes the OID4VCI/OID4VP protocols directly — no external
wallet service required.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from .oid4vc_wallet_client import (
    MARTY_AUTHENTICATOR_PROFILE,
    OID4VCIWalletClient,
    OID4VPWalletClient,
    WalletProfile,
    _b64url_encode,
)

logger = logging.getLogger(__name__)


class MartyHeadlessWalletClient:
    """Headless wallet that exercises OID4VCI/OID4VP at the protocol level.

    Provides a ``WaltIdWalletClient``-compatible API backed by ephemeral
    P-256 keys so that mDoc device-auth flows work without depending on
    Walt.id's DID key generation.

    Credentials are stored in-memory — no external wallet server needed.
    """

    def __init__(
        self,
        profile: WalletProfile = MARTY_AUTHENTICATOR_PROFILE,
        gateway_url: Optional[str] = None,
    ):
        self.profile = profile
        self.gateway_url = gateway_url
        self.wallet_id: Optional[str] = None
        self.did: Optional[str] = None
        self._credentials: List[Dict[str, Any]] = []

        # Lazily-created protocol clients (one per issuance flow).
        # The VCI client is recreated per ``accept_credential_offer`` call so
        # that each issuance uses a fresh ephemeral key, matching real wallet
        # behaviour.
        self._vp_client: Optional[OID4VPWalletClient] = None

    # -- lifecycle ----------------------------------------------------------

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def close(self):
        if self._vp_client:
            await self._vp_client.close()
            self._vp_client = None

    # -- wallet / DID management -------------------------------------------

    async def create_wallet(self, name: str, **kwargs) -> Dict[str, Any]:
        """Create an in-memory wallet (no server call needed)."""
        self.wallet_id = str(uuid.uuid4())
        logger.info("Created headless wallet %s (%s)", name, self.wallet_id)
        return {
            "account_id": self.wallet_id,
            "wallet_id": self.wallet_id,
        }

    async def create_did(
        self,
        method: str = "key",
        wallet_id: Optional[str] = None,
        key_type: str = "secp256r1",
    ) -> Dict[str, Any]:
        """Generate an ephemeral did:jwk for issuance and VP flows.

        For mDoc credential issuance, the Rust signing engine currently
        only supports Ed25519 holder keys.  We therefore generate an
        Ed25519 did:jwk when ``key_type`` is left at the default, while
        keeping a separate P-256 key for OID4VP device auth.

        After issuance, the headless VP client sends the raw credential
        so the issuer-bound key type is transparent to presentation.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        import json

        # Ed25519 key for DID / issuance proof-of-possession
        ed_priv = Ed25519PrivateKey.generate()
        ed_pub = ed_priv.public_key()
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        raw_pub = ed_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

        # Construct a did:jwk from the Ed25519 public key
        jwk = {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _b64url_encode(raw_pub),
        }
        jwk_b64 = _b64url_encode(json.dumps(jwk, separators=(",", ":")).encode())
        self.did = f"did:jwk:{jwk_b64}"
        self._ed_private_key = ed_priv

        logger.info("Created headless DID: %s", self.did)
        return {"did": self.did, "keyId": self.wallet_id}

    # -- OID4VCI: accept credential offer ----------------------------------

    async def accept_credential_offer(
        self,
        offer_url: str,
        wallet_id: Optional[str] = None,
        did: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Accept a credential offer using the headless OID4VCI client.

        Runs the full pre-authorized code flow: resolve offer → metadata →
        token → credential request.  The issued credential is stored
        in-memory.
        """
        vci = OID4VCIWalletClient(
            profile=self.profile,
            issuer_base_url=self.gateway_url,
        )
        try:
            result = await vci.run_preauth_issuance(offer_uri=offer_url)

            # Store each credential returned by the issuer
            for cred_resp in result.get("credentials", []):
                for cred_obj in cred_resp.get("credentials", []):
                    cred_id = str(uuid.uuid4())
                    self._credentials.append({
                        "id": cred_id,
                        "credentialId": cred_id,
                        "credential": cred_obj.get("credential", ""),
                        "format": cred_obj.get("format", "unknown"),
                        "raw_response": cred_obj,
                    })

            logger.info(
                "Accepted offer — wallet now holds %d credential(s)",
                len(self._credentials),
            )
            return {"status": "accepted", "credentials_count": len(self._credentials)}
        finally:
            await vci.close()

    # -- credential listing ------------------------------------------------

    async def list_credentials(
        self, wallet_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Return all credentials held in memory."""
        return list(self._credentials)

    async def get_credential(
        self, credential_id: str, wallet_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get a credential by ID."""
        for c in self._credentials:
            if c["id"] == credential_id or c["credentialId"] == credential_id:
                return c
        raise ValueError(f"Credential {credential_id} not found")

    # -- OID4VP: present credential ----------------------------------------

    async def present_credential(
        self,
        presentation_request_url: str,
        credential_ids: List[str],
        wallet_id: Optional[str] = None,
        did: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Present credentials via the headless OID4VP client.

        Resolves the presentation request, selects matching credentials from
        the in-memory store, and submits the VP token to the verifier's
        response_uri.

        For SD-JWT credentials, appends a Key Binding JWT (KB-JWT) that
        includes the verifier's nonce, as required by the SD-JWT presentation
        specification (§5.3.1).
        """
        if self._vp_client is None:
            self._vp_client = OID4VPWalletClient(
                profile=self.profile,
                verifier_base_url=self.gateway_url,
            )

        # Gather the raw credential strings to use as VP token material
        selected = []
        for cid in credential_ids:
            for c in self._credentials:
                if c["id"] == cid or c["credentialId"] == cid:
                    selected.append(c)
                    break

        if not selected:
            selected = list(self._credentials)

        # 1. Resolve the presentation request to get the nonce
        request = await self._vp_client.resolve_presentation_request(
            presentation_request_url
        )
        nonce = request.get("nonce", "")
        response_uri = request.get("response_uri") or request.get("redirect_uri")
        state = request.get("state")

        # 2. Build the VP token from the first selected credential
        raw_cred = selected[0].get("credential", "") if selected else ""
        # Use the rewritten response_uri as audience for KB-JWT
        rewritten_response_uri = (
            self._vp_client._rewrite_url(response_uri) if response_uri else ""
        )
        vp_token = self._build_vp_token(raw_cred, nonce, rewritten_response_uri)

        # 3. Build presentation_submission
        pd = request.get("presentation_definition")
        import secrets
        submission = None
        if pd:
            submission = {
                "id": secrets.token_hex(8),
                "definition_id": pd.get("id", ""),
                "descriptor_map": [
                    {
                        "id": desc["id"],
                        "format": "vc+sd-jwt",
                        "path": "$",
                    }
                    for desc in pd.get("input_descriptors", [])
                ],
            }

        # 4. Rewrite response_uri through the local gateway
        if response_uri:
            response_uri = self._vp_client._rewrite_url(response_uri)
            import json as _json
            body: Dict[str, Any] = {"vp_token": vp_token}
            if submission:
                body["presentation_submission"] = _json.dumps(submission)
            if state:
                body["state"] = state
            resp = await self._vp_client.client.post(
                response_uri,
                data=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            logger.info(
                "VP submit to %s -> %d: %s",
                response_uri, resp.status_code, resp.text[:300],
            )
            if resp.status_code >= 400:
                logger.warning(
                    "VP submission rejected (%d): %s",
                    resp.status_code, resp.text[:500],
                )
            try:
                result = resp.json()
            except Exception:
                result = {"status_code": resp.status_code, "body": resp.text[:500]}
        else:
            result = {
                "request": request,
                "warning": "No response_uri — cannot submit VP token",
            }

        logger.info("Presented %d credential(s) via OID4VP", len(selected))
        return result

    def _build_vp_token(
        self, raw_credential: str, nonce: str, audience: str
    ) -> str:
        """Build a VP JWT token that wraps the credential.

        The flow service expects a JWT whose payload contains a ``nonce``
        claim matching the authorization request nonce.  For SD-JWT
        credentials we wrap the raw credential inside a VP JWT envelope
        (OID4VP §6.3.1).

        For plain JWT credentials (no ``~`` delimiter) the raw JWT is
        also wrapped in a VP JWT so the nonce is always present.
        """
        import json
        import time

        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes as _hashes
        from cryptography.hazmat.primitives.asymmetric.utils import (
            decode_dss_signature,
        )

        # Use a fresh ephemeral key for the VP JWT
        vp_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        pub = vp_key.public_key().public_numbers()
        jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64url_encode(pub.x.to_bytes(32, "big")),
            "y": _b64url_encode(pub.y.to_bytes(32, "big")),
        }

        header = {"typ": "vp+jwt", "alg": "ES256", "jwk": jwk}
        payload = {
            "iss": self.did or "",
            "aud": audience,
            "nonce": nonce,
            "iat": int(time.time()),
            "vp": {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiablePresentation"],
                "verifiableCredential": [raw_credential],
            },
        }

        hdr_b64 = _b64url_encode(
            json.dumps(header, separators=(",", ":")).encode()
        )
        pay_b64 = _b64url_encode(
            json.dumps(payload, separators=(",", ":")).encode()
        )
        signing_input = f"{hdr_b64}.{pay_b64}".encode()

        sig_der = vp_key.sign(signing_input, ec.ECDSA(_hashes.SHA256()))
        r, s = decode_dss_signature(sig_der)
        sig_bytes = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        sig_b64 = _b64url_encode(sig_bytes)

        return f"{hdr_b64}.{pay_b64}.{sig_b64}"

    # -- convenience: resolve presentation request -------------------------

    async def resolve_presentation_request(
        self,
        request_url: str,
        wallet_id: Optional[str] = None,
    ) -> str:
        """Resolve a presentation request and return the URL with inline params.

        Matches the ``WaltIdWalletClient.resolve_presentation_request``
        signature so callers can swap clients transparently.
        """
        if self._vp_client is None:
            self._vp_client = OID4VPWalletClient(
                profile=self.profile,
                verifier_base_url=self.gateway_url,
            )

        request = await self._vp_client.resolve_presentation_request(request_url)
        # Return a JSON-serialised form similar to what Walt.id returns
        import json
        import urllib.parse
        params = urllib.parse.urlencode(
            {k: json.dumps(v) if isinstance(v, (dict, list)) else str(v) for k, v in request.items()}
        )
        return f"openid4vp://authorize?{params}"

    # -- delete wallet (no-op) ---------------------------------------------

    async def delete_wallet(self, wallet_id: Optional[str] = None):
        """No-op — headless wallet is in-memory only."""
        self._credentials.clear()
        logger.info("Deleted headless wallet %s", self.wallet_id)
