"""EUDI Reference Implementation clients for interoperability testing.

Provides clients for two official EU Digital Identity Wallet reference services:

1. EUDI Wallet Tester (eudi-app-web-wallet-tester-py)
   - Flask-based OID4VCI wallet client
   - Tests issuer compliance with OID4VCI draft-13
   - Image: ghcr.io/eu-digital-identity-wallet/eudi-app-web-wallet-tester-py

2. EUDI Verifier Endpoint (eudi-srv-verifier-endpoint)
   - Kotlin/Spring OID4VP v1 verifier
   - Validates credential presentations against the EU reference stack
   - Image: ghcr.io/eu-digital-identity-wallet/eudi-srv-verifier-endpoint

References:
  - https://github.com/eu-digital-identity-wallet/eudi-app-web-wallet-tester-py
  - https://github.com/eu-digital-identity-wallet/eudi-srv-verifier-endpoint
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes
import httpx

logger = logging.getLogger(__name__)


# ── Helper functions ──

def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _decode_jwt_payload(token: str) -> dict:
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        return json.loads(_b64url_decode(parts[1]))
    except Exception:
        return {}


def _int_to_b64url(n: int, length: int) -> str:
    return _b64url_encode(n.to_bytes(length, "big"))


def build_kb_jwt(
    private_key: ec.EllipticCurvePrivateKey,
    sd_jwt_without_kb: str,
    audience: str,
    nonce: str,
) -> str:
    """Build a Key Binding JWT (KB-JWT) for an SD-JWT presentation.

    Per SD-JWT-VC §5.2 the KB-JWT proves holder possession of the key
    that was bound to the credential at issuance time.

    Header: {"typ": "kb+jwt", "alg": "ES256"}
    Payload: {"aud": <verifier>, "nonce": <nonce>, "iat": <now>, "sd_hash": <hash>}
    """
    sd_hash = _b64url_encode(
        hashlib.sha256(sd_jwt_without_kb.encode("ascii")).digest()
    )
    header = {"typ": "kb+jwt", "alg": "ES256"}
    payload = {
        "aud": audience,
        "nonce": nonce,
        "iat": int(time.time()),
        "sd_hash": sd_hash,
    }
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()

    sig_der = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(sig_der)
    sig_bytes = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    sig_b64 = _b64url_encode(sig_bytes)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


class EUDIVerifierClient:
    """Client for the EUDI Reference Verifier Endpoint (OID4VP v1).

    Wraps the Verifier API to create presentation requests and retrieve
    wallet responses.  Used to cross-validate that Marty-issued credentials
    are accepted by the official EU reference verifier.

    API docs: http://<host>:8080/swagger-ui
    """

    def __init__(self, base_url: Optional[str] = None):
        self.base_url = (
            base_url
            or os.getenv("EUDI_VERIFIER_URL", "http://localhost:8090")
        ).rstrip("/")
        self.client = httpx.AsyncClient(
            base_url=self.base_url, timeout=60.0, follow_redirects=True,
        )

    async def close(self):
        await self.client.aclose()

    async def health(self) -> bool:
        """Check if the EUDI verifier is reachable."""
        try:
            resp = await self.client.get("/swagger-ui")
            return resp.status_code == 200
        except Exception:
            return False

    async def initialize_transaction(
        self,
        dcql_query: Dict[str, Any],
        *,
        response_mode: str = "direct_post",
        jar_mode: str = "by_reference",
        nonce: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Initialize a presentation transaction (OID4VP).

        Calls POST /ui/presentations to create a new verification session.

        Args:
            dcql_query: DCQL query describing the requested credentials.
            response_mode: "direct_post" or "direct_post.jwt".
            jar_mode: "by_value" or "by_reference".
            nonce: Optional nonce for the request.

        Returns:
            Dict with transaction_id, client_id, request_uri, etc.
        """
        payload: Dict[str, Any] = {
            "dcql_query": dcql_query,
            "response_mode": response_mode,
            "jar_mode": jar_mode,
        }
        if nonce:
            payload["nonce"] = nonce

        resp = await self.client.post(
            "/ui/presentations",
            json=payload,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json()
        logger.info(
            "[EUDI Verifier] Transaction created: id=%s",
            data.get("transaction_id", "?"),
        )
        return data

    async def get_wallet_response(
        self,
        transaction_id: str,
        response_code: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Retrieve the wallet's response for a transaction.

        Calls GET /ui/presentations/{transactionId}

        Args:
            transaction_id: The transaction identifier.
            response_code: Optional response code (same-device flow).

        Returns:
            The wallet-submitted VP token as JSON.
        """
        url = f"/ui/presentations/{transaction_id}"
        if response_code:
            url += f"?response_code={response_code}"

        resp = await self.client.get(url)
        resp.raise_for_status()
        return resp.json()

    async def get_presentation_events(
        self, transaction_id: str,
    ) -> List[Dict[str, Any]]:
        """Retrieve the event log for a presentation transaction."""
        resp = await self.client.get(
            f"/ui/presentations/{transaction_id}/events",
        )
        resp.raise_for_status()
        return resp.json()

    async def get_request_object(self, request_uri: str) -> Dict[str, Any]:
        """Fetch the authorization request JWT from the verifier.

        The request_uri returned by initialize_transaction points to
        /wallet/request.jwt/{requestId}.  This endpoint returns a signed
        JWT containing the state, nonce, and DCQL query.

        Returns the decoded JWT payload (not verified — we only need
        the state and nonce for building a wallet response).
        """
        # The request_uri may be an absolute URL with internal hostname;
        # rewrite it to use our base_url so we can reach it from the host.
        if request_uri.startswith("http"):
            from urllib.parse import urlparse
            parsed = urlparse(request_uri)
            # Keep the path, replace the scheme+host with our base_url
            url = f"{self.base_url}{parsed.path}"
        else:
            url = request_uri

        resp = await self.client.get(url)
        resp.raise_for_status()

        raw_jwt = resp.text
        # Decode the payload (signature verification is the verifier's job)
        payload = _decode_jwt_payload(raw_jwt)
        payload["_raw_jwt"] = raw_jwt
        logger.info(
            "[EUDI Verifier] Got request object: state=%s, nonce=%s",
            payload.get("state", "?")[:16],
            payload.get("nonce", "?")[:16],
        )
        return payload

    async def submit_wallet_response(
        self,
        state: str,
        vp_token: Any,
        response_uri: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Submit a wallet response to the verifier's direct_post endpoint.

        This is the OID4VP wallet→verifier response.  The verifier uses
        per-transaction URLs: ``/wallet/direct_post/{requestId}``.  The
        correct URL is found in the ``response_uri`` field of the
        authorization request JWT returned by ``get_request_object()``.

        Args:
            state: The state from the authorization request JWT.
            vp_token: The VP token — either a JSON-serializable object
                (DCQL map) or a string (single credential).
            response_uri: The ``response_uri`` from the auth request JWT.
                If provided, the host is rewritten to match ``self.base_url``
                and the path is used as-is.  Falls back to
                ``/wallet/direct_post`` (unlikely to work without requestId).
        """
        if isinstance(vp_token, dict):
            vp_token_str = json.dumps(vp_token)
        else:
            vp_token_str = str(vp_token)

        # Determine the URL to POST to
        post_url = "/wallet/direct_post"
        if response_uri:
            from urllib.parse import urlparse
            parsed = urlparse(response_uri)
            post_url = f"{self.base_url}{parsed.path}"

        resp = await self.client.post(
            post_url,
            data={"state": state, "vp_token": vp_token_str},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        logger.info(
            "[EUDI Verifier] direct_post response: status=%d",
            resp.status_code,
        )
        result: Dict[str, Any] = {"status_code": resp.status_code}
        try:
            result["body"] = resp.json()
        except Exception:
            result["body"] = resp.text[:500]
        return result

    async def run_presentation_flow(
        self,
        dcql_query: Dict[str, Any],
        vp_token: Any,
        nonce: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run the full presentation flow: init → get request → submit.

        Returns a dict with transaction_id, request_state, and submission result.
        """
        import uuid
        nonce = nonce or uuid.uuid4().hex

        # 1. Initialize transaction
        txn = await self.initialize_transaction(
            dcql_query=dcql_query,
            nonce=nonce,
        )
        transaction_id = txn["transaction_id"]
        request_uri = txn.get("request_uri")
        if not request_uri:
            return {"error": "No request_uri in transaction", "transaction": txn}

        # 2. Fetch authorization request to get state
        auth_request = await self.get_request_object(request_uri)
        state = auth_request.get("state")
        if not state:
            return {
                "error": "No state in auth request",
                "transaction": txn,
                "auth_request_keys": list(auth_request.keys()),
            }

        # 3. Submit wallet response (use response_uri which contains the requestId)
        submission = await self.submit_wallet_response(
            state=state,
            vp_token=vp_token,
            response_uri=auth_request.get("response_uri"),
        )

        # 4. Collect events
        events = await self.get_presentation_events(transaction_id)

        return {
            "transaction_id": transaction_id,
            "state": state,
            "submission": submission,
            "events": events,
        }

    async def validate_mdoc_device_response(
        self, device_response_b64url: str,
    ) -> Any:
        """Validate an MSO MDoc DeviceResponse using the EUDI utility endpoint.

        Calls POST /utilities/validations/msoMdoc/deviceResponse

        Args:
            device_response_b64url: Base64url-encoded MSO MDoc DeviceResponse.

        Returns:
            Validation result (list of document summaries, or error object).
        """
        resp = await self.client.post(
            "/utilities/validations/msoMdoc/deviceResponse",
            data={"device_response": device_response_b64url},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        return resp.json()


# ── Standard DCQL queries for common credential types ──

PID_DCQL_QUERY = {
    "credentials": [
        {
            "id": "pid-query",
            "format": "mso_mdoc",
            "meta": {"doctype_value": "eu.europa.ec.eudi.pid.1"},
            "claims": [
                {"path": ["eu.europa.ec.eudi.pid.1", "family_name"]},
                {"path": ["eu.europa.ec.eudi.pid.1", "given_name"]},
            ],
        }
    ],
}

MDL_DCQL_QUERY = {
    "credentials": [
        {
            "id": "mdl-query",
            "format": "mso_mdoc",
            "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
            "claims": [
                {"path": ["org.iso.18013.5.1", "family_name"]},
                {"path": ["org.iso.18013.5.1", "given_name"]},
                {"path": ["org.iso.18013.5.1", "birth_date"]},
            ],
        }
    ],
}

SD_JWT_DCQL_QUERY = {
    "credentials": [
        {
            "id": "sd-jwt-query",
            "format": "dc+sd-jwt",
            "meta": {"vct_values": [
                "https://marty.example/credentials/open_badge",
                "https://beta.elevenidllc.com/credentials/open_badge",
                "urn:credential:open_badge",
            ]},
            "claims": [
                {"path": ["given_name"]},
                {"path": ["family_name"]},
            ],
        }
    ],
}

AGE_VERIFICATION_DCQL_QUERY = {
    "credentials": [
        {
            "id": "age-query",
            "format": "mso_mdoc",
            "meta": {"doctype_value": "eu.europa.ec.eudi.pid.1"},
            "claims": [
                {"path": ["eu.europa.ec.eudi.pid.1", "age_over_18"]},
            ],
        }
    ],
    "credential_sets": [
        {
            "options": [["age-query"]],
            "purpose": "We need to verify you are over 18",
        }
    ],
}


class EUDIWalletTesterClient:
    """Client for the EUDI Wallet Tester (Flask/Python).

    The wallet tester is a GUI-driven Flask app that exercises OID4VCI
    draft-13.  This client drives it programmatically by following its
    session-based routes with persistent cookies.

    Its value in integration testing is to prove that:
      1. The wallet tester container can reach Marty's metadata endpoints
         via Docker networking.
      2. Marty's .well-known metadata is parseable by a real EUDI client.
    """

    def __init__(self, base_url: Optional[str] = None):
        self.base_url = (
            base_url
            or os.getenv("EUDI_WALLET_TESTER_URL", "http://localhost:5050")
        ).rstrip("/")
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=30.0,
            follow_redirects=False,  # We track redirects manually
        )

    async def close(self):
        await self.client.aclose()

    async def health(self) -> bool:
        """Check if the wallet tester is reachable."""
        try:
            resp = await self.client.get("/")
            return resp.status_code == 200
        except Exception:
            return False

    async def get_home_page(self) -> Dict[str, Any]:
        """Fetch the home page and verify it renders."""
        resp = await self.client.get("/")
        return {
            "status_code": resp.status_code,
            "contains_wallet_test": "WALLET Test" in resp.text,
            "contains_credential_offer": "credOffer" in resp.text,
            "contains_preauth": "preauth" in resp.text,
        }

    async def trigger_preauth(self) -> Dict[str, Any]:
        """Hit the /preauth endpoint and check the redirect target.

        The wallet tester redirects to {serv_url}/dynamic/preauth which
        should be the Marty gateway.  We don't follow the redirect —
        we just verify it points to the right place.
        """
        resp = await self.client.get("/preauth")
        return {
            "status_code": resp.status_code,
            "redirect_location": resp.headers.get("location", ""),
            "redirects_to_gateway": "gateway" in resp.headers.get("location", "")
                                    or "8000" in resp.headers.get("location", ""),
        }

    async def fetch_metadata_via_tester(self) -> Dict[str, Any]:
        """Drive the wallet tester through Marty's metadata endpoints.

        Calls the tester's ``/metadata1_na`` and ``/metadata_na`` routes
        which internally fetch:
          1. ``{serv_url}/.well-known/openid-configuration`` (OIDC discovery)
          2. ``{issuer}/.well-known/openid-credential-issuer``

        The tester parses them with its own code — so a successful
        pass proves Marty's metadata is parseable by a real EUDI client,
        not just our own code.

        Returns a dict with step results and any errors.
        """
        # Use a session-aware client to match the Flask session flow
        async with httpx.AsyncClient(
            base_url=self.base_url, timeout=30.0,
            follow_redirects=False, cookies=httpx.Cookies(),
        ) as session_client:
            steps: Dict[str, Any] = {}

            # Step 0: Hit home to init Flask session
            r0 = await session_client.get("/")
            steps["home"] = {"status": r0.status_code}

            # Step 0b: Hit /auth to set session['authmode'] = 'auth'
            # (the wallet tester requires this before metadata_na)
            r0b = await session_client.get("/auth", follow_redirects=False)
            steps["auth"] = {"status": r0b.status_code}

            # Step 1: /metadata1_na — the tester GETs openid-configuration
            # from Marty, parses issuer/par/token/credential endpoints
            r1 = await session_client.get("/metadata1_na")
            steps["metadata1_na"] = {
                "status": r1.status_code,
                "ok": r1.status_code == 200,
                "error": None,
            }
            if r1.status_code != 200:
                steps["metadata1_na"]["error"] = r1.text[:500]
                return {"success": False, "steps": steps, "error": "metadata1_na failed"}

            # Step 2: /metadata_na — the tester GETs openid-credential-issuer
            # and extracts credential_configurations_supported, formats, vcts, etc.
            r2 = await session_client.get("/metadata_na")
            steps["metadata_na"] = {
                "status": r2.status_code,
                "ok": r2.status_code in (200, 302),
                "is_redirect": r2.status_code in (301, 302, 303, 307, 308),
                "error": None,
            }
            if r2.status_code >= 400:
                steps["metadata_na"]["error"] = r2.text[:500]
                return {"success": False, "steps": steps, "error": "metadata_na failed"}

            return {"success": True, "steps": steps}

    async def run_preauth_metadata_flow(
        self,
        credential_offer_uri: str,
    ) -> Dict[str, Any]:
        """Drive the wallet tester through the pre-auth flow using a
        credential offer URI from Marty.

        This exercises the tester's ``/redirect_preauth`` route which:
          1. Parses the credential offer JSON
          2. Extracts credential_configuration_ids
          3. Fetches OpenID metadata via ``/metadata1_na`` and ``/metadata_na``

        This proves an independent EUDI client can consume Marty's
        credential offer and metadata without errors.

        Args:
            credential_offer_uri: Full ``openid-credential-offer://`` URI
                from Marty's issuance flow.

        Returns:
            Dict with step results, parsed offer data, and metadata status.
        """
        from urllib.parse import urlparse, parse_qs

        parsed = urlparse(credential_offer_uri)
        qs = parse_qs(parsed.query)
        credential_offer_param = qs.get("credential_offer", [None])[0]
        if not credential_offer_param:
            return {"success": False, "error": "No credential_offer param in URI"}

        async with httpx.AsyncClient(
            base_url=self.base_url, timeout=30.0,
            follow_redirects=False, cookies=httpx.Cookies(),
        ) as session_client:
            steps: Dict[str, Any] = {}

            # Step 0: Init session
            r0 = await session_client.get("/")
            steps["home"] = {"status": r0.status_code}

            # Step 1: /redirect_preauth — parses the credential offer,
            # sets session state, redirects to /getmeta1_na
            r1 = await session_client.get(
                "/redirect_preauth",
                params={
                    "credential_offer": f"credential_offer={credential_offer_param}",
                    "code": "",
                    "tx_code": "",
                },
            )
            steps["redirect_preauth"] = {
                "status": r1.status_code,
                "ok": r1.status_code in (200, 302),
                "location": r1.headers.get("location", ""),
            }
            if r1.status_code >= 400:
                steps["redirect_preauth"]["error"] = r1.text[:500]
                return {"success": False, "steps": steps, "error": "redirect_preauth failed"}

            # Step 2: /metadata1_na — fetch openid-configuration from Marty
            r2 = await session_client.get("/metadata1_na")
            steps["metadata1_na"] = {
                "status": r2.status_code,
                "ok": r2.status_code == 200,
            }
            if r2.status_code != 200:
                steps["metadata1_na"]["error"] = r2.text[:500]
                return {"success": False, "steps": steps, "error": "metadata1_na failed"}

            # Step 3: /metadata_na — fetch openid-credential-issuer
            # For preauth mode, this redirects to /token_preAuth_payload
            r3 = await session_client.get("/metadata_na")
            steps["metadata_na"] = {
                "status": r3.status_code,
                "ok": r3.status_code in (200, 302),
                "redirects_to_token": "token" in r3.headers.get("location", "").lower(),
            }
            if r3.status_code >= 400:
                steps["metadata_na"]["error"] = r3.text[:500]
                return {"success": False, "steps": steps, "error": "metadata_na failed"}

            return {"success": True, "steps": steps}


def select_disclosures(
    sd_jwt: str,
    requested_claims: List[str],
) -> str:
    """Build an SD-JWT with only the requested disclosures included.

    An SD-JWT has the form: ``header.payload.sig~disc1~disc2~...~``
    Each disclosure is a base64url-encoded JSON array ``[salt, name, value]``.
    This function decodes each, keeps only those whose ``name`` is in
    ``requested_claims``, and reassembles.

    Args:
        sd_jwt: The full SD-JWT with all disclosures.
        requested_claims: Claim names to include (e.g. ["given_name"]).

    Returns:
        SD-JWT with only the selected disclosures, trailing ``~``.
    """
    parts = sd_jwt.split("~")
    # First part is always header.payload.sig
    issuer_jwt = parts[0]
    disclosures = [p for p in parts[1:] if p]  # strip empty trailing

    selected = []
    for disc in disclosures:
        try:
            decoded = json.loads(_b64url_decode(disc))
            # SD-JWT disclosure: [salt, claim_name, value]
            if isinstance(decoded, list) and len(decoded) >= 2:
                claim_name = decoded[1]
                if claim_name in requested_claims:
                    selected.append(disc)
        except Exception:
            # Not a valid disclosure (could be KB-JWT) — skip
            continue

    return issuer_jwt + "~" + "~".join(selected) + "~"
