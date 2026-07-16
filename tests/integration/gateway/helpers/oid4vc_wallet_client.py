"""Headless OID4VCI/OID4VP wallet client for interoperability testing.

A protocol-level wallet simulator that exercises the OID4VCI v1 and OID4VP v1
specs directly, without depending on a third-party wallet implementation.
Used for interoperability testing against the behaviour expected from
Google Wallet (Android CredentialManager / OID4VP + mdoc/sd-jwt) and
Apple Wallet (ISO 18013-5 mdoc + Verify with Wallet API).

This client implements the OID4VC "happy path" at the HTTP level:
  1. Resolve credential_offer → fetch issuer metadata → token → credential
  2. Resolve presentation request → build VP token → submit

It intentionally does NOT verify cryptographic signatures — that is the
issuer/verifier's job.  The client only checks structural conformance so
that we can test Marty's OID4VCI/OID4VP endpoints against the v1 spec.

References:
  - OID4VCI v1: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
  - OID4VP v1:  https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
  - ISO 18013-5 (mso_mdoc credential format)
  - SD-JWT VC:  draft-ietf-oauth-sd-jwt-vc-11
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import httpx

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class WalletProfile:
    """Describes the capabilities of the wallet being simulated."""

    name: str
    credential_formats: List[str]  # e.g. ["dc+sd-jwt", "mso_mdoc"]
    issuance_protocol: str = "OID4VCI_PRE_AUTH"
    did_methods: List[str] = field(default_factory=lambda: ["did:key"])
    proof_types: List[str] = field(default_factory=lambda: ["jwt"])
    supported_platforms: List[str] = field(default_factory=lambda: ["android", "ios"])


# Pre-built profiles matching real-world wallet capabilities
GOOGLE_WALLET_PROFILE = WalletProfile(
    name="Google Wallet (Android CredentialManager)",
    credential_formats=["dc+sd-jwt", "mso_mdoc"],
    issuance_protocol="OID4VCI_PRE_AUTH",
    did_methods=["did:key", "did:jwk"],
    proof_types=["jwt"],
    supported_platforms=["android"],
)

APPLE_WALLET_PROFILE = WalletProfile(
    name="Apple Wallet (Verify with Wallet / ISO 18013-5)",
    credential_formats=["mso_mdoc"],
    issuance_protocol="OID4VCI_PRE_AUTH",
    did_methods=["cose_key"],
    proof_types=["jwt"],
    supported_platforms=["ios"],
)

EUDI_WALLET_PROFILE = WalletProfile(
    name="EUDI Reference Wallet",
    credential_formats=["dc+sd-jwt", "mso_mdoc", "jwt_vc_json"],
    issuance_protocol="OID4VCI_PRE_AUTH",
    did_methods=["did:key", "did:jwk"],
    proof_types=["jwt"],
    supported_platforms=["android", "ios"],
)

MARTY_AUTHENTICATOR_PROFILE = WalletProfile(
    name="Marty Authenticator",
    credential_formats=["dc+sd-jwt", "mso_mdoc", "jwt_vc_json"],
    issuance_protocol="OID4VCI_PRE_AUTH",
    did_methods=["did:key", "did:jwk"],
    proof_types=["jwt"],
    supported_platforms=["android", "ios", "web"],
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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


def _decode_jwt_header(token: str) -> dict:
    try:
        return json.loads(_b64url_decode(token.split(".")[0]))
    except Exception:
        return {}


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _int_to_b64url(n: int, length: int) -> str:
    """Encode an integer as base64url."""
    return _b64url_encode(n.to_bytes(length, "big"))


def _build_proof_jwt(
    private_key: ec.EllipticCurvePrivateKey,
    audience: str,
    nonce: str,
) -> str:
    """Build an OID4VCI proof JWT (§7.2.1) signed with an ephemeral ES256 key.

    Returns a compact-serialized JWT with:
      Header: {"typ": "openid4vci-proof+jwt", "alg": "ES256", "jwk": {...}}
      Payload: {"aud": <issuer>, "iat": <now>, "nonce": <c_nonce>}
    """
    pub = private_key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _int_to_b64url(pub.x, 32),
        "y": _int_to_b64url(pub.y, 32),
    }
    header = {
        "typ": "openid4vci-proof+jwt",
        "alg": "ES256",
        "jwk": jwk,
    }
    payload = {
        "aud": audience,
        "iat": int(time.time()),
        "nonce": nonce,
    }

    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()

    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    sig_der = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(sig_der)
    sig_bytes = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    sig_b64 = _b64url_encode(sig_bytes)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


# ---------------------------------------------------------------------------
# OID4VCI v1 Headless Wallet Client
# ---------------------------------------------------------------------------

class OID4VCIWalletClient:
    """Headless wallet that exercises OID4VCI v1 endpoints.

    Simulates the wallet side of credential issuance:
      offer → metadata discovery → token request → credential request

    Validates that the issuer's responses conform to the OID4VCI v1 spec
    and that the credential format matches the requested profile.

    All HTTP requests are routed through the ``issuer_base_url`` (the gateway).
    If the server's metadata or offer contains external endpoint URLs,
    they are rewritten to use the gateway so that tests never bypass
    the gateway API.
    """

    def __init__(
        self,
        profile: WalletProfile = GOOGLE_WALLET_PROFILE,
        issuer_base_url: Optional[str] = None,
    ):
        self.profile = profile
        self.issuer_base_url = issuer_base_url or os.getenv(
            "GATEWAY_URL", "http://localhost:8000"
        )
        self.client = httpx.AsyncClient(timeout=30.0, follow_redirects=True)

        # Ephemeral key pair for proof-of-possession (OID4VCI §7.2)
        self._private_key = ec.generate_private_key(
            ec.SECP256R1(), default_backend()
        )

        # State accumulated during flow
        self.issuer_metadata: Optional[Dict[str, Any]] = None
        self.credential_offer: Optional[Dict[str, Any]] = None
        self.access_token: Optional[str] = None
        self.c_nonce: Optional[str] = None
        self.credentials: List[Dict[str, Any]] = []

    async def close(self):
        await self.client.aclose()

    def _rewrite_url(self, url: str) -> str:
        """Rewrite an external endpoint URL to go through the local gateway.

        The server's issuer metadata often advertises public URLs
        (e.g. https://beta.example.com/v1/issuance/token) that are
        unreachable from the test environment.  We replace the scheme+host
        with ``self.issuer_base_url`` so all traffic goes through the gateway.
        """
        if not url:
            return url
        parsed = urllib.parse.urlparse(url)
        gateway_parsed = urllib.parse.urlparse(self.issuer_base_url)
        # Only rewrite if the host differs from the gateway
        if parsed.netloc != gateway_parsed.netloc:
            rewritten = urllib.parse.urlunparse((
                gateway_parsed.scheme,
                gateway_parsed.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            ))
            logger.debug(
                "[%s] Rewrote URL %s -> %s",
                self.profile.name, url, rewritten,
            )
            return rewritten
        return url

    # -- Step 1: Parse credential offer -----------------------------------

    async def resolve_offer(self, offer_uri: str) -> Dict[str, Any]:
        """Parse a credential offer URI (OID4VCI §4.1).

        Handles:
          - openid-credential-offer://?credential_offer=<json>
          - openid-credential-offer://?credential_offer_uri=<url>
        """
        parsed = urllib.parse.urlparse(offer_uri)
        qs = urllib.parse.parse_qs(parsed.query)

        if "credential_offer" in qs:
            self.credential_offer = json.loads(qs["credential_offer"][0])
        elif "credential_offer_uri" in qs:
            uri = self._rewrite_url(qs["credential_offer_uri"][0])
            resp = await self.client.get(uri)
            resp.raise_for_status()
            self.credential_offer = resp.json()
        else:
            raise ValueError(f"Cannot parse credential offer from: {offer_uri[:200]}")

        logger.info(
            "[%s] Resolved offer: issuer=%s  configs=%s",
            self.profile.name,
            self.credential_offer.get("credential_issuer"),
            self.credential_offer.get("credential_configuration_ids"),
        )
        return self.credential_offer

    # -- Step 2: Fetch issuer metadata ------------------------------------

    async def fetch_issuer_metadata(
        self, org_id: Optional[str] = None, path_suffix: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Fetch /.well-known/openid-credential-issuer (OID4VCI §12.2).

        Always uses ``self.issuer_base_url`` (the gateway) for the actual
        HTTP request, even if the credential offer advertises an external
        ``credential_issuer`` URL.  This ensures all test traffic goes
        through the gateway API.

        ``path_suffix`` appends an additional path segment after the org id,
        e.g. ``/credential-manager`` or ``/spruce``.
        """
        # Always use the gateway for the well-known request
        base = self.issuer_base_url

        wellknown_url = f"{base}/.well-known/openid-credential-issuer"
        if org_id:
            wellknown_url = (
                f"{base}/.well-known/openid-credential-issuer/org/{org_id}"
            )
        if path_suffix:
            wellknown_url = f"{wellknown_url}{path_suffix}"

        resp = await self.client.get(wellknown_url)
        if resp.status_code == 404 and org_id:
            # Fall back to standard path
            wellknown_url = f"{base}/.well-known/openid-credential-issuer"
            resp = await self.client.get(wellknown_url)
        resp.raise_for_status()
        self.issuer_metadata = resp.json()

        # Validate required fields (OID4VCI v1 §12.2.4)
        required_fields = ["credential_issuer", "credential_endpoint"]
        for f in required_fields:
            assert f in self.issuer_metadata, (
                f"Issuer metadata missing required field '{f}'. "
                f"Keys: {list(self.issuer_metadata.keys())}"
            )

        assert "credential_configurations_supported" in self.issuer_metadata, (
            "Issuer metadata missing 'credential_configurations_supported'"
        )

        logger.info(
            "[%s] Fetched issuer metadata: %d credential configurations",
            self.profile.name,
            len(self.issuer_metadata["credential_configurations_supported"]),
        )
        return self.issuer_metadata

    # -- Step 3: Token request (pre-authorized code) ----------------------

    async def request_token(self) -> Dict[str, Any]:
        """Exchange pre-authorized code for access token (OID4VCI §6).

        Uses the pre-authorized_code grant type.
        """
        if not self.credential_offer:
            raise RuntimeError("No credential offer resolved yet")

        grants = self.credential_offer.get("grants", {})
        pre_auth = grants.get("urn:ietf:params:oauth:grant-type:pre-authorized_code", {})
        pre_auth_code = pre_auth.get("pre-authorized_code")

        if not pre_auth_code:
            raise ValueError(
                "Credential offer does not contain a pre-authorized_code grant. "
                f"Available grants: {list(grants.keys())}"
            )

        # Determine token endpoint from metadata or gateway base URL
        token_endpoint = None
        if self.issuer_metadata:
            token_endpoint = self._rewrite_url(
                self.issuer_metadata.get("token_endpoint", "")
            )
        if not token_endpoint:
            token_endpoint = f"{self.issuer_base_url}/v1/issuance/token"

        resp = await self.client.post(
            token_endpoint,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "pre-authorized_code": pre_auth_code,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        token_data = resp.json()

        self.access_token = token_data.get("access_token")
        self.c_nonce = None

        assert self.access_token, (
            f"Token response missing 'access_token'. Keys: {list(token_data.keys())}"
        )

        logger.info(
            "[%s] Got access token; proof nonce must be fetched separately",
            self.profile.name,
        )
        return token_data

    # -- Step 3b: Nonce endpoint (OID4VCI §7) -----------------------------

    async def request_nonce(self) -> str:
        """Fetch a fresh c_nonce from the nonce endpoint (OID4VCI §7)."""
        nonce_endpoint = None
        if self.issuer_metadata:
            nonce_endpoint = self._rewrite_url(
                self.issuer_metadata.get("nonce_endpoint", "")
            )
        if not nonce_endpoint:
            nonce_endpoint = f"{self.issuer_base_url}/v1/issuance/nonce"

        resp = await self.client.post(nonce_endpoint, json={})
        resp.raise_for_status()
        data = resp.json()

        self.c_nonce = data.get("c_nonce")
        assert self.c_nonce, (
            f"Nonce response missing 'c_nonce'. Keys: {list(data.keys())}"
        )

        logger.info("[%s] Got fresh c_nonce", self.profile.name)
        return self.c_nonce

    # -- Step 4: Credential request ---------------------------------------

    async def request_credential(
        self,
        credential_config_id: str,
        credential_identifier: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Request credential from the credential endpoint (OID4VCI §8).

        Validates the response structure per the v1 spec.
        """
        if not self.access_token:
            raise RuntimeError("No access token — call request_token() first")

        credential_endpoint = None
        if self.issuer_metadata:
            credential_endpoint = self._rewrite_url(
                self.issuer_metadata.get("credential_endpoint", "")
            )
        if not credential_endpoint:
            credential_endpoint = f"{self.issuer_base_url}/v1/issuance/credential"

        body: Dict[str, Any] = {}
        if credential_identifier:
            body["credential_identifier"] = credential_identifier
        else:
            body["credential_configuration_id"] = credential_config_id

        # Build proof-of-possession JWT (OID4VCI §7.2)
        if self.c_nonce:
            # Determine the audience (credential_issuer from offer or metadata).
            # Prefer the offer's credential_issuer because it includes the
            # full org-specific path (e.g. .../org/{id}), whereas the
            # issuer metadata may advertise a shorter base URL.
            audience = self.issuer_base_url
            if self.credential_offer:
                audience = self.credential_offer.get(
                    "credential_issuer", audience
                )
            elif self.issuer_metadata:
                audience = self.issuer_metadata.get(
                    "credential_issuer", audience
                )

            proof_jwt = _build_proof_jwt(
                private_key=self._private_key,
                audience=audience,
                nonce=self.c_nonce,
            )
            body["proofs"] = {"jwt": [proof_jwt]}
            logger.debug(
                "[%s] Attached proof JWT (nonce=%s...)",
                self.profile.name,
                self.c_nonce[:8] if self.c_nonce else "N/A",
            )

        resp = await self.client.post(
            credential_endpoint,
            json=body,
            headers={
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json",
            },
        )
        resp.raise_for_status()
        cred_data = resp.json()

        # Validate response structure (OID4VCI §8.3)
        if "credentials" in cred_data:
            for c in cred_data["credentials"]:
                assert "credential" in c, (
                    f"Credential object missing 'credential' field. Keys: {list(c.keys())}"
                )
            self.credentials.extend(cred_data["credentials"])
        elif "transaction_id" in cred_data:
            # Deferred issuance (§9) — credential not ready yet
            logger.info(
                "[%s] Deferred issuance: transaction_id=%s",
                self.profile.name,
                cred_data["transaction_id"],
            )
        else:
            raise AssertionError(
                f"Credential response missing both 'credentials' and 'transaction_id'. "
                f"Keys: {list(cred_data.keys())}"
            )

        logger.info(
            "[%s] Received %d credential(s)",
            self.profile.name,
            len(cred_data.get("credentials", [])),
        )
        return cred_data

    # -- Full pre-auth flow -----------------------------------------------

    async def run_preauth_issuance(
        self,
        offer_uri: str,
        org_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run the complete pre-authorized code issuance flow.

        Returns the credential response.
        """
        # 1. Resolve offer
        offer = await self.resolve_offer(offer_uri)

        issuer_path_suffix = None
        credential_issuer = offer.get("credential_issuer") if isinstance(offer, dict) else None
        if isinstance(credential_issuer, str) and credential_issuer.strip():
            issuer_path = urllib.parse.urlparse(credential_issuer).path.rstrip("/")
            if issuer_path.endswith("/spruce"):
                issuer_path_suffix = "/spruce"
            elif issuer_path.endswith("/credential-manager"):
                issuer_path_suffix = "/credential-manager"
            elif issuer_path.endswith("/apple-wallet"):
                issuer_path_suffix = "/apple-wallet"

        # 2. Fetch metadata
        await self.fetch_issuer_metadata(org_id=org_id, path_suffix=issuer_path_suffix)

        # 3. Get token
        token_data = await self.request_token()

        # 4. Request credential for each configuration
        config_ids = offer.get("credential_configuration_ids", [])
        if not config_ids and self.issuer_metadata:
            config_ids = list(
                self.issuer_metadata.get(
                    "credential_configurations_supported", {}
                ).keys()
            )[:1]

        results = []
        for config_id in config_ids:
            cred_resp = await self.request_credential(config_id)
            results.append(cred_resp)

        return {
            "offer": offer,
            "token": token_data,
            "credentials": results,
        }

    # -- Credential format validation -------------------------------------

    def validate_credential_format(
        self, raw_credential: str, expected_format: str
    ) -> Dict[str, Any]:
        """Validate a credential matches the expected format profile.

        Args:
            raw_credential: The credential string from the response
            expected_format: One of "dc+sd-jwt", "vc+sd-jwt", "jwt_vc_json", "mso_mdoc"

        Returns:
            Decoded credential info for further assertions
        """
        info: Dict[str, Any] = {"raw": raw_credential, "format": expected_format}

        if expected_format in ("dc+sd-jwt", "vc+sd-jwt"):
            # SD-JWT: header.payload.sig~disclosure1~disclosure2~
            assert "~" in raw_credential, (
                f"SD-JWT credential should contain ~ delimiters"
            )
            base_jwt = raw_credential.split("~")[0]
            header = _decode_jwt_header(base_jwt)
            payload = _decode_jwt_payload(base_jwt)
            assert header.get("typ") in ("dc+sd-jwt", "vc+sd-jwt"), (
                f"SD-JWT typ should be dc+sd-jwt or vc+sd-jwt, got: {header.get('typ')}"
            )
            assert payload.get("iss"), "SD-JWT missing 'iss' claim"
            info["header"] = header
            info["payload"] = payload
            info["disclosures"] = raw_credential.split("~")[1:]

        elif expected_format == "jwt_vc_json":
            # JWT-VC: header.payload.sig
            parts = raw_credential.split(".")
            assert len(parts) == 3, f"JWT-VC should have 3 parts, got {len(parts)}"
            header = _decode_jwt_header(raw_credential)
            payload = _decode_jwt_payload(raw_credential)
            assert header.get("typ") == "vc+jwt", (
                f"JWT-VC typ should be 'vc+jwt', got: {header.get('typ')}"
            )
            assert payload.get("vc"), "JWT-VC missing 'vc' claim"
            info["header"] = header
            info["payload"] = payload

        elif expected_format == "mso_mdoc":
            # mso_mdoc: base64url-encoded CBOR
            # We can't fully parse CBOR here without a dependency,
            # but we can verify it's valid base64url
            try:
                decoded = _b64url_decode(raw_credential)
                assert len(decoded) > 0, "mso_mdoc credential is empty after decoding"
                info["size_bytes"] = len(decoded)
            except Exception as e:
                raise AssertionError(
                    f"mso_mdoc credential is not valid base64url: {e}"
                )

        else:
            logger.warning("Unknown credential format: %s", expected_format)

        return info


# ---------------------------------------------------------------------------
# OID4VP v1 Headless Wallet Client (Presentation)
# ---------------------------------------------------------------------------

class OID4VPWalletClient:
    """Headless wallet for OID4VP v1 presentation flows.

    Simulates submitting a VP token to a verifier:
      1. Resolve presentation request (from request_uri)
      2. Select matching credentials
      3. Submit VP token
    """

    def __init__(
        self,
        profile: WalletProfile = GOOGLE_WALLET_PROFILE,
        verifier_base_url: Optional[str] = None,
    ):
        self.profile = profile
        self.verifier_base_url = verifier_base_url or os.getenv(
            "GATEWAY_URL", "http://localhost:8000"
        )
        self.client = httpx.AsyncClient(timeout=30.0, follow_redirects=True)

    async def close(self):
        await self.client.aclose()

    def _rewrite_url(self, url: str) -> str:
        """Rewrite an external URL to go through the local gateway."""
        if not url:
            return url
        parsed = urllib.parse.urlparse(url)
        gateway_parsed = urllib.parse.urlparse(self.verifier_base_url)
        if parsed.netloc != gateway_parsed.netloc:
            rewritten = urllib.parse.urlunparse((
                gateway_parsed.scheme,
                gateway_parsed.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            ))
            logger.debug(
                "[%s] VP: Rewrote URL %s -> %s",
                self.profile.name, url, rewritten,
            )
            return rewritten
        return url

    async def resolve_presentation_request(
        self, request_uri: str
    ) -> Dict[str, Any]:
        """Fetch and parse an OID4VP authorization request.

        Handles:
          - ``openid4vp://?request_uri=<url>&client_id=...`` deep links
          - Direct HTTP(S) URLs pointing to a JWT-secured authorization request

        Returns the decoded request parameters.
        """
        # If this is an openid4vp:// deep-link, extract the request_uri param
        if request_uri.startswith("openid4vp://"):
            parsed = urllib.parse.urlparse(request_uri)
            qs = urllib.parse.parse_qs(parsed.query)
            actual_uri = (qs.get("request_uri") or [None])[0]
            if not actual_uri:
                raise ValueError(
                    f"openid4vp:// deep-link missing 'request_uri' param: "
                    f"{request_uri[:200]}"
                )
            # Rewrite to go through local gateway
            request_uri = self._rewrite_url(actual_uri)

        resp = await self.client.get(request_uri)
        resp.raise_for_status()

        content_type = resp.headers.get("content-type", "")
        if "jwt" in content_type or resp.text.count(".") == 2:
            # JWT-secured request
            payload = _decode_jwt_payload(resp.text)
            return payload
        else:
            return resp.json()

    def validate_presentation_definition(
        self, request: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Validate the presentation_definition in an OID4VP request.

        Checks conformance with OID4VP v1 spec.
        """
        pd = request.get("presentation_definition")
        dcql = request.get("dcql_query")

        if pd:
            assert "input_descriptors" in pd, (
                "presentation_definition missing 'input_descriptors'"
            )
            for desc in pd["input_descriptors"]:
                assert "id" in desc, "input_descriptor missing 'id'"
                assert "constraints" in desc or "format" in desc, (
                    f"input_descriptor '{desc.get('id')}' missing constraints or format"
                )
            return {"type": "presentation_definition", "definition": pd}

        elif dcql:
            # DCQL (Digital Credentials Query Language) - newer approach
            assert "credentials" in dcql, "dcql_query missing 'credentials'"
            return {"type": "dcql", "query": dcql}

        else:
            raise AssertionError(
                "OID4VP request missing both 'presentation_definition' and 'dcql_query'. "
                f"Keys: {list(request.keys())}"
            )

    async def submit_vp_token(
        self,
        response_uri: str,
        vp_token: str,
        presentation_submission: Optional[Dict[str, Any]] = None,
        state: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Submit a VP token to the verifier's response endpoint.

        In a real wallet this would include a properly signed VP.
        For interop testing, we verify the endpoint accepts the submission format.
        """
        body: Dict[str, Any] = {"vp_token": vp_token}
        if presentation_submission:
            body["presentation_submission"] = json.dumps(presentation_submission)
        if state:
            body["state"] = state

        resp = await self.client.post(
            response_uri,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        # 200, 201, 302 are all valid responses depending on response_mode
        assert resp.status_code < 500, (
            f"VP submission returned server error {resp.status_code}: {resp.text[:500]}"
        )

        try:
            return resp.json()
        except Exception:
            return {"status_code": resp.status_code, "body": resp.text[:500]}

    async def run_verification_flow(
        self,
        request_uri: str,
        vp_token: str,
    ) -> Dict[str, Any]:
        """Run the full OID4VP verification flow as the wallet would.

        Steps:
          1. Resolve the authorization request from request_uri
          2. Validate the presentation_definition / dcql_query
          3. Submit the VP token to the response_uri

        Returns:
            Dict with 'request', 'definition_info', and 'submission_result' keys.
        """
        # 1. Resolve presentation request
        request = await self.resolve_presentation_request(request_uri)

        # 2. Validate the definition
        definition_info = self.validate_presentation_definition(request)

        # 3. Build submission metadata
        submission = None
        if definition_info["type"] == "presentation_definition":
            pd = definition_info["definition"]
            submission = {
                "id": secrets.token_hex(8),
                "definition_id": pd.get("id", ""),
                "descriptor_map": [
                    {
                        "id": desc["id"],
                        "format": "jwt_vp",
                        "path": "$",
                    }
                    for desc in pd.get("input_descriptors", [])
                ],
            }

        # 4. Determine response_uri
        response_uri = request.get("response_uri") or request.get("redirect_uri")
        state = request.get("state")

        result: Dict[str, Any] = {
            "request": request,
            "definition_info": definition_info,
        }

        if response_uri:
            submission_result = await self.submit_vp_token(
                response_uri=response_uri,
                vp_token=vp_token,
                presentation_submission=submission,
                state=state,
            )
            result["submission_result"] = submission_result
        else:
            logger.warning(
                "[%s] No response_uri in presentation request — "
                "cannot submit VP token. Keys: %s",
                self.profile.name,
                list(request.keys()),
            )
            result["submission_result"] = None

        return result
