"""OID4VP 1.0 Final — Verifier Conformance Tests (OIDF-mirrored).

All tests route through the gateway (GATEWAY_BASE, port 8000).
Test names mirror OIDF OpenID4VP conformance suite module names.

Gateway routing:
  - POST /v1/flows/verify         Admin — creates a verification session (auth required)
  - GET  /v1/flows/instances/{id}/request  Public — wallet fetches request object
  - POST /v1/flows/instances/{id}/submit   Public — wallet submits VP token

References:
  OID4VP 1.0 Final: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
  OIDF conformance: https://gitlab.com/openid/conformance-suite

Run standalone:
    SESSION_ID=<cookie> ORG_ID=<org> PRESENTATION_POLICY_ID=<policy> \\
        python -m tests.integration.test_oid4vp_verifier_conformance

Run via pytest:
    pytest tests/integration/test_oid4vp_verifier_conformance.py -v
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any


# ============================================================================
# Config
# ============================================================================

GATEWAY_BASE = os.environ.get("GATEWAY_BASE", "http://localhost:8000")
SESSION_ID = os.environ.get("SESSION_ID", "")
ORG_ID = os.environ.get("ORG_ID", "default")
PRESENTATION_POLICY_ID = os.environ.get("PRESENTATION_POLICY_ID", "")


# ============================================================================
# Holder keypair (generated once per test run, using Ed25519 for DID:key)
# ============================================================================

def _make_holder_credentials() -> tuple[Any, Any, str]:
    """Generate a fresh Ed25519 keypair and derive a did:key for the holder.

    Returns (private_key, public_key, did_key_str).
    Falls back to a static dummy DID if the cryptography package is unavailable.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        private_key = Ed25519PrivateKey.generate()
        pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        # Multicodec varint for Ed25519 public key: 0xed01
        multicodec_bytes = b"\xed\x01" + pub_bytes
        # Base58btc multibase prefix: 'z'
        encoded = _base58_encode(multicodec_bytes)
        did = f"did:key:z{encoded}"
        return private_key, private_key.public_key(), did
    except ImportError:
        return None, None, "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"


def _base58_encode(data: bytes) -> str:
    """Base58btc encoding (Bitcoin alphabet) — used for did:key multibase."""
    ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = int.from_bytes(data, "big")
    result = []
    while num > 0:
        num, remainder = divmod(num, 58)
        result.append(ALPHABET[remainder : remainder + 1])
    # Leading zero bytes become '1'
    for byte in data:
        if byte == 0:
            result.append(ALPHABET[0:1])
        else:
            break
    return b"".join(reversed(result)).decode("ascii")


def _sign_jwt_ed25519(header: dict, payload: dict, private_key: Any) -> str:
    """Build and sign a JWT using Ed25519 (for test VPs)."""
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    signing_input = f"{h}.{p}".encode()
    signature = private_key.sign(signing_input)
    sig = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    return f"{h}.{p}.{sig}"


# Holder credentials shared across all VP tests in this module
_HOLDER_PRIVATE_KEY, _HOLDER_PUBLIC_KEY, HOLDER_DID = _make_holder_credentials()



# ============================================================================
# HTTP helper (stdlib only — no httpx/requests)
# ============================================================================

@dataclass
class HttpResult:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body)

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


def http(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    json_body: Any = None,
    form_body: dict[str, str] | None = None,
    timeout: int = 30,
) -> HttpResult:
    hdrs = dict(headers or {})
    data = None
    if json_body is not None:
        data = json.dumps(json_body).encode()
        hdrs.setdefault("Content-Type", "application/json")
    elif form_body is not None:
        data = urllib.parse.urlencode(form_body).encode()
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
    if urllib.parse.urlparse(url).scheme not in {"http", "https"}:
        raise ValueError("conformance HTTP client only permits http(s) URLs")
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            body = resp.read()
            return HttpResult(resp.status, dict(resp.headers), body)
    except urllib.error.HTTPError as e:
        body = e.read() if hasattr(e, "read") else b""
        return HttpResult(e.code, dict(e.headers) if hasattr(e, "headers") else {}, body)


# ============================================================================
# Results tracker
# ============================================================================

@dataclass
class Results:
    _ok: list[str] = field(default_factory=list)
    _fail: list[tuple[str, str]] = field(default_factory=list)

    def ok(self, name: str) -> None:
        self._ok.append(name)
        print(f"  PASS  {name}")

    def fail(self, name: str, reason: str = "") -> None:
        self._fail.append((name, reason))
        print(f"  FAIL  {name}")
        if reason:
            print(f"        {reason}")

    def summary(self) -> bool:
        print(f"\n{'=' * 70}")
        print(f"OID4VP Conformance: {len(self._ok)} passed, {len(self._fail)} failed")
        if self._fail:
            print("\nFailed checks (missing features or spec violations):")
            for name, reason in self._fail:
                print(f"  - {name}: {reason}")
        return len(self._fail) == 0


R = Results()


# ============================================================================
# Gateway helpers
# ============================================================================

def _session_headers() -> dict[str, str]:
    """Cookie header for gateway admin endpoints."""
    if not SESSION_ID:
        raise RuntimeError(
            "SESSION_ID env var is required for admin gateway calls. "
            "Use AuthHelper.get_session_id() to obtain it."
        )
    return {"Cookie": f"sessionId={SESSION_ID}"}


def _create_verification_session(
    policy_id: str | None = None,
    org_id: str = ORG_ID,
) -> dict:
    """POST /v1/flows/verify — create a presentation request session.

    OID4VP 1.0 Final §5: The Verifier initiates the flow by creating a request.
    Returns the gateway response (contains instance_id and request_uri or request).
    """
    body: dict[str, Any] = {"organization_id": org_id}
    if policy_id or PRESENTATION_POLICY_ID:
        body["presentation_policy_id"] = policy_id or PRESENTATION_POLICY_ID

    resp = http(
        "POST",
        f"{GATEWAY_BASE}/v1/flows/verify",
        headers=_session_headers(),
        json_body=body,
    )
    if resp.status not in (200, 201):
        raise RuntimeError(
            f"Failed to create verification session: {resp.status} {resp.text}"
        )
    return resp.json()


def _decode_jwt_payload(jwt_str: str) -> dict:
    """Decode the payload section of a JWT without verifying the signature."""
    parts = jwt_str.strip().split(".")
    if len(parts) != 3:
        raise ValueError(f"Not a valid JWT: {jwt_str[:80]}")
    payload_b64 = parts[1]
    # Add padding
    payload_b64 += "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(payload_b64))


def _fetch_request_object(instance_id: str) -> dict:
    """GET /v1/flows/instances/{id}/request — wallet fetches the Authorization Request.

    OID4VP 1.0 Final §5.2: Returns application/oauth-authz-req+jwt (signed JWT).
    The JWT payload contains the OID4VP authorization request parameters.
    """
    resp = http("GET", f"{GATEWAY_BASE}/v1/flows/instances/{instance_id}/request")
    if resp.status != 200:
        raise RuntimeError(
            f"Failed to fetch request object for {instance_id}: {resp.status} {resp.text}"
        )
    # Response is a signed JWT (application/oauth-authz-req+jwt), decode payload
    content_type = resp.headers.get("content-type", resp.headers.get("Content-Type", ""))
    jwt_str = resp.text
    if "jwt" in content_type or (jwt_str.count(".") == 2 and not jwt_str.startswith("{")):
        return _decode_jwt_payload(jwt_str)
    # Fallback: try JSON (shouldn't be needed but defensive)
    return resp.json()


def _submit_vp_token(
    instance_id: str,
    vp_token: str,
    presentation_submission: dict | None = None,
    state: str | None = None,
) -> HttpResult:
    """POST /v1/flows/instances/{id}/submit — wallet returns VP token.

    OID4VP 1.0 Final §7: Direct Post response_mode uses application/x-www-form-urlencoded.
    """
    form: dict[str, str] = {
        "vp_token": vp_token,
    }
    if presentation_submission is not None:
        form["presentation_submission"] = json.dumps(presentation_submission)
    if state:
        form["state"] = state
    return http(
        "POST",
        f"{GATEWAY_BASE}/v1/flows/instances/{instance_id}/submit",
        form_body=form,
    )


def _build_mock_vp_token(
    request_obj: dict,
    holder_did: str = HOLDER_DID,
) -> tuple[str, dict | None]:
    """Build a structurally valid, properly signed VP token (when cryptography is available).

    Returns (vp_token_str, presentation_submission_dict_or_none).
    Uses Ed25519 signing with the module-level holder keypair so the verifier can
    verify the signature by resolving the did:key. Falls back to a dummy signature
    if the cryptography package is unavailable.
    """
    nonce = request_obj.get("nonce", "test-nonce")
    client_id = request_obj.get("client_id", GATEWAY_BASE)

    # Build minimal VP JWT
    key_id = f"{holder_did}#{holder_did.split(':')[-1]}"
    header = {"alg": "EdDSA", "typ": "JWT", "kid": key_id}
    payload = {
        "iss": holder_did,
        "aud": client_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,
        "nonce": nonce,
        "vp": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "verifiableCredential": ["dummy-vc-jwt-string"],
        },
    }
    if _HOLDER_PRIVATE_KEY is not None and holder_did == HOLDER_DID:
        vp_token = _sign_jwt_ed25519(header, payload, _HOLDER_PRIVATE_KEY)
    else:
        h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        sig = base64.urlsafe_b64encode(b"\x00" * 64).rstrip(b"=").decode()
        vp_token = f"{h}.{p}.{sig}"

    # Minimal legacy presentation_submission, only for PE-shaped requests
    presentation_submission = None
    pd = request_obj.get("presentation_definition")
    if pd:
        presentation_submission = {
            "id": "ps-1",
            "definition_id": pd.get("id", "pd-1"),
            "descriptor_map": [
                {
                    "id": "credential",
                    "format": "jwt_vp",
                    "path": "$",
                    "path_nested": {"id": "credential", "format": "jwt_vc", "path": "$.vp.verifiableCredential[0]"},
                }
            ],
        }
    return vp_token, presentation_submission


# ============================================================================
# Tests
# ============================================================================

# ---------------------------------------------------------------------------
# A. Verifier Metadata — OID4VP 1.0 Final §10
# ---------------------------------------------------------------------------

def test_verifier_metadata_wallet_endpoint():
    """OID4VP 1.0 Final §10: Wallet metadata endpoint at /.well-known/openid-wallet.

    OIDF: VPVerifierTest (wallet metadata discovery)
    If the verifier acts as a wallet-facing entity, §10.2 defines well-known discovery.
    This checks that the verifier publishes its client_id and response_types.
    NOTE: Many deployments skip wallet metadata — report gap if absent.
    """
    print("\n--- §10 Verifier/Wallet Metadata ---")
    # Try verifier metadata at gateway root
    resp = http("GET", f"{GATEWAY_BASE}/.well-known/openid-configuration")
    if resp.status == 200:
        meta = resp.json()
        if "response_types_supported" in meta:
            R.ok("verifier_metadata.response_types_supported")
        else:
            R.fail("verifier_metadata.response_types_supported",
                   "OID4VP-1FINAL §10: response_types_supported MUST be listed in OIDC metadata")
    else:
        R.fail("verifier_metadata.endpoint_available",
               f"OID4VP-1FINAL §10: /.well-known/openid-configuration not available ({resp.status})")


def test_verifier_request_object_required_fields():
    """OID4VP 1.0 Final §5: Authorization Request MUST contain required fields.

    OIDF: VPVerifierTest
    Required: response_type, client_id, nonce. MUST also have presentation_definition
    or presentation_definition_uri or dcql_query (OID4VP Final adds dcql_query §6).
    """
    print("\n--- §5 Authorization Request Required Fields ---")
    try:
        session = _create_verification_session()
    except RuntimeError as e:
        R.fail("verifier_request.create_session", str(e))
        return
    R.ok("verifier_request.create_session")

    instance_id = session.get("instance_id") or session.get("id")
    if not instance_id:
        R.fail("verifier_request.instance_id_in_response",
               f"gateway response missing instance_id: {list(session.keys())}")
        return
    R.ok("verifier_request.instance_id_in_response")

    try:
        req_obj = _fetch_request_object(instance_id)
    except RuntimeError as e:
        R.fail("verifier_request.fetch_request_object", str(e))
        return
    R.ok("verifier_request.fetch_request_object")

    # response_type MUST be present
    rt = req_obj.get("response_type")
    if rt == "vp_token":
        R.ok("verifier_request.response_type_vp_token")
    elif rt:
        R.fail("verifier_request.response_type_vp_token",
               f"OID4VP-1FINAL §5: response_type SHOULD be vp_token, got {rt!r}")
    else:
        R.fail("verifier_request.response_type_vp_token",
               "OID4VP-1FINAL §5: response_type MUST be present")

    # client_id MUST be present
    ci = req_obj.get("client_id")
    if ci:
        R.ok("verifier_request.client_id_present")
    else:
        R.fail("verifier_request.client_id_present",
               "OID4VP-1FINAL §5: client_id MUST be present in authorization request")

    # nonce MUST be present
    nonce = req_obj.get("nonce")
    if nonce:
        R.ok("verifier_request.nonce_present")
    else:
        R.fail("verifier_request.nonce_present",
               "OID4VP-1FINAL §5: nonce MUST be present to prevent replay attacks")

    # presentation_definition, dcql_query, or presentation_definition_uri
    has_pd = "presentation_definition" in req_obj
    has_dcql = "dcql_query" in req_obj
    has_pd_uri = "presentation_definition_uri" in req_obj
    if has_pd or has_dcql or has_pd_uri:
        R.ok("verifier_request.credential_query_present")
        if has_dcql:
            R.ok("verifier_request.dcql_query_supported")
            if has_pd:
                R.fail(
                    "verifier_request.default_dcql_only",
                    "Default OID4VP request should omit presentation_definition; "
                    "PE is reserved for legacy compat such as compat=lissi.",
                )
            else:
                R.ok("verifier_request.default_dcql_only")
        else:
            R.fail("verifier_request.dcql_query_supported",
                   "OID4VP-1FINAL §6: dcql_query not present (Final spec feature — missing)")
    else:
        R.fail("verifier_request.credential_query_present",
               "OID4VP-1FINAL §5: MUST contain presentation_definition, dcql_query, "
               "or presentation_definition_uri")


def test_verifier_request_response_mode():
    """OID4VP 1.0 Final §8.1: response_mode MUST be direct_post for wallet-submitted tokens.

    OIDF: VPVerifierTest
    response_mode=direct_post means the wallet POSTs the VP to response_uri.
    """
    print("\n--- §8.1 response_mode=direct_post ---")
    try:
        session = _create_verification_session()
        instance_id = session.get("instance_id") or session.get("id")
        req_obj = _fetch_request_object(instance_id)
    except RuntimeError as e:
        R.fail("verifier_response_mode.available", str(e))
        return

    rm = req_obj.get("response_mode")
    if rm == "direct_post":
        R.ok("verifier_response_mode.direct_post")
    elif rm == "direct_post.jwt":
        R.ok("verifier_response_mode.direct_post_jwt")
    else:
        R.fail("verifier_response_mode.direct_post",
               f"OID4VP-1FINAL §8.1: response_mode SHOULD be direct_post, got {rm!r}")

    # response_uri MUST exist if direct_post
    if rm and rm.startswith("direct_post"):
        ru = req_obj.get("response_uri")
        if ru:
            R.ok("verifier_response_mode.response_uri_present")
        else:
            R.fail("verifier_response_mode.response_uri_present",
                   "OID4VP-1FINAL §8.1: response_uri MUST be present with direct_post")


def test_verifier_client_id_scheme():
    """OID4VP 1.0 Final §5.10: client_id_scheme indicates how client_id is to be verified.

    OIDF: VPVerifierTest
    Final spec defines schemes: redirect_uri, entity_id, did, x509_san_dns, etc.
    Presence of client_id_scheme indicates Final spec adoption.
    """
    print("\n--- §5.10 client_id_scheme ---")
    try:
        session = _create_verification_session()
        instance_id = session.get("instance_id") or session.get("id")
        req_obj = _fetch_request_object(instance_id)
    except RuntimeError as e:
        R.fail("verifier_client_id_scheme.available", str(e))
        return

    scheme = req_obj.get("client_id_scheme")
    VALID_SCHEMES = {"redirect_uri", "entity_id", "did", "x509_san_dns", "x509_san_uri", "verifier_attestation"}
    if scheme is None:
        R.fail("verifier_client_id_scheme.present",
               "OID4VP-1FINAL §5.10: client_id_scheme not present (Final spec feature — missing). "
               "Required for OIDF certification.")
    elif scheme in VALID_SCHEMES:
        R.ok(f"verifier_client_id_scheme.valid [{scheme}]")
    else:
        R.fail("verifier_client_id_scheme.valid",
               f"OID4VP-1FINAL §5.10: unknown client_id_scheme {scheme!r}, "
               f"expected one of {VALID_SCHEMES}")


# ---------------------------------------------------------------------------
# B. Happy Flows — OIDF: VPVerifierHappyFlow
# ---------------------------------------------------------------------------

def test_verifier_happy_flow_direct_post():
    """Full OID4VP 1.0 Final flow: create session → fetch request → submit VP.

    OIDF: VPVerifierHappyFlow
    OID4VP-1FINAL §5 + §8: Verifier creates request, wallet submits VP via direct_post.
    Response MUST be 200 with redirect_uri or 204.
    """
    print("\n--- VPVerifierHappyFlow: direct_post ---")
    try:
        session = _create_verification_session()
        instance_id = session.get("instance_id") or session.get("id")
        req_obj = _fetch_request_object(instance_id)
    except RuntimeError as e:
        R.fail("VPVerifierHappyFlow.setup", str(e))
        return
    R.ok("VPVerifierHappyFlow.setup")

    vp_token, presentation_submission = _build_mock_vp_token(req_obj)
    state = req_obj.get("state")
    resp = _submit_vp_token(instance_id, vp_token, presentation_submission, state=state)

    if resp.status in (200, 204):
        R.ok("VPVerifierHappyFlow.vp_submission_accepted")
        if resp.status == 200:
            body = resp.json()
            if "redirect_uri" in body:
                R.ok("VPVerifierHappyFlow.redirect_uri_in_response")
            else:
                # 200 with empty body or different payload is OK per spec
                R.ok("VPVerifierHappyFlow.response_200")
    elif resp.status == 400:
        # Server may reject the dummy-signed VP — report which case it is
        R.fail("VPVerifierHappyFlow.vp_submission_accepted",
               f"OID4VP-1FINAL §8: VP submission returned 400 — server may be validating "
               f"signatures/presentation_submission: {resp.text}")
    else:
        R.fail("VPVerifierHappyFlow.vp_submission_accepted",
               f"OID4VP-1FINAL §8: expected 200/204, got {resp.status}: {resp.text}")


def test_verifier_happy_flow_request_by_uri():
    """OID4VP 1.0 Final §5.2: Authorization Request by reference (request_uri).

    OIDF: VPVerifierHappyFlow (by-reference variant)
    Verifier returns request_uri; wallet fetches the JWT request object.
    """
    print("\n--- §5.2 Authorization Request by reference ---")
    try:
        session = _create_verification_session()
    except RuntimeError as e:
        R.fail("verifier_request_by_uri.create", str(e))
        return

    # Check if response contains a request_uri (redirect) or inline request object
    request_uri_raw = session.get("request_uri", "")
    if request_uri_raw:
        R.ok("verifier_request_by_uri.request_uri_in_session")
        # The request_uri may be "openid4vp://authorize?request_uri=https://..." —
        # extract the actual HTTPS fetch URL embedded in the query params.
        if "request_uri=" in request_uri_raw:
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(request_uri_raw).query)
            request_uri = qs.get("request_uri", [request_uri_raw])[0]
        else:
            request_uri = request_uri_raw
        # Rewrite external hostname to localhost if needed
        request_uri = request_uri.replace("https://beta.elevenidllc.com", GATEWAY_BASE)
        # Wallet fetches the request object
        resp = http("GET", request_uri)
        if resp.status == 200:
            R.ok("verifier_request_by_uri.request_object_fetchable")
        else:
            R.fail("verifier_request_by_uri.request_object_fetchable",
                   f"OID4VP-1FINAL §5.2: request_uri must return 200, got {resp.status}")
    else:
        # May be direct embed — report gap
        R.fail("verifier_request_by_uri.request_uri_in_session",
               "OID4VP-1FINAL §5.2: request_uri not in session response "
               "(by-reference requests not supported or not default)")


# ---------------------------------------------------------------------------
# C. Presentation Definition — OID4VP 1.0 Final §5
# ---------------------------------------------------------------------------

def test_verifier_presentation_definition_structure():
    """OID4VP 1.0 Final §5: presentation_definition matches PE v2 spec.

    OIDF: VPVerifierTest (PD validation)
    PD MUST have: id (string), input_descriptors (non-empty array).
    Each descriptor MUST have: id, constraints.fields.
    """
    print("\n--- §5 Presentation Definition Structure ---")
    try:
        session = _create_verification_session()
        instance_id = session.get("instance_id") or session.get("id")
        req_obj = _fetch_request_object(instance_id)
    except RuntimeError as e:
        R.fail("verifier_pd.available", str(e))
        return

    pd = req_obj.get("presentation_definition")
    if pd is None:
        if "dcql_query" in req_obj:
            R.ok("verifier_pd.dcql_query_alternative")
        else:
            R.fail("verifier_pd.available",
                   "OID4VP-1FINAL §5: no presentation_definition or dcql_query in request")
        return

    # id MUST be string
    if isinstance(pd.get("id"), str):
        R.ok("verifier_pd.id_present")
    else:
        R.fail("verifier_pd.id_present",
               "PresentationExchange v2 §5: presentation_definition MUST have string id")

    # input_descriptors MUST be non-empty array
    ids = pd.get("input_descriptors", [])
    if isinstance(ids, list) and len(ids) > 0:
        R.ok("verifier_pd.input_descriptors_non_empty")
    else:
        R.fail("verifier_pd.input_descriptors_non_empty",
               "PresentationExchange v2 §5: input_descriptors MUST be non-empty array")
        return

    # Each descriptor: id, constraints
    for desc in ids:
        desc_id = desc.get("id", "<missing>")
        if "constraints" in desc:
            R.ok(f"verifier_pd.descriptor_has_constraints[{desc_id}]")
        else:
            R.fail(f"verifier_pd.descriptor_has_constraints[{desc_id}]",
                   "PresentationExchange v2: descriptor MUST have constraints")


def test_verifier_dcql_query():
    """OID4VP 1.0 Final §6: dcql_query as alternative to presentation_definition.

    OIDF: VPVerifierTest (dcql_query variant)
    dcql_query §6.1: MUST have credentials array; each entry has id and format.
    This test WILL FAIL if dcql_query is not implemented.
    """
    print("\n--- §6 DCQL Query ---")
    try:
        session = _create_verification_session()
        instance_id = session.get("instance_id") or session.get("id")
        req_obj = _fetch_request_object(instance_id)
    except RuntimeError as e:
        R.fail("verifier_dcql.available", str(e))
        return

    dcql = req_obj.get("dcql_query")
    if dcql is None:
        R.fail("verifier_dcql.present",
               "OID4VP-1FINAL §6: dcql_query not in authorization request. "
               "DCQL is a Final spec feature required for OID4VP 1.0 certification.")
        return
    R.ok("verifier_dcql.present")

    credentials = dcql.get("credentials")
    if isinstance(credentials, list) and len(credentials) > 0:
        R.ok("verifier_dcql.credentials_array_non_empty")
    else:
        R.fail("verifier_dcql.credentials_array_non_empty",
               "OID4VP-1FINAL §6.1: dcql_query MUST have non-empty credentials array")
        return

    for cred in credentials:
        if "id" in cred and "format" in cred:
            R.ok(f"verifier_dcql.credential_has_id_and_format[{cred.get('id')}]")
        else:
            R.fail("verifier_dcql.credential_has_id_and_format",
                   f"OID4VP-1FINAL §6.1: each credential entry MUST have id and format: {cred}")


# ---------------------------------------------------------------------------
# D. Negative Tests — OIDF: VPVerifierFail* modules
# ---------------------------------------------------------------------------

def test_verifier_fail_on_missing_vp_token():
    """Submit to /submit endpoint without vp_token — MUST return 400.

    OIDF: VPVerifierFailOnMissingVPToken
    OID4VP-1FINAL §8: vp_token is REQUIRED in the submission body.
    """
    print("\n--- VPVerifierFailOnMissingVPToken (§8) ---")
    try:
        session = _create_verification_session()
        instance_id = session.get("instance_id") or session.get("id")
    except RuntimeError as e:
        R.fail("VPVerifierFailOnMissingVPToken.setup", str(e))
        return

    resp = http(
        "POST",
        f"{GATEWAY_BASE}/v1/flows/instances/{instance_id}/submit",
        json_body={"presentation_submission": {"id": "ps-1", "definition_id": "pd-1", "descriptor_map": []}},
    )
    if resp.status == 400:
        R.ok("VPVerifierFailOnMissingVPToken")
    else:
        R.fail("VPVerifierFailOnMissingVPToken",
               f"OID4VP-1FINAL §8: missing vp_token MUST return 400, got {resp.status}: {resp.text}")


def test_verifier_fail_on_wrong_nonce():
    """Submit VP token with nonce that doesn't match the request nonce.

    OIDF: VPVerifierFailOnInvalidNonce
    OID4VP-1FINAL §8.6: verifier MUST verify nonce from VP matches the request nonce.
    """
    print("\n--- VPVerifierFailOnInvalidNonce (§8.6) ---")
    try:
        session = _create_verification_session()
        instance_id = session.get("instance_id") or session.get("id")
        req_obj = _fetch_request_object(instance_id)
    except RuntimeError as e:
        R.fail("VPVerifierFailOnInvalidNonce.setup", str(e))
        return

    # Build VP with wrong nonce
    req_obj_bad_nonce = dict(req_obj)
    req_obj_bad_nonce["nonce"] = "totally-wrong-nonce-xyz"
    vp_token, presentation_submission = _build_mock_vp_token(req_obj_bad_nonce)
    resp = _submit_vp_token(instance_id, vp_token, presentation_submission)

    if resp.status == 400:
        R.ok("VPVerifierFailOnInvalidNonce")
    else:
        R.fail("VPVerifierFailOnInvalidNonce",
               f"OID4VP-1FINAL §8.6: wrong nonce in VP MUST be rejected with 400, "
               f"got {resp.status}: {resp.text}")


def test_verifier_fail_on_expired_session():
    """Submit VP to an expired or unknown session instance_id — MUST return 400 or 404.

    OID4VP-1FINAL §8: session binding via instance_id.
    """
    print("\n--- Expired/Unknown Session Rejection ---")
    resp = _submit_vp_token(
        "00000000-0000-0000-0000-000000000000",
        "dummy.vp.token",
        {"id": "ps", "definition_id": "pd", "descriptor_map": []},
    )
    if resp.status in (400, 404):
        R.ok("verifier_fail_on_expired_session")
    else:
        R.fail("verifier_fail_on_expired_session",
               f"Unknown session ID MUST return 400 or 404, got {resp.status}")


def test_verifier_fail_on_invalid_presentation_submission():
    """Submit VP with malformed presentation_submission — MUST return 400.

    OID4VP-1FINAL §8: presentation_submission MUST conform to PresentationExchange v2.
    """
    print("\n--- VPVerifierFailOnInvalidPresentationSubmission (§8) ---")
    try:
        session = _create_verification_session()
        instance_id = session.get("instance_id") or session.get("id")
        req_obj = _fetch_request_object(instance_id)
    except RuntimeError as e:
        R.fail("VPVerifierFailOnInvalidPS.setup", str(e))
        return

    if "presentation_definition" not in req_obj:
        R.ok("VPVerifierFailOnInvalidPresentationSubmission.not_applicable_for_dcql")
        return

    vp_token, _ = _build_mock_vp_token(req_obj)
    bad_ps = {"this_is": "not_a_valid_presentation_submission"}
    resp = _submit_vp_token(instance_id, vp_token, bad_ps)

    if resp.status == 400:
        R.ok("VPVerifierFailOnInvalidPresentationSubmission")
    else:
        R.fail("VPVerifierFailOnInvalidPresentationSubmission",
               f"OID4VP-1FINAL §8: invalid presentation_submission MUST return 400, "
               f"got {resp.status}: {resp.text}")


def test_verifier_fail_on_signature_verification():
    """VP with corrupted signature MUST be rejected.

    OIDF: VPVerifierFailOnInvalidSignature
    OID4VP-1FINAL §8.6: Verifier MUST verify the holder's signature on the VP.
    This test WILL FAIL if signature verification is not implemented.
    """
    print("\n--- VPVerifierFailOnInvalidSignature (§8.6) ---")
    try:
        session = _create_verification_session()
        instance_id = session.get("instance_id") or session.get("id")
        req_obj = _fetch_request_object(instance_id)
    except RuntimeError as e:
        R.fail("VPVerifierFailOnInvalidSignature.setup", str(e))
        return

    nonce = req_obj.get("nonce", "nonce")
    client_id = req_obj.get("client_id", GATEWAY_BASE)
    header = {"alg": "EdDSA", "typ": "JWT", "kid": f"{HOLDER_DID}#key"}
    payload = {"iss": HOLDER_DID, "aud": client_id, "iat": int(time.time()),
               "nonce": nonce, "vp": {"@context": [], "type": [], "verifiableCredential": []}}
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    bad_sig = base64.urlsafe_b64encode(b"\xff" * 64).rstrip(b"=").decode()
    bad_vp = f"{h}.{p}.{bad_sig}"

    ps = None
    if "presentation_definition" in req_obj:
        ps = {
            "id": "ps-bad",
            "definition_id": req_obj.get("presentation_definition", {}).get("id", "pd"),
            "descriptor_map": [],
        }
    resp = _submit_vp_token(instance_id, bad_vp, ps)

    if resp.status == 400:
        R.ok("VPVerifierFailOnInvalidSignature")
    else:
        R.fail("VPVerifierFailOnInvalidSignature",
               f"OID4VP-1FINAL §8.6: invalid signature MUST be rejected with 400, "
               f"got {resp.status}. NOTE: Verifier likely not verifying VP signatures yet.")


# ---------------------------------------------------------------------------
# E. Session State — OID4VP flow management
# ---------------------------------------------------------------------------

def test_verifier_session_result_polling():
    """After VP submission, verifier MUST provide result to the relying party.

    OID4VP-1FINAL §8.7: Response to verifier backend (out-of-band).
    This tests whether the gateway exposes a result endpoint for the session.
    """
    print("\n--- Session Result Polling ---")
    try:
        session = _create_verification_session()
        instance_id = session.get("instance_id") or session.get("id")
        req_obj = _fetch_request_object(instance_id)
    except RuntimeError as e:
        R.fail("verifier_session_result.setup", str(e))
        return

    # Try to get result (may not be implemented)
    result_resp = http(
        "GET",
        f"{GATEWAY_BASE}/v1/flows/instances/{instance_id}/result",
        headers=_session_headers(),
    )
    if result_resp.status == 200:
        body = result_resp.json()
        # Before submission, state SHOULD be pending/waiting
        state_val = body.get("state") or body.get("status")
        if state_val in ("pending", "waiting", "created", None):
            R.ok("verifier_session_result.pending_state")
        else:
            R.ok(f"verifier_session_result.state_present [{state_val}]")
    elif result_resp.status == 404:
        R.fail("verifier_session_result.endpoint_available",
               "OID4VP-1FINAL §8.7: No result polling endpoint at /instances/{id}/result. "
               "Relying party cannot check verification result — missing feature.")
    else:
        R.fail("verifier_session_result.endpoint_available",
               f"Unexpected {result_resp.status} from result endpoint")


def test_verifier_nonce_uniqueness():
    """Two verification sessions MUST have different nonces.

    OID4VP-1FINAL §5: nonce prevents replay — MUST be unique per session.
    """
    print("\n--- Verifier Nonce Uniqueness ---")
    try:
        s1 = _create_verification_session()
        s2 = _create_verification_session()
        iid1 = s1.get("instance_id") or s1.get("id")
        iid2 = s2.get("instance_id") or s2.get("id")
        r1 = _fetch_request_object(iid1)
        r2 = _fetch_request_object(iid2)
    except RuntimeError as e:
        R.fail("verifier_nonce_uniqueness.setup", str(e))
        return

    n1 = r1.get("nonce", "")
    n2 = r2.get("nonce", "")
    if n1 and n2 and n1 != n2:
        R.ok("verifier_nonce_uniqueness")
    elif n1 == n2:
        R.fail("verifier_nonce_uniqueness",
               f"OID4VP-1FINAL §5: nonce MUST be unique per session, got same nonce twice: {n1!r}")
    else:
        R.fail("verifier_nonce_uniqueness", f"nonce missing in request (n1={n1!r}, n2={n2!r})")


# ---------------------------------------------------------------------------
# F. Client ID Verification — OID4VP 1.0 Final §5.10
# ---------------------------------------------------------------------------

def test_verifier_client_id_prefix_did():
    """OID4VP 1.0 Final §5.10: If client_id_scheme=did, client_id MUST be a DID.

    OIDF: VPVerifierTest (DID client verification)
    This test WILL FAIL if did client_id_scheme is not used.
    """
    print("\n--- §5.10 client_id_scheme=did ---")
    try:
        session = _create_verification_session()
        instance_id = session.get("instance_id") or session.get("id")
        req_obj = _fetch_request_object(instance_id)
    except RuntimeError as e:
        R.fail("verifier_client_id_did.available", str(e))
        return

    scheme = req_obj.get("client_id_scheme")
    if scheme != "did":
        R.fail("verifier_client_id_did.scheme_is_did",
               f"OID4VP-1FINAL §5.10: client_id_scheme=did not used (got {scheme!r}). "
               "DID-based client identification is required for wallet interoperability.")
        return
    R.ok("verifier_client_id_did.scheme_is_did")

    client_id = req_obj.get("client_id", "")
    if client_id.startswith("did:"):
        R.ok("verifier_client_id_did.client_id_is_did")
    else:
        R.fail("verifier_client_id_did.client_id_is_did",
               f"OID4VP-1FINAL §5.10: client_id_scheme=did requires DID as client_id, got {client_id!r}")


def test_verifier_client_id_prefix_https():
    """OID4VP 1.0 Final §5.10: client_id_scheme=redirect_uri — client_id is the response_uri.

    OIDF: VPVerifierTest (redirect_uri scheme)
    """
    print("\n--- §5.10 client_id_scheme=redirect_uri ---")
    try:
        session = _create_verification_session()
        instance_id = session.get("instance_id") or session.get("id")
        req_obj = _fetch_request_object(instance_id)
    except RuntimeError as e:
        R.fail("verifier_client_id_https.available", str(e))
        return

    scheme = req_obj.get("client_id_scheme", "")
    client_id = req_obj.get("client_id", "")
    response_uri = req_obj.get("response_uri", "")

    if scheme == "redirect_uri":
        # client_id and response_uri MUST be identical
        if client_id == response_uri:
            R.ok("verifier_client_id_https.client_id_equals_response_uri")
        else:
            R.fail("verifier_client_id_https.client_id_equals_response_uri",
                   f"OID4VP-1FINAL §5.10: with redirect_uri scheme, client_id MUST equal response_uri. "
                   f"client_id={client_id!r}, response_uri={response_uri!r}")
    else:
        R.fail("verifier_client_id_https.scheme_is_redirect_uri",
               f"OID4VP-1FINAL §5.10: client_id_scheme=redirect_uri not used (got {scheme!r})")


# ============================================================================
# Runner
# ============================================================================

def main() -> None:
    print("=" * 70)
    print("OID4VP Verifier Conformance Test Suite")
    print(f"Target: {GATEWAY_BASE}")
    print(f"Org: {ORG_ID}")
    print("=" * 70)

    try:
        resp = http("GET", f"{GATEWAY_BASE}/health")
        if resp.status != 200:
            print(f"FATAL: gateway not healthy: {resp.status} {resp.text}")
            sys.exit(1)
    except Exception as e:
        print(f"FATAL: gateway unreachable at {GATEWAY_BASE}: {e}")
        sys.exit(1)
    print("Gateway healthy ✓\n")

    # A. Metadata
    test_verifier_metadata_wallet_endpoint()
    # B. Request Object
    test_verifier_request_object_required_fields()
    test_verifier_request_response_mode()
    test_verifier_client_id_scheme()
    # C. Happy Flows
    test_verifier_happy_flow_direct_post()
    test_verifier_happy_flow_request_by_uri()
    # D. Presentation Definition
    test_verifier_presentation_definition_structure()
    test_verifier_dcql_query()
    # E. Negative Tests
    test_verifier_fail_on_missing_vp_token()
    test_verifier_fail_on_wrong_nonce()
    test_verifier_fail_on_expired_session()
    test_verifier_fail_on_invalid_presentation_submission()
    test_verifier_fail_on_signature_verification()
    # F. Session State
    test_verifier_session_result_polling()
    test_verifier_nonce_uniqueness()
    # G. Client ID
    test_verifier_client_id_prefix_did()
    test_verifier_client_id_prefix_https()

    all_pass = R.summary()
    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
