# Protocol Compliance Post-Action Report

Status: in progress  
Last updated: 2026-07-28

## Purpose

This report records what the official OIDF, W3C, and EUDI interoperability
work actually exercised, what it exposed in Marty, which findings have been
corrected, and which product gaps remain. A passing adapted test is not treated
as proof of native product support or certification.

Every capability is classified as one of:

- **native**: an official assertion traverses the supported production
  contract and implementation;
- **adapted**: an official assertion reaches production through a documented
  compatibility facade;
- **partial**: only a defined subset of the capability has evidence;
- **missing**: the product does not implement the required behavior;
- **bypassed**: the test substitutes or short-circuits production behavior and
  therefore provides no compliance evidence; or
- **unproven**: implementation may exist, but released immutable evidence is
  absent.

## Boundary under audit

The intended public signing contract is:

`organization_id + issuer_did + purpose + credential format + algorithm`

Marty must resolve that input to exactly one active, authorized issuer profile.
The profile is the signing authority and uses its configured managed-custody
service internally. Public callers must not select an issuer profile, signing
service, KMS provider, key reference, or custody implementation.

The audit distinguishes four execution paths:

| Path | Current use | Claim |
| --- | --- | --- |
| Normal public gateway API | OID4VCI, OID4VP, EUDI fixtures and callbacks | Production-path evidence |
| Official library behind a thin HTTP facade | EUDI wallet libraries and Multipaz | Official-library interoperability, not certification |
| Gated compatibility adapter | W3C VC Data Model v2 VC-API shape | Adapted coverage only |
| Internal service or inline verifier | Prohibited as compliance evidence | No public interoperability claim |

## What the official tests exposed

### 1. Canonical and wire-format names had drifted

Credential templates store Marty canonical payload names such as
`w3c_vcdm_v2_sd_jwt` and `mdoc`, while signing services advertise wire-format
names such as `dc+sd-jwt` and `mso_mdoc`. Template creation normalized one
path, but issuance forwarded the canonical name directly. A valid issuer DID
therefore failed signing-service resolution with HTTP 404. An mdoc template
could also omit the derived wire format and reach the wrong default.

Action: centralize public-to-signing format normalization and apply it during
both template creation and issuance. Infer the wire format from supported
formats when an older stored template lacks it.

### 2. A legacy issuer profile could erase the resolved algorithm

The DID resolver could correctly select ES256 from the request and active
signing service, then return an older profile's blank `algorithm` field. The
OID4VP request-object path subsequently failed with HTTP 503.

Action: return the effective resolved algorithm. A blank legacy field no
longer overrides an explicit compatible request or an unambiguous service
capability.

### 3. The negative tests over-specified internal lifecycle behavior

The wallet-facing OID4VP callback intentionally does not expose the relying
party's `decision` or `verified_claims`. The original replay and tamper tests
incorrectly expected those internal fields in the public callback. The expiry
test also confused a healthy harness HTTP response containing an official
resolver failure with successful protocol resolution.

The compatibility facade also named two transport-derived fields `success`
and `verifierAccepted`; both were calculated solely from the callback HTTP
status. They cannot establish the relying party's cryptographic decision. A
2xx privacy-preserving callback may accompany a completed authenticated deny,
while a pre-finalization rejection may use 4xx and leave the flow retryable.
The authenticated result also separates policy evaluation from the final
access-control decision: a policy evaluation label is not authorization and
may remain successful when a later cryptographic gate produces `deny`.

Action: assert the stable security boundary:

- the first valid response is accepted and its authenticated result is allow;
- replay and tampered-signature submissions never produce an authenticated
  allow result or a 5xx callback;
- a finalized tampered response has the authoritative decision `deny` and no
  verified claims, regardless of a non-authoritative policy-evaluation label;
- public callbacks disclose no internal decision or verified claims;
- an invalid response either finalizes as an authenticated deny or remains a
  retryable flow with no result resource; a retryable outcome must use 4xx,
  while a 2xx callback is accepted only with a completed authenticated deny;
- an expired request fails in the official resolver before dispatch.

This change does not accept 5xx errors, disable signature verification, inject
an allow result, or mutate production evidence.

The corrected assertion then exposed a release-blocking product defect:
v1.1.38 finalized a presentation with a deliberately corrupted SD-JWT
key-binding signature as `allow`. The reusable presentation policy had not
explicitly enabled holder binding, so the policy service discarded the
OID4VP nonce and audience before calling the Rust verifier. That policy option
is valid for credential-only checks but must never disable holder proof in an
OID4VP verifier transaction.

Action: the flow service now marks every request-object-backed OID4VP
transaction as verifier context. The policy service treats that trusted
context as requiring nonce and audience binding regardless of the reusable
policy's credential-only setting. PR
[marty-ui#126](https://github.com/ElevenID/marty-ui/pull/126) merged this fix
with focused flow and policy regression tests. A released immutable-stack
rerun remains required.

### 4. The checked-in immutable stack pin lagged the reviewed release

Manual investigation used reviewed tag and manifest overrides while
`conformance/stack-under-test.json` still named `marty-ui` v1.1.34. The
released DID-first fixes are in v1.1.38, and the holder-binding correction
will first appear in a later release.

Action required: after the final v1.1.39-or-newer lanes are green, update the
checked-in pin to that release and its independently verified manifest digest.

### 5. The old stack proved that the harness does not silently fall back

Running the current harness against v1.1.34 stopped at public credential
template creation because that release required `issuer_profile_id`. The
harness did not add the deprecated selector to make the run proceed. This is
useful negative evidence that the DID-only public boundary is enforced by the
test client rather than bypassed for compatibility.

### 6. OID4VP Final and HAIP work through the production gateway

The official OIDF `release-v5.2.0` OID4VP Final and HAIP verifier plans both
passed against the immutable v1.1.38 stack. The lanes used signed request
objects, the public request URI and callback, and authenticated relying-party
results. No verifier service, inline verifier, or private signing selector was
substituted.

Action: mark these interoperability profiles active while continuing to state
that the upstream profiles are pre-certification/alpha and that a passing run
is not an OIDF certification.

### 6a. ISO mDL now has an official OIDF verifier lane

The scheduled `oid4vp-mdoc` lane uses the pinned OIDF OID4VP Final verifier
plan with its `iso_mdl` credential variant. It creates an ISO 18013-5 mDL
template and active policy through Marty's authenticated public gateway, asks
for `mso_mdoc` through the normal DID-first verification flow, and lets the
official runner generate the mdoc presentation and negative cases. The
fixture's managed `mdoc_dsc` profile is used only for profile administration;
the runtime flow exposes no profile, service, key, or KMS selector.

Scope: this is native official verifier coverage, not an OIDF mdoc issuer
claim. The pinned upstream runner has no corresponding OID4VCI mdoc issuer
plan. EUDI reference-library issuance and independent COSE/CBOR/X.509 checks
remain the issuance evidence until such a plan is available.

### 7. W3C Data Integrity issuance was configuration-only and reconstructed the document

The official W3C lane stopped at the public credential-template API with HTTP
404 because the managed signer registry did not advertise `ldp_vc`. This was a
real production configuration gap. Marty supports the
`eddsa-rdfc-2022` verification suite; assigning Data Integrity to the default
ES256 key would have falsely advertised an unsupported cryptographic pairing.

The audit then exposed a more important implementation gap: the VC-API adapter
discarded every top-level official credential field except
`credentialSubject`, and the production Data Integrity helper still required
local private key material. A suite could therefore appear to exercise
contexts, types, validity, schemas, status, names, and issuer objects while the
actual signed document had been reconstructed from a much narrower input.
That was not acceptable compliance evidence.

Remediation in the current change set:

- [marty-core#72](https://github.com/ElevenID/marty-core/pull/72) is merged and
  provides native prepare/complete `eddsa-rdfc-2022` operations. It returns the
  canonical signing bytes, rejects private JWK input, and verifies that the
  completion identity and algorithm match the preparation.
- `marty-credentials#74` sends those canonical bytes through the DID-mediated
  issuer-profile signer, preserves the complete unsigned VCDM v2 document,
  and rejects caller proofs, issuer mismatches, invalid signatures, and signing
  identity substitution.
- `marty-ui#138` passes the complete unsigned document through the normal
  issuance transaction, token, nonce, and real holder-proof path. It no longer
  substitutes a JWT envelope or forwards only `credentialSubject`.
- The official fixture now provisions one managed EdDSA/Data Integrity profile
  for the lane, registers the product-resolved issuer DID, and advertises only
  `vc2.0`; it no longer claims `EnvelopingProof` or JOSE coverage.

This is native product-path issuance behind an adapted VC-API facade. It is
not yet immutable official evidence: both open component changes must merge,
release, enter the stack manifest, and pass the pinned official suite.

The audit also found and removed an adapter-owned anti-cheat risk. The adapter
had performed suite-specific semantic VCDM and related-resource validation
before the production issuance call. Those structural rules now live in a
production `marty-credentials` domain validator invoked by the ordinary
issuance request model. Remote `relatedResource` digest verification is an
allowlisted production issuance policy with HTTPS-only exact URLs, no
redirects, bounded responses, and request timeouts. The adapter-owned
validators and their tests were deleted; equivalent official negative
regressions now run against production code. The adapter also stopped
duplicating the gateway's template lookup and DID/profile resolution: it now
submits `organization_id`, the fixture's public `issuer_did`, template ID, and
the complete document to the same `create_issuance` application path used by
the general UI API. This remediation is locally passing but still needs
component merge, release, and pinned-suite evidence before it is an immutable
native-compliance result.

### 7a. DID-first resolution did not yet extend to every internal signing call

The public gateway correctly accepted only an organization and `issuer_did`,
then resolved the active compatible issuer profile.  However, the OID4VCI,
mdoc, DIDComm, and gRPC issuance workers subsequently addressed the internal
signing endpoint by the resolved `issuer_profile_id`.  This was not a test
bypass—profile resolution had already happened through the DID resolver and
the worker still had no KMS selector—but it left a second identity selector in
the protocol-service-to-custody boundary.  It would make a stale profile
binding easier to misuse and contradicted the intended DID-first architecture.

Action: add a gateway-only DID-mediated signing endpoint.  It receives only
`organization_id`, `issuer_did`, credential format/purpose, algorithm, and the
payload; it resolves exactly one active compatible profile internally and
rejects profile, service, and key overrides.  The endpoint returns only the
DID verification material and signature.  Update OID4VCI, mdoc, DIDComm, and
gRPC issuance to use this endpoint.  The gateway-to-KMS mapping remains
issuer-profile mediated and private.

Merged evidence:

- [marty-ui#137](https://github.com/ElevenID/marty-ui/pull/137) adds the
  DID-mediated signer and override-rejection tests;
- [marty-credentials#73](https://github.com/ElevenID/marty-credentials/pull/73)
  removes profile IDs from issuance-to-signer calls and covers REST/gRPC
  signing requests.

Both changes merged on 2026-07-28. The native Data Integrity remediation in
section 7 builds on this boundary: canonical proof bytes are signed by issuer
DID through the resolved profile, never by passing a private JWK or public KMS
selector.

### 7b. The managed EdDSA key was published as provider metadata, not a JWK

The first W3C run against immutable `marty-ui` v1.1.42 passed stack
materialization, provenance verification, anonymous image pulls, and public
fixture setup through issuer-profile creation. It then failed at the normal
public credential-template API with HTTP 503:

`Issuer DID verification method has no usable public key material.`

This was a production defect, not an official-runner or adapter failure.
OpenBao returned the managed Ed25519 public key as PEM. The gateway stored a
provider metadata object containing `public_key_pem` beneath
`publicKeyJwk`, so the DID resolver correctly rejected the verification method
because it had no JWK `kty`. The same adapter always prehashed signing input
with SHA-256, which is invalid for OpenBao Ed25519 keys, and the public signing
response would have mislabeled the resulting Ed25519 bytes as DER.

Action:

- convert provider PEM into standards-shaped public EC, RSA, or OKP JWK
  material before DID publication;
- reject missing, malformed, or unsupported public keys instead of publishing
  provider metadata as cryptographic identity;
- propagate the issuer profile's selected algorithm into the custody adapter;
- send the original canonical proof bytes with `prehashed=false` for EdDSA;
- report EdDSA output as raw signatures; and
- make the official fixture's administrative issuer-profile payload explicitly
  declare EdDSA rather than relying on the legacy ES256 default.

[marty-ui#140](https://github.com/ElevenID/marty-ui/pull/140) and
[marty-integration-tests#157](https://github.com/ElevenID/marty-integration-tests/pull/157)
contain the fixes and regression tests. All issuer private keys remain in
OpenBao, and the runtime request still selects only the organization and
issuer DID. A new component release, stack manifest, and official rerun are
required before the W3C capability is classified as immutable passing
evidence.

### 8. The OID4VCI runner lacked its emulated wallet identities

OID4VCI metadata passed, while all interaction modules entered `INTERRUPTED`
before issuer interaction. The official plan requires static `client` and
`client2` identifiers for its private-key-JWT wallet emulators; our generated
runner configuration omitted them. This was a harness configuration defect,
not evidence of thirteen separate product failures.

Action: generate two disposable client identifiers and continue allowing the
official suite to generate their ephemeral JWKS. The corrected rerun will
expose the first actual authorization, DPoP, token, credential, notification,
or negative-response gap instead of failing during module configuration.

The first corrected rerun then exposed a second configuration mismatch at
`VCISelectOAuthorizationServer`: Marty advertises the organization-specific
credential issuer URL as its authorization server, while the runner config
forced the gateway origin. The runner now uses the exact advertised
per-organization issuer URL; no metadata or production endpoint is rewritten.

The next reruns exposed two distinct identifier mistakes. Marty's internal
credential-template UUID is not an OID4VCI
`credential_configuration_id`, and the bare `PID` configuration advertises
JWT VC rather than the SD-JWT format selected by the official plan. The
harness now resolves the unique `dc+sd-jwt` configuration with the fixture's
published `vct` from Marty's public issuer metadata. It therefore selects the
actual advertised `PID#sd-jwt` identifier instead of guessing from an
internal resource ID or accepting the wrong wire format.

Run
[`30232463613`](https://github.com/ElevenID/marty-integration-tests/actions/runs/30232463613)
then proved that the resolved public identifier was correct but exposed one
more harness-only constraint: the fixture channel's identifier allowlist did
not permit `#`. The bootstrap created every resource through the public
gateway and stopped before invoking the official runner. The allowlist now
accepts Marty's printable fragment-style protocol identifiers while continuing
to reject whitespace and control characters. The sanitized summary is
`sha256:efef32378fc30dbe8caa30577559b06f7e34f1bccec0f90c04c44892c4b86b58`.
No product endpoint, metadata document, or official assertion was changed to
accommodate this harness correction.

### 9. Declared private-key JWT authentication was not an enforced boundary

The official issuer profile declared `private_key_jwt`, but the production
stack had no tenant-owned wallet-client registration contract. The token
endpoint accepted `none`, while the gRPC `ExchangeToken` transport did not
process a client assertion at all. A test could therefore appear configured
for authenticated clients without proving that the client which received an
offer was the client redeeming it.

The audit also found three related production-boundary gaps:

- authorization and pre-authorization codes were read and then updated in
  separate repository operations, allowing concurrent redemption races;
- per-organization authorization-server metadata advertised a PAR endpoint
  whose form body could still nominate a different organization;
- global authorization-server metadata advertised tenant-only client
  authentication without a tenant from which to resolve the registration.

Actions:

- add tenant-owned registrations containing public P-256 ES256 JWKs only;
- bind an issuance offer to the registered wallet client through an internal
  opaque identifier;
- verify RFC 7523 identity, audience, signature, bounded timestamps, and
  one-time `jti` through one application service used by REST and gRPC;
- reject embedded/private key material, unregistered or cross-tenant clients,
  transport bypasses, and assertion replay;
- atomically claim both authorization-code grant types so concurrent
  redemption has exactly one winner;
- bind organization-specific PAR endpoints to their organization and prevent
  form data from overriding that binding;
- advertise `none` globally and advertise `private_key_jwt` only in
  organization-scoped metadata where the registration can be resolved.

The public gateway accepts a typed authorized-client public JWKS through the
normal authenticated `/v1/issuance` route. It registers that public material
internally and sends only the opaque client identifier to the issuance
service. The official runner receives the corresponding disposable private
JWK through its mode-0600 local configuration. Wallet private keys do not
enter Marty, and this holder-client registration does not alter issuer
signing: issuer keys remain in managed custody and signing remains
issuer-profile mediated after DID-first resolution.

Evidence under review:

- [marty-credentials#67](https://github.com/ElevenID/marty-credentials/pull/67)
  implements the shared authentication service, tenant persistence, atomic
  replay/code claims, REST/gRPC parity, and truthful metadata;
- [marty-ui#133](https://github.com/ElevenID/marty-ui/pull/133) implements the
  normal public issuance contract and strict public-JWK validation;
- [marty-integration-tests#147](https://github.com/ElevenID/marty-integration-tests/pull/147)
  provisions two disposable clients without an internal-service or API-key
  issuance bypass.

The OID4VCI profile remains `planned`. These changes are necessary evidence,
but they are not sufficient to claim the official issuer profile until merged
component releases are pinned by digest and the complete upstream plan passes.

## Do the tests cheat?

No production-verification bypass has been found in the reviewed EUDI path:

- Marty is reconstructed from a released stack manifest and digest-pinned,
  attested images.
- Fixtures are created through the authenticated public gateway.
- Credential and request-object signing is issuer-profile mediated; test code
  obtains public keys and certificates but not issuer private keys.
- The official EUDI libraries create holder-bound presentations.
- Replay and invalid-signature cases mutate the exact library-produced bytes
  only after creation and are labeled `compatibility_only`; they are not
  represented as official-library dispatch cases.
- Raw logs, cookies, generated keys, and unredacted reports remain job-local.
- Evidence claims are bound one-to-one to stable JUnit evidence IDs and cannot
  pass when the corresponding test is missing, duplicated, skipped, failed, or
  errored.

Two paths must remain described as adapted:

- The EUDI wallet HTTP service is an ElevenID facade over pinned official JVM
  libraries, not the reference mobile wallet binary.
- The W3C suite reaches a gated VC-API-shaped facade. Valid issuance now
  traverses the ordinary product transaction/token/nonce/holder-proof path,
  and suite-specific semantic validation has been removed from the facade.
  The VC-API transport itself remains adapted and is not represented as a
  native Marty deployment endpoint.

No W3C pass may be claimed merely because the adapter rejects an invalid
fixture. Every negative assertion must be traceable to a shared production
validator or explicitly labeled adapted until that gap is removed.

OID4VP URL-query is not an adapted path. Marty supports the native signed
`request_uri` transport, including the OID4VP `request_uri_method=post`
wallet-nonce exchange. The OIDF adapter rejects any request method other than
`request_uri_signed`; it does not unpack a signed JAR and re-encode its claims
as URL-query parameters. URL-query remains explicitly unsupported until the
product implements it as a separately reviewed transport.

## Does the suite use Marty Protocol abstractions?

Partially.

The current `marty-protocol` contract defines DID-first issuance and
verification-flow inputs and includes conformance fixtures rejecting public
KMS selectors and profile-only issuance. The gateway and compliance clients
use the same public field names for organization, issuer DID, credential
template, presentation policy, issuance, and verification flow.

The runtime still owns duplicated Python and JavaScript request models rather
than consuming generated `marty-protocol` types at every public boundary.
Internal gRPC and persistence models legitimately retain
`issuer_profile_id`, but the separation is convention- and test-enforced
rather than generated from one schema. Contract drift is therefore reduced,
not eliminated.

Required follow-up:

- validate public requests and responses against the published schemas in CI;
- generate or consume shared types for all supported public clients;
- reject public-only fields at the gateway before internal translation;
- add response-shape fixtures, not only request fixtures;
- cover organization, policy, template, issuance, flow, and result schemas in
  the same drift gate.

## Organizations and multitenancy

The official lanes authenticate a disposable operator and create resources in
one configured organization. This proves organization-scoped happy paths but
does not prove tenant isolation.

Missing evidence:

- two authenticated organizations with distinct issuer DIDs and profiles;
- resource-ID substitution across templates, policies, flows, and results;
- cross-tenant issuer-DID resolution and ambiguous DID rejection;
- membership, role, API-key, and SCIM authorization boundaries;
- response, audit, webhook, and error-message leakage checks.

A dedicated two-organization adversarial matrix is required before the
multitenancy objective is satisfied.

Initial executable coverage in
[marty-integration-tests#154](https://github.com/ElevenID/marty-integration-tests/pull/154)
creates two disposable organizations through the normal authenticated gateway,
then proves that template lists do not leak and that template-issuance and
policy-template resource-ID substitutions fail closed.  It deliberately uses
one operator able to administer both organizations, so it tests resource
isolation independently of role assignment.  Membership, RBAC, API-key,
SCIM, result, audit, webhook, and error-message isolation remain separate
required matrix rows.

## Does the suite use the UI's general API?

The EUDI and OIDF paths use the same authenticated public gateway that the UI
is expected to use. They do not call KMS or the issuer signing service
directly. That is useful API-boundary evidence.

They do not drive the browser UI. Consequently they cannot prove that UI
forms omit deprecated selectors, generated clients match runtime responses,
or browser issuance and verification use only the supported general API.
A Playwright issuance-and-verification smoke test against released UI and
service images remains required.

## Features and gaps exposed

| Capability | Current evidence | Remaining gap |
| --- | --- | --- |
| DID-first OID4VCI issuance | Public-path EUDI issuance; tenant-bound `private_key_jwt` registration, REST/gRPC parity, replay rejection, atomic grant consumption, PAR binding, and DID-mediated signer calls are implemented in the current remediation set | Merge/release the remediation set and pass the complete official issuer interaction plan against its immutable artifacts |
| DID-first signed OID4VP request | Official OID4VP Final plan passes on immutable v1.1.38 | Keep the active profile green as the official runner updates |
| HAIP request-object trust | Official HAIP verifier plan passes on immutable v1.1.38 | Keep the active pre-certification profile green; fund certification separately |
| SD-JWT holder binding | Official-library KB-JWT and missing-key negative exposed a v1.1.38 fail-open policy interaction; marty-ui#126 makes OID4VP context authoritative | Release and prove corrupted holder signatures finalize as deny |
| mdoc issuance/presentation | EUDI libraries plus independent COSE/CBOR/X.509 checks; scheduled native OIDF ISO mDL verifier lane | Run and retain immutable official verifier evidence; OIDF has no suitable mdoc issuer plan, so keep issuance claims limited to EUDI/reference evidence |
| OID4VP URL-query transport | Explicitly unsupported; the official adapter accepts only native signed `request_uri` and rejects JAR-to-query rewriting | Do not claim URL-query coverage; implement it only as a separately reviewed product transport |
| W3C VCDM v2 verification and issuance | v1.1.42 contains the native proof, full-document, production-validator, general issuance API, and DID-mediated custody work; its immutable run reached the production DID resolver | Release the OpenBao PEM-to-JWK and EdDSA signing correction, then rerun the pinned suite against the new attested stack |
| UI issuance/verification | API paths only | Browser-driven released-stack smoke tests |
| Multitenancy | One organization | Two-organization adversarial isolation matrix |
| Protocol contract | DID-first schemas and request fixtures | Generated runtime/client types and response drift checks |
| Wider Marty feature model | Not covered by official suites | RBAC/SCIM, saved flows, vetting, devices, API keys, revocation, trust registries, notifications, audit, wallet profiles, DIDComm |

### Exposed-gap action ledger

| Finding | Classification | Impact | Owner/remediation | Status and required evidence |
| --- | --- | --- | --- | --- |
| W3C adapter reconstructed only `credentialSubject` | Bypass risk | Could pass top-level VCDM assertions without signing the tested document | `marty-core#72`, `marty-credentials#74`, `marty-ui#138` | Product code fixed locally/partly merged; requires released-stack official run |
| W3C adapter performed suite-specific semantic validation | Adapted gap / bypass risk | Negative cases could pass before production code saw the input | `marty-ui#138` deletes adapter-owned validation; `marty-credentials#74` owns structural and allowlisted digest validation | Remediated locally with production negative regressions; merge/release and immutable official rerun required |
| W3C adapter duplicated the general UI issuance boundary | API bypass risk | Private template/resolver calls could drift from the API the UI is required to use | `marty-ui#138` calls the shared general `create_issuance` path with only organization, public issuer DID, template, and complete document | Remediated locally; gateway tests assert no private resolver/template call and immutable official rerun remains required |
| Managed registry lacked `ldp_vc`/EdDSA | Missing feature | Public template bootstrap failed; unsafe ES256 substitution was possible if forced | Official fixture bootstrap plus managed EdDSA profile | Implemented locally; requires immutable stack proof |
| Public `application_id` was rejected downstream | Protocol drift | A gateway-valid issuance request could fail at the issuance service and lose application linkage | `marty-protocol` issuance schema and `marty-credentials` request/transaction mapping | Fixed locally; requires protocol and credentials CI/merge |
| Generated `credential_subject` type collapsed object/array to string | Protocol drift | Generated clients could not represent the production request | `marty-protocol` code generator and generated bindings | Fixed locally; Python/Rust/TypeScript checks pass |
| Official W3C registration claimed JOSE enveloping proof | Misleading claim | Selected assertions Marty was not exercising natively | `w3c_vc_conformance.py` registration | Fixed locally; official config now advertises `vc2.0` only |
| OpenBao public PEM was stored beneath `publicKeyJwk` | Product implementation gap | DID resolution rejected the managed EdDSA verification method before official assertions | `marty-ui#140` converts supported public keys to JWKs and fails closed on invalid material | Local gateway regression suite passes; merge, release, and immutable official rerun required |
| OpenBao prehashed EdDSA input and advertised DER output | Product implementation gap | Native Data Integrity signatures could not be produced or described correctly | `marty-ui#140` propagates the profile algorithm, sends raw EdDSA input, and returns raw signature metadata | Local gateway regression suite passes; merge, release, and immutable official rerun required |
| W3C fixture profile omitted its algorithm | Harness configuration gap | The managed Ed25519 key was provisioned behind a profile that defaulted to ES256 | `marty-integration-tests#157` explicitly declares EdDSA in profile administration | Unit tests pass; merge and include the released suite in the next stack manifest |
| Official lanes use one organization | Missing evidence | Tenant isolation and cross-tenant DID resolution remain unproven | Two-organization adversarial matrix | Partial template isolation exists; full matrix remains open |
| Official lanes do not drive the browser | Missing evidence | UI request shapes and exclusive general-API use remain unproven | Released-stack Playwright issuance/verification smoke | Open |

## Immutable evidence collected

| Evidence | Result |
| --- | --- |
| `marty-ui` v1.1.36, manifest `sha256:33273c4bbe6ccfc33f22735986f0019e21715f4adf99b425af99d6dccba80f7c` | 52/55 EUDI tests passed; real format/algorithm fixes validated |
| `marty-ui` v1.1.37, manifest `sha256:3a8ed3f65a98333bf75f1082ed181709b2910215db082ea443ac72e25c4a5897` | 53/55 passed; expiry negative corrected |
| `marty-ui` v1.1.38, manifest `sha256:091ea151f25c2297c2ad4546cfe089393301652039614379ce69516f353cf050` | 54/55 EUDI tests passed; the remaining negative exposed an authoritative fail-open holder-binding defect |
| EUDI run [30231825647](https://github.com/ElevenID/marty-integration-tests/actions/runs/30231825647), sanitized summary `sha256:d85211cd6d960d72a1c97921516f03db2a307229da2af8a010494b434e8e452f` | Failed safely and specifically as `eudi-invariant-tamper-final-decision-allow`; prompted marty-ui#126 |
| OID4VP Final run [30230194196](https://github.com/ElevenID/marty-integration-tests/actions/runs/30230194196), sanitized summary `sha256:f96a634c36b0adf65c77308272836b2a1dfb2f869e56051d4bdbe867c83d94ea` | Passed against v1.1.38 and official runner `release-v5.2.0` |
| HAIP run [30230195076](https://github.com/ElevenID/marty-integration-tests/actions/runs/30230195076), sanitized summary `sha256:b7a9200e66a59f5b319d2c095102e30e640e78df8a7dedf676caadc660332950` | Passed against v1.1.38 and official runner `release-v5.2.0` |
| W3C v2 run [30230312063](https://github.com/ElevenID/marty-integration-tests/actions/runs/30230312063), sanitized summary `sha256:5674d1b6c52e5d5291082f542af6c132a3b5ce72168f7dfe08fb9d7149d8e88b` | Failed at public template bootstrap; exposed missing managed `ldp_vc` capability |
| `marty-ui` v1.1.42, manifest `sha256:82404a3586fd2fd50b1fc6c99ef3f0c125dc25433247bf2f20c90c7b32b9e9b1` | Materialized seven immutable components and pulled the released credentials image anonymously |
| W3C v2 run [30348779384](https://github.com/ElevenID/marty-integration-tests/actions/runs/30348779384), sanitized artifact `official-w3c-v2-30348779384-1`, artifact digest `sha256:4d1cc64f224d7683dad284199bbabb4181b34dff6505c05929c78b891064e857` | Reached the production DID resolver and failed closed on malformed OpenBao public-key publication; exposed the PEM-to-JWK and EdDSA adapter gaps |
| OID4VCI issuer run [30230312937](https://github.com/ElevenID/marty-integration-tests/actions/runs/30230312937), sanitized summary `sha256:eacc7f2d7fd9edc2ffec43e3faaa590d1c733d429c74bcdaf47c7e3f7189b444` | Metadata passed; interaction modules exposed missing official-runner client identities |
| OID4VCI issuer run [30231686437](https://github.com/ElevenID/marty-integration-tests/actions/runs/30231686437), sanitized summary `sha256:4adb5cc1e43b14953fc3603a63f3e396a211890399d0de7914562e26a73852a9` | Authorization-server identity passed; exposed internal-template/public-configuration ID confusion |
| OID4VCI issuer run [30232003181](https://github.com/ElevenID/marty-integration-tests/actions/runs/30232003181), sanitized summary `sha256:de313a9f8dc4338f1ff83dbb0ae60822dda6f468fc7b219f3f0b41e25412d1cb` | Reached issuer interaction; exposed selection of bare JWT VC `PID` instead of advertised SD-JWT `PID#sd-jwt` |

The report must be updated with the passing run URL, harness commit, sanitized
artifact digest, and final count before the v1.1.38 pin is described as ready.

## Completion criteria for this report

This report becomes final only when:

- the immutable v1.1.39-or-newer EUDI lane passes with all required evidence;
- the default stack pin names that reviewed release;
- OID4VP Final, HAIP, W3C v2, and applicable mdoc official lanes have explicit
  native/adapted/unsupported outcomes;
- the two-organization matrix and browser UI path have executable evidence;
- public protocol schema drift is enforced in CI; and
- every remaining limitation links to an owned remediation item.
