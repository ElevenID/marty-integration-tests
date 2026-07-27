# Protocol Compliance Post-Action Report

Status: in progress  
Last updated: 2026-07-26

## Purpose

This report records what the official OIDF, W3C, and EUDI interoperability
work actually exercised, what it exposed in Marty, which findings have been
corrected, and which product gaps remain. A passing adapted test is not treated
as proof of native product support or certification.

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

Action: assert the stable security boundary:

- the first valid response is accepted and its authenticated result is allow;
- replay and tampered-signature submissions never produce an authenticated
  allow result or a 5xx callback;
- public callbacks disclose no internal decision or verified claims;
- an invalid response either finalizes as an authenticated deny or remains a
  retryable flow with no result resource; a retryable outcome must use 4xx,
  while a 2xx callback is accepted only with a completed authenticated deny;
- an expired request fails in the official resolver before dispatch.

This change does not accept 5xx errors, disable signature verification, inject
an allow result, or mutate production evidence.

### 4. The checked-in immutable stack pin lagged the reviewed release

Manual investigation used reviewed tag and manifest overrides while
`conformance/stack-under-test.json` still named `marty-ui` v1.1.34. The
released DID-first fixes are in v1.1.38.

Action required: after the final v1.1.38 lane is green, update the checked-in
pin to v1.1.38 and its independently verified manifest digest.

### 5. The old stack proved that the harness does not silently fall back

Running the current harness against v1.1.34 stopped at public credential
template creation because that release required `issuer_profile_id`. The
harness did not add the deprecated selector to make the run proceed. This is
useful negative evidence that the DID-only public boundary is enforced by the
test client rather than bypassed for compatibility.

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
- The W3C suite currently reaches a gated VC-API-shaped adapter. It must move
  to a supported public VC-API or the ordinary product path before Marty
  claims native VC-API coverage.

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
| DID-first OID4VCI issuance | Public-path EUDI issuance on corrected releases | Activate and keep the official OIDF issuer plan green |
| DID-first signed OID4VP request | Public request-URI flow and EUDI library resolution | Complete every official OID4VP Final module |
| HAIP request-object trust | Signed JAR, `x509_hash`, separate PKIX trust in EUDI lane | Complete the official HAIP verifier plan |
| SD-JWT holder binding | Official-library KB-JWT and missing-key negative | Keep invalid signature and replay evidence green |
| mdoc issuance/presentation | EUDI libraries plus independent COSE/CBOR/X.509 checks | Add applicable official OIDF mdoc issuer/verifier coverage |
| OID4VP URL-query transport | Not synthesized or claimed | Implement natively or explicitly retain unsupported status |
| W3C VCDM v2 verification | Adapted official-suite execution | Supported public path and native Data Integrity issuance |
| UI issuance/verification | API paths only | Browser-driven released-stack smoke tests |
| Multitenancy | One organization | Two-organization adversarial isolation matrix |
| Protocol contract | DID-first schemas and request fixtures | Generated runtime/client types and response drift checks |
| Wider Marty feature model | Not covered by official suites | RBAC/SCIM, saved flows, vetting, devices, API keys, revocation, trust registries, notifications, audit, wallet profiles, DIDComm |

## Immutable evidence collected

| Evidence | Result |
| --- | --- |
| `marty-ui` v1.1.36, manifest `sha256:33273c4bbe6ccfc33f22735986f0019e21715f4adf99b425af99d6dccba80f7c` | 52/55 EUDI tests passed; real format/algorithm fixes validated |
| `marty-ui` v1.1.37, manifest `sha256:3a8ed3f65a98333bf75f1082ed181709b2910215db082ea443ac72e25c4a5897` | 53/55 passed; expiry negative corrected |
| `marty-ui` v1.1.38, manifest `sha256:091ea151f25c2297c2ad4546cfe089393301652039614379ce69516f353cf050` | Final EUDI negative assertion under investigation |

The report must be updated with the passing run URL, harness commit, sanitized
artifact digest, and final count before the v1.1.38 pin is described as ready.

## Completion criteria for this report

This report becomes final only when:

- the immutable v1.1.38-or-newer EUDI lane passes with all required evidence;
- the default stack pin names that reviewed release;
- OID4VP Final, HAIP, W3C v2, and applicable mdoc official lanes have explicit
  native/adapted/unsupported outcomes;
- the two-organization matrix and browser UI path have executable evidence;
- public protocol schema drift is enforced in CI; and
- every remaining limitation links to an owned remediation item.
