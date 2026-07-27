# Protocol Compliance Post-Action Report

Status: in progress  
Last updated: 2026-07-27

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

### 7. W3C Data Integrity had no managed signer capability

The official W3C lane stopped at the public credential-template API with HTTP
404 because the managed signer registry did not advertise `ldp_vc`. This was a
real production configuration gap. Marty supports the
`eddsa-rdfc-2022` verification suite; assigning Data Integrity to the default
ES256 key would have falsely advertised an unsupported cryptographic pairing.

Action: normalize W3C Data Integrity aliases to `ldp_vc`, advertise that
format only on the managed EdDSA issuer key, and provision separate JWT/ES256
and Data Integrity/EdDSA profiles sharing the same issuer DID. Runtime callers
still provide only the issuer DID; custody selectors remain administrative.
A released-stack rerun is required before the adapted W3C lane is green.

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
- The W3C suite currently reaches a gated VC-API-shaped adapter. It must move
  to a supported public VC-API or the ordinary product path before Marty
  claims native VC-API coverage.

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
| DID-first OID4VCI issuance | Public-path EUDI issuance; official metadata module passes; tenant-bound `private_key_jwt` registration, REST/gRPC parity, replay rejection, atomic grant consumption, and PAR binding are implemented in the current remediation set | Release the remediation set and pass the complete official issuer interaction plan against its immutable artifacts |
| DID-first signed OID4VP request | Official OID4VP Final plan passes on immutable v1.1.38 | Keep the active profile green as the official runner updates |
| HAIP request-object trust | Official HAIP verifier plan passes on immutable v1.1.38 | Keep the active pre-certification profile green; fund certification separately |
| SD-JWT holder binding | Official-library KB-JWT and missing-key negative exposed a v1.1.38 fail-open policy interaction; marty-ui#126 makes OID4VP context authoritative | Release and prove corrupted holder signatures finalize as deny |
| mdoc issuance/presentation | EUDI libraries plus independent COSE/CBOR/X.509 checks | Add applicable official OIDF mdoc issuer/verifier coverage |
| OID4VP URL-query transport | Explicitly unsupported; the official adapter accepts only native signed `request_uri` and rejects JAR-to-query rewriting | Do not claim URL-query coverage; implement it only as a separately reviewed product transport |
| W3C VCDM v2 verification | Public bootstrap exposed missing `ldp_vc` managed capability | Release the EdDSA profile fix, rerun the adapted suite, then add native Data Integrity issuance |
| UI issuance/verification | API paths only | Browser-driven released-stack smoke tests |
| Multitenancy | One organization | Two-organization adversarial isolation matrix |
| Protocol contract | DID-first schemas and request fixtures | Generated runtime/client types and response drift checks |
| Wider Marty feature model | Not covered by official suites | RBAC/SCIM, saved flows, vetting, devices, API keys, revocation, trust registries, notifications, audit, wallet profiles, DIDComm |

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
