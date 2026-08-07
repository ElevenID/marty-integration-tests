# Protocol Compliance Post-Action Report

Status: in progress  
Last updated: 2026-08-07

## Current evidence snapshot

The current stack under test is immutable `marty-ui` v1.1.112 at release
commit `f83f068e2d201b9cbb248d8741b49d470f0cd4fc` and manifest digest
`sha256:698180c0e3f2df93ff52ad05442206216c029c7f79208a246edabc60f5366190`.
[OID4VP Final run 31206756608](https://github.com/ElevenID/marty-integration-tests/actions/runs/31206756608),
[URL-query run 31207275778](https://github.com/ElevenID/marty-integration-tests/actions/runs/31207275778),
and [HAIP run 31207277971](https://github.com/ElevenID/marty-integration-tests/actions/runs/31207277971)
executed exact harness `bf0e6d5b2d099768e3ee0b3987edeb669143a971` and
unmodified OIDF `release-v5.2.2` commit
`321bc5bc53601b9690b54c023c0cbfac0f0230f2`. Imported source,
assertions, fixtures, expected results, selections, and exclusions remained
unchanged.

- OID4VCI issuer, W3C VC Data Model v2, and EUDI completed successfully.
- OIDF 5.2.2 added a required verification-result screenshot/review step for
  verifier responses returning 2xx. Marty's OID4VP Final, URL-query, and HAIP
  product interactions first exposed a runner-TLS trust defect and then a
  missing top-level test alias. The latter caused OIDF to serve `/test/{id}`
  while its own reviewed browser matcher accepts only `/test/a/{alias}`.
  PRs #283 and #285 corrected only disposable runner topology/configuration;
  no imported source, assertion, fixture, expected result, selection, or
  exclusion changed. Exact immutable reruns now pass Final, native URL-query,
  and HAIP with zero expected failures/skips and all official screenshot
  placeholders filled.
- The unchanged W3C VC Data Model v2 suite at commit
  `e92936564867da9150b99b167fe1c73b9370ad6c` passed its issuer, credential
  verifier, and presentation verifier capabilities under Node 24.
- The EUDI lane passed 45 tests with zero failures, errors, or skips. It
  exercised official current OID4VCI, OID4VP, SD-JWT, Multipaz, and verifier
  components across SD-JWT VC and mdoc issuance/presentation, trusted request
  objects, wallet-key attestation, replay, invalid-signature, expired-request,
  and missing-holder-binding-key cases.
- The OIDF mdoc lane executed all five official modules. Its invalid-session-
  transcript negative passed, while all three positive presentations reached
  Marty's normal authorization endpoint and were rejected with HTTP 400. The
  renewed certificate is current, but remains `CA:true` with
  `keyCertSign,cRLSign`; ISO 18013-5 Table B.3 requires a document signer with
  `digitalSignature`. OIDF tracks the defect in
  [work item 1891](https://gitlab.com/openid/conformance-suite/-/work_items/1891).
  Marty correctly keeps its profile validation enabled for exact pins, so the
  lane remains visibly red until an unmodified reviewed OIDF release fixes the
  fixture. No product trust rule or imported test is weakened.

Separately labeled ElevenID-owned product-security evidence now includes:

- forced ambiguous issuer-profile rejection and recovery against exact
  v1.1.105 in
  [run 31145134598](https://github.com/ElevenID/marty-integration-tests/actions/runs/31145134598);
  and
- CA-validated HTTPS DIDComm v2 delivery, holder-key decryption, Issue
  Credential plaintext equality through an independent implementation, and
  cross-tenant transaction-substitution denial against exact v1.1.112 in
  [run 31198519056](https://github.com/ElevenID/marty-integration-tests/actions/runs/31198519056).

Neither owned lane is an official standards-conformance result. The DIDComm
receiver remains an ElevenID-owned minimal HTTPS agent, but the exact reviewed
`notabene-id/go-didcomm` release independently decrypts and classifies Marty's
envelope. This proves cross-implementation interoperability for the selected
outbound profile, not independent full-agent exchange, official certification,
or complete DIDComm compliance.

One earlier v1.1.97 W3C invocation reported a single transient
issuer request failure. The exact same immutable images and upstream commit
then passed. The released native binding, released issuance wrapper, and
concurrent canonicalization path also completed repeated copies of the exact
temporality/status shape without failure. No standard assertion or product
validation was weakened in response; the successful unchanged-suite rerun is
the current evidence, and future recurrence must be investigated from
product-owned service diagnostics.

Because the stack remains pre-1.0, obsolete selectors, aliases, deprecated
formats, and compatibility-only code are removed rather than preserved.
This does not authorize removal of current standards capabilities: mdoc,
SD-JWT VC, JWT VC, VCDM v2 Data Integrity, OID4VCI, OID4VP, HAIP, and EUDI
paths remain acceptance requirements.

Open Badges 2 is the one explicit temporary compatibility exception. It
remains supported for a short migration period under
[marty-ui issue 260](https://github.com/ElevenID/marty-ui/issues/260), with a
2026-09-01 review and 2026-10-01 target removal. Its retention does not
authorize restoring any private signing selector or weakening Open Badges 3
coverage.

## Owned pseudo-conformance retirement (2026-08-06)

The local regression target previously included two obsolete ElevenID-owned
files that could be mistaken for official evidence. One called itself
"OIDF-mirrored" while its positive OID4VP path embedded a placeholder
credential and could construct a zero-signature token. The other targeted
SIOPv2 Draft 13, generated only zero-signature ID tokens, and explicitly said
all tests were expected to fail until an unimplemented feature existed.

Both files were removed rather than repaired or relabeled. They did not import
or execute the official runner, did not provide passing production evidence,
and their removal does not remove a supported product capability. Current
OID4VP coverage remains the exact unmodified OIDF OID4VP Final, URL-query, and
HAIP plans plus the released browser product-path smoke. Current local
`conformance-local` is explicitly an ElevenID-owned OID4VCI regression and
cannot be presented as official-suite evidence. A repository guard rejects a
future owned suite that uses mirrored/official claims, placeholder positive
credentials, dummy signatures, or expected-to-fail semantics.

Imported official source remains unchanged. Open Badges 2 is also unchanged
and remains the sole time-bounded legacy exception described above.

## Current EUDI wallet-library upgrade audit (2026-08-02)

The EUDI lane now pins the current official OID4VCI wallet library v0.13.0
source at commit `07dc0b96dcd5c56197414c80c0fb70ce0d4f377d`. The retired web-wallet
tester and its draft-era behavior were removed. Imported upstream source,
assertions, expected results, selections, and exclusions remain unchanged.

The upgrade exposed four product or ElevenID-harness defects before a
credential could be accepted:

1. Marty's JWT proof metadata omitted `key_attestations_required` when a
   profile imposed no additional wallet-key constraints. The current official
   EUDI parser rejects that metadata instead of treating the member as absent.
2. The ElevenID HTTP facade returned a JOSE raw `r || s` ECDSA signature from
   its callback. The official library's callback contract expects JCA/ASN.1
   DER and performs the DER-to-JOSE conversion itself. This produced an
   `Invalid ECDSA signature format` error inside the official library.
3. Marty rejected the current ETSI key-attestation proof selector `kid: "0"`.
   In this profile it means the first public key in the already validated
   `attested_keys` array; it is not an unrestricted numeric index or a public
   KMS selector.
4. One owned SD-JWT fixture created a second profile for an already provisioned
   issuer DID, while owned mdoc and DTC fixtures created purpose-specific
   profiles without the external wallet-attester trust policy. The duplicate
   path is removed, and each legitimate format/purpose profile is configured
   explicitly through the public profile-administration API.

No compliance assertion was relaxed to address these findings. The obsolete
Python pseudo-wallet tests and a dummy-presentation event-count test were
deleted because they bypassed current key attestation or submitted an invalid
placeholder presentation and therefore provided misleading evidence. Current
positive evidence must traverse the official wallet library, the public
organization-scoped gateway, DID-first profile resolution, issuer-profile
mediated custody, and the production issuance or verification callback.
Crafted-response helpers remain evidence only for negative signature, replay,
expiry, and malformed-input cases; they cannot establish a positive
interoperability claim.

The remediation passed its release gate in
[run 30739444518](https://github.com/ElevenID/marty-integration-tests/actions/runs/30739444518).
The run executed harness commit
`abd99e71234309091d9e21128fa686780ffe226f` against immutable `marty-ui`
v1.1.94 commit `0c1740491619f04aae11f69ca50e3346917d61c9` and the manifest digest above.
All 45 tests passed with zero failures, errors, or skips. The evidence pins
official OID4VCI library v0.13.0 at
`07dc0b96dcd5c56197414c80c0fb70ce0d4f377d`, OID4VP v0.15.1, SD-JWT
v0.20.1, Multipaz v0.100.0, and verifier endpoint v0.11.0. The sanitized
artifact is ID `8830838450`, digest
`sha256:7725c9a8f6b93170967fe8803ae72c5cf198178cb8e2bc83931ee9ed75fb3b17`.
It records the released issuance image
`sha256:a0a0962dd5c6fa113fb0dbb265ba1a2ceaa76a98af4df0ecbf19c0548593df92`
and UI, services, and migrations image digests. Imported official source and
assertions were not changed; only ElevenID-owned adapters, fixtures, and
negative-response mutation helpers changed.

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

Manual investigation initially used reviewed tag and manifest overrides while
`conformance/stack-under-test.json` still named `marty-ui` v1.1.34. That could
cause a default or scheduled lane to test an obsolete pre-DID-first stack even
while manually dispatched evidence used newer artifacts.

Action completed: the checked-in pin now names `marty-ui` v1.1.90 and its
independently verified manifest digest
`sha256:1529c3f8e28cec088ae14f4173fc2223a8a7bffeffe87ec9d21c157fbe4811f9`.
Overrides remain available for controlled candidate testing, but the default
is the latest stack that passed its artifact-only release gate, released-browser
issuance and verification journey, unmodified OIDF OID4VP Final verifier lane,
and the active direct URL-query verifier lane. Earlier immutable releases,
including the v1.1.66 native ISO mDL result, remain bound to their original
evidence rather than being reinterpreted through this newer pin.

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

### 6b. The official ISO mDL lane exposed silent claim-contract loss

The first cryptographically valid official presentations passed issuer
signature, certificate trust, and device-authentication checks but were denied
by Marty's presentation policy because the requested mdoc claim namespace had
been lost at the public gateway. `marty-protocol` already defined the canonical
`namespace` field; a duplicated gateway model omitted it, and its permissive
validation silently discarded it before the credential-template service could
map it to the ISO mdoc namespace and element identifier.

[marty-ui#187](https://github.com/ElevenID/marty-ui/pull/187) preserves the
canonical namespace across the public gateway and internal template boundary.
The stricter model then exposed adjacent drift: valid protocol fields
`description`, canonical `display`, and `derived_from` were also absent or
reconstructed incorrectly. [marty-ui#189](https://github.com/ElevenID/marty-ui/pull/189)
preserves those fields through the gateway, protobuf, service, and persistence
layers and rejects unknown, duplicate, self-derived, or missing-source claims.
[marty-integration-tests#186](https://github.com/ElevenID/marty-integration-tests/pull/186)
uses the canonical public namespace in the ElevenID-owned fixture.

The exact released v1.1.66 stack then passed all three active official modules:
the happy flow, `request_uri_method=post`, and invalid-session-transcript
negative. The official runner reported 134 successes, zero failures, and zero
warnings, with no expected failures or skips. The invalid transcript was
rejected because nonce and transcript bindings failed while issuer, trust,
device-signature, response-URI, and presentation-definition bindings remained
intact.

This run used OIDF commit
`dee9a25160e789f0f80517674693ef7989ab9fa1` from the unmodified
`openid/conformance-suite` checkout. Its HEAD matched before and after
execution; tracked, staged, and untracked state were clean after execution. No
assertion, fixture, expected result, test selection, exclusion, or upstream
source file was changed. All compatibility work remained in Marty product code,
deployment, or the separately owned ElevenID harness.

The lane exercised the authenticated public gateway, a disposable organization,
tenant-scoped template, policy and flow resources, the public request URI and
callback, and the normal flow/policy/template gRPC path. Signing remained
issuer-profile mediated through managed custody. The test sent no public
profile, KMS, service, or key selector. It proves one-organization public API
behavior, not browser UI behavior or adversarial cross-tenant isolation.

### 6c. Released-browser evidence exposed a legacy DID-binding bypass

The first released-browser product-path run against immutable `marty-ui`
v1.1.68 failed before applying for a credential because the active seeded
`Member Login Credential` had no public `issuer_did`. The same template had
previously issued successfully. Source review showed why: the artifact-pipeline
migration added the DID column and populated internal `issuer_profile_id`,
remote-signing mode, and KMS key metadata, but never backfilled the public DID.
The legacy flow could therefore reach managed signing through internal profile
state even though the catalog did not expose the DID-first identity required by
the public contract.

This failure came from the separate ElevenID-owned browser smoke in
[run 30499787424](https://github.com/ElevenID/marty-integration-tests/actions/runs/30499787424).
The exact unmodified OIDF suite in the same run remained green: 11 modules,
417 successes, zero failures, and zero warnings. No upstream assertion,
fixture, expected result, test selection, exclusion, or source file was changed
to obtain either result.

The first remediation release exposed a second, independent legacy selector
in [run 30501528652](https://github.com/ElevenID/marty-integration-tests/actions/runs/30501528652).
The disposable credential template correctly supplied only its organization,
public issuer DID, format, and algorithm, but flow-definition validation still
read the removed protobuf fields `issuer_profile_id` and `key_access_mode`.
Those fields are intentionally reserved and absent from
`TemplateResponse`, so a valid DID-only template could never satisfy that
check. The harness did not add either private field to make the test pass.

Remediation completed:

- [marty-ui#194](https://github.com/ElevenID/marty-ui/pull/194) adds a one-way
  migration that binds active Marty templates already using a KMS-backed remote
  issuer profile to that profile's public `did:web` identity. Existing non-empty
  DID bindings are preserved.
- [marty-ui#196](https://github.com/ElevenID/marty-ui/pull/196) removes the
  stale flow-service selector check. The flow now resolves
  `organization_id + issuer_did + credential format + key purpose + algorithm`
  through the internal organization-scoped resolver and requires exactly one
  active KMS-backed issuer profile. Public callers still cannot select the
  profile, service, KMS provider, or key reference.
- The ElevenID harness now creates a disposable DID-bound MemberCredential,
  linked active Application Template, and normal application-approved OID4VCI
  flow through the public gateway. The released browser selects those exact
  fixture IDs, so evidence no longer depends on ambient demo data.
- Public browser requests and responses continue to reject issuer-profile,
  signing-service, key-reference, KMS-provider, and custody selectors.

Immutable `marty-ui` v1.1.70 passed the exact released-stack rerun in
[run 30503123595](https://github.com/ElevenID/marty-integration-tests/actions/runs/30503123595).
The stack manifest digest was
`sha256:cb157c988fd0be7a623b1c28b46ddb4524caa1343667357976556c725d5fe58d`
and resolved Marty commit
`d9a1cf91f941ca6e787f6c474e6352b28678e448`. The browser completed the
normal public verification, application, claim, and submit routes for one
disposable organization; received a credential offer; observed no private
selector; and used the exact DID-bound fixture IDs.

The unmodified OIDF verifier suite in that same run also passed all 11
executed modules with 417 successes, zero failures, and zero warnings. The
runner was exact commit
`dee9a25160e789f0f80517674693ef7989ab9fa1`, with no expected failures or
skips. Its checkout-clean guards passed before and after execution. No
upstream test, assertion, fixture, expected result, selection, exclusion, or
source file was modified. This closes the released-browser DID-binding gap
without weakening the compliance suite.

The merged harness and final stack rerun then exposed one more product-path
leak. [Run 30504449794](https://github.com/ElevenID/marty-integration-tests/actions/runs/30504449794)
used the released v1.1.71 stack and the released v1.2.30 harness. The exact
unmodified OIDF plan still passed all 11 modules with 417 successes, zero
failures, and zero warnings, but the ElevenID-owned browser boundary check
failed because the browser requested `/v1/signing-keys/issuer-profiles`.

The verification manager was already using the public
`/v1/signing-keys/issuer-identities` projection. The internal request came from
the transient organization-dashboard route used while switching from the
applicant console to verification. Its readiness hook still loaded full issuer
profiles. The credential-template authoring step independently used the same
internal collection even though it displayed only a DID. That meant ordinary
dashboard and template-authoring journeys could receive custody coordinates
that the public abstraction intentionally hides.

[marty-ui#204](https://github.com/ElevenID/marty-ui/pull/204) replaces both
ordinary-journey lookups with the public issuer-identity projection. Dashboard
readiness now matches an active public DID and compatible algorithm; the
organization registry remains responsible for resolving that identity to
managed custody. The template wizard submits only the public DID and no longer
constructs profile, service, key-reference, mode, or KMS fields. Explicit
issuer-profile administration pages remain available for authorized custody
setup. Focused regressions prove the template journey does not request
`/issuer-profiles`, and the complete UI suite passed 1,061 tests under Node 24
and Vite 8.

Immutable `marty-ui` v1.1.72 closes the leak. Its release commit is
`28ec57babcb8ff69f80d06c0f933476623f9caaa`; its manifest digest is
`sha256:792b00ccd367044d51ff7ece87e3303513536ade7cd77fe276c2d5a73968031f`.
All release input, image, provenance, signature, SBOM, artifact-only smoke, and
manifest publication jobs passed in
[run 30505939766](https://github.com/ElevenID/marty-ui/actions/runs/30505939766).

The exact released-stack rerun in
[run 30506329100](https://github.com/ElevenID/marty-integration-tests/actions/runs/30506329100)
used harness commit `f3d23e91fd326f47e967a419a0bcc168af80125b`.
The real browser completed organization-scoped application creation,
submission, claim, credential-offer receipt, and signed verification through
the normal gateway. Every public request used the organization and issuer DID;
no private selector or internal issuer-profile request was observed.

The official runner in the same run was the exact `release-v5.2.0` commit
`dee9a25160e789f0f80517674693ef7989ab9fa1`. It ran 11 modules with
417 successes, zero failures, and zero warnings, with no expected failures or
skips. The checkout guard verified the exact commit and clean source policy;
no upstream test, assertion, fixture, expected result, test selection,
exclusion, or source file was changed. This result therefore fixes product
code while preserving the official suite as independent compliance evidence.

### 6d. The final browser rerun exposed an obsolete compliance-profile path

The first OIDF 5.2.1 reruns after the application-template integration repair
proved two independent facts. URL-query and HAIP passed unchanged against
v1.1.82, and the official OID4VP Final plan itself also passed all 11 modules
with 417 successes, zero failures, and zero warnings. The combined OID4VP lane
still failed because its separately labeled ElevenID-owned browser smoke
received HTTP 500 while listing `/v1/credential-templates`.

The traceback showed that older seeded templates predated
`compliance_profile_id`. One null row caused strict response validation to
abort the entire organization catalog. Making the response field optional
would have made the browser pass, but the pinned Marty Protocol contract
correctly rejected that change: every Credential Template must reference a
real Compliance Profile. The failure therefore exposed an obsolete inline
`CUSTOM` compliance hint and missing data migration, not a reason to weaken
the public abstraction.

[marty-ui#233](https://github.com/ElevenID/marty-ui/pull/233) resolves the
architectural gap without deleting credential functionality. It adds stable
system profiles for OID4VC, ISO 18013-5 mdoc, Open Badges 3.0, and ICAO VDS-NC;
maps every existing active and deprecated template to the format-appropriate
profile; and makes the database relationship non-null after the one-way
backfill. Runtime proof against a cloned v1.1.82 database mapped all 19 rows
with no nulls: 9 OID4VC, 3 mdoc, 2 Open Badges, and 5 VDS-NC. The exact pinned
Marty Protocol checker and the full GitHub service, UI, security, browser,
release, dependency, and workflow gates passed.

Immutable v1.1.83 then passed its artifact-only release pipeline in
[run 30693812851](https://github.com/ElevenID/marty-ui/actions/runs/30693812851).
Its release commit is `922472494eedc64b74f62f66a259770ab2b019c7`, and the
attested manifest pins UI
`sha256:b65ccf5f2bfff8673515db415953d493e9d77f0913ac34f828b5f82805b76542`,
services
`sha256:5d832508f6a0628c932715d494e0a658343a0aa2a4765bb3ff15f29e88b71c23`,
and migrations
`sha256:e6de605de5d584480af621af5127b67af19dd1f604afe5bf6a7513e5a4d59230`.

The exact-stack rerun in
[run 30694181042](https://github.com/ElevenID/marty-integration-tests/actions/runs/30694181042)
passed end to end. The exact unmodified OIDF `release-v5.2.1` commit
`932b46f1e507871eb0b34621aaef65ff04442e6f` ran 11 modules with 417
successes, zero failures, and zero warnings, with no expected failures or
skips. The independent browser evidence completed organization-scoped
application, submit, claim, credential-offer, and DID-only verification paths
and observed no profile, service, key, or KMS selector. No imported runner,
test, assertion, fixture, expected result, selection, exclusion, or source
file was changed to obtain this result.

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

### 7b. The managed EdDSA key was not converted from OpenBao's native form

The first W3C run against immutable `marty-ui` v1.1.42 passed stack
materialization, provenance verification, anonymous image pulls, and public
fixture setup through issuer-profile creation. It then failed at the normal
public credential-template API with HTTP 503:

`Issuer DID verification method has no usable public key material.`

This was a production defect, not an official-runner or adapter failure. The
gateway stored an OpenBao provider metadata object beneath `publicKeyJwk`, so
the DID resolver correctly rejected the verification method because it had no
JWK `kty`. The same adapter always prehashed signing input with SHA-256, which
is invalid for OpenBao Ed25519 keys, and the public signing response would
have mislabeled the resulting Ed25519 bytes as DER.

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
merged the first fixes and regression tests. Immutable v1.1.43 then exposed a
second, more precise representation gap while creating the issuer profile:
OpenBao 2 returns Ed25519 public keys as standard-base64 raw 32-byte values,
while its P-256 and RSA keys are PEM. The fail-closed PEM parser correctly
rejected the raw value. This behavior was reproduced against the exact
digest-pinned conformance OpenBao image.

[marty-ui#142](https://github.com/ElevenID/marty-ui/pull/142) adds type-aware,
length-checked raw Ed25519 decoding while preserving PEM support for EC, RSA,
and compatible Ed25519 responses. All issuer private keys remain in OpenBao,
and the runtime request still selects only the organization and issuer DID.
The fix is released in immutable stack v1.1.44. Its official rerun passed both
earlier OpenBao boundaries and reached the upstream W3C assertions.

### 7c. Duplicated generated protobuf code dropped the template issuer DID

The v1.1.44 run successfully provisioned the real OpenBao Ed25519 key, created
the issuer profile, published usable DID verification material, created the
W3C resources through the authenticated gateway, and started the pinned
official W3C suite. Most positive issuer assertions then received HTTP 422:

`credential_template_id must reference a template with an issuer_did`

The public fixture supplied `issuer_did`, and the credential-template service
correctly resolved, persisted, and returned it. The issuance image nevertheless
shipped an older duplicate of `credential_template_service_pb2.py` whose
`TemplateResponse` descriptor ended at field 27. Protobuf treated the service's
new field 28 as unknown and silently discarded it. The gRPC request therefore
succeeded while the DID appeared absent, so the production issuance guard
correctly rejected the template as legacy.

This is protocol transport drift, not a missing issuer feature and not a reason
to weaken the guard. One shared descriptor defect caused many apparent
failures—including contexts, subjects, types, validity, status, schema, and
related-resource cases—before cryptographic issuance began. Those capabilities
remain unproven until the rerun reaches their individual assertions.

The evidence guard did not count attempted requests as successful coverage.
Although the upstream process invoked issuer and credential-verifier cases,
the sanitized result credited only `vp_verifier`, the sole required normative
role row that passed. The lane remains failed unless passed official report
rows prove `issuer`, `vc_verifier`, and `vp_verifier`; a zero process exit alone
is insufficient.

Action:

- synchronize the issuance image's credential-template descriptor with the
  current DID-first service contract;
- assert field numbers for `issuer_did` on create, update, and response;
- assert that public protobuf requests cannot reintroduce issuer-profile,
  signing-key, access-mode, or remote-KMS selectors; and
- retain the fail-closed legacy-template and DID-mismatch checks.

[marty-credentials#77](https://github.com/ElevenID/marty-credentials/pull/77)
contains this remediation and its descriptor regression. The finding also
strengthens the case for generated/shared internal contracts instead of
independently copied protobuf outputs. The change merged after its complete
Python, Rust, WASM, migration, security, dependency-review, CodeQL, and
workflow-policy matrix passed. It is released as `marty-credentials` v0.1.24
and pinned by immutable stack v1.1.45.

The same run exposed a separate error-boundary defect in one negative
assertion. The VC-API facade validates its outer shape through FastAPI, then
constructs the normal public `IssuanceCreate` model for the inner credential.
An invalid empty `credentialSubject` therefore raised Pydantic validation
inside the route and produced an unhandled ASGI traceback. The document was
not accepted, but invalid public input must return a controlled 422 without
logging credential content or internal stack details.

[marty-ui#144](https://github.com/ElevenID/marty-ui/pull/144) translates that
production-model validation result at the compatibility boundary. It does not
relax the validator, make a negative assertion pass as valid, or bypass the
normal issuance path. The change merged after its service, browser, UI,
security, release-contract, and workflow-policy checks passed and is included
in immutable stack v1.1.45.

### 7d. The descriptor-corrected run exposed two final W3C product gaps

Immutable v1.1.45 passed stack provenance, anonymous digest pulls, managed
Ed25519 provisioning, issuer-DID resolution, the general issuance transaction,
token, nonce, holder-proof, remote profile-mediated signature, and the
official W3C runner bootstrap. The official suite passed 35 normative
assertions and failed three:

- two valid Data Integrity credentials reached the public verifier but were
  classified as an unknown format before the Rust VCDM verifier ran; and
- a syntactically valid credential whose `validUntil` was in the past was
  rejected during issuance completion as expired.

The first defect was caused by transport routing that required both an exact
VCDM context and a `DataIntegrityProof` before invoking the released verifier.
Candidate detection is not semantic acceptance. A document with a Data
Integrity proof must reach the VCDM verifier, which remains responsible for
context, type, proof configuration, signature, and current-validity checks.

The second defect conflated issuance correctness with relying-party acceptance
at the current instant. VCDM v2 permits a syntactically valid `validFrom` in
the future or `validUntil` in the past. Remote signing completion must validate
the date syntax and ordering and verify the exact returned proof, but it must
not refuse to create the document solely because it is not currently valid.
The normal public verifier continues to reject expired and premature
credentials.

Released remediation:

- [marty-ui#146](https://github.com/ElevenID/marty-ui/pull/146) routes
  `DataIntegrityProof` candidates to the released Rust verifier and proves
  that an invalid context still fails there. It merged as
  `52e35cbceb06d9d2ed541f9e36b7be79d7ba9bbc` after the complete service,
  browser, UI, security, release-contract, CodeQL, dependency, and policy
  checks passed; and
- [marty-core#75](https://github.com/ElevenID/marty-core/pull/75) separates
  proof completion from current-time verification, validates RFC 3339 syntax
  and date ordering, and adds past, future, malformed, reversed, tampered, and
  invalid-signature regressions. It merged as
  `13b690b7bb61c004d75d5faff297f8c07bcb6d9e`, passed the 174-test library
  suite, integrations, documentation, Clippy, feature combinations, and the
  complete GitHub matrix, and is released in `marty-core` v0.1.23.

This is not a test accommodation: no official input is rewritten, no signature
is fabricated, and the public verifier's current-time policy is not weakened.
`marty-credentials` v0.1.25 consumes the corrected core and publishes the
issuance image as
`sha256:45bc3dfd6623d3350f35147942d380dff2761b1ce49ebdee6c42edb5200c3c94`
and the verification image as
`sha256:72e680b8a237f0dd5934341af88d25e1b99e3bb8340328bf49c99ca340fc8cda`.
The three assertions remain failed until one attested stack manifest pins
these releases and the exact official suite passes against it.

### 7e. The immutable rerun exposed source/image drift and did:web verification

Immutable stack v1.1.46 correctly pins core v0.1.23, credentials v0.1.25, and
the merged verifier-routing change. Its manifest, checksum record, attestation,
anonymous digest pulls, image builds, and artifact-only public smoke test all
passed. Official run
[30366183232](https://github.com/ElevenID/marty-integration-tests/actions/runs/30366183232)
nevertheless reproduced the same three normative failures.

The rerun changed these findings from hypotheses into two narrower product and
release gaps:

- the UI services image installed the corrected core v0.1.23 wheel, but the
  separately released credentials issuance image still downloaded core
  v0.1.22 from its own `release/dependencies.json`. Its redacted production
  diagnostic emitted the older completion error, proving that source-level
  Cargo tests and the deployed image were exercising different core builds;
  and
- structured Data Integrity credentials now reached the Rust verifier, but
  that verifier resolved only `did:key`. The managed issuer profile correctly
  publishes a tenant-scoped `did:web` DID, so the verifier had no product-
  resolved public method with which to check the proof.

Neither gap justifies changing the fixture to `did:key`, placing a key in test
code, accepting the credential without verification, or passing a KMS
coordinate. The intended production repair is to have the presentation-policy
service resolve the proof's DID through Marty's DID resolver, require the exact
DID document, controller, verification-method ID, and assertion/authentication
relationship, and pass only the resulting public JWK to the Rust cryptographic
verifier. The Rust boundary must reject private JWK parameters, duplicate or
conflicting methods, wrong controllers, wrong keys, invalid signatures, and
tampered documents while retaining offline `did:key` support.

Actions:

- [marty-core#77](https://github.com/ElevenID/marty-core/pull/77), merged as
  `364b4863059d449f8d0dc1c7561d035d16e1cdd4`, adds the resolver-owned
  public-method input and fail-closed Rust verification; it is released as
  core v0.1.24 at `f2074854ca31f76d6f44cbf03dc055a912814330`;
- [marty-ui#148](https://github.com/ElevenID/marty-ui/pull/148), merged as
  `c3d44f6bb229ad6ae116bdb2a03343d1427adf71`, resolves exact
  `did:web` proof relationships without exposing a public key, profile, KMS,
  provider, or custody selector; and
- [marty-credentials#80](https://github.com/ElevenID/marty-credentials/pull/80)
  makes Cargo's core crate revisions and the release image's core wheel name
  the same immutable release commit, with a regression contract preventing
  future source/image drift; it merged as
  `4d8b004b10a4eb4278957dc46228166d800f45ac` and is released as v0.1.26.

Until all three changes are released together and pass the same pinned official
suite, W3C Data Integrity issuance and verification remain **partial**, not
native passing evidence. A green source pull request or merged commit is not
used as a substitute for immutable released-stack evidence.

### 7f. The corrected release exposed a public DID-document identity mismatch

Immutable stack v1.1.47 pins core v0.1.24 and credentials v0.1.26, so the
official rerun exercised the same corrected core in source tests, the released
Python wheel, and the deployed issuance image. Its seven-component manifest,
checksums, provenance, three stack image attestations, anonymous registry
pulls, and artifact-only public smoke test passed.

Official run
[30380594927](https://github.com/ElevenID/marty-integration-tests/actions/runs/30380594927)
then passed 57 normative assertions and failed two valid verifier assertions
with HTTP 422:

`DID resolution failed: resolved document id does not match the proof controller`

This result proves that the prior source/image drift and issuance-time validity
defect are closed. It also proves that native managed-key Data Integrity
issuance reaches a cryptographic verifier; the remaining failures are both the
same publication defect. The organization-scoped public URL requested
`did:web:<public-domain>:orgs:<slug>`, while the endpoint returned an otherwise
usable issuer-profile document with its stored source/alias DID in `id`,
`controller`, and relationship identifiers. The resolver correctly refused to
use a public method from a document representing another DID.

The repair is at the production DID boundary, not in the official adapter:

- the tenant-bound public route retargets the stored document to the exact
  requested public DID, including embedded verification relationships;
- the resolver ignores any 200 response whose document `id` differs from the
  requested DID and tries the next legitimate candidate; and
- if no exact document exists, verification continues to fail closed.

No private key is published or passed to the verifier, and no profile, KMS,
provider, signing-service, or key selector is accepted. Signing remains
issuer-profile mediated in managed custody. A `Protected term redefinition`
diagnostic in the same run came from an expected invalid-input case and did not
fail a normative assertion; it is not counted as an exposed product gap.

[marty-ui#150](https://github.com/ElevenID/marty-ui/pull/150) merged as
`56147d7cc2af1fc4d9c6d6472e97bc7ca3512faf` after every PR check passed.
Immutable stack v1.1.48 then passed all five release jobs and independently
verified checksum, provenance, OCI-attestation, anonymous-pull, and
artifact-only smoke gates.

Official run
[30382577365](https://github.com/ElevenID/marty-integration-tests/actions/runs/30382577365)
passed all 59 normative assertions with zero failures. Its evidence guard
proved all required `issuer`, `vc_verifier`, and `vp_verifier` roles against
the exact v1.1.48 manifest and image digests. The W3C Data Integrity
implementation is therefore **native** at the production issuance,
issuer-profile custody, DID resolution, and cryptographic verification layers.
The official suite's VC-API entry shape remains a documented **adapted**
transport surface: it is gated, calls the shared general issuance/public
verification paths, performs no suite-owned semantic acceptance, and provides
no evidence for a generally supported public VC-API product.

Historical run 30382577365 used the reviewed one-file change proposed in
upstream PR 174 to work around an invalid Chai invocation. It is now classified
only as adapted runner evidence and cannot support an official-unmodified
compliance claim. The local patch mechanism has been removed. Current runs use
the exact pinned official commit with a clean-check before and after execution;
the upstream assertion defect remains visible until the official repository
merges its fix and the reviewed commit pin advances.

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

Released evidence:

- [marty-credentials#67](https://github.com/ElevenID/marty-credentials/pull/67)
  implements the shared authentication service, tenant persistence, atomic
  replay/code claims, REST/gRPC parity, and truthful metadata;
- [marty-ui#133](https://github.com/ElevenID/marty-ui/pull/133) implements the
  normal public issuance contract and strict public-JWK validation;
- [marty-integration-tests#147](https://github.com/ElevenID/marty-integration-tests/pull/147)
  provisions two disposable clients without an internal-service or API-key
  issuance bypass.

All three changes are merged. They are necessary production controls, but the
first immutable official rerun still rejected every active interaction module
at the token endpoint. The failure was retained rather than dismissed or
listed as expected.

### 9a. The official client assertion exposed an overly strict duplicate identifier check

Official run
[30385508700](https://github.com/ElevenID/marty-integration-tests/actions/runs/30385508700)
proved the exact remaining failure as token-endpoint HTTP 401. The OIDF wallet
sent an RFC 7523 `client_assertion` with its authenticated identity in signed
`iss` and `sub` claims, but did not redundantly send the optional OAuth form
`client_id`. Marty had already selected the one transaction-bound,
tenant-owned registration and verified assertions only against that
registration's public JWKS, yet it also required the absent form value to
equal the registered client ID.

This was a production interoperability defect. It was not corrected in the
test adapter. [marty-credentials#81](https://github.com/ElevenID/marty-credentials/pull/81)
changes the shared REST/gRPC authentication service so that:

- an omitted form `client_id` is accepted only after the assertion's signed
  identity and signature establish the registered client;
- a supplied mismatched form `client_id` is still rejected;
- the transaction remains bound to one organization and one opaque
  registration;
- signature, audience, bounded time, key ID, and one-time `jti` checks remain
  mandatory; and
- the issuer signing operation continues through DID-first issuer-profile
  custody, independently of holder-client authentication.

The fix is released as `marty-credentials` v0.1.27 and pinned by immutable
stack `marty-ui` v1.1.49. Official run
[30389863768](https://github.com/ElevenID/marty-integration-tests/actions/runs/30389863768)
then passed the exact OIDF `release-v5.2.0` runner commit
`dee9a25160e789f0f80517674693ef7989ab9fa1`. The runner reported 16 modules,
1,015 successful conditions, zero failures, and zero warnings. Every active
non-skipped module passed, including metadata, normal issuance, additional
requests, multiple registered clients, notification omission, invalid nonce,
invalid JWT proof signature, missing proof, unknown configuration, unknown
credential identifier, and access-token-in-query rejection.

At the time of that historical v1.1.49 run, four optional capabilities were
deliberately unadvertised and recorded as expiring skips:

- signed Credential Issuer Metadata;
- batch credential issuance;
- holder-key attestation; and
- credential-response encryption.

Key-attestation-bound proof trust was subsequently implemented through the
tenant-bound issuer-profile policy and current EUDI/OIDF paths. The v1.1.97
evidence therefore retains only three optional skips: signed metadata, batch
issuance, and credential-response encryption. Those are **missing optional
features**, not hidden failures in the active profile. The OID4VCI issuer
profile is now **native** for the tested pre-authorized-code, DPoP,
private-key-JWT, SD-JWT VC, and key-attestation-bound proof configuration.
This is official-suite interoperability evidence, not an OIDF certification.

## Do the tests cheat?

Official upstream suites are immutable evidence inputs. Each lane checks out
the reviewed full commit and treats the imported tree as read-only. ElevenID
must not patch assertions, fixtures, expected results, test selection,
exclusions, or any other upstream source to obtain a pass. Product, deployment,
and harness code may adapt Marty to an upstream interface, but the adaptation
must remain outside the upstream suite and be identified in the evidence
classification. Source-integrity checks compare the exact HEAD and tracked,
staged, and untracked state before and after execution. Any ElevenID-originated
source mutation invalidates the run. If an upstream runner writes its own
runtime report files, execution is isolated from the canonical checkout and
those writes cannot alter tests or become a compatibility patch.

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

OID4VP URL-query requires a precise qualification. Marty supports the native
signed `request_uri` transport, including the OID4VP
`request_uri_method=post` wallet-nonce exchange, and separately supports a
signed Request Object passed by value in the standard `request` parameter.
The OIDF runner's `url_query` variant instead sends unsigned request parameters
directly in the query. Marty now exposes that exact production transport as
`request_transport=url_query`, derives the required
`redirect_uri:<response-uri>` client identifier, and performs no Request
Object signing. Signed by-value behavior remains available separately as
`request_transport=request_object`.

Run
[30509192015](https://github.com/ElevenID/marty-integration-tests/actions/runs/30509192015)
used immutable `marty-ui` v1.1.73 and the exact unmodified OIDF
`release-v5.2.0` commit
`dee9a25160e789f0f80517674693ef7989ab9fa1`. All ten official modules passed
with 273 successful conditions, zero failures, zero warnings, and no expected
failures or skips. The adapter forwarded the exact raw direct-query parameters
to the official wallet and did not unpack, synthesize, or repair a signed JAR.

## Does the suite use Marty Protocol abstractions?

Partially.

The current `marty-protocol` contract defines DID-first Credential Templates,
public issuance requests, public verification-flow start requests and
responses, complete Presentation Policy and Organization resource, create,
and update contracts, and distinct IssuerEntity trust-record and IssuerIdentity
DID-projection contracts. It includes conformance fixtures rejecting public
profile, signing-service, key-reference, verification-method, KMS, provider,
commerce, and private organization-state selectors.
Marty-Protocol PRs
[#15](https://github.com/Marty-Protocol/Marty-Protocol/pull/15),
[#16](https://github.com/Marty-Protocol/Marty-Protocol/pull/16),
[#17](https://github.com/Marty-Protocol/Marty-Protocol/pull/17),
[#18](https://github.com/Marty-Protocol/Marty-Protocol/pull/18),
[#19](https://github.com/Marty-Protocol/Marty-Protocol/pull/19),
[#20](https://github.com/Marty-Protocol/Marty-Protocol/pull/20), and
[#21](https://github.com/Marty-Protocol/Marty-Protocol/pull/21) publish those
operation schemas and generated Python, Rust, and TypeScript bindings at exact
commit `85770d02b6c225acbe4fc3446b71c4d206933bfd`. The latest phase adds distinct
strict Flow create/update/start, Flow resource/execution/result, issuance
initiation/transaction, issued-credential lifecycle, renewal-offer, and
lifecycle-mutation contracts instead of overloading one loose shape.

[marty-ui#224](https://github.com/ElevenID/marty-ui/pull/224),
[#226](https://github.com/ElevenID/marty-ui/pull/226),
[#227](https://github.com/ElevenID/marty-ui/pull/227),
[#228](https://github.com/ElevenID/marty-ui/pull/228),
[#229](https://github.com/ElevenID/marty-ui/pull/229), and
[#230](https://github.com/ElevenID/marty-ui/pull/230) pin and enforce that
contract. CI compares fields and requiredness, the reserved issuance-claim
boundary, representative schema-valid runtime messages, tenant-scoped
Presentation Policy, Organization, issuer, Flow, and issuance operations, and
the prohibition on custody or private organization selectors. The gateway
strips internal routing fields, forwards only validated fields, validates
successful service responses before returning them, uses canonical wire
serialization, and removes the deprecated public holder-key-reference
derivation endpoint. [marty-credentials#89](https://github.com/ElevenID/marty-credentials/pull/89)
applies the same issuance and issued-credential boundary in the authoritative
service and persistence layer.

The runtime still owns duplicated Python and JavaScript request models rather
than consuming generated `marty-protocol` types at every public boundary.
Internal gRPC and persistence models legitimately retain
`issuer_profile_id`, but that value is resolver-produced routing state and is
not a public selector. Contract drift is mechanically blocked for the covered
operations. The published generated bindings are freshness-tested, but the
Python gateway and JavaScript UI still duplicate some generated types rather
than importing them directly.

Required follow-up:

- consume or mechanically compare shared types for all supported public
  clients, including nullability and conditional response fields; and
- retain the fail-closed public-to-internal translation tests as generated
  types replace duplicated runtime models.

The remaining contract work is owned by
[marty-ui#222](https://github.com/ElevenID/marty-ui/issues/222).

## Organizations and multitenancy

The official lanes authenticate a disposable operator and create resources in
one configured organization. This proves organization-scoped happy paths but
not, by itself, prove tenant isolation. Tenant evidence therefore remains
separate from every official result.

The Organization contract audit exposed product drift outside the official
suites. The UI offered `jurisdiction` even though no production path persisted
it, mapped admission choices into fields the service ignored, and offered
organization types that the service rejected. The gateway validated a reduced
Pydantic object but proxied the caller's raw body, returned successful raw
service responses without response-model enforcement, exposed `PUT` while the
UI and service used `PATCH`, and advertised a delete operation the service did
not implement. `/organizations/mine` used a separate legacy response shape and
included internal membership identifiers and email fields outside the public
Organization resource.

Marty-Protocol [#19](https://github.com/Marty-Protocol/Marty-Protocol/pull/19)
and marty-ui [#228](https://github.com/ElevenID/marty-ui/pull/228) correct those
owned production paths. Create and partial update requests are strict;
discoverability, admission mode, approval, and all supported organization types
are persisted; successful responses fail closed unless they match the public
resource; `/mine` reuses that resource; internal membership identity fields are
not returned; `PATCH` is canonical; and the unimplemented public delete and
false jurisdiction control are removed. No upstream compliance test, runner,
fixture, vector, assertion, expected result, exclusion, or test selection was
changed to obtain this result.

The same public-boundary audit then separated three concepts that the product
had partially conflated: `IssuerEntity` is a tenant trust-registry authority
record, `IssuerIdentity` is the public active DID/purpose/algorithm projection,
and an issuer profile is private resolver and custody-routing state. The
official suites exercised DID-first issuance and verification, but did not
prove that the issuer administration boundary itself was tenant-safe. Direct
inspection exposed that create/update models accepted extra fields, the gateway
validated a reduced model but forwarded the raw body and returned raw successful
service responses, update was advertised as `PUT`, arbitrary nested metadata
could carry profile/KMS/provider coordinates, and a global/system issuer could
be mutated or deleted without an organization membership check. The public
issuer-identity list already omitted private profile IDs, but had no strict
published response contract.

Marty-Protocol [#20](https://github.com/Marty-Protocol/Marty-Protocol/pull/20)
and marty-ui [#229](https://github.com/ElevenID/marty-ui/pull/229) correct those
owned production paths. Public create and `PATCH` update are strict and
tenant-bound; global/system mutation is internal-only; revocation attribution
comes from the authenticated principal; successful gateway responses fail
closed; custody, key-routing, provider, and KMS selectors are prohibited
recursively; and the issuer-identity list is a typed DID-only projection that
continues to reject inactive, incompatible, unknown, or ambiguous mappings.
RSA/RS256 profiles, mdoc, OID4VCI, OID4VP, and all existing signing purposes
remain supported through issuer-profile resolution. No imported official suite,
runner, fixture, vector, assertion, expected result, exclusion, or selection was
changed to produce these results.

The Flow and issuance audit exposed the same class of drift in the next public
resource families. Flow create and update accepted overlapping nullable
shapes, the UI used `PUT` while partial update semantics required `PATCH`,
verification start could omit its tenant, and service responses could include
private state, resolved internal steps, or null fields that violate the
conditional public schema. Issuance initiation could expose pre-authorized-code
and custody state, while issued-credential records could expose internal
delivery routing. Several management and lifecycle paths accepted a record
identifier without first binding it to the authenticated organization.

Marty-Protocol [#21](https://github.com/Marty-Protocol/Marty-Protocol/pull/21),
marty-credentials [#89](https://github.com/ElevenID/marty-credentials/pull/89),
and marty-ui [#230](https://github.com/ElevenID/marty-ui/pull/230) correct those
owned paths. Flow create, `PATCH`, start, resource, execution, and result shapes
are distinct and strict; every public operation is organization-bound; nested
private state is rejected and projected out; lifecycle operations require an
API-key or trusted organization context; cross-tenant identifier substitution
returns a non-enumerating 404; and public issuance responses omit
pre-authorization, profile, custody, and delivery-routing records. The trusted
VC-API adapter uses the shared internal issuance application helper when it
must redeem a transaction immediately, so it does not introduce an alternate
signing path. Signing remains issuer-profile mediated and keys remain in
managed custody. No imported official suite, runner, fixture, vector,
assertion, expected result, exclusion, or test selection was changed.

The ElevenID-owned public-boundary lane now creates two organizations with
distinct active issuer DIDs and profiles, uses two authenticated principals
plus an organization-bound API key, and exercises only browser-equivalent
public HTTPS routes. It proves:

- template list isolation plus template, policy, and issuer-DID substitution
  denial;
- organization membership and assigned-role enforcement for a second
  principal;
- API-key machine-principal binding and cross-organization denial;
- SCIM direct-access and resource-ID substitution denial;
- saved flow definition, instance, and result isolation;
- webhook ownership, URL, and signing-secret leakage prevention; and
- audit-event list and detail isolation without foreign identifiers or
  metadata in denial responses.

The follow-up DID-first negative matrix additionally proves that:

- credential-template, issuance, and signed-verification requests reject
  profile, signing-service, key-reference, and KMS-provider selectors;
- successful public responses do not expose those custody coordinates;
- an unknown DID, a non-active issuer profile, and a profile with only an
  incompatible signing purpose all fail closed; and
- repeated setup of the same DID/service/purpose tuple is idempotent rather
  than creating an ambiguous active mapping.

The final run
[30524717116](https://github.com/ElevenID/marty-integration-tests/actions/runs/30524717116)
passed against exact `marty-ui` v1.1.78 artifacts and manifest
`sha256:88488c84d46ca29538b71c71bf12ada6b213e5069bf931d74ef8ce97108dc378`.
Its evidence schema identifies the lane as
`elevenid-owned-product-security`, records `official_suite_invoked=false` and
`official_suite_source_modified=false`, and pins the owned test source to
commit `ea14814a7e25106d07cf7bb5e97122e5bc0b4490`.

The expanded run
[30528390251](https://github.com/ElevenID/marty-integration-tests/actions/runs/30528390251)
passed the same immutable v1.1.78 artifacts with owned test commit
`76efd50a0d896e008053d2697b6397ef7402a201`. Its artifact digest is
`sha256:db94b4c9aafc55416d10e88766c616cebc23cfdc846b4478f13323578f44f542`
and its public summary digest is
`sha256:3027ac3b707d79ff7119cb2b542dd77475df752a37bf82ba22c9672b11b52668`.
It retains the same explicit non-official evidence classification and records
that no official suite was invoked or modified.

This lane exposed real production defects before it passed:

- organization member persistence assumed every SCIM `externalId` fit a
  36-character UUID column;
- webhook, subscription, notification, and SSE routes were absent from the
  shared Cedar route registry, and some notification resource routes did not
  independently verify tenant ownership;
- validated API keys were incorrectly sent through human-membership lookup
  instead of remaining organization-bound machine principals; and
- organization audit list/detail/export routes were absent from the shared
  Cedar map, allowing an organization-A reviewer to retrieve organization-B
  audit events.

It also exposed owned harness drift rather than product defects: the Compose
coordinator lacked a Marty-only lifecycle, the foreign flow fixture initially
had no issuer, the flow helper still sent removed top-level `steps`/`type`
fields, a dependent credential template was left in draft state, and the
negative DID test initially called the non-active state `inactive` even though
the supported lifecycle value is `draft`. Those were corrected only in
ElevenID-owned orchestration and fixtures. The imported OIDF, W3C, and EUDI
suites were not edited.

The Canvas mirror provenance audit added a second concrete isolation slice.
The previously anonymous gateway route could query a delivery record,
external Canvas credential ID, or canonical credential ID without a required
organization, and its response exposed internal issuer-profile and mode
fields. [marty-credentials#86](https://github.com/ElevenID/marty-credentials/pull/86)
now requires the internal management credential plus an exact trusted
organization header/query match, scopes every selector to that organization,
returns a non-enumerating 404 for cross-tenant substitutions, and returns only
the public issuer DID and credential-issuer URL.
[marty-ui#177](https://github.com/ElevenID/marty-ui/pull/177) requires normal
user authentication, selected-organization membership, and the
`integration-connector:view` permission before the gateway calls issuance.
Focused tests cover all three resource-ID substitution paths and a
two-organization denial before the backend. This is useful production-boundary
evidence and is now complemented by the released two-principal matrix above.

Remaining multitenancy evidence is narrower: forced ambiguous same-tenant DID
state beyond the public API's idempotent uniqueness guard, notification/SSE
cross-tenant delivery in the released external lane, adversarial browser
substitution, trust registries beyond organization trust profiles, wallet
profiles, devices/deployments, and DIDComm where applicable. These are not
implicitly satisfied by the green matrix. The complete owned evidence backlog
is tracked by
[marty-integration-tests#224](https://github.com/ElevenID/marty-integration-tests/issues/224);
it explicitly prohibits modifying any imported official suite.

### 10. Strict production contracts exposed owned harness and service drift

The v1.1.81 contract release intentionally made tenant context, holder binding,
and proof profiles explicit. The first rerun stopped before official dispatch
where the ElevenID-owned fixture still omitted those fields. The harness was
corrected to send the complete public contract; no imported runner, test,
fixture, assertion, expected result, exclusion, or test selection changed.

That correction produced current immutable evidence against exact harness
commit `6344bcc6510c5d604d73a8afefac7c28f2dd2b4c` and exact stack manifest
`sha256:d1b4d3f5dc64ebdcedf9e8c6e1ff2f7524175b8ff4a2da75ba73bcdf7d938055`:

- OID4VCI and W3C VCDM v2 passed their exact pinned upstream suites;
- EUDI passed all 55 tests, including real production expiry, replay,
  tampered-signature, and missing-holder-binding negatives;
- the owned two-organization public-boundary matrix passed; and
- OID4VP Final, URL-query, and HAIP stopped before official dispatch because
  application-template activation could not resolve the active credential
  template through the issuance service's duplicate raw HTTP lookup.

The last failure is a product integration defect, not a compliance result.
The gateway had already resolved the same tenant-scoped template, and other
issuance paths used the credential-template gRPC contract. Credentials PR
[marty-credentials#91](https://github.com/ElevenID/marty-credentials/pull/91)
now makes application validation use that internal contract first, retains an
HTTP compatibility fallback, and distinguishes a genuinely missing resource
from an unavailable dependency. Its complete Linux, macOS, Windows, Python,
Rust, WASM, migration, security, CodeQL, and policy matrix passed. A new
immutable credentials and stack release is required before the affected
official lanes are rerun.

The mdoc lane remains a separate upstream-fixture limitation. OIDF 5.2.2
rotated the expired certificate, but the current leaf is still `CA:true` and
asserts `keyCertSign`/`cRLSign`, so Marty correctly rejects it as an ISO 18013-5
document signer. The harness explicitly refuses to patch the certificate,
weaken profile validation, or relabel the failure as an expected pass.

### 11. Expanded lifecycle isolation exposed ownership and managed-KMS defects

The expanded ElevenID-owned boundary lane added issuance-transaction,
revocation-status, issued-credential lifecycle, and trust-profile ownership
checks to the existing two-principal matrix. It uses real organizations and
the authenticated public gateway that the UI consumes. The lane does not call
KMS directly. Administrative setup creates issuer profiles, while runtime
issuance and verification select the profile by organization plus issuer DID.
All keys and provider credentials remain in KMS.

The first exact-stack attempts exposed product defects rather than reasons to
change the test:

- internal issuance and trust-resource routes did not consistently carry the
  owning organization through every identifier lookup, leaving BOLA and
  enumeration risk in cross-tenant lifecycle operations;
- a newly created organization could see live managed KMS inventory but did
  not persist its own purpose authorization when an issuer profile was
  created, so real OID4VCI redemption failed with `issuer-signing-conflict`;
- after the first tenant-local VC issuer binding, the managed OpenBao service's
  current bindings were incorrectly treated as its complete capability list,
  hiding the dedicated `oid4vp-verifier-*` key and rejecting the second
  profile; and
- the immutable release workflow used a two-step draft publication pattern.
  A manually published and deleted v1.1.85 release demonstrated GitHub's
  immutable tag tombstone: that release name cannot be reused even after the
  release object is deleted.

The product corrections are merged in marty-credentials
[#93](https://github.com/ElevenID/marty-credentials/pull/93) and
[#94](https://github.com/ElevenID/marty-credentials/pull/94), Marty
[#18](https://github.com/ElevenID/Marty/pull/18), and marty-ui
[#236](https://github.com/ElevenID/marty-ui/pull/236),
[#238](https://github.com/ElevenID/marty-ui/pull/238),
[#240](https://github.com/ElevenID/marty-ui/pull/240), and
[#241](https://github.com/ElevenID/marty-ui/pull/241). Managed service
capability now comes from live KMS inventory, while tenant-local registry rows
remain authorization bindings. Purpose-specific namespaces select the correct
managed key, and profile creation rejects a KMS key from another protocol
namespace or with a mismatched algorithm. The release workflow now stages and
publishes the immutable release in one action-owned transaction.

The evidence forms a controlled before/after comparison using the same owned
test commit `250985275555b91d46a498585a66164732a47868`:

- run [30698331923](https://github.com/ElevenID/marty-integration-tests/actions/runs/30698331923)
  against v1.1.84 failed honestly at real DID-mediated OID4VCI signing because
  the clean tenant lacked a local KMS purpose binding;
- run [30699913145](https://github.com/ElevenID/marty-integration-tests/actions/runs/30699913145)
  against v1.1.86 passed three tests and failed the unchanged DID-first test at
  OID4VP profile creation because existing tenant bindings hid the managed
  service's remaining capability; and
- run [30700898083](https://github.com/ElevenID/marty-integration-tests/actions/runs/30700898083)
  passed the complete matrix against exact v1.1.87 manifest
  `sha256:8f431ab324b9c26cab8e8f729c207f9d2aa782a9ceeb7c0c17e11806c31ef7a0`.
  Artifact `tenant-boundary-30700898083-1` has GitHub artifact digest
  `sha256:f5a300a1c7ac17aedf7a8203f6b6b92db65a0e4f996290cc464aadfe280226f4`;
  its summary digest is
  `sha256:0fb61e418e01864bc481f9fa685846c6a444d9a88dbd4dbaca7bb9623e61c508`.

This evidence is deliberately classified as
`elevenid-owned-product-security`, not official standards compliance. It
records `official_suite_invoked=false` and
`official_suite_source_modified=false`. No imported official suite, runner,
fixture, certificate, vector, assertion, expected result, exclusion, or test
selection was edited to obtain the pass. Upstream suites remain pinned,
read-only inputs and are updated only by reviewing a new upstream commit.

### 12. The v1.1.87 official matrix preserved the upstream boundary

The complete scheduled-shape matrix ran from merged harness commit
`b021510b5219f8bc582cde32a12df9ec7c0b1097` against exact v1.1.87 manifest
`sha256:8f431ab324b9c26cab8e8f729c207f9d2aa782a9ceeb7c0c17e11806c31ef7a0`.
Run [30701213399](https://github.com/ElevenID/marty-integration-tests/actions/runs/30701213399)
produced the following outcomes without a stack override:

- the exact unmodified OIDF `release-v5.2.1` OID4VCI issuer plan passed with
  zero expected failures; the same four optional, unadvertised capabilities
  remain explicit skips;
- OID4VP Final, the direct URL-query transport, and HAIP each passed with zero
  expected failures or skips;
- the separately labeled browser evidence accompanying OID4VP Final passed the
  public application, submit, claim, offer, and DID-only verification path and
  observed no private profile, service, key, or KMS selector;
- the exact W3C VCDM v2 commit
  `e92936564867da9150b99b167fe1c73b9370ad6c` passed issuer, VC-verifier, and
  VP-verifier capabilities with no exclusions; its evidence records
  `official_upstream_unmodified=true` and
  `test_or_assertion_source_modified=false`; and
- the pinned EUDI reference components passed all 55 tests with zero failures,
  errors, or skips, including SD-JWT and mdoc issuance/presentation plus the
  required replay, invalid-signature, expired-request, and missing-holder-key
  negatives under their existing native-versus-owned evidence labels.

OIDF `release-v5.2.2` rotated the expired mdoc fixture and the unchanged lane
now executes all five official modules. The replacement certificate is current
from 2026-08-03 through 2027-08-03, but incorrectly asserts `CA:true`,
`keyCertSign`, and `cRLSign`. Its invalid-session-transcript negative passes;
the positive presentations reach Marty's production authorization endpoint and
are rejected by strict ISO document-signer validation. The genuine failure is
recorded by [run 31196611597](https://github.com/ElevenID/marty-integration-tests/actions/runs/31196611597),
artifact `9001227018` with digest
`sha256:ec152235fad67b2a861d9c178e2297e385a59773f080d44e9767da4b4b73ef01`.
OIDF tracks the fixture-profile defect in
[work item 1891](https://gitlab.com/openid/conformance-suite/-/work_items/1891),
and ElevenID tracks release adoption in
[marty-integration-tests#243](https://github.com/ElevenID/marty-integration-tests/issues/243).
No local certificate replacement, source patch, validation bypass, exclusion,
or expected failure is permitted.

### 13. DIDComm delivery exposed authorization, transport, and harness gaps

The new ElevenID-owned DIDComm lane exercises the authenticated public gateway,
a real disposable organization, DID-first managed issuer resolution, the
released credentials service, a fresh `did:peer:2` X25519 holder key, and a
holder-controlled HTTPS service endpoint. The public issuance request supplies
no issuer-profile, signing-service, key, KMS, or provider selector. Platform
signing remains mediated by the issuer profile and its managed custody service;
the disposable holder's TLS and X25519 private keys are external test-agent
material, not platform signing keys.

The unchanged positive test exposed three distinct gaps in sequence:

- [run 31147992185](https://github.com/ElevenID/marty-integration-tests/actions/runs/31147992185)
  reached the production route but received HTTP 403 because the exact DIDComm
  path was absent from the shared Cedar authorization map. `marty-common`
  0.2.5 added the exact tenant-scoped route instead of bypassing authorization.
- [run 31149067032](https://github.com/ElevenID/marty-integration-tests/actions/runs/31149067032)
  then reached delivery and correctly failed HTTP 422 because the owned mock
  endpoint used plaintext HTTP. The HTTPS requirement was retained. The
  disposable conformance topology now generates a CA-signed holder certificate,
  mounts only that root into the issuance service, and reaches the host receiver
  through an explicitly isolated bridge. Production compose files contain none
  of those conformance-only settings.
- [run 31152798249](https://github.com/ElevenID/marty-integration-tests/actions/runs/31152798249)
  delivered the encrypted body, but the owned runner lacked the released
  `marty-core` wheel needed for its holder-side decryption assertion. The
  workflow now selects exactly one `marty-core-python` artifact from the
  attested stack manifest, constrains it to the ElevenID release repository,
  verifies its SHA-256 and GitHub provenance, installs it without dependency
  resolution or an index, and confirms `didcomm_decrypt` exists. No source
  checkout or mutable package lookup was added.

The final immutable
[run 31153194710](https://github.com/ElevenID/marty-integration-tests/actions/runs/31153194710)
passed all five selected tests against stack v1.1.108, manifest
`sha256:39bed88b9ac6bf3946835c870188a1bdd0909fe68247690dc087e13846a83cec`,
and harness `592a24fef4b982fd1419ee8f0498a063144ac713`. The positive DIDComm assertion
proves that the holder endpoint received one
`application/didcomm-encrypted+json` JWE-shaped body, the holder private key
decrypted it, the plaintext carried the Issue Credential 3.0 message type,
sender, intended holder, issuance thread ID, and an attachment, and the
transaction became `issued`.

A subsequent immutable
[run 31198519056](https://github.com/ElevenID/marty-integration-tests/actions/runs/31198519056)
used exact v1.1.112, merged harness
`91f6b439a24720519d5cf3857ba08676e09bb897`, and pinned
`notabene-id/go-didcomm v0.4.0` commit
`5ffd085c2b5088a639c1c0d3910d668887298ce5`. The independent Go decoder
accepted the released JWE, identified it as encrypted anoncrypt with no signed
or authenticated sender, and produced the same plaintext, including nested
attachments, as the attested Marty decoder. Only absent-versus-null
representation of optional `pthid` and `expires_time` is normalized. The same
run proves a foreign organization cannot substitute another tenant's DIDComm
transaction: denial occurs before attacker-controlled DID resolution, does not
reflect the transaction identifier, and leaves the transaction unchanged.
Sanitized artifact `9001965825` has digest
`sha256:50e1d6eeae446c1f599f219b255aca431b672f7cca452b44140839920b41aca5`.

This proves cross-implementation interoperability for the selected outbound
DIDComm Messaging 2.1 profile: Issue Credential 3.0 `issue-credential`,
anoncrypt, General JSON, `ECDH-ES+A256KW`, X25519, `A256CBC-HS512`, one
`did:peer:2` recipient, and CA-validated HTTPS. It does not prove independent
full-agent exchange, authcrypt/signed modes, inbound behavior, every algorithm
or DID method, mediator/routing behavior, multiple recipients, malformed-input
coverage, or the complete Issue Credential state machine. This owned lane must
not be presented as an official suite or certification.

### 14. OIDF 5.2.2 browser review exposed runner TLS and alias defects

OIDF `release-v5.2.2` added a mandatory verification-result screenshot review
for successful verifier responses. ElevenID adopted the upstream-documented
`verification-evidence` BrowserControl task without modifying the official
runner. The first immutable rerun exposed that the official JVM could not
validate the conformance nginx certificate for `localhost.emobix.co.uk`.
PR #283 retained strict TLS by generating a disposable hostname-valid runner
leaf and giving only the unchanged official JVM a read-only CA truststore.

After that correction, immutable
[run 31203856791](https://github.com/ElevenID/marty-integration-tests/actions/runs/31203856791)
proved a second, independent harness defect. All seven signature, hash, nonce,
audience, and time negatives passed, while the four positive modules each
remained `WAITING` with the safe diagnostic `automation-not-observed`. Artifact
`9004532816` has digest
`sha256:9e5be13c04df3fae7917a808692b533a9fd1d5b16ef0d5ed06aa16a764e693d1`.
The exact upstream example has top-level alias `oidf-vp-test-wallet`; the
generated ElevenID configurations did not. Without an alias, OIDF served
`/test/{id}/verification-evidence`, which cannot match its configured
`/test/a/*/verification-evidence` BrowserControl pattern. This was not a Marty
protocol failure or a Docker-network failure.

PR #285 adds the upstream alias to standard, direct URL-query, mdoc, and HAIP
runner configurations and makes the ElevenID validator reject a missing or
changed alias. The imported OIDF checkout remains byte-for-byte clean. Exact
v1.1.112 reruns at harness commit
`bf0e6d5b2d099768e3ee0b3987edeb669143a971` then produced:

- [OID4VP Final run 31206756608](https://github.com/ElevenID/marty-integration-tests/actions/runs/31206756608):
  12 modules, 463 successes, zero failures/warnings, four positive `REVIEW`
  results with every placeholder filled, and seven required negatives passed;
  artifact `9005205225`, digest
  `sha256:b71bbbabb8684b2099f2fb80c8928e6dd1df51b0f738a2b6d9e35a431164ce3b`.
- [native URL-query run 31207275778](https://github.com/ElevenID/marty-integration-tests/actions/runs/31207275778):
  12 modules, 302 successes, zero failures/warnings, the same four completed
  review results and seven negatives; artifact `9005372575`, digest
  `sha256:1dabf33e039c0b38d43547b05100dbf4b0d102317d86aa89afaca7f47854e7cc`.
- [HAIP run 31207277971](https://github.com/ElevenID/marty-integration-tests/actions/runs/31207277971):
  12 modules, 566 successes, zero failures/warnings, four completed review
  results and seven negatives under the `x509_hash`, signed `request_uri`, HAIP
  variant; artifact `9005383490`, digest
  `sha256:669b6f94afd01929ca0232dad95d4aa1f184007bc7d1428b0c9800c8d0eb2715`.

All three summaries bind exact stack manifest
`sha256:698180c0e3f2df93ff52ad05442206216c029c7f79208a246edabc60f5366190`,
Marty commit `f83f068e2d201b9cbb248d8741b49d470f0cd4fc`, and unmodified OIDF commit
`321bc5bc53601b9690b54c023c0cbfac0f0230f2`; verifier exclusions are empty.
The Final run's separately labeled released-browser smoke also completed the
normal public application, submit, claim, offer, and verification paths using
only organization ID and issuer DID, and observed no public profile, signing
service, key, KMS, or provider selector.

## Does the suite use the UI's general API?

The EUDI and OIDF paths use the same authenticated public gateway as the UI.
They do not call KMS or the issuer signing service directly. The released-stack
browser smoke drives the real UI through login, applicant catalog, disposable
application creation, submission, credential claim, organization selection,
verification configuration, and signed verification. The current run
[31206756608](https://github.com/ElevenID/marty-integration-tests/actions/runs/31206756608)
used exact `marty-ui` v1.1.112 artifacts and harness commit
`bf0e6d5b2d099768e3ee0b3987edeb669143a971`. The browser selected public
tenant DIDs, observed no private selectors or issuer-profile collection
request, and submitted through `/v1/me/applications`, `/submit`, `/claim`, and
`/v1/flows/verify`.

This closes the released-browser issuance and verification slice for one
organization. The generated-client and runtime contract drift work under
[marty-ui#222](https://github.com/ElevenID/marty-ui/issues/222) is complete and
remains enforced against the exact protocol pin. Adversarial cross-tenant
browser coverage remains separate work under
[marty-integration-tests#224](https://github.com/ElevenID/marty-integration-tests/issues/224);
the official suite itself remains API-driven and unmodified.

## Features and gaps exposed

| Capability | Current evidence | Remaining gap |
| --- | --- | --- |
| DID-first OID4VCI issuance | Native official OIDF 5.2.2 issuer evidence on immutable v1.1.112: pre-authorized code, DPoP, `private_key_jwt`, SD-JWT VC, multiple clients, tenant/profile-owned key-attestation trust, nonce/proof/configuration negatives, notifications, and token-query rejection | Signed metadata, batch issuance, and credential-response encryption are optional, unadvertised gaps tracked by [marty-integration-tests#225](https://github.com/ElevenID/marty-integration-tests/issues/225); keep the active profile green as the runner updates |
| DID-first signed OID4VP request | Exact unmodified OIDF 5.2.2 Final evidence on immutable v1.1.112 completes 463 conditions with zero failures/warnings or exclusions; all four review placeholders fill, seven security negatives pass, and the separately labeled browser path observes no private selector | Keep the active profile green as the official runner updates |
| HAIP request-object trust | Exact unmodified OIDF 5.2.2 HAIP evidence on immutable v1.1.112 completes 566 conditions with zero failures/warnings or exclusions under `x509_hash` and signed `request_uri` | Keep the active pre-certification profile green; fund certification separately |
| SD-JWT holder binding | Exact v1.1.112 EUDI evidence uses the official library for key-attestation-bound issuance and holder-bound presentation, rejects a missing binding key before presentation, and proves a tampered holder signature is denied by the production callback | Retain the native-versus-owned evidence labels: official libraries construct and resolve the positive path, while deterministic replay/signature mutations remain explicitly ElevenID-owned negative evidence |
| mdoc issuance/presentation | Exact v1.1.112 EUDI evidence passes mdoc issuance and presentation with independent COSE/CBOR/X.509 validation; the unmodified OIDF 5.2.2 verifier lane executes all five modules and passes its invalid-session-transcript negative | OIDF's current document-signer fixture is current but invalid because it is a CA with CA-signing usage. Adopt the first reviewed fix under [#243](https://github.com/ElevenID/marty-integration-tests/issues/243) without patching or weakening the suite. OIDF still has no suitable mdoc issuer plan, so issuance claims remain EUDI/reference evidence |
| EUDI reference interoperability | Exact v1.1.112 artifacts pass 45/45 tests through current pinned EUDI OID4VCI, OID4VP, SD-JWT, verifier-endpoint, and Multipaz components. Required key-attestation-bound issuance, mdoc issuance/presentation, SD-JWT presentation, signed JAR trust, replay, invalid-signature, real expired-request, and missing-holder-binding evidence is green | The HTTP facade and deterministic negative mutations remain ElevenID-owned and accurately labeled; current upstream libraries and their assertions are unchanged |
| OID4VP URL-query transport | Exact unmodified OIDF 5.2.2 `url_query` + `redirect_uri` evidence on immutable v1.1.112 completes 302 conditions with zero failures/warnings or exclusions; signed by-value Request Objects remain a separate `request_object` transport | Keep the active profile green as the pinned official runner advances; do not merge the two transport claims |
| W3C VCDM v2 verification and issuance | The exact pinned upstream suite passes from an unmodified disposable worktree against immutable v1.1.112; issuer, VC-verifier, and VP-verifier roles execute with no exclusions | Retain the adapted VC-API entry-shape qualification and keep the lane green as the reviewed upstream pin advances |
| UI issuance/verification | Separately labeled released v1.1.112 browser evidence completes disposable application, submit, claim, credential-offer, and signed-verification journeys using public DIDs; no private selector or issuer-profile collection request is observed. The generated-client/runtime drift work under `marty-ui#222` is closed and enforced | Add stronger adversarial cross-tenant browser cases under [marty-integration-tests#224](https://github.com/ElevenID/marty-integration-tests/issues/224) |
| DIDComm delivery | Exact v1.1.112 owned evidence resolves a fresh `did:peer:2` X25519 holder, performs CA-validated HTTPS delivery, validates normative headers for the selected anoncrypt profile, and produces identical plaintext through the released Marty decoder and pinned independent `go-didcomm` implementation. The same run denies cross-tenant transaction substitution before DID resolution | This is selected-profile cross-implementation evidence, not official certification or full independent-agent exchange. Add authcrypt/signed and inbound modes, the complete Issue Credential exchange, broader algorithms and DID methods, routing/mediation, multi-recipient, and malformed-input negatives |
| Multitenancy | Released v1.1.112 owned evidence runs the current two-principal/two-organization matrix, the independent DIDComm positive case, and cross-tenant DIDComm transaction substitution. It covers membership/RBAC, template/policy/DID substitution, API-key binding, SCIM, flows/results, issuance/revocation, trust, applicant/evidence, deployment/device, webhook, wallet, notification/SSE, audit, custody-selector rejection, unknown/inactive/incompatible DID denial, idempotent uniqueness, forced ambiguity rejection/recovery, and non-leaking denials | The shipped browser still needs stronger adversarial cross-tenant cases. Broader trust registries beyond organization trust profiles remain open under [marty-integration-tests#224](https://github.com/ElevenID/marty-integration-tests/issues/224) |
| Protocol contract | Public DID-only Credential Template, Organization Trust Profile, issuance and issued-credential lifecycle, verification-flow start/resource/execution/result, complete Presentation Policy and Organization operations, strict IssuerEntity trust-record operations, and the DID-only IssuerIdentity lifecycle are merged. Main CI and the E2E repository variable now both pin protocol commit `8129a3b0a30addae1c163ffdcde538c1cae59dce`; schema parity and generated Python/Rust/TypeScript freshness pass, raw-model/private-field bypasses are rejected, and cross-tenant or global/system mutation fails closed | The remediation tracked by [marty-ui#222](https://github.com/ElevenID/marty-ui/issues/222) is complete. Retain the single exact cross-repository pin, generated-binding checks, and public/internal adapter separation |
| Wider Marty feature model | Official suites do not cover it; the ElevenID-owned released matrix now covers membership/RBAC, API keys, SCIM, saved verification flows/results, issuance and revocation, organization trust profiles, applicant/vetting and evidence, deployments/devices, webhooks, wallet profiles, notification/SSE delivery, audit, DID resolution, forced ambiguity, independent DIDComm decoding, and DIDComm cross-tenant substitution | Broader trust registries, broader DIDComm modes, and adversarial cross-tenant browser paths remain owned work under [marty-integration-tests#224](https://github.com/ElevenID/marty-integration-tests/issues/224) |

### Exposed-gap action ledger

| Finding | Classification | Impact | Owner/remediation | Status and required evidence |
| --- | --- | --- | --- | --- |
| Flow public models conflated create, partial update, runtime state, execution, and verification results | Protocol drift / public API bypass / multitenancy defect | Loose nullable bodies, raw response forwarding, `PUT`/`PATCH` disagreement, and omitted organization context allowed the UI, gateway, and service to accept different contracts or expose internal state | [Marty-Protocol#21](https://github.com/Marty-Protocol/Marty-Protocol/pull/21) publishes distinct strict schemas and generated bindings; [marty-ui#230](https://github.com/ElevenID/marty-ui/pull/230) validates canonical create, `PATCH`, start, resource, execution, and result messages and binds every call to selected-organization membership | Merged as protocol `85770d02b6c225acbe4fc3446b71c4d206933bfd` and marty-ui `a3892004c90f95d73100a3e8b409534d4e40ae15`; released in immutable stack v1.1.81 at manifest `sha256:d1b4d3f5dc64ebdcedf9e8c6e1ff2f7524175b8ff4a2da75ba73bcdf7d938055`. Protocol, UI, and release checks passed. Exact-stack official and owned reruns remain required. No imported official evidence source changed |
| Issuance initiation and issued-credential lifecycle exposed overlapping internal state and incomplete tenant checks | Protocol drift / information disclosure / BOLA defect | Public responses could carry pre-authorized-code, custody, or delivery-routing records; identifier-only management paths could be probed across organizations | [Marty-Protocol#21](https://github.com/Marty-Protocol/Marty-Protocol/pull/21) separates issuance, transaction, public credential, renewal, and lifecycle mutation contracts; [marty-credentials#89](https://github.com/ElevenID/marty-credentials/pull/89) and [marty-ui#230](https://github.com/ElevenID/marty-ui/pull/230) enforce organization binding, non-enumerating denials, public projection, and a shared trusted internal issuance helper | Merged as credentials `3a07f751aad360551292d1ce2337423906ee6acd` and marty-ui `a3892004c90f95d73100a3e8b409534d4e40ae15`. Local and hosted suites passed; credentials v0.1.32 published image `sha256:8919a58cf1afada5d50f38b29767833556191c2a6d237afa88a2ed61428ea133`, and stack v1.1.81 pins it with attestations and anonymous pulls. Exact-stack official and owned reruns remain required. No official suite input changed |
| Published public operation contracts and production models were not mechanically coupled | Protocol drift | A repository could add a public custody selector, leak internal routing, or change required request/response fields while both repositories remained independently green | Marty-Protocol [#13](https://github.com/Marty-Protocol/Marty-Protocol/pull/13) through [#21](https://github.com/Marty-Protocol/Marty-Protocol/pull/21) define the DID-first core, policy, organization, issuer, Flow, issuance, and issued-credential contracts; marty-ui [#220](https://github.com/ElevenID/marty-ui/pull/220) through [#230](https://github.com/ElevenID/marty-ui/pull/230) incrementally align and enforce the runtime boundary; [marty-credentials#89](https://github.com/ElevenID/marty-credentials/pull/89) enforces the authoritative lifecycle boundary | Exact protocol commit `85770d02b6c225acbe4fc3446b71c4d206933bfd` is pinned in code and repository variables. The gate covers strict request/response fields, requiredness, canonical partial updates, tenant binding, conditional serialization, and recursive private-state rejection across every audited family. Generated-binding consumption remains owned by [marty-ui#222](https://github.com/ElevenID/marty-ui/issues/222). No imported official suite, runner, fixture, vector, assertion, expected result, exclusion, or test selection changed |
| Organization create/update and response behavior drifted from the public product contract | Public API bypass / protocol drift / data-minimization defect | The UI submitted ignored fields and offered unsupported types; the gateway forwarded unvalidated raw JSON and returned unsanitized successful service bodies; update methods disagreed; an unimplemented delete was advertised; and the legacy `/mine` shape could expose internal membership identifiers and email | [Marty-Protocol#19](https://github.com/Marty-Protocol/Marty-Protocol/pull/19) publishes strict Organization resource/create/update schemas and regenerated bindings. [marty-ui#228](https://github.com/ElevenID/marty-ui/pull/228) serializes only validated input, persists canonical discovery/admission settings, validates every public success response, unifies `/mine`, rejects private membership fields, uses `PATCH`, removes dead delete behavior, and removes the false jurisdiction UI | Merged as protocol `1816b7c5f7c03e145eab148a98127cbab00a8e1f` and marty-ui `ad0b9636109ed262e2164ad981c6fd93b157ead4`. Protocol CI/CodeQL/policy and every marty-ui PR gate passed: 653 local gateway/organization tests, 1,065 local UI tests, Vite 8 production build, Ruff, ESLint with zero errors, npm audit with zero vulnerabilities, pinned protocol contract, service/UI/browser/release/security/dependency/workflow-policy/CodeQL checks. Post-merge [main CI 30684640181](https://github.com/ElevenID/marty-ui/actions/runs/30684640181) and [CodeQL 30684640101](https://github.com/ElevenID/marty-ui/actions/runs/30684640101) also passed. No imported official evidence source changed |
| Issuer trust records, signing identities, and private custody profiles were not fully separated at the public boundary | Public API bypass / protocol drift / multitenancy defect | Raw request/response proxying could bypass strict models or leak nested custody coordinates; a caller could attempt to forge system authority or revocation attribution; global/system issuer mutation skipped membership enforcement; and `PUT` obscured partial-update semantics | [Marty-Protocol#20](https://github.com/Marty-Protocol/Marty-Protocol/pull/20) publishes strict tenant-bound IssuerEntity create/update/resource schemas plus a DID-only IssuerIdentity projection and regenerated clients. [marty-ui#229](https://github.com/ElevenID/marty-ui/pull/229) serializes validated requests, validates successful responses, rejects custody selectors recursively, binds update to the stored tenant, blocks public global/system mutation, derives `revoked_by` from authentication, and types active DID identity discovery | Merged as protocol `429fb97a2a17322211c4577f42c26396a98c81eb` and marty-ui `edfc892cf0b255975a5c4de96f58f1ae9ae06768`. Protocol PR and post-merge checks passed; every marty-ui PR gate passed, including 635 local gateway/trust-profile tests, Ruff, protocol contract, service/UI/browser/release/security/dependency/workflow-policy/CodeQL checks. Post-merge [main CI 30685579116](https://github.com/ElevenID/marty-ui/actions/runs/30685579116), [push checks 30685579077](https://github.com/ElevenID/marty-ui/actions/runs/30685579077), [organization quality 30685579291](https://github.com/ElevenID/marty-ui/actions/runs/30685579291), and [open-source policy 30685579288](https://github.com/ElevenID/marty-ui/actions/runs/30685579288) passed. RSA compatibility and every existing signing purpose remain supported. No imported official evidence source changed |
| Presentation Policy validation was bypassable and legitimate policy semantics were mislabeled as legacy | Public API bypass / protocol drift / multitenancy defect | The gateway validated a reduced Pydantic model but forwarded caller-controlled raw JSON, so unknown fields bypassed validation. Template-bound requirements, alternatives, consent metadata, compliance linkage, and version were hidden from the public resource. The UI sent `PATCH` while the gateway exposed `PUT`, and update-by-ID lacked an explicit organization match at the gateway boundary | [Marty-Protocol#17](https://github.com/Marty-Protocol/Marty-Protocol/pull/17) publishes the complete resource contract and typed bindings. [marty-ui#226](https://github.com/ElevenID/marty-ui/pull/226) serializes only validated models, resolves every direct and alternative requirement through its authoritative same-organization Credential Template, validates/sanitizes successful responses, exposes `PATCH`, and rejects cross-tenant resource substitution without proxying | Merged as protocol `6f4e5cfe12dc847fb4fd3072fea324e8e555de22` and marty-ui `10706cc72d6828b797cfc945984d9f78aa143832`. Protocol CI/CodeQL/policy is green; marty-ui [post-merge main CI 30560427372](https://github.com/ElevenID/marty-ui/actions/runs/30560427372) passed the contract, 1,146 service tests, browser lifecycle, UI, release, and security gates; organization quality, open-source policy, and [CodeQL 30560423528](https://github.com/ElevenID/marty-ui/actions/runs/30560423528) also passed. No imported compliance source changed |
| Credential Template read-by-ID lacked a tenant authorization boundary | Product multitenancy defect | An authenticated or unauthenticated caller with a guessed template ID could read another organization's public template metadata; incomplete API-key context could also reach resource routes without the full organization binding | [marty-ui#220](https://github.com/ElevenID/marty-ui/pull/220) requires membership or complete API-key identity, organization, permission, and scopes for every template-ID read or mutation; the gateway forwards the required permission and issuance uses the same complete internal context | Merged as `c526063ba6ac4a0d30ad899445061e30772e31fe`; 124 service tests, 97 focused gateway tests, 1,061 UI tests, the PR matrix, and main browser gate pass. Immutable release and released two-organization rerun remain required |
| Public response models marked schema-required `compliance_profile_id` optional | Protocol drift | A response could validate in local runtime models but violate the published Credential Template representation | [marty-ui#221](https://github.com/ElevenID/marty-ui/pull/221) makes the field required in both service and gateway response models and validates representative public responses against the pinned external schema | Merged as `6ad1e0b421cea115d02029af7127874425691881`; the PR matrix, 124 local credential-template tests, and the main-branch external contract job pass |
| Public claim model silently dropped canonical mdoc `namespace` | Protocol drift | Cryptographically valid official mdoc presentations contained no requested claims and were denied by policy | `marty-ui#187` carries canonical namespace through the public gateway and maps it only at the internal template boundary; `marty-integration-tests#186` uses the published field | Remediated and released in v1.1.66; the unmodified OIDF ISO mDL verifier lane passes all three active modules with 134/0/0 conditions |
| Public claim model omitted `description`, canonical `display`, and true `derived_from` | Protocol drift | Strict validation would reject valid protocol requests, while permissive validation had previously lost display and derivation semantics | `marty-ui#189` synchronizes gateway, protobuf, service, persistence, and response mapping and validates the claim graph | Remediated and released in v1.1.66; 625 focused tests, 173 persistence/flow tests, the complete PR matrix, release gates, and official mdoc lane pass |
| W3C adapter reconstructed only `credentialSubject` | Bypass risk | Could pass top-level VCDM assertions without signing the tested document | `marty-core#72`, `marty-credentials#74`, `marty-ui#138` | Removed and released; v1.1.48 signs the complete supplied document and passes 59/59 official assertions |
| W3C adapter performed suite-specific semantic validation | Adapted gap / bypass risk | Negative cases could pass before production code saw the input | `marty-ui#138` deletes adapter-owned validation; `marty-credentials#74` owns structural and allowlisted digest validation | Removed and released; production validators/verifiers own acceptance and the immutable official negative assertions pass |
| W3C adapter duplicated the general UI issuance boundary | API bypass risk | Private template/resolver calls could drift from the API the UI is required to use | `marty-ui#138` calls the shared general `create_issuance` path with only organization, public issuer DID, template, and complete document | Removed and released; gateway regressions prohibit private resolver/template calls and v1.1.48 passes the official suite through the shared path |
| Managed registry lacked `ldp_vc`/EdDSA | Missing feature | Public template bootstrap failed; unsafe ES256 substitution was possible if forced | Official fixture bootstrap plus managed EdDSA profile | Implemented and released; v1.1.48 proves managed EdDSA profile creation, full-document issuance, remote signing, and verification |
| Public `application_id` was rejected downstream | Protocol drift | A gateway-valid issuance request could fail at the issuance service and lose application linkage | `marty-protocol` issuance schema and `marty-credentials` request/transaction mapping | Fixed locally; requires protocol and credentials CI/merge |
| Generated `credential_subject` type collapsed object/array to string | Protocol drift | Generated clients could not represent the production request | `marty-protocol` code generator and generated bindings | Fixed locally; Python/Rust/TypeScript checks pass |
| Official W3C registration claimed JOSE enveloping proof | Misleading claim | Selected assertions Marty was not exercising natively | `w3c_vc_conformance.py` registration | Fixed locally; official config now advertises `vc2.0` only |
| W3C runtime cleanup deleted the upstream tracked `reports/.gitkeep` sentinel | Harness integrity failure | The first unmodified-suite run correctly refused to publish official evidence even though no assertion was edited | Preserve every tracked upstream file and delete only ignored runtime report output; verify the exact commit and clean tracked state again after execution | Guard worked as designed in run 30427157292; cleanup regression added and immutable rerun required |
| The official W3C suite rewrites tracked `reports/related-resource.json` as runtime scratch state | Harness integrity failure | The second unmodified-suite run correctly refused evidence, but a clean canonical checkout cannot also be the suite's writable execution directory | Keep the pinned canonical checkout immutable; execute the exact same commit in a disposable Git worktree, allow and record only this upstream-owned runtime mutation, and reject every test/assertion or other tracked-source change | Exposed by run 30427767456; focused guards pass and an immutable rerun is required |
| W3C conformance burst exhausted two independent production limiters | Harness configuration gap | Later normative assertions observed HTTP 429 rather than product acceptance/rejection, making their results unusable | Keep both limiters active. Use finite 100,000-request gateway and OID4VCI token-endpoint budgets only in the disposable W3C stack; retain the token endpoint's production default of 30 | Run 30427767456 proved the gateway budget was effective (`X-RateLimit-Limit: 100000`) and exposed the separate 30-request token limiter; clean rerun required before classifying any later assertion |
| Released Compose omitted `VCDM_RELATED_RESOURCE_URLS` from issuance | Deployment contract gap | The production validator correctly failed closed on the official valid `relatedResource`, leaving the unmodified suite at 58/59 despite correct digest-validation code | Forward an operator-controlled exact-URL allowlist with an empty default; record the pinned suite's reviewed URL beside its commit and pass it only to the disposable W3C deployment | Remediated in v1.1.60; GitHub run 30446716188 passed the exact suite with no assertion, fixture, expected-result, or test-selection change |
| Recent-error diagnostics were not request-correlated | Investigation quality gap | A protected-term error from an expected negative assertion appeared next to the later related-resource failure and was initially misattributed | Treat the redacted diagnostic tail only as uncorrelated context; use response bodies, transaction persistence, isolated requests, and a fresh full-suite rerun before assigning root cause | Audit corrected the attribution: no related-resource transaction was persisted, the public response reported `related_resource_validation_not_configured`, and the deployment-only correction passed the exact suite |
| OpenBao provider metadata was stored beneath `publicKeyJwk` | Product implementation gap | DID resolution rejected the managed EdDSA verification method before official assertions | `marty-ui#140` converts supported public keys to JWKs and fails closed on invalid material | Merged and released in v1.1.43; immutable rerun passed this earlier boundary |
| OpenBao Ed25519 public keys are raw base64 rather than PEM | Product implementation gap | v1.1.43 rejected the real managed public key during issuer-profile creation | `marty-ui#142` decodes an exact 32-byte Ed25519 value by provider key type and retains PEM paths | Merged and released in v1.1.44; run 30353063442 passed this boundary |
| OpenBao prehashed EdDSA input and advertised DER output | Product implementation gap | Native Data Integrity signatures could not be produced or described correctly | `marty-ui#140` propagates the profile algorithm, sends raw EdDSA input, and returns raw signature metadata | Merged, released, and proven by the v1.1.48 59/59 issuer/verifier run |
| W3C fixture profile omitted its algorithm | Harness configuration gap | The managed Ed25519 key was provisioned behind a profile that defaulted to ES256 | `marty-integration-tests#157` explicitly declares EdDSA in profile administration | Merged and released in v1.2.22; run 30353063442 passed profile creation |
| Issuance protobuf descriptor silently dropped template `issuer_did` | Protocol drift | The template existed and was correctly bound, but issuance saw it as legacy; one transport defect blocked most positive W3C issuer assertions | `marty-credentials#77` synchronizes the descriptor and asserts DID-first field numbers and forbidden selectors | Released in credentials v0.1.24 and immutable stack v1.1.45; run 30357905195 passed this boundary |
| Inner VC issuance validation escaped as an ASGI exception | Public error-boundary gap | Invalid standards input was rejected but produced a 500 traceback instead of a controlled 422 | `marty-ui#144` translates the normal issuance-model validation error without echoing credential input | Released in immutable stack v1.1.45; the official negative assertions now return controlled responses |
| Valid Data Integrity credentials were classified as unknown before verification | Product routing gap | The released Rust verifier was bypassed for otherwise valid structured credentials | `marty-ui#146` uses proof shape only for routing and leaves all acceptance checks to the Rust verifier | Released in stack v1.1.46; run 30366183232 proved that structured credentials reached the Rust verifier |
| Issuance completion enforced current-time validity | Product semantics gap | A standards-conforming past/future credential could not be issued even though its proof was valid | `marty-core#75` validates syntax/order and proof during completion while retaining current-time checks in normal verification | Remediated and released; v1.1.47 passed the previously failing past/future issuance assertions |
| Credentials release image pinned an older core than its source workspace | Release provenance/consistency gap | Local and source-wheel tests exercised corrected completion behavior while the deployed issuance image retained the expired-claim rejection | `marty-credentials#80` aligns Cargo revisions and release-wheel commit and adds a coherence contract | Remediated in v0.1.26 and proven in v1.1.47; exact manifests, checksums, attestations, anonymous digest access, and the formerly failing official assertions pass |
| Data Integrity verifier resolved only did:key | Product DID-resolution gap | Correct tenant-scoped did:web credentials reached Rust but could not be cryptographically verified | `marty-core#77` accepts resolver-owned public methods; `marty-ui#148` enforces exact DID document, controller, method, and relationship | Released in v1.1.47; run 30380594927 reached the exact document-identity guard, exposing the separate public alias-publication defect rather than the prior did:key-only limitation |
| Public did:web route returned a stored alias DID | Product DID-publication gap | The exact resolver correctly rejected the managed public method because the document `id`, controller, and relationship identifiers represented another DID | `marty-ui#150` retargets the tenant-bound public document and makes candidate resolution skip mismatched documents | Remediated and released; 197 focused tests, every PR/release gate, and the v1.1.48 59/59 official run pass |
| Token endpoint required a redundant form `client_id` with RFC 7523 client assertions | Product interoperability gap | Every active official OID4VCI interaction reached the real token endpoint but failed HTTP 401 despite a transaction-bound registered client and a signed assertion identity | `marty-credentials#81` permits omission only after signed `iss`/`sub`, public-JWKS signature, audience, time, key, and replay checks establish the exact registered client; supplied mismatches still fail | Remediated in credentials v0.1.27 and immutable stack v1.1.49; official run 30389863768 reports 1,015 successful conditions, zero failures, and zero warnings |
| Public mdoc template vocabulary drifted from the Marty contract | Protocol drift / bypass risk | The gateway and official fixture used the external `mso_mdoc` wire label where the internal public contract requires `MDOC`; callers could also fabricate `vct` for an mdoc and request automatic artifact generation | `marty-protocol#13`, `marty-ui#153`, and `marty-integration-tests#165` use the canonical contract, derive `doctype`, make `vct` conditional, and remove public `auto_generate_artifacts` | Merged and released in v1.1.51; the immutable release, no-commerce scan, artifact-only stack smoke, and manifest attestation pass |
| DID-first issuer resolution dropped the profile certificate chain | Product DID-resolution defect | The certificate administration API verified and persisted a chain matching the managed profile key, but issuance resolving the same identity solely by `issuer_did` received no `issuer_x5c`; independent SD-JWT verification therefore reported `UnsupportedVerificationMethod`, and mdoc issuance had no usable chain | `marty-ui#154` preserves the profile-owned public chain on the exact organization + DID + purpose + format + algorithm resolution result, while keeping service and key coordinates private | Merged with 145 focused gateway tests; immutable stack release and EUDI rerun remain required |
| mdoc `x5chain` was encoded in the protected COSE header | Product ISO 18013-5 interoperability defect | Marty-local parsing accepted the credential, but Multipaz follows ISO 18013-5 section 9.1.2.4 and reads `x5chain` from the unprotected header; official issuance and presentation therefore failed despite a valid profile-owned chain | `marty-core#79` moves only `x5chain` to the unprotected header, retains `alg` in the protected header, and covers local plus remote/HSM prepare/assemble signing paths | Merged after the full cross-platform matrix plus local locked tests, Clippy, formatting, and black-box COSE regression passed; release propagation and immutable EUDI/mdoc evidence remain required |
| OIDF mdoc verifier adapter omitted `organization_id` | Harness public-boundary defect | Every official module reached the production gateway, which correctly rejected `/v1/flows/verify` with HTTP 422 before request-object creation; the runner then timed out in `WAITING`, so the run provides no mdoc cryptographic evidence | Pass the disposable fixture organization through `OIDF_MARTY_ORGANIZATION_ID` and include it in the normal authenticated public flow request | Fixed locally with 57 focused tests; merge and immutable official rerun required |
| Signed issuer metadata, batch issuance, and credential-response encryption are not advertised | Missing optional features | The active profile is narrower than the complete optional OID4VCI feature set | Keep explicit capability metadata and owned, expiring skip records; implement each only through a separately reviewed production path | Open by design; never represent these skipped modules as passed. Key-attestation-bound proof trust is implemented and no longer belongs in this gap row |
| Official lanes use one organization | Missing official evidence, addressed by separate product-security evidence | Official results cannot prove tenant isolation | `marty-integration-tests#203` adds a separately labeled two-organization public-boundary lane; `#204`, `#207`, `#208`, `#209`, `#212`, and `#213` add and correct owned setup, lifecycle, and DID-negative evidence without touching imported suites | Released-stack runs 30524717116 and 30528390251 pass on v1.1.78. Together they cover two principals, distinct issuer DIDs/profiles, template/policy/DID substitution, RBAC, API key, SCIM, flows/results, webhook, audit, leakage prevention, custody-selector rejection, unknown/non-active/incompatible DID denial, and idempotent uniqueness; wider feature rows remain open |
| DIDComm positive delivery lacked an exact authorization rule, a valid HTTPS test agent, and an installed released holder-side verifier | Product authorization/transport defects plus owned harness dependency defect | The route initially failed closed at authorization, then correctly rejected plaintext transport; after product delivery succeeded, the runner could not perform its decryption assertion | [marty-common 0.2.5](https://github.com/ElevenID/Marty/commit/2f14f77fa7e70c1ea9655ea94dd22c2af8bf7f59) publishes the exact Cedar rule; `marty-credentials#120`/`#121` publish operator-only additional TLS roots while retaining system trust and mandatory HTTPS; `marty-ui#293` confines the private-IP bridge and root mount to conformance; `marty-integration-tests#267` installs only the manifest-pinned, digest- and provenance-verified released wheel | Exact stack v1.1.108 and owned harness `592a24fef4b982fd1419ee8f0498a063144ac713` pass run 31153194710 with artifact `sha256:d6333c0718f1ae90bf1e13b6904525fd4b08bd4f64d65e048b65c0eddd5cc898`. This proves released self-interoperability, not official or cross-vendor conformance; cross-tenant and independent-agent cases remain open |
| SCIM `externalId` exceeded the organization member identity column | Product persistence/error-boundary defect | A valid opaque external identifier caused PostgreSQL rejection and a public HTTP 500 | `marty-ui#210` expands the field to 255 characters with migration and schema/route regressions | Released before v1.1.78; the unchanged external matrix creates and isolates the non-UUID SCIM identity successfully |
| Notification and webhook routes were absent from the Cedar route map | Public BOLA/authorization defect | An organization-A session could enumerate organization-B webhook metadata; resource routes and SSE could select conflicting tenant inputs | `marty-ui#208` adds ownership checks; `marty-ui#212` maps webhook/subscription/notification/SSE permissions, rejects conflicting selectors, and rechecks ownership in the service | Released before v1.1.78; webhook collection/resource/secret isolation passes externally, while notification/SSE delivery retains focused gateway/service/UI regressions and still needs an external matrix row |
| Organization-bound API keys were treated as human members | Authentication-principal defect | A valid B-scoped machine credential failed its own organization access, encouraging unsafe bypasses; selector substitution still had to remain denied | `Marty#14` and `#15` introduce fail-closed machine-principal authorization in `marty-common` 0.2.2; `marty-ui#214` consumes the attested artifact | Released in v1.1.77; the unchanged external matrix proves the B key reads B and cannot select A |
| Organization audit routes were absent from the shared Cedar map | Public cross-tenant data leak | An organization-A reviewer received organization-B audit events including identifiers and metadata | `Marty#16` maps list/detail/export to `audit:view`/`audit:export` in `marty-common` 0.2.3; `marty-ui#216` adds organization-service defense in depth | Released in v1.1.78; unchanged run 30524717116 proves direct B list denial plus A-path foreign-event substitution denial without foreign-data leakage |
| Owned tenant fixture sent stale flow fields, incomplete dependencies, and one unsupported lifecycle label | Harness contract/setup drift | The product correctly rejected a missing issuer, removed top-level flow fields, a draft dependency, and the invented literal `inactive` status before the security assertion could execute | `marty-integration-tests#207`, `#208`, `#209`, and `#213` provision the issuer, use the current server-resolved flow contract, activate the dependency, and use `draft` as the supported non-active profile state | Corrected only in ElevenID-owned code; 446 unit tests and the final released-stack lane pass, with imported official suites unchanged |
| Canvas provenance accepted an unscoped organization and exposed issuer-profile internals | Public authorization/data-boundary defect | A guessed delivery, external credential, or canonical credential identifier could cross the intended tenant boundary; public responses leaked internal profile/mode metadata | `marty-credentials#86` requires trusted tenant context and scopes all selectors; `marty-ui#177` adds authentication, membership, permission, and internal service authentication | Released in v1.1.61 after all three selector substitutions, trusted-context mismatch, two-organization pre-backend denial, public response-shape regressions, full PR checks, and the artifact-only stack smoke passed |
| Ordinary dashboard and template-authoring journeys fetched internal issuer profiles | Public abstraction leak | A transient dashboard route and credential-template wizard received custody coordinates even though verification itself used the public DID projection | `marty-ui#204` moves ordinary readiness and authoring to `/issuer-identities`; profile administration remains isolated to authorized setup pages | Released in v1.1.72; run 30506329100 completes browser issuance and verification with no private selectors or issuer-profile collection request |
| Official lanes do not drive the browser | Missing evidence | API-only official lanes could not prove UI request shapes or private-selector absence | Released-stack Playwright smoke in run 30506329100 selected public DIDs and completed ordinary application, submit, claim, offer, and verification routes | One-organization issuance/verification slice complete; adversarial cross-tenant browser coverage remains open |
| Marty called a signed by-value Request Object `url_query` | Protocol/transport drift | The name did not match the official OIDF runner, so signed behavior could have been misrepresented as direct-query compliance | `marty-protocol#15` defines `request_uri`, `request_object`, and direct unsigned `url_query`; `marty-ui#206` implements the direct production path while retaining signed by-value behavior separately; `marty-integration-tests#200` forwards the exact raw query to the unchanged official wallet | Released in v1.1.73; run 30509192015 passes all ten official URL-query modules with 273/0/0 conditions and no expected failures/skips |

## Immutable evidence collected

| Evidence | Result |
| --- | --- |
| Current v1.1.97 official matrix [30789127694](https://github.com/ElevenID/marty-integration-tests/actions/runs/30789127694), exact harness `74c934018f0739a9f5eaed7317d4cc5399f9526c` | OID4VCI issuer (`sha256:d51c5fcf4bb8a8d27217066180b883fdebe04e98a01150457e6d748352f7b874`), OID4VP Final plus released browser (`sha256:d04ec1892d1f379537470e6e001822c45b574b0d761f5c6cb11a1af89c0f06f8`), native URL-query (`sha256:d16b05b8ac477a5fada754e74487c751661b337c58846be0dca15a201c826a4d`), HAIP (`sha256:feb7dd957d593cda8e12657910e755863b69682a7ed4e58188d97f38577ddee2`), W3C VCDM v2 (`sha256:6688008237954ddf445fd7faf40836d1888fb8be0ed5a7a79252c6e2e81135eb`), and EUDI 45/45 (`sha256:a0239e8e2a0a88d8e2f49bb87184c938356a74047ce3d6d69aff898f8a2e4672`) passed. The OIDF mdoc artifact (`sha256:39f91687b4bf569613284ae54c6ccc77a99ae87ca8bac84c428794c4f2f1e729`) records zero official evidence because the unchanged upstream certificate is expired. |
| `marty-ui` v1.1.36, manifest `sha256:33273c4bbe6ccfc33f22735986f0019e21715f4adf99b425af99d6dccba80f7c` | 52/55 EUDI tests passed; real format/algorithm fixes validated |
| `marty-ui` v1.1.37, manifest `sha256:3a8ed3f65a98333bf75f1082ed181709b2910215db082ea443ac72e25c4a5897` | 53/55 passed; expiry negative corrected |
| `marty-ui` v1.1.38, manifest `sha256:091ea151f25c2297c2ad4546cfe089393301652039614379ce69516f353cf050` | 54/55 EUDI tests passed; the remaining negative exposed an authoritative fail-open holder-binding defect |
| EUDI run [30231825647](https://github.com/ElevenID/marty-integration-tests/actions/runs/30231825647), sanitized summary `sha256:d85211cd6d960d72a1c97921516f03db2a307229da2af8a010494b434e8e452f` | Failed safely and specifically as `eudi-invariant-tamper-final-decision-allow`; prompted marty-ui#126 |
| OID4VP Final run [30230194196](https://github.com/ElevenID/marty-integration-tests/actions/runs/30230194196), sanitized summary `sha256:f96a634c36b0adf65c77308272836b2a1dfb2f869e56051d4bdbe867c83d94ea` | Passed against v1.1.38 and official runner `release-v5.2.0` |
| HAIP run [30230195076](https://github.com/ElevenID/marty-integration-tests/actions/runs/30230195076), sanitized summary `sha256:b7a9200e66a59f5b319d2c095102e30e640e78df8a7dedf676caadc660332950` | Passed against v1.1.38 and official runner `release-v5.2.0` |
| W3C v2 run [30230312063](https://github.com/ElevenID/marty-integration-tests/actions/runs/30230312063), sanitized summary `sha256:5674d1b6c52e5d5291082f542af6c132a3b5ce72168f7dfe08fb9d7149d8e88b` | Failed at public template bootstrap; exposed missing managed `ldp_vc` capability |
| `marty-ui` v1.1.42, manifest `sha256:82404a3586fd2fd50b1fc6c99ef3f0c125dc25433247bf2f20c90c7b32b9e9b1` | Materialized seven immutable components and pulled the released credentials image anonymously |
| W3C v2 run [30348779384](https://github.com/ElevenID/marty-integration-tests/actions/runs/30348779384), sanitized artifact `official-w3c-v2-30348779384-1`, artifact digest `sha256:4d1cc64f224d7683dad284199bbabb4181b34dff6505c05929c78b891064e857` | Reached the production DID resolver and failed closed on malformed OpenBao public-key publication; exposed the PEM-to-JWK and EdDSA adapter gaps |
| `marty-ui` v1.1.43, manifest `sha256:6bf612248e8246a500d06a5975c5a6d698566eb692eacf966893cdbb49a6e4f6` | Provenance checks, corrected image builds, and the artifact-only public stack smoke passed |
| W3C v2 run [30351469090](https://github.com/ElevenID/marty-integration-tests/actions/runs/30351469090), sanitized artifact `official-w3c-v2-30351469090-1`, artifact digest `sha256:e19a8e909a778fc0249bedffea686bfbe470c5f19e2d1325dc649139a110cbe9` | Passed the prior JWK-shape boundary, reached the real OpenBao Ed25519 public key, and failed closed because the provider returns raw base64 rather than PEM |
| `marty-ui` v1.1.44, manifest `sha256:aa35b7ece5771f5d8d0d1b07dc38b97d75fb2b8796ff95239c988cf01a6a4076` | Provenance checks, anonymous digest pulls, corrected Ed25519 key publication, and the artifact-only public stack smoke passed |
| W3C v2 run [30353063442](https://github.com/ElevenID/marty-integration-tests/actions/runs/30353063442), sanitized artifact `official-w3c-v2-30353063442-1`, artifact digest `sha256:aa5988e2982dd8ff9e0aebd462da0a79799b64dfee3ff2a300d9211b16c539e2` | Reached the pinned official suite at commit `1db599924e6601555933550e0e65925a6abbd0a8`; passed both OpenBao boundaries, then exposed the stale issuance protobuf descriptor and uncontrolled inner validation error |
| `marty-credentials` v0.1.24, release commit `e866439a4bf443beb09c0b86b861fd83f91d305a` | Release contract, checksums, SBOM, signatures, provenance, and final public issuance/verification images passed; issuance image `sha256:b5522b65898e62b03453ef86496d64ed58430f3460cd8c25d58096d3d53d526b` |
| `marty-ui` v1.1.45, manifest `sha256:8ee54dec98af141d348a7963b83c70875b95fe94a8fa8010773b3b00ea3bbe00` | Attested seven-component manifest, artifact-only public stack smoke, and anonymous digest pulls passed; it pins credentials v0.1.24 |
| W3C v2 run [30357905195](https://github.com/ElevenID/marty-integration-tests/actions/runs/30357905195), sanitized artifact `official-w3c-v2-30357905195-1`, artifact digest `sha256:da0de923b8e098a62b7ae38f010164e187a0b328fd54bf5cc19f19869dddff06` | Exact official commit `1db599924e6601555933550e0e65925a6abbd0a8` passed 35 normative assertions and failed three, exposing verifier routing and issuance-time validity semantics; the evidence guard credited issuer and VP-verifier roles but correctly withheld VC-verifier completion |
| `marty-core` v0.1.23, release commit `3a073cfa54672e7ed3905aa59227ab7d5e4e3f49` | Locked tests, feature checks, cross-platform release artifacts, checksums, SBOM, Sigstore bundles, and provenance passed; Linux Python wheel `sha256:359beb4502b24dccb40756a6a067fe4430af051e1ef71195cc7d7a042f22cb44` |
| `marty-core` v0.1.24, release commit `f2074854ca31f76d6f44cbf03dc055a912814330`, run [30372799402](https://github.com/ElevenID/marty-core/actions/runs/30372799402) | All 19 release jobs passed; the independently downloaded Linux `marty_rs` wheel matches `SHA256SUMS` at `sha256:b70e61dc95a3e11a616445491f6812ac4673cdd8281b2bd83212fc3540144c14` and its GitHub provenance attestation verifies |
| `marty-credentials` v0.1.25, release commit `4fd7785e70b71e12038d58b3509256336522835f` | Full Python/Rust/WASM, security, policy, image-build, checksum, SBOM, signature, and provenance gates passed; issuance image `sha256:45bc3dfd6623d3350f35147942d380dff2761b1ce49ebdee6c42edb5200c3c94`, verification image `sha256:72e680b8a237f0dd5934341af88d25e1b99e3bb8340328bf49c99ca340fc8cda` |
| `marty-credentials` v0.1.26, release commit `4d8b004b10a4eb4278957dc46228166d800f45ac`, source run [30377296203](https://github.com/ElevenID/marty-credentials/actions/runs/30377296203), finalization run [30378769520](https://github.com/ElevenID/marty-credentials/actions/runs/30378769520) | All nine source-artifact jobs and four finalization jobs passed; published digest files match `SHA256SUMS`; OCI attestations and anonymous registry access verify for issuance `sha256:63d71bfe0c8c62733293d2faf607a86074f84a297e8cd90706bd461de7947980` and verification `sha256:a1e7b079b60894918f24c5cc1aad381b8987bee4a185007cfc226acbdca1674d` |
| `marty-ui` v1.1.46, release commit `dd860a9173cfe01a175fd0b11dbdae3ce0cb2b69`, manifest `sha256:b9acedb2e531a833be038b49f80c56721f9348e5fa17f4585a8119c54d4787b4` | Attested seven-component manifest, checksums, signed images, anonymous digest pulls, and artifact-only public stack smoke passed; UI `sha256:68f5a0648f185244f72daf0a2d24274b71054422036fb7c3473bf68c73dc6fb5`, services `sha256:b2e75cc0ca82b145155f97a43df94adfb43c7edf70450e32f12cdd0e7db572d8`, migrations `sha256:a826c53e7a2c591a3146dc46a55325818065b4210a0319be3398985be48c1aa1` |
| W3C v2 run [30366183232](https://github.com/ElevenID/marty-integration-tests/actions/runs/30366183232), sanitized artifact `official-w3c-v2-30366183232-1`, artifact digest `sha256:570c1760511c43b09839561f9f73ac44c45658bc236142f89412398b4b3bfce2` | Exact official commit `1db599924e6601555933550e0e65925a6abbd0a8` reproduced the three failed assertions and narrowed them to credentials image/source drift plus missing product-resolved did:web verification; the evidence guard again withheld VC-verifier completion |
| `marty-ui` v1.1.47, release commit `ac0b7809fc20c2ed8ecf0bef0ebdeffe73d1ea4a`, manifest `sha256:da7f476dfa4bcc8cb6352b2aa5b32efbaf265f6257c883a2c6cefba44ec783e3`, run [30379854048](https://github.com/ElevenID/marty-ui/actions/runs/30379854048) | All five release jobs passed; manifest checksum and attestation verify; anonymous digest access and OCI attestations verify for UI `sha256:d253b76f6d40c0e0ff727d4d2e8ee7702d856fde31f54dfc36008d423d7adf5f`, services `sha256:611e121a4df22b2e59b95a2b2fe04a2bf4e8d87f6402cf5ee6363f7112cdfa59`, and migrations `sha256:da259f3ebd8595688d513da7f75a3141a51edc486fbf3e29bdf91c70eeac7325` |
| W3C v2 run [30380594927](https://github.com/ElevenID/marty-integration-tests/actions/runs/30380594927), sanitized artifact `official-w3c-v2-30380594927-1`, artifact digest `sha256:92161f74ed38a98d83ef45803da7d69480f424d60fc6a4031c9f01d3b0283be7`, summary `sha256:7adf65a1fea8d4dec3a458f84b49bdf087a22efad9c38f7691f85d905f19bcca` | Exact official commit `1db599924e6601555933550e0e65925a6abbd0a8` passed 57 normative assertions and failed two exact-DID verifier assertions; it proves the release-coherence and issuance-validity fixes and exposes one public DID-document alias mismatch |
| `marty-ui` v1.1.48, release commit `56147d7cc2af1fc4d9c6d6472e97bc7ca3512faf`, manifest `sha256:dadff3abe5fd721148c53a9b99f5b86473e8fcd3a80b41962dcf73ee7a1639be`, run [30381800023](https://github.com/ElevenID/marty-ui/actions/runs/30381800023) | All five release jobs passed; the independently downloaded manifest matches `SHA256SUMS` and its provenance verifies; anonymous digest access and OCI attestations verify for UI `sha256:4b3c4fec9f7169531e4cc7efed3e866b6f3c967b3957656481ebfbc49eeec446`, services `sha256:4044102f32d3e80915d641780e7b7dac7fe4f9d9d51e806a2427bd7a7d78f436`, and migrations `sha256:786dc77a1817c7be7f09d6b401018e013ea0a158576c99c79499a26df2b6aecc` |
| W3C v2 run [30382577365](https://github.com/ElevenID/marty-integration-tests/actions/runs/30382577365), sanitized artifact `official-w3c-v2-30382577365-1`, artifact digest `sha256:ecae45c7972e0e9b589c6eea9d51a21559470c6164088f601b70ba9a8ee6dbea`, summary `sha256:4f2dd455dfc0dacc921359b55b6ab5888439f375890757e31c74b87d455c5a60` | Historical adapted-runner evidence: official base commit `1db599924e6601555933550e0e65925a6abbd0a8` plus the proposed PR 174 assertion fix passed 59/59 against v1.1.48. It is not an unmodified official-suite pass and is retained only as product-path regression evidence. |
| `marty-ui` v1.1.57, release commit `32eb84f26242759e0f3f8fbba81f06e5bf845109`, manifest `sha256:226aa31d75fcf4e7d55eda798bb9634fe6fd0cd11e495225dcba827a79cf99ca`, run [30426673558](https://github.com/ElevenID/marty-ui/actions/runs/30426673558) | All five release jobs passed; the independently downloaded manifest matches `SHA256SUMS` and its GitHub provenance verifies. The services image `sha256:007e9d43e129fcdf910e23882e3d5b07465b725d01fa2730da0ad179719d5b9a` contains the organization-bound API-key verification fix. |
| Unmodified W3C v2 run [30427157292](https://github.com/ElevenID/marty-integration-tests/actions/runs/30427157292), sanitized artifact `official-w3c-v2-30427157292-1`, artifact digest `sha256:a4f0c233eb0f987e1d13977ac114362fbdd73f93624d5b19656c753270c333b8`, summary `sha256:95b85c546d98946a5659518853cc73af3a5ce1430bd24368ba8e6c63f2716925` | Exact v1.1.57 artifacts passed provenance, anonymous pulls, public fixture creation, organization-bound API-key verification, and the exact official checkout. The clean-source after-check then rejected deletion of tracked `reports/.gitkeep`; a 10,000-request transport budget also caused late HTTP 429s. No official evidence was credited and no product assertion is classified from the polluted tail. |
| Unmodified W3C v2 run [30427767456](https://github.com/ElevenID/marty-integration-tests/actions/runs/30427767456), sanitized artifact `official-w3c-v2-30427767456-1`, artifact digest `sha256:56725a5ee96a7a50bf85fc50a4213110709fd694f5b1155911f1e23ce64b62cf`, summary `sha256:38642acaad30810bd73c48ddf257a80381dcf807c0672e77f99519d259e540cd` | Exact v1.1.57 artifacts and official commit ran without an ElevenID test patch. The source-integrity guard rejected the suite's own tracked `reports/related-resource.json` runtime rewrite, while response headers proved the 100,000-request gateway budget was active and exposed a separate 30-request OID4VCI token limit. One 422 occurred amid the polluted tail, so no assertion is classified and no official evidence is credited. |
| Unmodified W3C v2 run [30430439330](https://github.com/ElevenID/marty-integration-tests/actions/runs/30430439330), sanitized artifact ID `8715369635`, artifact digest `sha256:9a6e8a5e62fbe8aea060e5cd3a912dd8886a87b36c63a40230e1c06fa0d669ee`, summary `sha256:69469f66928b18e7b2acd27b38394993d218d3165dd3db061b27b391e3af69c3` | Exact official commit and immutable v1.1.58 stack executed all three configured roles with no source modification or exclusion and failed one valid related-resource assertion. |
| Unmodified W3C v2 run [30441474283](https://github.com/ElevenID/marty-integration-tests/actions/runs/30441474283), sanitized artifact ID `8719883865`, artifact digest `sha256:c57c4fc429d47ba378e948c8f4b97d29436edd3ae232cd56bd9622a6ff580f14`, summary `sha256:5cdd6377c3b20d8c76cdb75c0eae95019cbb6fe41e820a1dad72a57d0c628b9a` | Exact v1.1.59 artifacts reproduced 58/59. Isolated public-API replay proved the failure was the issuance service's fail-closed `related_resource_validation_not_configured` response because released Compose did not forward an allowlist; the nearby protected-term log belonged to the preceding expected negative. |
| Local clean-stack W3C v2 diagnostic against v1.1.59 manifest `sha256:79a319534c9de76b27e06473300f185d43c21baf87d39618d5357d3e6acf8d1`, suite report `sha256:3cf41766be230c01435b27b61c09826648980aa5e28e8bd878a182aa50ef1f35` | Passed the complete pinned suite with issuer, VC-verifier, and VP-verifier evidence after only deployment configuration was corrected. Evidence records `official_upstream_unmodified=true`, `disposable_exact_commit_worktree=true`, `test_or_assertion_source_modified=false`, and an empty exclusions list. This is remediation validation, not the final immutable GitHub release claim. |
| `marty-ui` v1.1.60, release commit `a8a1e3626097d220131f0f6021b3d3c9cefa620e`, manifest `sha256:f11da15a32884b737d23632dec5a029edda25f5837e2a33c15a19d42243ae904`, run [30446107785](https://github.com/ElevenID/marty-ui/actions/runs/30446107785) | Every release job passed, including dependency provenance, anonymous digest pulls, signed images, no-commerce scan, and the artifact-only public stack smoke. |
| Unmodified W3C v2 run [30446716188](https://github.com/ElevenID/marty-integration-tests/actions/runs/30446716188), sanitized artifact ID `8721818953`, artifact digest `sha256:2a5670c499ce8e5da352bb86547e2b37f5f7815318986e21014dafd15836bf5f`, summary `sha256:b3c63d3365148c9a6208c26de6aa524249e6b3bc300f1cc49c2e00b0b1904df9` | Passed against exact v1.1.60 artifacts and upstream commit `1db599924e6601555933550e0e65925a6abbd0a8`. Evidence records all three configured capabilities, `official_upstream_unmodified=true`, `disposable_exact_commit_worktree=true`, `test_or_assertion_source_modified=false`, no runtime source mutations, and no exclusions. |
| `marty-credentials` v0.1.31, release commit `8def9c22cd0e4d2913ced6e5e3d1852c7b28e7db`, source run [30450485232](https://github.com/ElevenID/marty-credentials/actions/runs/30450485232), finalization run [30451746630](https://github.com/ElevenID/marty-credentials/actions/runs/30451746630) | Cross-platform Rust/Python/WASM artifacts, tests, checksums, SBOMs, signatures, provenance, and digest-first image publication passed. The attested issuance image `sha256:c5da4dbb1209d6e28ffd234077cdf391bb625360b401ec72329765fd8b9466e9` contains the organization-bound Canvas provenance lookup and public issuer response model. |
| `marty-ui` v1.1.61, release commit `6ae8e47ff5af8800c2bf392ec684c583dd63a01d`, manifest `sha256:d8dea9e10d592b592833284abb3100daf5eef8640dd925f856828a08840f10b5`, run [30452533884](https://github.com/ElevenID/marty-ui/actions/runs/30452533884) | Every release job passed, including dependency and OCI provenance, signed images, no-commerce scanning, upgrade/rollback validation, the artifact-only public integration suite, and manifest attestation. The release pins credentials v0.1.31 and removes issuer-profile/mode metadata from the Canvas provenance UI. UI `sha256:848bb2e85a615ac44b57570a2c604b3aeeb44180ecaff78613dc863e8ce9e74e`, services `sha256:b0550e7485338b2de711db910f232bc9ca8b00642d319fc25fc20eaa871efe42`, and migrations `sha256:dfd317cf79085b6ae806c12025a95197a4e2bfee81f6362a9b25fcb6e3bb34dc` independently verify against GitHub attestations. No upstream official-suite source was changed or rerun to manufacture this product-boundary result. |
| OID4VCI issuer run [30230312937](https://github.com/ElevenID/marty-integration-tests/actions/runs/30230312937), sanitized summary `sha256:eacc7f2d7fd9edc2ffec43e3faaa590d1c733d429c74bcdaf47c7e3f7189b444` | Metadata passed; interaction modules exposed missing official-runner client identities |
| OID4VCI issuer run [30231686437](https://github.com/ElevenID/marty-integration-tests/actions/runs/30231686437), sanitized summary `sha256:4adb5cc1e43b14953fc3603a63f3e396a211890399d0de7914562e26a73852a9` | Authorization-server identity passed; exposed internal-template/public-configuration ID confusion |
| OID4VCI issuer run [30232003181](https://github.com/ElevenID/marty-integration-tests/actions/runs/30232003181), sanitized summary `sha256:de313a9f8dc4338f1ff83dbb0ae60822dda6f468fc7b219f3f0b41e25412d1cb` | Reached issuer interaction; exposed selection of bare JWT VC `PID` instead of advertised SD-JWT `PID#sd-jwt` |
| OID4VCI issuer run [30385508700](https://github.com/ElevenID/marty-integration-tests/actions/runs/30385508700), sanitized artifact `official-oid4vci-issuer-30385508700-1`, artifact digest `sha256:97524a4f3117fe376ba48371061ae2438c7b66fec9481f2c73628c87e5c3bc19` | Exact v1.1.48 artifacts reached the real token endpoint; every active interaction failed safely and specifically as HTTP 401, exposing the redundant form `client_id` requirement |
| `marty-credentials` v0.1.27, release commit `cf4edaad499f42fa06215cadfc96365ec0ae01d4`, source run [30386890440](https://github.com/ElevenID/marty-credentials/actions/runs/30386890440), finalization run [30388324868](https://github.com/ElevenID/marty-credentials/actions/runs/30388324868) | Full Python/Rust/WASM, cross-platform artifacts, security, checksum, SBOM, signature, and provenance gates passed; the issuance image is `sha256:43f8a2de5dc8f6d66acfa0197f2a552a80a7c54317d93c5c99f45959b06dab2c` |
| `marty-ui` v1.1.49, release commit `c40b9c398a3a28be0d02f7f65ead975720f8b729`, manifest `sha256:abf954ffa8fe2cc763734b9e3b98b3f38d39d0ee98eb76649e31ba7b44d345c3`, run [30389205086](https://github.com/ElevenID/marty-ui/actions/runs/30389205086) | All release jobs passed, including exact dependency provenance, signed images, no-commerce scan, upgrade/rollback rendering, anonymous digest pulls, and the artifact-only public integration suite |
| OID4VCI issuer run [30389863768](https://github.com/ElevenID/marty-integration-tests/actions/runs/30389863768), sanitized artifact `official-oid4vci-issuer-30389863768-1`, artifact digest `sha256:30bbb18e66e11fa4b73b8af15ddc88f791a88b1b88cbc919ea14a1b653fe25c9` | Exact OIDF `release-v5.2.0` commit `dee9a25160e789f0f80517674693ef7989ab9fa1` passed every active module against exact v1.1.49 artifacts: 1,015 successful conditions, zero failures, zero warnings; four optional unadvertised capabilities remain explicit skips |
| `marty-ui` v1.1.51, release commit `4a6d83da3f5325b25ecbe5055edbe01b6abefd40`, manifest `sha256:d3b792ef11cc3b4558e33fa407b275ca6fe8eb4ff21f44fd2421dd639da1df65`, run [30394311312](https://github.com/ElevenID/marty-ui/actions/runs/30394311312) | Every release job passed; the release uses the canonical public mdoc contract, contains no caller artifact-generation shortcut, and pins credentials issuance image `sha256:43f8a2de5dc8f6d66acfa0197f2a552a80a7c54317d93c5c99f45959b06dab2c` |
| EUDI run [30395235968](https://github.com/ElevenID/marty-integration-tests/actions/runs/30395235968), exact harness `f618d5d46a12c792412eeb39f75e40f6e06cb0ee`, exact v1.1.51 manifest above | 55 tests: 47 passed, 8 failed, 0 skipped. All required replay, tampered-signature, expired-request, and missing-holder-binding negatives passed. Two SD-JWT failures exposed the DID-resolver x5c loss; two mdoc issuance and four mdoc presentation failures exposed the missing/wrong-location x5chain path. No failure was dismissed or converted to an expected pass |
| OIDF mdoc verifier run [30395234162](https://github.com/ElevenID/marty-integration-tests/actions/runs/30395234162), exact harness and v1.1.51 manifest above | All three official modules were active with zero expected failures/skips, but each public flow start failed HTTP 422 because the adapter omitted required `organization_id`. The production API failed closed; the modules timed out in `WAITING`, and no mdoc compliance claim is credited |
| `marty-ui` v1.1.66, release commit `c683976fc7b00a8356adc58b89b6331aaafe8d9b`, manifest `sha256:88e1b229dea3cae86a4c79c98add35d27ab9d13573b8699d78ba20a66ef78bd1`, run [30486641952](https://github.com/ElevenID/marty-ui/actions/runs/30486641952) | Immutable-input validation, UI/services/migrations builds, attestations, keyless signatures, SBOMs, anonymous artifact-only stack smoke, release upload, and manifest checksum/signature/attestation passed. The manifest pins UI `sha256:bbf355fb13b0fc32aad9388caec4cf861aa7673e1da2317bf5c2f2548fea3260`, services `sha256:9920e7b3ae067e4dd090e83cc69bab932c43b2a0fd2d67726ab1d6f3d7925ec8`, and migrations `sha256:baff3cc49029a04652b4304231c45805ae47fd18d6bf785cb7c310eb6d9172c3`. A transient GitHub/Sigstore OIDC response made the first service-signing attempt fail; rerunning the failed job passed without weakening the signing gate. |
| Native OIDF ISO mDL verifier run against v1.1.66, official evidence archive digest `sha256:3fc43830b661e78daa69c8c86250f0468ce917064c4a8385fb6fd085c82fa176` | Exact official commit `dee9a25160e789f0f80517674693ef7989ab9fa1` passed the happy flow, `request_uri_method=post`, and invalid-session-transcript modules with 134 successes, zero failures, and zero warnings. There were no expected failures/skips; the upstream checkout remained exact and clean before and after; and public organization, DID-first flow, request-URI, callback, policy, template, trust, issuer-signature, and device-authentication paths were exercised. |
| `marty-ui` v1.1.68, release commit `cd009001e05253a921cbe8ad99723a313e83c47b`, manifest `sha256:ac513fbae303a66a9688cc3a84d6d5074d08f14b5a34819f9367d6b65f43f202`, run [30497503068](https://github.com/ElevenID/marty-ui/actions/runs/30497503068) | All release and provenance jobs passed. Signed, attested images are pinned as UI `sha256:7bcf3e60c23a1a3ab8029c509b0a6c7181f31abf0c310f8f51600bfb815a4a43`, services `sha256:06521dc884185f1c8e1adb7a54ed92cdca95b76edf4d185e3df7facdb02511db`, and migrations `sha256:8a88a0f01cc4064bf9456ed575fe26b09a0d0aecfcdf93e640db6430e52c108f`. |
| OID4VP Final plus released-browser run [30497973782](https://github.com/ElevenID/marty-integration-tests/actions/runs/30497973782), sanitized artifact ID `8742444913`, artifact digest `sha256:6c31fd336f1e3567f84855177959285563f480dbc04ad5cc0cffc64542b94a6c` | Exact unmodified OIDF commit `dee9a25160e789f0f80517674693ef7989ab9fa1` passed 11 modules with 417 successes, zero failures, and zero warnings against exact v1.1.68 artifacts. The released UI smoke selected the tenant public DID, observed no profile/service/key/KMS selectors, and submitted through the normal public verification API. |
| OID4VP Final plus released-browser run [30504449794](https://github.com/ElevenID/marty-integration-tests/actions/runs/30504449794) against v1.1.71 | Exact unmodified OIDF commit `dee9a25160e789f0f80517674693ef7989ab9fa1` remained green at 417/0/0, while the ElevenID-owned browser check failed on an internal issuer-profile collection request. No official assertion was weakened to hide the product leak. |
| `marty-ui` v1.1.72, release commit `28ec57babcb8ff69f80d06c0f933476623f9caaa`, manifest `sha256:792b00ccd367044d51ff7ece87e3303513536ade7cd77fe276c2d5a73968031f`, run [30505939766](https://github.com/ElevenID/marty-ui/actions/runs/30505939766) | All immutable-input, UI/services/migrations build, provenance, keyless signature, SBOM, anonymous artifact-only smoke, and manifest publication jobs passed. Images are pinned as UI `sha256:0c1f2b46c358cdfceb493a83d4c790ece1c9c8b3a4c95b6677c13b405c51f3ef`, services `sha256:b2e5dc657f70cb057ffe5006683f319791e0cb2dc9f61a9f874e7e07963cfcd4`, and migrations `sha256:41573a989d11c73702badb7495d80e81b8c98ff5a49bb6fc68aa8a15f53be29e`. |
| OID4VP Final plus released-browser run [30506329100](https://github.com/ElevenID/marty-integration-tests/actions/runs/30506329100), sanitized artifact ID `8745544253`, artifact digest `sha256:6606490c0aec5dc5e43660d6a2bdb54f7e3260ba8f2c16f2d3d6e985e3a7c16f`, summary `sha256:af19e954f26d4501f3548ac9ba1d2f6ce9da87639baef8d991f445b629ee691f` | Exact v1.1.72 artifacts and harness `f3d23e91fd326f47e967a419a0bcc168af80125b` passed. The browser completed application, submit, claim, credential-offer, and signed-verification paths with no private selector or internal profile request. Exact unmodified OIDF commit `dee9a25160e789f0f80517674693ef7989ab9fa1` passed 11 modules with 417 successes, zero failures, zero warnings, and no expected failures/skips. |
| `marty-ui` v1.1.73, release commit `060e12799e110a2e662543fd18d79c7ee9441a2b`, manifest `sha256:0d97218e5edea4626b6af75140f478f79e6fbf794f98b2f889a210e7674ce0a7`, run [30508843494](https://github.com/ElevenID/marty-ui/actions/runs/30508843494) | All immutable-input, provenance, UI/services/migrations build, keyless signature, SBOM, anonymous artifact-only smoke, upgrade/rollback, and manifest publication jobs passed. Images are pinned as UI `sha256:f429c26b9c3457f2615322de0286ba9369db817311864ea949e514c1df4576b6`, services `sha256:bab16989d2dd55ac88974b5dbe33cd9e44566287e7bd9ef17067ab90a16a115e`, and migrations `sha256:07b6807f8310aae6f3049ee3e51151ffef576cca7e51399068cc9a3fbec0dc1a`. |
| Direct OID4VP URL-query run [30509192015](https://github.com/ElevenID/marty-integration-tests/actions/runs/30509192015), sanitized artifact ID `8746500090`, artifact digest `sha256:0e7db020196aa8deb07a2c49aba37e03540b555795c9a4d7a4aded21f4948dc8`, summary `sha256:881edd005432620339bdbf25548436fb266ca4d10938b5d4ae7f148d2d485704` | Exact v1.1.73 artifacts and harness `b4be1df46aa7d3ba1c6fc12a3f75b3ea8e86bed1` passed in pre-activation mode. Exact unmodified OIDF commit `dee9a25160e789f0f80517674693ef7989ab9fa1` ran the `url_query` + `redirect_uri` plan: all ten official modules passed with 273 successes, zero failures, zero warnings, and no expected failures/skips. This row activates the profile; future runs use active mode. |
| Active direct OID4VP URL-query run [30509798974](https://github.com/ElevenID/marty-integration-tests/actions/runs/30509798974), sanitized artifact ID `8746701288`, artifact digest `sha256:9f37ca39bee3c71a3dbc6760544518dc75e210b06ed66ec94af0737733e6935f`, summary `sha256:cfe3fabba9d937c2df21e6a5000391c2ffa4e496ed91e0c4a49b415b79e86ec0` | Harness `33410c70fdb7d2f14efcc1af7946780ff9619748` resolved the checked-in default v1.1.73 pin without an override and records `execution_mode=active`. The exact unmodified OIDF runner passed again with no expected failures/skips, proving scheduled runs no longer rely on the planned-profile switch. |
| OID4VCI issuer run [30499049492](https://github.com/ElevenID/marty-integration-tests/actions/runs/30499049492), sanitized artifact ID `8742812832`, artifact digest `sha256:2791885fd090a180bb0f96cf34859a226f7f8bb15065c97ba2c7926a25b91e09` | Exact unmodified OIDF commit `dee9a25160e789f0f80517674693ef7989ab9fa1` passed every active module against exact v1.1.68 artifacts in active execution mode: 16 modules, 1,015 successful conditions, zero failures, and zero warnings. Four optional capabilities Marty does not advertise remain explicit, owned, expiring skips; there are no expected failures. The source checkout was exact and clean before and after execution. |
| `marty-ui` v1.1.78, release commit `4944112a8afe14b1874d3ecc57bc6bd424457833`, manifest `sha256:88488c84d46ca29538b71c71bf12ada6b213e5069bf931d74ef8ce97108dc378`, run [30520912018](https://github.com/ElevenID/marty-ui/actions/runs/30520912018) | Every immutable-input, build, provenance, SBOM, public-stack smoke, and manifest-publication job passed. The release consumes attested `marty-common` 0.2.3 and contains the gateway plus organization-service audit authorization fix. |
| EUDI reference interoperability run [30535981956](https://github.com/ElevenID/marty-integration-tests/actions/runs/30535981956), artifact ID `8756815122`, artifact digest `sha256:dc92ddf5a35f325c4fb42d2229948354f56f69d713b33063b24771ac39d9c4a4` | Exact v1.1.78 artifacts and harness commit `7d416c58950f2dc8bdf5d7a0044f98e315e0c777` passed 55 tests with zero failures, errors, or skips. Evidence pins EUDI OID4VCI 0.9.1, OID4VP 0.15.1, SD-JWT 0.20.1, verifier endpoint v0.11.0, wallet tester v0.5.2, and Multipaz 0.100.0. It proves SD-JWT and mdoc issuance/presentation, signed JAR trust, and required replay, tampered-signature, expired-request, and missing-holder-binding negatives. The facade and its replay/mutation negatives are explicitly labeled ElevenID-owned compatibility evidence; the upstream libraries, images, and expected behavior were not modified. |
| Two-organization public-boundary run [30524717116](https://github.com/ElevenID/marty-integration-tests/actions/runs/30524717116), artifact `tenant-boundary-30524717116-1`, artifact digest `sha256:7a9383e56dc276ea94ddfd7efb95e6fff96ceeeb90419492fff5099159d0e6c1`, summary `sha256:ab2cab089deb9c45329b4604fc5a16006632cf7e39e466c66e7a5a2b57a83d57` | Exact v1.1.78 artifacts and owned harness commit `ea14814a7e25106d07cf7bb5e97122e5bc0b4490` passed. Evidence is explicitly `elevenid-owned-product-security`, invokes no official suite, modifies no official-suite source, and covers two principals, membership/RBAC, template/policy/DID substitution, API-key binding, SCIM, flows/results, webhooks, audit events, and leakage prevention. |
| Expanded DID-first public-boundary run [30528390251](https://github.com/ElevenID/marty-integration-tests/actions/runs/30528390251), artifact ID `8753695945`, artifact digest `sha256:db94b4c9aafc55416d10e88766c616cebc23cfdc846b4478f13323578f44f542`, summary `sha256:3027ac3b707d79ff7119cb2b542dd77475df752a37bf82ba22c9672b11b52668` | Exact v1.1.78 artifacts and owned harness commit `76efd50a0d896e008053d2697b6397ef7402a201` passed. The public API rejects profile/service/key/KMS selectors, unknown, draft/non-active, and purpose-incompatible DID mappings; returns no custody coordinates on success; and makes duplicate profile setup idempotent. Evidence is explicitly non-official and records that no imported suite was invoked or modified. |
| OIDF 5.2.1 mdoc verifier run [30529444741](https://github.com/ElevenID/marty-integration-tests/actions/runs/30529444741), artifact ID `8754164370`, artifact digest `sha256:2f128c5bf8a6ffc59763182c5d1747fea8ebea57db003592d1454aa6eeb69100`, summary `sha256:ae7cf3bf1ee552e03e5632bc5879d253dfeedcbd0d9173ac381a79543b2ac38b` | Exact unmodified OIDF commit `932b46f1e507871eb0b34621aaef65ff04442e6f` and exact v1.1.78 artifacts ran with no exclusions. Happy flow and request-URI POST were rejected because the official source's embedded document-signer certificate expired at `2026-07-30T07:47:22Z`; the invalid-session-transcript negative still passed. This is an upstream-fixture expiry, not a Marty regression and not a current passing compliance claim. |
| OIDF 5.2.0 mdoc control run [30529900491](https://github.com/ElevenID/marty-integration-tests/actions/runs/30529900491), artifact ID `8754355802`, artifact digest `sha256:e6901547ac698a42ec35df4719e09159849dc154805ee045a42fc9de3d7e1d43`, summary `sha256:0e3502ba763950fdad1cca8aa6657be090d12bf828a6646a1aaa8b0483d7f367` | The prior exact unmodified commit `dee9a25160e789f0f80517674693ef7989ab9fa1` failed identically against the same v1.1.78 stack. A local exact-stack diagnostic proved issuer and device signatures valid in the positive modules and isolated the rejection to `Certificate 0: Certificate has expired`. Marty remains fail closed; the harness now preflights the public certificate and refuses to patch upstream source, weaken certificate validation, or convert the result into an expected failure. Renewal is tracked by [#243](https://github.com/ElevenID/marty-integration-tests/issues/243), while strict ISO document-signer certificate-profile enforcement is tracked separately by [marty-core#88](https://github.com/ElevenID/marty-core/issues/88) using Marty-owned vectors. |
| OIDF 5.2.1 OID4VCI issuer run [30531145886](https://github.com/ElevenID/marty-integration-tests/actions/runs/30531145886), artifact ID `8754818891`, artifact digest `sha256:903aabc2b65421f8812c1554d4b117fa270953dc130b22a5ea39647df9ed14ed`, summary `sha256:d55dc7aea4c99548407f509923a8f3ec58fb7a7ba9c4b74896feeb9912e766f3` | Merged harness `8a2cf5014e3168a6b8d8dffc315699704ce4ddee`, exact unmodified OIDF commit `932b46f1e507871eb0b34621aaef65ff04442e6f`, and exact v1.1.78 artifacts passed all 16 active modules with 1,013 successes, zero failures, and zero warnings. There are no expected failures; the four optional capabilities Marty does not advertise remain explicit expiring skips. |
| OIDF 5.2.1 OID4VP Final plus released-browser run [30531147674](https://github.com/ElevenID/marty-integration-tests/actions/runs/30531147674), artifact ID `8754848712`, artifact digest `sha256:be876d429f24f971e6f3050652f123082f81dcb7213b5b1abfb733bb6257e619`, summary `sha256:7b5a896bdb5a9267a911894fa361475f508667d548baf951e1e18901de14e078` | The exact clean official runner passed all 11 modules with 417 successes, zero failures, and zero warnings. Separately labeled ElevenID-owned browser evidence passed application, submission, claim, credential-offer, and signed-verification paths through public organization + DID APIs and observed no private profile/service/key/KMS selector. |
| OIDF 5.2.1 direct URL-query run [30531149520](https://github.com/ElevenID/marty-integration-tests/actions/runs/30531149520), artifact ID `8754830952`, artifact digest `sha256:c218927cfc78098bbfdb367cf9580c9e4147b83bc2369599ca73e51338eda0f0`, summary `sha256:e2e740280f2b64ea2107d480a4b9824cc282b93534102e8f4ed68f04e8b62fdb` | The exact clean official runner passed all 11 modules with 273 successes, zero failures, zero warnings, and no expected failures/skips against the ordinary public unsigned URL-query transport. |
| OIDF 5.2.1 HAIP verifier run [30531151409](https://github.com/ElevenID/marty-integration-tests/actions/runs/30531151409), artifact ID `8754829101`, artifact digest `sha256:fa11e3195a5cf3085e8469fe1b22f192b4c1fd60c0fd2c38d16ff3e856888c13`, summary `sha256:2caef98677748060d08404e678b2a06e301082208d4dc3d90c06ce262a34dbe1` | The exact clean official runner passed all 11 modules with 510 successes, zero failures, zero warnings, and no expected failures/skips. The upstream plan remains labeled alpha/not currently certifiable, so this is official-runner interoperability evidence rather than a certification claim. |
| Unmodified W3C VCDM v2 run [30532056106](https://github.com/ElevenID/marty-integration-tests/actions/runs/30532056106), artifact ID `8755183994`, artifact digest `sha256:96efec3d05988b3d00299913267c997a2fe07afd41e6a039d2a491696093da65`, summary `sha256:dce7d768b2f595736549f9333b1d4272e86bde6b73617eb2aa2738885e4838f4` | Exact upstream commit `e92936564867da9150b99b167fe1c73b9370ad6c` passed issuer, VC-verifier, and VP-verifier capabilities against exact v1.1.78 artifacts with no exclusions. Evidence records `official_upstream_unmodified=true`, `disposable_exact_commit_worktree=true`, `test_or_assertion_source_modified=false`, and no upstream-owned runtime mutations. The complete reviewed upstream delta from the prior pin adds only `CODEOWNERS`; no test, assertion, fixture, package, or lockfile changed. |
| `marty-ui` v1.1.81, release commit `b4080aed2f6b5723d730afb790f3afed41f96ff1`, manifest `sha256:d1b4d3f5dc64ebdcedf9e8c6e1ff2f7524175b8ff4a2da75ba73bcdf7d938055` | Signed and attested immutable stack pins credentials issuance `sha256:8919a58cf1afada5d50f38b29767833556191c2a6d237afa88a2ed61428ea133`, UI `sha256:d7610f2fcd2b111daca2c05f2568a6c283952dfbda6f1948e264dbe27de7b558`, services `sha256:4d3f972d6d43d45bd1cb5bd6e64e61803ef5067a7e66093a6997c24f79443efc`, and migrations `sha256:040815386f79b612f3bcea676f1bd1d6475442d623c4f9fb64719ad54f74541d`. |
| Current OID4VCI and W3C run [30689799465](https://github.com/ElevenID/marty-integration-tests/actions/runs/30689799465), exact harness `6344bcc6510c5d604d73a8afefac7c28f2dd2b4c`, OID4VCI artifact `sha256:7b1563f6e2a52ac6bd1c25bb68924dd1bbea5294980a2e0ab202723f0eec37cd`, W3C artifact `sha256:28b1d95df36bc97a14a4fb1655f33adb8d145e6f4b4b7d05fa363a5dfd49810a` | Both exact pinned upstream suites pass against v1.1.81. Sanitized summaries are `sha256:ffc3325e0f144fb055b017e7d80f6c42aeb47f5ac2ba2f3bcd1e5f898291c4bf` and `sha256:dc3e578af865b3c53808e42720f24635e74d3e17606c230a06b73b692222a301`; official evidence count is one for each. |
| Current EUDI run [30689799465](https://github.com/ElevenID/marty-integration-tests/actions/runs/30689799465), artifact ID `8815327788`, artifact digest `sha256:06fb0d55e02fecd88659c7ab58b53f35c761c858b2f29f6cb326ea4a1354411b`, summary `sha256:92688e309a3b8861f4a782efa3f982a620ff3ca960b861d053c0477c2c38695a` | Exact v1.1.81 stack passed all 55 tests with zero failures, errors, or skips. Evidence includes official-library resolution/dispatch and separately labeled owned replay/mutation negatives; it does not claim those mutations are official-library dispatch evidence. |
| Current two-organization public-boundary run [30689800207](https://github.com/ElevenID/marty-integration-tests/actions/runs/30689800207), artifact ID `8815287069`, artifact digest `sha256:57455ee9b4ace54a1fc1e42b41a45b80ec5f8bcae45026c56643f5fe3f0eb8d8`, summary `sha256:420e2e7e1d71d75e2a94a1f2e7e0481835f7b822d6e0660bfdeaa9a8175e027c` | The ElevenID-owned product-security matrix passes against exact v1.1.81 artifacts. It is not official-suite evidence and modifies no imported source. |
| Current OID4VP/HAIP pre-dispatch evidence from run [30689799465](https://github.com/ElevenID/marty-integration-tests/actions/runs/30689799465) | Final, URL-query, and HAIP each stopped before official execution because application-template activation returned the same owned `credential_template_id NOT_FOUND` integration defect; official evidence count is zero. The mdoc lane separately stopped on the exact upstream certificate expiry. No failure was hidden, skipped, converted to an expected pass, or repaired by changing imported material. |
| v1.1.82 OID4VP Final diagnostic [30692104419](https://github.com/ElevenID/marty-integration-tests/actions/runs/30692104419), artifact ID `8816064495`, artifact digest `sha256:b727bf3a3594474f73b50474901328a93d7617af44c5dddd0fd1ccf49abcb0f8`, summary `sha256:3767f76854435de78159bb68076f5c097ff60fb47e3fe020c89a662f6068af4c` | Exact unmodified OIDF 5.2.1 passed 11 modules at 417/0/0, while the owned browser path failed honestly at credential-template discovery because legacy null profile references poisoned the catalog response. The overall lane remained red; the report did not relabel the isolated official pass as a full product-path pass. |
| `marty-ui` v1.1.83 release [30693812851](https://github.com/ElevenID/marty-ui/actions/runs/30693812851), release commit `922472494eedc64b74f62f66a259770ab2b019c7`, manifest `sha256:34f460a69c2ee89bee26a4e98c426036940ba343d58902a9d71b1e9f115d4c74` | Immutable-input validation, UI/services/migrations builds, SBOMs, provenance, keyless signatures, artifact-only public stack, no-commerce, upgrade/rollback, integration, and manifest publication all passed. Images are UI `sha256:b65ccf5f2bfff8673515db415953d493e9d77f0913ac34f828b5f82805b76542`, services `sha256:5d832508f6a0628c932715d494e0a658343a0aa2a4765bb3ff15f29e88b71c23`, and migrations `sha256:e6de605de5d584480af621af5127b67af19dd1f604afe5bf6a7513e5a4d59230`. |
| Final v1.1.83 OID4VP plus browser run [30694181042](https://github.com/ElevenID/marty-integration-tests/actions/runs/30694181042), artifact ID `8816728169`, artifact digest `sha256:ecea68443479b65f9534d735391221e52b49a5155d53e8dffc803783493dcafe`, summary `sha256:450341666605f8e378cf3cc8f4c32b8cc04de45a686a2b7b356dcaccf77ece6c` | Harness `0faa4ac5e8074bc581ff7dc6fa7d008921ac2910` attested the exact v1.1.83 manifest. Exact unmodified OIDF commit `932b46f1e507871eb0b34621aaef65ff04442e6f` passed 11 modules with 417 successes, zero failures, zero warnings, and no exclusions. Separately labeled owned browser evidence passed application, submit, claim, credential-offer, and DID-only verification through the public organization path with no private selector observed. |
| `marty-ui` v1.1.87 release [30700582206](https://github.com/ElevenID/marty-ui/actions/runs/30700582206), release commit `f77b544dbaf7d3481f61a57faed11a2f69546278`, manifest `sha256:8f431ab324b9c26cab8e8f729c207f9d2aa782a9ceeb7c0c17e11806c31ef7a0` | Immutable-input and provenance validation, signed UI/services images, SBOMs, anonymous artifact-only public-stack smoke, and atomic manifest/release publication all passed. This release contains the clean-tenant KMS purpose-binding and managed-service capability corrections without adding a public KMS selector. |
| Expanded lifecycle/trust boundary run [30700898083](https://github.com/ElevenID/marty-integration-tests/actions/runs/30700898083), artifact ID `8818810906`, artifact digest `sha256:f5a300a1c7ac17aedf7a8203f6b6b92db65a0e4f996290cc464aadfe280226f4`, summary `sha256:0fb61e418e01864bc481f9fa685846c6a444d9a88dbd4dbaca7bb9623e61c508` | The unchanged owned test commit `250985275555b91d46a498585a66164732a47868` passed against exact v1.1.87 artifacts after failing honestly on v1.1.84 and v1.1.86 product defects. Coverage includes issuance transaction/status ownership, issued-credential lifecycle and revocation, trust-profile ownership/mutation, DID-first KMS-backed signing, two organizations, and the prior RBAC/resource-substitution matrix. Evidence is explicitly non-official and records that no imported suite was invoked or modified. |
| v1.1.87 official matrix run [30701213399](https://github.com/ElevenID/marty-integration-tests/actions/runs/30701213399), exact harness `b021510b5219f8bc582cde32a12df9ec7c0b1097` | OID4VCI artifact `sha256:2aa01a43007543f2b4d95a3c97dd040ace387b73a1103afe313af33699492e30`, OID4VP Final `sha256:50f91a012a57a53e83d564d43fdd6429d6324b9d4a4887a547dd0ea5659d6e68`, URL-query `sha256:4957320e6041f774b1404795f0771f041eb2a7a0c907889809711d6f5f5ed491`, HAIP `sha256:d89f9d43533d0ee1dc4eec8f6ca4f81e3d014efd6c358395b607c74c57911e42`, W3C VCDM v2 `sha256:b45edbd64e6320a5ade616b0c3af9fc9e0e52bff69c782cca738e32fa0eccc83`, and EUDI `sha256:d80fcc927083b27b90781521d0e380d7496a9601c8784cf1f91aacb264e94223` passed against the exact v1.1.87 manifest. Upstream OIDF/W3C source remained unmodified, OIDF passing profiles had zero expected failures, and EUDI passed 55/55. |
| v1.1.87 OIDF mdoc pre-dispatch evidence from run [30701213399](https://github.com/ElevenID/marty-integration-tests/actions/runs/30701213399), artifact ID `8818915043`, artifact digest `sha256:e0dacfa251bde7c33e8129819a955a459aba2a9a5321aabe7fc21dcd26001f82`, summary `sha256:5d0b063943e4f9b159096d4a0bd7d07c549ba5e95eb097e6e289a3f26c09f694` | The lane produced zero official evidence because the exact imported OIDF document-signer certificate expired before dispatch. The guard refused to modify the suite or bypass X.509 validation. No newer upstream release or renewed certificate exists yet; tracking remains open in #243. |
| `marty-ui` v1.1.103 release [31133646751](https://github.com/ElevenID/marty-ui/actions/runs/31133646751), release commit `9cb375477f27c5800c14c539da9af79f422f881e`, manifest `sha256:67772e23cd8f93273b9b8c6d93b62005d2be152ab4dacda296391664658a0606` | Immutable-input and provenance validation, signed UI/services/migrations images, SBOMs, no-commerce checks, anonymous artifact-only public-stack smoke, upgrade/rollback validation, and manifest publication passed. Images are UI `sha256:21decc58bede7a562268cf1eac868d25259dacef92462e8483bcee4e70b7d5e8`, services `sha256:d4312d79c4b58db4f98405207f01c1b66f0b50452318ce89948e74f65147a889`, and migrations `sha256:485bc2467d7b9093bd5699a710f9e0d80b893399ef19a2030d9a82b6425a5e94`. The release fixes the seeded managed issuer profile's missing `ES256` algorithm without exposing a profile, service, key, or KMS selector. |
| Released browser and two-organization boundary run [31134184550](https://github.com/ElevenID/marty-integration-tests/actions/runs/31134184550), artifact ID `8977328426`, artifact digest `sha256:9309b49cae7940de70469cdc1a151fd45bd096c728f2a4a86e386d5fb6edab35`, summary `sha256:ec37065479232270220e1fa399943f1d08f49fee926ceba29ca4882486e5aaba` | Exact v1.1.103 artifacts and owned harness `6049b39262b1414bb949f83363174619a45488ea` passed in immutable-release mode. The shipped browser UI completed application approval, credential-offer issuance, and signed verification through public organization + DID requests. The wider matrix passed two-principal/two-organization RBAC, resource substitution, API-key, SCIM, flow/result, issuance/revocation, trust, applicant-evidence, deployment/device, webhook, wallet, notification-SSE, audit, DID-resolution, and leakage checks. Evidence is explicitly ElevenID-owned, invokes no official suite, modifies no imported source, and uploads no screenshot or private diagnostics. |
| v1.1.103 official interoperability matrix [31134185874](https://github.com/ElevenID/marty-integration-tests/actions/runs/31134185874), exact harness `6049b39262b1414bb949f83363174619a45488ea` | Exact unmodified OIDF `release-v5.2.1` commit `932b46f1e507871eb0b34621aaef65ff04442e6f` passed OID4VCI issuer at 16 modules and 1,076/0/0 conditions, OID4VP Final at 11 modules and 417/0/0, URL-query at 11 modules and 273/0/0, and HAIP at 11 modules and 510/0/0. OID4VCI retained three explicit, owned, expiring skips for optional unadvertised capabilities; the passing verifier profiles had no exclusions. Exact unmodified W3C commit `e92936564867da9150b99b167fe1c73b9370ad6c` passed issuer, VC-verifier, and VP-verifier capabilities with no exclusions. The EUDI lane passed 45/45, including SD-JWT and mdoc issuance/presentation plus missing-holder-binding, replay, invalid-signature, and expired-request negatives; owned replay/mutation evidence remains separately labeled. Passing artifact digests are OID4VCI `sha256:8bd5896b902af273b9db5fb7a80920e4f24170ca95609bb5dbe6de0d54f99792`, OID4VP Final `sha256:b6bd2f5aa680572c4935f4b009fbba2252d1033bf5961fe6f54aab1bf1272917`, URL-query `sha256:b1cef9647428fb6e35620ca5f051cf2fe2943e7fcc81a93db0266d9535eea737`, HAIP `sha256:bbc11887254c82adbda099ecb7cc392efdb8ad8bcd885ee86be49ea174da3a07`, W3C `sha256:e59ec533ea1361fc954312e63e44f8dd680496df24d0db0b4dccc4b72df81387`, and EUDI `sha256:416b842890334267369405f9ef16dc6ebe3741b894bc736ebfd8db5feef8de1a`. |
| v1.1.103 OIDF mdoc pre-dispatch evidence from run [31134185874](https://github.com/ElevenID/marty-integration-tests/actions/runs/31134185874), artifact ID `8977333651`, artifact digest `sha256:3dd63156c6d76939bf4a61ae5503fdc29b0992af9fe61a9c2b2ab78df49cd3b0`, summary `sha256:309c87b3cceb623e255b6397a13e96d13099ca2a6d28800c635a434062a38f54` | The exact imported OIDF document-signer certificate still expired at `2026-07-30T07:47:22Z`, so the guard stopped before official dispatch with zero official evidence. It did not patch the suite, bypass X.509 validation, add an expected failure, or claim a Marty regression. Renewal remains tracked by #243. |
| v1.1.105 official interoperability run [31144091769](https://github.com/ElevenID/marty-integration-tests/actions/runs/31144091769), exact harness `9fee02453c1303dd3039fb12df2409e7b11a9669`, manifest `sha256:68b2150c54c01602be8c3e3453060b5587c35def1f8368ca05640f66d25b0fb8` | The unmodified OIDF OID4VCI issuer, OID4VP Final, native URL-query, and HAIP plans passed, as did the unmodified W3C VCDM v2 suite and the 45/45 EUDI lane. Artifact IDs/digests are OID4VCI `8980918065`/`sha256:743fb5fc24c8847e3fef4c0df42e43e2608da0556d649ff2dc27e886650f97db`, OID4VP Final `8980931689`/`sha256:7a7e0569870c36b6486830a0e4cd01f45ee51a36708e2b87233f81a2ad6a96e5`, URL-query `8980916672`/`sha256:8953e0d143a5e23083c4d500fb48d1ab1b40a9a62b6352a44d5a140004e83536`, HAIP `8980922958`/`sha256:2374b84192503fd1c9866786ba746b4fdd947443963db4d262c0a5b4072d91e2`, W3C `8980902011`/`sha256:d4ec3ec20622e6caa1af86ced887fac1d74b64d154197a84acf563a36dce54f6`, and EUDI `8980949898`/`sha256:9844611d912979daa44bd9ba7e7bbed179817309f9e04b7c20eba58c3dcd7df0`. |
| v1.1.105 OIDF mdoc pre-dispatch artifact from run [31144091769](https://github.com/ElevenID/marty-integration-tests/actions/runs/31144091769), artifact ID `8980916895`, digest `sha256:e306c077f6ce78f4f30beb796c4b8ee5eae18aa2942ac19edda2d49c88be9b91` | The exact tagged suite still contains the expired document-signer certificate, so official evidence is empty. Upstream master `8f69782356ef61c77907fdc33718b159e80b9f74` contains a rotated certificate but no newer tag; ElevenID will adopt the first reviewed release rather than mutable master or a local patch. |
| Forced ambiguous DID-resolution run [31145134598](https://github.com/ElevenID/marty-integration-tests/actions/runs/31145134598), artifact ID `8981342977`, digest `sha256:6ca4d9c27d1494d75bcdc81e270737f84858eff853c9ce10ab65ef453289ad30` | Owned harness `c59c52f50982b0ef67395cfc1ad552218d62c02c` passed against exact v1.1.105. It creates an otherwise compatible duplicate managed profile through controlled internal setup, proves the public organization-plus-DID path fails closed without exposing custody coordinates, removes the ambiguity, and proves recovery. It is product-security evidence, not official-suite evidence. |
| `marty-ui` v1.1.108 release [31152274114](https://github.com/ElevenID/marty-ui/actions/runs/31152274114), release commit `313930401bb4bc8cc9a670da2881c887c1e346a6`, manifest `sha256:39bed88b9ac6bf3946835c870188a1bdd0909fe68247690dc087e13846a83cec` | Immutable input/provenance validation, UI and services builds, signed SBOMs, anonymous artifact-only public-stack smoke, and manifest publication passed. It pins credentials 0.1.46 issuance `sha256:b4ba8d83f6250edced7d38b25ca1eb2116bcf19da995d93bc1e2ada684d340fb`; stack images are UI `sha256:e066f77fc380723f37068e34e5f37153cc57dd1ffdb2c917e20e2aa389d6456a`, services `sha256:3b767f7a5c2c43fc475dfb36a36a71fd767734aed42cf0d5bf77ecc9539f2cf7`, and migrations `sha256:ac63874db5cf09d1ec958b6f94f6aa98523f863e34a96428d4687e7bc001b340`. |
| Released DIDComm production-path run [31153194710](https://github.com/ElevenID/marty-integration-tests/actions/runs/31153194710), artifact ID `8984169004`, digest `sha256:d6333c0718f1ae90bf1e13b6904525fd4b08bd4f64d65e048b65c0eddd5cc898` | Exact v1.1.108 and owned harness `592a24fef4b982fd1419ee8f0498a063144ac713` passed five selected tests. The positive case used the public organization path, managed DID-first issuer resolution, CA-validated HTTPS holder transport, an X25519 `did:peer:2`, the attested released holder-side library, encrypted-envelope receipt, holder-key decryption, core Issue Credential fields, and issued transaction state. The artifact explicitly records `elevenid-owned-product-security`, `official_suite_invoked=false`, and `official_suite_source_modified=false`; it is not cross-vendor or full-spec evidence. |
| Independent DIDComm and cross-tenant run [31198519056](https://github.com/ElevenID/marty-integration-tests/actions/runs/31198519056), artifact ID `9001965825`, digest `sha256:50e1d6eeae446c1f599f219b255aca431b672f7cca452b44140839920b41aca5` | Exact v1.1.112 and harness `91f6b439a24720519d5cf3857ba08676e09bb897` passed in immutable-release mode. Pinned `notabene-id/go-didcomm v0.4.0` independently decrypted and classified Marty's selected outbound anoncrypt envelope, and its full plaintext matched the released Marty decoder. The same lane denied a foreign organization's transaction before DID resolution without leakage or mutation. This is selected-profile cross-implementation and product-security evidence, not official certification or full agent/protocol coverage. |
| OIDF 5.2.2 adoption run [31193237615](https://github.com/ElevenID/marty-integration-tests/actions/runs/31193237615), exact stack v1.1.112 and harness `8b9303f8957f407cb6fd37ce26976a62a5c55427` | Exact unmodified OIDF `release-v5.2.2` commit `321bc5bc53601b9690b54c023c0cbfac0f0230f2` passed OID4VCI issuer with artifact `8999831726`/`sha256:ea516c519801c7878664b5005d4c0000cf3be89e29a147239b0f51b59f842cae`; exact W3C VCDM v2 and EUDI lanes also passed with artifacts `8999825111`/`sha256:8b8bf34eb99924a395523085e51e1136ab45b3e4742fb66c7522664ca62ddde3` and `8999931333`/`sha256:411e5e23f3e40b41b15abe50dbdb668f97b48e9dc96849fb0e576be7878beaf2`. The mdoc plan completed all five modules at 174 successes, three failures, and three warnings: its invalid-session-transcript negative passed, but positive authorization requests were correctly rejected because the upstream fixture still uses a CA certificate with `keyCertSign`/`cRLSign` as a document signer, tracked upstream in [openid/conformance-suite#1891](https://gitlab.com/openid/conformance-suite/-/work_items/1891). Artifact `8999852468`/`sha256:61a57a9c28736599045bba625e9f3a409f2fcbf5f2d7316c8ddcbcd05a536358` records the genuine failure; Marty was not weakened and no expected failure was added. Final, URL-query, and HAIP reached OIDF 5.2.2's new verification-evidence review page but were canceled only after the missing upstream-documented screenshot automation was diagnosed; their partial artifacts are `9000367914`/`sha256:b5c2a4a593bbde7142f98489f4613da2ca75583f9f32650e0ac89804c064b203`, `9000368197`/`sha256:a679c0a529e0229265ac2a7e7becf1d4220e35613fd2a13021885c4a8641d6cb`, and `9000367683`/`sha256:d2baf956d1ef06bbe19eb53ce370b0bddee6eb2e2ab1edf80b260fa084873a7b`. They are not passing evidence and require the corrected immutable rerun. |
| OIDF 5.2.2 TLS diagnostic matrix run [31196611597](https://github.com/ElevenID/marty-integration-tests/actions/runs/31196611597), exact stack v1.1.112 and harness `85ebd7828e02bd68bb77295bd6c7a51e45084bde` | Exact unmodified OIDF commit `321bc5bc53601b9690b54c023c0cbfac0f0230f2`, W3C, and EUDI pins were retained. OID4VCI, W3C VCDM v2, and EUDI 45/45 passed with artifact IDs/digests `9001177944`/`sha256:feb26fdc6e13011fb73f67dc0e603caf4a49690f7b03decc64061dc93e429bc4`, `9001168330`/`sha256:11124ec3f3b7fa663cc61fa52b76822480c145cd467607e969d117a001cd8a43`, and `9001296312`/`sha256:dafa065ce163e90e16f465ce6f01d4e603a07e1d34ad3abcac38d142da86323b`. The mdoc failure is the unchanged invalid upstream document-signer profile, artifact `9001227018`/`sha256:ec152235fad67b2a861d9c178e2297e385a59773f080d44e9767da4b4b73ef01`. Final, URL-query, and HAIP product interactions returned 2xx but the mandatory browser evidence remained waiting because the official JVM could not validate upstream nginx's self-signed `CN=localhost` certificate for `localhost.emobix.co.uk`. PR #283 supplied a disposable hostname-valid runner leaf and read-only JVM CA truststore without modifying official source; the next diagnostic run then isolated the separate missing-alias defect. |
| OIDF 5.2.2 alias diagnostic run [31203856791](https://github.com/ElevenID/marty-integration-tests/actions/runs/31203856791), artifact `9004532816`/`sha256:9e5be13c04df3fae7917a808692b533a9fd1d5b16ef0d5ed06aa16a764e693d1` | With strict runner TLS corrected, all seven negative modules passed but four positive modules remained `WAITING`; safe diagnostics reported only `automation-not-observed`. The imported example proved that the top-level alias creates `/test/a/{alias}` URLs matching OIDF's own BrowserControl rule. PR #285 added and enforced that runner-owned alias without modifying the official suite. |
| Current OIDF 5.2.2 verifier evidence at exact v1.1.112 and harness `bf0e6d5b2d099768e3ee0b3987edeb669143a971` | Final [31206756608](https://github.com/ElevenID/marty-integration-tests/actions/runs/31206756608) passed 463/0/0 conditions with artifact `9005205225`/`sha256:b71bbbabb8684b2099f2fb80c8928e6dd1df51b0f738a2b6d9e35a431164ce3b`; native URL-query [31207275778](https://github.com/ElevenID/marty-integration-tests/actions/runs/31207275778) passed 302/0/0 with `9005372575`/`sha256:1dabf33e039c0b38d43547b05100dbf4b0d102317d86aa89afaca7f47854e7cc`; HAIP [31207277971](https://github.com/ElevenID/marty-integration-tests/actions/runs/31207277971) passed 566/0/0 with `9005383490`/`sha256:669b6f94afd01929ca0232dad95d4aa1f184007bc7d1428b0c9800c8d0eb2715`. Every lane has zero expected failures/skips, all four positive review placeholders fill, and all seven negatives pass against unmodified OIDF commit `321bc5bc53601b9690b54c023c0cbfac0f0230f2`. |

The v1.1.66 image digests are signed, attested, and pinned, but the services and
migrations images produced different digests when the failed release job was
rerun from the same source commit. This does not weaken the released manifest,
which names the successful signed outputs, but it is evidence that OCI builds
are not yet byte-for-byte reproducible. Build timestamps and unfrozen base or
OS-package inputs must be audited before the project claims reproducible image
builds. Remediation and an independent double-build acceptance gate are tracked
by [marty-ui#225](https://github.com/ElevenID/marty-ui/issues/225).

The current OID4VCI passing run is bound to harness commit
`cd5b7f1e654ea62fa1134431cebe91cdd6d1696f`, artifact ID `8742812832`, and
the exact v1.1.68 stack manifest above.

## Completion criteria for this report

This report becomes final only when:

- [x] the immutable EUDI lane passes with all required evidence;
- [x] the default stack pin names a reviewed immutable release;
- [x] OID4VP Final, HAIP, W3C v2, and applicable mdoc official lanes have
  explicit native/adapted/unsupported outcomes;
- [x] the two-organization matrix and browser UI path have executable evidence;
- [x] core DID-first template, trust-profile, issuance-request, and
  verification-start request/response schema drift is enforced in CI;
- [x] Flow definition/execution/result and issuance/issued-credential lifecycle
  schema drift is enforced in CI;
- [ ] all supported public clients consume or mechanically compare the generated
  bindings under [marty-ui#222](https://github.com/ElevenID/marty-ui/issues/222);
  and
- [ ] every remaining limitation links to an owned remediation item.

The checked tenant and browser criteria are evidence milestones, not a claim
that the full DID-first or wider Marty feature objective is complete.
