# Protocol conformance: retained requirements and open gaps

Status: open requirements; historical evidence is not current qualification.
The 1,960-line implementation/evidence chronology is retired at Integration
Git checkpoint `1ff32cb439a9c32baaf6311a7bd5c6e7940a7118`. This condensation
preserves unfinished features and assurance boundaries; it closes no issue.

Use [the checked-in immutable stack pin](stack-under-test.json), current
upstream pins and the [official workflow](../.github/workflows/official-interoperability.yml)
for a new run. That stack pin has advanced beyond the historical checkpoint
below. A prior pass, source fix or this documentation cleanup does not qualify
new images or establish that an old failure is fixed.

## Historical source-bound checkpoint

The historical recorded stack was immutable `marty-ui` v1.1.134 at release
commit `9a81accb3c725d3a1db5f279c6ed84243bac0a94` and manifest digest
`sha256:cb2898b8cc8dd2596633bf3be2cb9da0f63da3118580c6e79f78bcc5d145de90`.
[Official interoperability run 31450664822](https://github.com/ElevenID/marty-integration-tests/actions/runs/31450664822)
executed exact harness `cf2397c2d73bb5671887d203b23b34c189f775d6`, unmodified OIDF
`release-v5.2.2` commit `321bc5bc53601b9690b54c023c0cbfac0f0230f2`, unmodified W3C
commit `e92936564867da9150b99b167fe1c73b9370ad6c`, and the reviewed EUDI
component pins. Imported source, assertions, fixtures, expected results,
selections, and exclusions remained unchanged.

- OID4VCI issuer, OID4VP Final, native OID4VP URL-query, and HAIP completed
  successfully against the same exact release. OIDF mdoc, W3C VC Data Model
  v2, and EUDI remained visibly failing.
- OID4VCI exercised real holder-key proof signing, invalid-signature and nonce
  rejection, DPoP, private-key JWT, notification, and key-attestation paths.
  Its only skips are three optional capabilities Marty does not advertise:
  signed metadata, batch issuance, and credential-response encryption.
- OID4VP Final, URL-query, and HAIP ran their public request and callback paths
  with zero expected failures or skips.
- The W3C suite executed the issuer capability, but VC-verifier and VP-verifier
  positives received HTTP 422 because unrestricted public-DID fallback remains
  disabled. One issuer case also hit JSON-LD protected-term redefinition. This
  requires governed deterministic DID resolution and JSON-LD compatibility,
  not enabling an unrestricted resolver or changing the imported suite.
- EUDI executed 45 tests with zero errors or skips and 11 failures. The failures
  cluster in SD-JWT callback/result handling and verifier rejection of mdoc/DTC
  presentations. The exact upstream-library cases and ElevenID-owned negative
  mutations remain separately labeled; no failed case is converted to a pass.
- The OIDF mdoc lane remains a genuine visible failure. All three positive
  presentations had valid issuer signatures and valid holder device
  authentication; the invalid-session-transcript negative correctly produced
  an invalid device signature. Marty rejected only the upstream fixture's
  `CA:true`/`keyCertSign,cRLSign` certificate because ISO 18013-5 Table B.3
  requires a non-CA document signer with `digitalSignature`. OIDF tracks this
  in [work item 1891](https://gitlab.com/openid/conformance-suite/-/work_items/1891).
  No product trust rule, official assertion, or expected result was weakened.

Separately labeled ElevenID-owned product-security evidence in
[run 31237661261](https://github.com/ElevenID/marty-integration-tests/actions/runs/31237661261)
last passed against the v1.1.122 manifest. It covers two authenticated
organizations, public API and shipped-UI adversarial substitutions, DID-first
unknown/draft/incompatible/ambiguous rejection, external trust-registry atomic
sync and rollback, issuer/accreditation decisions, lifecycle and revocation,
and independent DIDComm decryption plus tamper rejection. Its summary records
`official_suite_invoked=false` and `official_suite_source_modified=false`.

The recorded public contract was MIP v0.4.1 at Marty-Protocol commit
`6387a02fe4a6eaa08b4743cae97590adee11190c`. Trust Profile lifecycle status is
now a required canonical lowercase enum across schema fixtures and generated
Python, Rust, and TypeScript bindings. The released runtime matches the exact
public Trust Profile fields and requiredness, including revocation and time
policy fields, and exposes no stale validation or custody-routing members.

The owned boundary lane is not an official standards-conformance result. The DIDComm
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
validation was weakened in response; the successful unchanged-suite rerun was
the then-current evidence, and future recurrence must be investigated from
product-owned service diagnostics.

Because the stack remains pre-1.0, obsolete selectors, aliases, deprecated
formats, and compatibility-only code are removed rather than preserved.
This does not authorize removal of current standards capabilities: mdoc,
SD-JWT VC, JWT VC, VCDM v2 Data Integrity, OID4VCI, OID4VP, HAIP, and EUDI
paths remain acceptance requirements.

The report recorded a temporary Open Badges 2 exception under
[marty-ui issue 260](https://github.com/ElevenID/marty-ui/issues/260), with a
2026-09-01 review and 2026-10-01 removal target. Those dates are past; this note
does not assert current support or authorize dropping Open Badges 3 coverage.
Reconcile the exception against current source and its owner before closure.

## Features still requiring explicit evidence

Treat the recorded failures as unclosed until the responsible owner supplies
fresh, exact-source evidence. Do not restore an obsolete implementation to
satisfy an old report or silently turn failed standards cases into skips.

| Feature or gap | Required completion evidence |
| --- | --- |
| EUDI SD-JWT callback/result and mdoc/DTC presentation | Repeat the actual official wallet-library/public gateway journey and prove accepted positives plus signature, replay, expiry, malformed-input and tenant negatives. The recorded 11 failures are not passes. |
| W3C VCDM v2 / Data Integrity issuance and VC/VP verification | Deterministic governed DID resolution, correct JSON-LD protected-term handling, complete document signing and canonical Rust verification. Do not enable unrestricted public-DID fallback or add suite-specific acceptance shortcuts. |
| OIDF mdoc fixture compatibility | Resolve the upstream CA/document-signer certificate problem through the owned/upstream issue, then rerun unchanged positives and invalid-session negatives. Keep independent issuer and holder/device authentication. |
| Optional OID4VCI features | Signed metadata, batch issuance and credential-response encryption are separate unadvertised feature proposals, not implemented capabilities. Keep the exact scoped [skip policy](expected-skips.json); enabling them needs reviewed public metadata, actual implementation and official positive/negative coverage. |
| Wider DIDComm exchange | Preserve current independent decryption/tamper/tenant regressions. A minimal HTTPS receiver plus a second library is not full-agent, all-mode or official conformance. Track wider modes and product scope separately under [Integration issue 224](https://github.com/ElevenID/marty-integration-tests/issues/224). |
| Notification/SSE external isolation | Focused gateway/service/UI regressions do not replace a released two-organization delivery matrix. Add explicit foreign-selector, delivery and leakage-denial assertions before closing that evidence gap. |
| Reproducible OCI builds | Signed/attested digests bind released bytes but do not prove byte-for-byte reproduction. Audit timestamps/base/OS inputs and run the independent double-build gate tracked by [UI issue 225](https://github.com/ElevenID/marty-ui/issues/225). |

The historical broad product scope also remains open: local official results do
not complete every trust-registry, DTC, VDS-NC, delegation or external wallet
feature. Keep those requirements with their canonical product owners and current
feature matrix; don't infer deletion authority from an old green milestone.

## Regression and evidence boundaries

- Keep OIDF, W3C and EUDI imported source, assertions, fixtures, expected results,
  selections and exclusions pinned and unchanged. Record only allowed upstream
  runtime scratch mutations in a separate disposable worktree. No product trust
  rule or official assertion is weakened to turn a fixture incompatibility green.
- Positive evidence traverses actual official libraries and the public tenant
  gateway, DID-first resolution and approved issuer custody. Placeholder
  credentials, dummy/zero signatures, mocked positive responses and expected-to-
  fail owned suites are not interoperability evidence. Synthetic responses are
  permitted for clearly labeled negative cases, not positive claims.
- Keep official-suite evidence separate from owned browser, tenant, lifecycle
  and DIDComm evidence. The latter records `official_suite_invoked=false` and
  `official_suite_source_modified=false`; independent library decryption is a
  scoped interoperability result, not an official certification.
- Preserve the two-organization API/browser matrix: public issuer identities,
  unknown/draft/incompatible/ambiguous DID denial, custody-selector rejection,
  issuer/accreditation trust decisions, cross-tenant request substitution,
  non-enumerating responses, lifecycle/revocation and trust-registry atomicity.
  Profile administration remains authorized setup; ordinary UI journeys must not
  retrieve private custody coordinates.
- Keep generated Python/Rust/TypeScript public schema/binding checks for trust
  profiles, DID-first templates, issuance, verification, flows/results and
  issued-credential lifecycle. Reconcile current contract pins mechanically;
  the historical MIP pin is provenance, not a replacement for current schemas.
- Use owned disposable stacks, exact project identity and source-bound manifests.
  Keep rate limits active; only reviewed finite disposable-suite budgets may
  differ. Never target customer data or production to reproduce an old result.

## Completion criteria

- [ ] Re-evaluate each recorded open feature/failure against the current immutable
  stack with exact upstream and harness pins.
- [ ] Link every remaining limitation to an owned remediation item and concrete
  acceptance criteria; preserve visible failures until then.
- [ ] Produce genuine official results and the separate owned tenant/browser/
  DIDComm matrix without conflating their evidence classes.
- [ ] Verify the applicable generated-contract, custody, release and deployment
  gates. No checked historical milestone establishes the wider goal complete.
