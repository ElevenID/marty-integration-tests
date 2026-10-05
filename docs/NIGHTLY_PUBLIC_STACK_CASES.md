# Candidate nightly public-stack cases

The five `nightly_public_smoke` cases in `tests/oss_stack/`
are an explicit, small *candidate* for the public-stack portion of a nightly
happy-path suite. Their exact pytest case IDs are pinned in
`tests/unit/test_nightly_public_smoke_selection.py`. Four cases check gateway
health, required service health, OID4VCI discovery, and UI serving. The fifth
creates a disposable application-approved Flow offer and redeems it through
the public gateway with the existing headless OID4VCI wallet. It requires an
immediate, nonempty issued credential and never skips. This is an issuance
journey, not an independent signature, presentation, or verifier decision check;
it cannot alone qualify a nightly release.
The wallet's existing JWT-VC structural parser is used to reject malformed
responses, and the decoded Open Badge subject must carry the generated member
ID and expected achievement name/description. This decodes but does not
cryptographically verify the signature.

The issuance case uses a per-run extension URI for targeted cleanup, including
after an uncertain Flow insert. The application-approved webhook is shared by
active Flow definitions for the seeded organization, so this OSS suite must
remain serial against one Compose project. Seeded production Flows may also
create offers for the event; the case requires exactly one offer from its own
unique Flow ID and redeems only that offer.

The official `marty-ui` stack release presently verifies the integration
source archive against `release/stack-lock.json`, constructs
`stack-manifest.json` with exact OCI digests, starts Compose from those
digests, runs **all** of `tests/oss_stack`, and records the source SHA, run ID,
and image digests in `public-stack.json`. This marker does not change that
workflow, its security-negative `test_public_api_has_no_commerce_routes`, or
the approval/recovery tests.

A future nightly orchestration may collect this candidate set with
`pytest tests/oss_stack -m nightly_public_smoke --collect-only`,
but execution must first be bound to the immutable nightly tag, its exact
stack manifest and image digests, the deployed stack identity, and a
machine-readable per-case result. The positive issuance case must pass against
the exact digest-pinned stack before it can be admitted; its collection alone
is not execution evidence. Verification needs a separately pinned, compatible
verifier artifact or an equivalent real verifier in the stack. A collect-only
success or a stable-release manifest is
not nightly qualification evidence. Preserve the separate official beta
lifecycle, demo qualification, and YouTube policy.

Local candidate check (2026-10-05): the five selected cases passed in 3.07s
against disposable Linux containers from published `marty-ui v1.1.226`, using
the exact `marty-integration-tests v1.2.81` Compose source pinned by that
release. The local stack manifest SHA-256 was
`97bb8e858301c29b5ccb08cc0ab6aff36b970517a5b9892fad2930fd3f8bcfff`
and matched the released checksum; the image digests came from that manifest.
The test runner was a Windows host, not the intended Linux nightly runner.
This is targeted local evidence, not release qualification, attestation of a
nightly tag, or a timing claim for CI.

After the structural assertion was added, the same manifest and isolated
Compose project passed all eight `tests/oss_stack` cases, including the
authentication/replay, recovery, and commerce-boundary checks, in 13.06s of
pytest time (14.44s command wall time). The manifest checksum and GitHub
attestation were rechecked; resolved Compose configuration selected
`DIDCOMM_DELIVERY_OWNER=native` and `http://issuance-native:8005`. This still
does not prove the future Linux nightly runner or nightly artifact lineage.

## A8 verifier feasibility replay (pinned `marty-ui` v1.1.226)

A disposable, digest-pinned public-stack replay tested whether the issued
member badge could complete an authorized issuance-to-verification journey.
The experiment generated ephemeral workload certificates with the Auth and Flow
SPIFFE URI SANs required by the released gRPC interfaces. With test-only
Compose wiring, Auth credential-login returned a real OID4VP request, and
Flow reached Presentation Policy over mTLS. The Trust Profile fixture also
needed its `PUBLIC_DOMAIN` aligned with the gateway's published issuer DID;
after that, its internal profile endpoint returned the issuer's DID keys.
The Presentation Policy fixture needed the actual `trust-profile-service` and
`issuance-service` URLs instead of the released services' default hostnames.

The resulting verifier decision was **deny**, not an infrastructure success or
an acceptable happy path. In the disposable local replay, Flow reported
`Credential signature was not verified:
VCDM VC-JWT verification rejected the credential (1 error(s))`, with
`signature_invalid`, `credential_format_mismatch`,
`trust_profile_not_verified`, `credential_timestamp_missing`,
`revocation_check_required`, and `claim_missing`. The released member-badge
template (`50000000-0000-0000-0000-000000000040`) issues `VC_JWT`, while the
released login trust profile (`60000000-0000-0000-0000-000000000001`) lists
only `SD_JWT_VC` and `MDOC`; the login policy
(`50000000-0000-0000-0000-000000000004`) requires that trust profile,
`openbadge-v3`, and an email claim. The format mismatch is a concrete released
seed/configuration incompatibility. The signature diagnostic needs a separate
product-level investigation; it is not evidence that changing the trust-profile
format alone would make this journey pass.

These runtime diagnostics are a transient local observation; sanitized run
output was not retained as an audit artifact. The seed-format mismatch above
is independently checkable in the released configuration.

All eight existing official OSS-stack cases passed on the experimental stack
(`8 passed, 1 experimental verifier case deselected`). The positive verifier
case failed closed and was not committed. Experimental Compose changes and
workload credentials were discarded; no production code or official test was
changed. A8 therefore makes **no verified-issuance-to-login claim** and must
not be promoted to nightly qualification on the strength of the issuance case.
Resolve the released issuer/template/trust/policy contract, then rerun a real
trusted presentation to an `allow` decision before adding such a claim.
