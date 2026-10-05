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
