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
