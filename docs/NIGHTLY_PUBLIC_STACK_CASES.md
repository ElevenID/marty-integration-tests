# Candidate nightly public-stack cases

The four `nightly_public_smoke` cases in `tests/oss_stack/test_public_stack.py`
are an explicit, small *candidate* for the public-stack portion of a nightly
happy-path suite. Their exact pytest case IDs are pinned in
`tests/unit/test_nightly_public_smoke_selection.py`. The cases check gateway
health, required service health, OID4VCI discovery, and UI serving. They are
not a credential issuance, verification, login, or browser-wallet journey and
cannot alone qualify a nightly release.

The official `marty-ui` stack release presently verifies the integration
source archive against `release/stack-lock.json`, constructs
`stack-manifest.json` with exact OCI digests, starts Compose from those
digests, runs **all** of `tests/oss_stack`, and records the source SHA, run ID,
and image digests in `public-stack.json`. This marker does not change that
workflow, its security-negative `test_public_api_has_no_commerce_routes`, or
the approval/recovery tests.

A future nightly orchestration may collect this candidate set with
`pytest tests/oss_stack/test_public_stack.py -m nightly_public_smoke --collect-only`,
but execution must first be bound to the immutable nightly tag, its exact
stack manifest and image digests, the deployed stack identity, and a
machine-readable per-case result. It also needs at least one real positive
credential journey. A collect-only success or a stable-release manifest is
not nightly qualification evidence. Preserve the separate official beta
lifecycle, demo qualification, and YouTube policy.
