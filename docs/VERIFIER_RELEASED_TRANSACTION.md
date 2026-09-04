# Published verifier transaction regression gate

The static published-transaction lane reruns the already-authoritative
`run-transaction` and `compare-transaction-evidence` owners. It does not add a
second verifier, change the frozen check sets or declare the Python oracle
capable of the Rust-only positive OID4VP runtime check.

Keep three distinct subjects in the artifact workflow:

- the immutable Python oracle;
- the immutable rejected Rust v1.1.208 negative control;
- the exact published Rust transaction in
  `config/credentials-verifier-released-transaction.json`.

The last pin uses the existing transaction-pin schema. Its `transaction` state
identifies the evidence format; publication is verified separately. In
particular, a late release tag does not change the image/SBOM's original
`refs/heads/main` attestation into tag-based provenance.

Before committing a new static pin, independently verify the aggregate release,
its protected source commit, transaction and manifest, exact services digest,
and the published services SBOM's digest and attestation. Derive the pin through
`create-transaction-pin` using those actual artifacts. Never use a placeholder,
an unqualified candidate, a quarantined release or a mutable image tag.

At runtime, the workflow validates the immutable pin, retrieves metadata from
its fixed repository, and checks the late annotated tag's name, commit and
transaction/claim/source message. It also requires a non-draft, non-prerelease
GitHub release with a publication timestamp. These identity checks do not
replace the subsequent exact-source image/SBOM provenance verification, SBOM
validation, fresh runtime execution or complete differential comparison.

Both comparison outputs are retained: the historical negative-control result
and the passing published-transaction result. Comparison uses full real Git
history so all evidence is tied to the same clean, hardened harness commit.
The new lane does not authorize a product publication or modify any deployed
stack. Beta deployment, release recordings and acceptance soak are separate
required evidence.

## Initial published subject: v1.1.214

The initial pin is derived from the actual published services SBOM in
[marty-ui v1.1.214](https://github.com/ElevenID/marty-ui/releases/tag/v1.1.214),
immutable GitHub release ID `383068679`. Protected
[release run 33930593794](https://github.com/ElevenID/marty-ui/actions/runs/33930593794)
passed both public-stack and verifier differential gates before publication.
The resume reused the three signed image digests from run `33928890712`;
that initial run failed only while downloading the previous rollback manifest.

Independently verified before adding the pin:

- all 11 downloaded release assets match GitHub's asset digests, and every
  `SHA256SUMS` entry matches;
- the annotated tag object `3938a47d1623642627db97dfdf6afc91ca0f8e96`
  binds source `24f5d5dc0bb47d3dadb118b4dbe45191c5cf71b1`, claim run
  `33928810880`, and the exact pinned transaction ID;
- the published terminal transaction validates against the exact source and
  stack lock, and binds release ID `383068679` and manifest digest
  `sha256:990c976800f85db83fd2631594e2426a523b34ed6d3b67eb3206e13eca83ab23`;
- the manifest preserves all nine locked component records and binds all
  three UI image roles to their qualified digests;
- manifest, promoted transaction, all three published SBOMs, and all three
  images have verified GitHub provenance for the exact protected-main source,
  with self-hosted runners denied.

The release's signed `release-transaction.json` is the pre-publication
`promoted` checkpoint. The separate `stack-release-published-33930593794`
Actions artifact contains the terminal `published` transaction, including the
GitHub release ID. They are deliberately distinct evidence, not interchangeable
files. The static pin uses the **published** services SBOM digest, not the
SBOM regenerated earlier during qualification.
