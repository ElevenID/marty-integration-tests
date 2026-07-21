# Official OID4VC conformance

This directory runs the OpenID Foundation Conformance Suite against a real
Marty deployment. It is deliberately separate from the mirrored pytest tests:
the official runner is the source of truth, while the local tests provide fast
feedback between official-suite releases.

## Safety and target boundary

The target must be a disposable deployment created from an attested
`marty.stack/v1` manifest. Start it with `make conformance-stack-start`; configure the suite with
the gateway-facing issuer or verifier URL. Do not point the suite at an
individual backend container, production customer data, a private service, or
commerce functionality. Test organizations, keys, credential templates, and
wallets are created for each run and discarded afterwards.

When an adapter needs Docker (for example the issuance and browser transport),
set `MARTY_CONFORMANCE_PROJECT` to the exact project-scoped Marty deployment
and `OIDF_CONFORMANCE_PROJECT` to the pinned runner's Compose project. Every
Docker exec target is checked against its `com.docker.compose.project` label.
The current local Docker context is safe because project identity—not a context
alias—is the isolation boundary. `MARTY_CONFORMANCE_DOCKER_CONTEXT` remains an
optional way to select a remote engine.

The exported official-suite results are evidence. They contain test identifiers
and URLs, so they are retained as a private CI artifact and are not committed.

## Run the official issuer plan

Install and start a pinned copy of the official suite following its upstream
instructions. The runner checkout must be at the commit recorded in
`oidf-runner.json`; the helper refuses a different revision.

```bash
cp conformance/marty-issuer.example.json /secure/work/marty-issuer.json
# Fill the disposable gateway-facing issuer URL and configuration ID.
python scripts/oidf_conformance.py validate
python scripts/oidf_conformance.py run \
  --runner /opt/openid-conformance-suite \
  --profile oid4vci-issuer \
  --config /secure/work/marty-issuer.json \
  --stack-manifest /secure/work/stack-manifest.json \
  --output-dir reports/oidf/issuer
```

`run` calls the official `scripts/run-test-plan.py` with the pinned active
OID4VCI plan variant; it does not simulate protocol calls or swallow test
failures. It creates the export directory, disables parallel plan execution
for reproducible evidence, and passes the configuration relative to the runner
checkout so Windows drive letters cannot be parsed as test-plan syntax. The official suite URL can be supplied with
`CONFORMANCE_SERVER` when it is not using its normal local default.

### Driving the real issuer path

Issuer-plan modules wait for an issuer to deliver a credential offer. Use the
included interaction adapter for unattended local, staging, and certification
runs. It creates the offer through Marty's normal issuance API, then supplies
that offer to the official suite; it does not mock an issuer or interpret test
results.

```bash
export CONFORMANCE_SERVER=https://oidf.test.example
export OIDF_ISSUANCE_URL=https://stack.test.example/v1/issuance/initiate
export OIDF_ISSUANCE_API_KEY="$(read_secret oidf-issuance-api-key)"
# Set only for a disposable development TLS endpoint.
export OIDF_INSECURE_TLS=1
python scripts/oidf_conformance.py run \
  --runner /opt/openid-conformance-suite \
  --profile oid4vci-issuer \
  --config /secure/work/marty-issuer.json \
  --output-dir reports/oidf/issuer \
  --interaction-script scripts/oidf_marty_offer.py
```

`marty-issuer.offer-request.example.json` contains only disposable fixture
claims. Override `OIDF_ISSUANCE_REQUEST` with a secure environment-specific
request when template identifiers differ. The adapter accepts TLS normally;
`OIDF_INSECURE_TLS=1` is intentionally limited to a disposable local stack.
Do not put the issuance URL, API key, or generated offers in repository files,
logs, or exported evidence.

For the local Docker stack, where the issuance management port is deliberately
not published to the host, set
`OIDF_ISSUANCE_COMMAND=scripts/oidf_docker_issuance.py` instead of the HTTP
variables. That adapter invokes the service inside its disposable container;
the container's API key never leaves it. The command-adapter contract is
simple: receive one JSON issuance request on standard input and emit the JSON
issuance response on standard output. It allows a protected certification
environment to use its own approved transport without changing the runner.

## OID4VP verifier and HAIP readiness

The verifier profiles are intentionally not active until they pass. Their
adapters are already versioned here so that no one needs to create a hidden
test wallet or a verification bypass. The command named by
`OIDF_VERIFIER_COMMAND` receives this JSON on standard input:

```json
{
  "test_id": "official-module-id",
  "test_name": "oid4vp-1final-verifier-happy-flow",
  "authorization_endpoint": "https://oidf.test.example/test/.../authorize",
  "request_method": "url_query"
}
```

Run a planned verifier profile only with `--allow-planned-profile` and an
attested `--stack-manifest`. This produces evidence marked
`execution_mode: pre-activation`; it does not advertise support or change the
profile status. Change the profile to `active` only after the exported official
result passes every applicable module and its review is merged.

It must start a normal, authenticated `POST /v1/flows/verify` gateway flow
using the disposable organization and policy, then write JSON containing its
ordinary `authorization_request` (`openid4vp://...?request_uri=...`) or the
HTTPS `request_uri`. The adapter fetches Marty's signed request object and
delivers it to the official mock wallet. The suite then posts its generated
presentation to Marty's actual public callback and determines the result.

### Separate runner Compose project

The official runner and Marty intentionally run as independent Compose
projects. Marty exposes only its TLS proxy on the external,
project-scoped `${MARTY_CONFORMANCE_PROJECT}_oidf-runner` bridge; its private
`marty-network` is never shared. The runner retains its default network for
MongoDB and runner-internal traffic, while only its `server` service also
joins that narrow bridge. This allows the official mock wallet to use Marty's
public HTTPS callback without a manual `docker network connect` or a broad
cross-stack network.

Start the pinned runner through the versioned overlay after the Marty OIDF
profile has created the bridge:

```bash
export MARTY_CONFORMANCE_PROJECT=marty-conformance-oidf
export OIDF_CONFORMANCE_PROJECT=oidf-runner
python scripts/oidf_runner_compose.py \
  --runner /opt/openid-conformance-suite \
  --prebuilt \
  -- up --detach
```

Use the same helper for `down`, `logs`, and `config`. It keeps the runner
project independent and only sets the external bridge-network name for the
official runner Compose overlay. `--prebuilt` is the normal reproducible
choice: it selects the runner's release Compose file and ElevenID's reviewed
image-digest overrides instead of its upstream mutable defaults. The overlay
pins the exact `server`, `nginx`, and upstream `mongodb` service images,
including the MongoDB image that upstream otherwise selects as `mongo:6.0.13`.
The source Compose option remains available only when developing a locally
built copy of the exact pinned runner revision.

### Separate EUDI reference Compose project

The pinned EUDI wallet tester, verifier endpoint, and wallet-kit harness also
run in their own Compose project. Start them only after the Marty OIDF profile
has created the scoped TLS bridge:

```bash
python scripts/eudi_reference_compose.py \
  --marty-project marty-conformance-oidf \
  --project eudi-reference-oidf \
  -- up --detach
```

The helper verifies that `${MARTY_CONFORMANCE_PROJECT}_oidf-runner` already
exists, then supplies it as the only Marty-facing network. It never attaches
the EUDI project to `marty-network`; use the same helper with `down`, `logs`,
or `config` for the matching project lifecycle.

### Unified Compose lifecycle

Use `official_suite_compose.py` in automation so every project uses one
validated Docker host and teardown happens in reverse order. A standard
GitHub-hosted Ubuntu runner can invoke Docker Compose directly; Docker-in-Docker
and a self-hosted runner are not required.

Generate a new local certificate authority, SAN TLS leaf, Java truststore, and
non-self-signed EUDI verifier access-certificate keystore for every disposable
run. Python creates the keys and certificates; JDK 17 or newer supplies
`keytool` for the two JKS files. The private environment manifest is not an
evidence artifact and must not be committed or uploaded.

```bash
export OFFICIAL_SUITE_RUN_ID="${GITHUB_RUN_ID:-local1}"
python scripts/eudi_test_material.py generate \
  --output "conformance/eudi-material/$OFFICIAL_SUITE_RUN_ID"
python scripts/eudi_test_material.py validate \
  --material "conformance/eudi-material/$OFFICIAL_SUITE_RUN_ID"

# The host-side clients and Docker bridge use this same certificate hostname.
# A GitHub-hosted Ubuntu runner may add this mapping in its disposable job.
getent hosts marty-oidf.test >/dev/null || \
  echo '127.0.0.1 marty-oidf.test' | sudo tee -a /etc/hosts >/dev/null

python scripts/official_suite_compose.py up \
  --marty-ui ../marty-ui \
  --oidf-runner /opt/openid-conformance-suite \
  --eudi-material "conformance/eudi-material/$OFFICIAL_SUITE_RUN_ID" \
  --oidf --eudi --w3c

# Capture results and logs, then always run:
python scripts/official_suite_compose.py down \
  --marty-ui ../marty-ui \
  --oidf-runner /opt/openid-conformance-suite \
  --eudi-material "conformance/eudi-material/$OFFICIAL_SUITE_RUN_ID" \
  --oidf --eudi --w3c
```

The launcher derives three distinct project names from the run ID. Marty starts
first so it creates its scoped TLS bridge; OIDF and EUDI start afterward.
Cleanup stops EUDI and OIDF before Marty removes the bridge. Docker locality is
derived from the actual endpoint selected by `MARTY_CONFORMANCE_DOCKER_CONTEXT`,
standard `DOCKER_CONTEXT`, `DOCKER_HOST`, or the active context. A named context
is not assumed remote: Unix sockets, Windows named pipes, and loopback endpoints
are inspected rather than guessed from its name. Only Unix sockets, Windows
named pipes, and `fd://` endpoints are local by default. TCP, HTTP, HTTPS, and
SSH endpoints remain remote even on loopback because they may be tunnels to a
different filesystem. Set `MARTY_CONFORMANCE_ALLOW_NETWORK_BINDS=1` only after
reviewing and proving that every client bind path is shared with that daemon.
Generated files can only be mounted into a local/shared Docker engine. The
launcher rejects generated material when the selected endpoint is remote
because Docker does not copy client-side bind mounts to the daemon host. For a
remote engine, provision external files on that host and use the external mode
below. Diagnostics and teardown do not validate certificate lifetimes, and can
still remove the project if the disposable material directory was deleted.

The generated manifest derives the exact HTTPS origins, host and bridge ports,
bridge DNS alias, trust root, keystore type, key alias, and passwords. Marty,
the official wallet tester, the EUDI verifier, and the wallet-kit harness then
use those normal public protocol URLs. No request URI or response URI is
rewritten to an internal container address, and the JVM harness uses the
generated truststore instead of a trust-all TLS manager.

Externally issued TLS certificates and an externally managed verifier
keystore remain the certification path. Export the same environment contract
(`OIDF_TLS_CERT_DIR`, `EUDI_VERIFIER_KEYSTORE_FILE`, its type/alias/passwords,
the three public HTTPS origins, the wallet-kit public URL, ports, and truststore
password), then validate it without `--material`:

```bash
python scripts/eudi_test_material.py validate
python scripts/official_suite_compose.py up \
  --marty-ui ../marty-ui \
  --oidf-runner /opt/openid-conformance-suite \
  --oidf --eudi --w3c
```

A complete external TLS-directory and EUDI-keystore pair takes precedence if
`--eudi-material` is also present. A partial pair is rejected before Docker is
called. On a local daemon, external validation checks the current TLS chain,
SANs, matching key, Java private-key alias, non-self-signed access-certificate
chain, and truststore root; it does not impose the disposable seven-day lifetime
cap. On a remote daemon those paths belong to the daemon host, so run
`eudi_test_material.py validate` on that host. The remote client validates only
the URL/port/store contract, then the startup readiness probes exercise the
public TLS paths. It never pretends that a remote file was validated locally.

Remote external mode also fails closed unless all checkout/config binds are
declared. `MARTY_CONFORMANCE_REMOTE_UI_ROOT` must equal the absolute local
`--marty-ui` checkout path and that identical path must exist on the daemon.
When OIDF is selected, `OIDF_CONFORMANCE_REMOTE_RUNNER_ROOT` has the same rule
for `--oidf-runner`. Set `EUDI_CONFORMANCE_CONFIG_ROOT` to the absolute
daemon-host directory containing `wallet-tester.nginx.conf` and
`verifier.nginx.conf`; Compose uses that value directly. The external
`OIDF_TLS_CERT_DIR` and `EUDI_VERIFIER_KEYSTORE_FILE` must likewise be absolute
daemon-host paths. This explicit contract prevents a remote run from silently
assuming that the client's repository exists on the daemon.

After Compose reports its healthchecks, the lifecycle also polls Marty's public
discovery endpoint, the wallet tester, the verifier Swagger endpoint, and the
wallet-kit health endpoint. Startup fails and unwinds all projects if any real
public path is not ready within the configured timeout.

Add `--haip` only when the disposable verifier signing key and matching
certificate are present in `VERIFIER_SIGNING_KEY_PEM` and
`VERIFIER_X509_CERT_PEM`. Certification later can supply externally issued
material without changing the lifecycle or production protocol path.

For local and CI HAIP runs, generate new material for every run. The helper
creates a P-256 disposable root, a matching P-256 verifier leaf and signing
key, and a separate P-256 credential-signing JWK for the official mock wallet.
It writes a ready `marty-verifier-haip.json`, embeds the root as the official
runner's request-object trust anchor, and stores the leaf-first certificate
bundle that Marty uses for its `x509_hash` and `x5c` request object. The root
is omitted from Marty's JOSE `x5c` header by the production verifier code and
is trusted independently by the official runner.

```bash
python scripts/haip_test_certificates.py \
  --output-dir /secure/work/haip-run1 \
  --gateway-url https://marty-oidf.test:8443

python scripts/official_suite_compose.py up \
  --run-id run1 \
  --marty-ui ../marty-ui \
  --oidf-runner /opt/openid-conformance-suite \
  --oidf --haip --haip-material /secure/work/haip-run1

python scripts/oidf_conformance.py run \
  --runner /opt/openid-conformance-suite \
  --profile oid4vp-haip-verifier \
  --config /secure/work/haip-run1/marty-verifier-haip.json \
  --stack-manifest /secure/work/stack-manifest.json \
  --allow-planned-profile \
  --output-dir reports/oidf/haip \
  --interaction-script scripts/oidf_marty_verifier.py
```

The default certificate lifetime is 24 hours and is capped at seven days.
Private files are created owner-readable/writable, existing material is never
overwritten, and standard output contains only paths, public certificate
fingerprints, validity, and configuration digests. Do not commit the generated
directory or upload it as an artifact.

For a financed certification run, provide both externally managed
`VERIFIER_SIGNING_KEY_PEM` and `VERIFIER_X509_CERT_PEM` values and an approved
HAIP configuration containing the issuer's trust anchor. Those environment
values take precedence even if `--haip-material` is present, so the same
Compose path exercises the real verifier implementation. A partial external
pair is rejected before any container starts.

```bash
cp conformance/marty-verifier.example.json /secure/work/marty-verifier.json
export CONFORMANCE_SERVER=https://oidf.test.example
# This checked-in deployment adapter starts a normal authenticated gateway flow.
export OIDF_VERIFIER_COMMAND="$PWD/scripts/oidf_marty_start_verification.py"
export OIDF_MARTY_GATEWAY_URL=https://stack.test.example
export OIDF_MARTY_OPERATOR_EMAIL=conformance@elevenid.dev
export OIDF_MARTY_OPERATOR_PASSWORD="$(read_secret oidf-disposable-operator-password)"
export OIDF_MARTY_PRESENTATION_POLICY_ID="$(read_secret oidf-disposable-policy-id)"
export OIDF_VERIFIER_REQUEST_METHOD=url_query
# The OID4VP Final baseline uses the standard redirect_uri client-ID prefix.
export OID4VP_CLIENT_ID_PREFIX=redirect_uri
python scripts/oidf_conformance.py run \
  --runner /opt/openid-conformance-suite \
  --profile oid4vp-verifier \
  --config /secure/work/marty-verifier.json \
  --stack-manifest /secure/work/stack-manifest.json \
  --allow-planned-profile \
  --output-dir reports/oidf/verifier \
  --interaction-script scripts/oidf_marty_verifier.py
```

The standard verifier plan asks the official wallet to receive a URL-query
authorization request. Marty production emits a signed `request_uri` instead,
so this lane fetches that normal signed JAR over public TLS and adapts its
claims into the official runner's URL-query input. Authentication, policy
selection, request generation, and callback processing all use production
paths, but the front-channel transport is adapted and must not be represented
as transport-identical URL-query evidence.

The HAIP profile uses the same command contract but is enabled only after
Marty produces signed `request_uri` requests with `x509_hash`, a fresh
per-request encryption key, and encrypted `direct_post.jwt` handling. Its
configuration additionally supplies the official runner's request-object trust
anchor. No HAIP profile may be marked active merely because a local test
adapter can execute it.

For `oid4vp-1final-verifier-request-uri-method-post` only, the flow-start
adapter selects production `request_uri_method=post`. The interaction bridge
forwards that original outer parameter and does not pre-fetch the POST-only
URI. The official mock wallet creates `wallet_nonce`, POSTs it to Marty's
ordinary public request endpoint, and verifies the returned signed JAR carries
the same nonce. Other signed-request modules keep GET retrieval, and the
standard URL-query plan is not forced into this behavior.

The EUDI wallet harness receives that request-object root through the read-only
file named by `EUDI_OID4VP_TRUST_ANCHOR_FILE` and validates Marty's JAR `x5c`
with PKIX. It does not infer verifier trust from the HTTPS truststore. Generated
`--haip-material` supplies the root automatically; an externally financed
certification run must supply its approved root file alongside the external
`VERIFIER_*` pair. The file may contain multiple approved CA certificates, but
it must not be empty and non-CA certificates are rejected.

Every runner export now includes `evidence.json`. It records the immutable
official-runner commit, stack-manifest digest and release, Marty commit when
provided as `MARTY_COMMIT`, configuration digest (never its secret contents),
allowlisted exclusions, exit status, and SHA-256 digests of the exported
official result files. Pass `--stack-manifest` for every release or
certification-grade run.

The deployment adapter deliberately requires a real gateway session and active
disposable presentation policy. It rejects HTTP URLs and creates neither an
authentication bypass nor a synthetic verifier flow. When
`OIDF_MARTY_SESSION_ID` is not explicitly supplied, it completes the normal
public `/v1/auth/login` → Keycloak → `/v1/auth/callback` flow with the
disposable reviewer and keeps the returned cookie only in the flow-start
process. Set `OIDF_MARTY_RESOLVE_IP=127.0.0.1` only for a local disposable
TLS host that is not in DNS; remote and certification targets use normal DNS.
For HAIP, set
`OIDF_MARTY_VERIFIER_PROFILE=haip`; the deployment must also provide a
matching verifier signing certificate and the official trust anchor.

## W3C VC Data Model v2

`w3c-vc-data-model-v2.json` pins the official W3C test-suite revision and
records the present proof-format boundary. A disposable stack enables the
adapter only with `W3C_VC_TEST_ADAPTER=1` and assigns an active fixture policy
through `W3C_VC_TEST_POLICY_ID`. The adapter has VC-API-shaped
`/credentials/verify` and `/presentations/verify` endpoints, but forwards
supported serialized credentials to the normal Marty presentation-policy
evaluator. It never uses the inline evaluator because that endpoint is for
ad-hoc policy simulation rather than an interoperability assertion.

The current W3C Data Integrity `eddsa-rdfc-2022` suite is explicitly excluded
in the manifest: Marty does not implement that proof suite yet. The adapter
returns a clear unsupported-serialization error instead of a false success.
Review the named exclusion on its date; add the official suite’s Data
Integrity modules only with real proof verification.

```bash
python scripts/w3c_vc_conformance.py validate
python scripts/w3c_vc_conformance.py write-local-config \
  --adapter-url https://stack.test.example/__test__/vc-api \
  --output /opt/vc-data-model-2.0-test-suite/localConfig.cjs
```

Run the pinned suite itself (using Node 24 and the exact npm version in the
manifest) only against the disposable HTTPS adapter deployment. `--install`
is explicit because the upstream suite does not publish a lockfile. The helper
recreates that lock, rejects it unless its SHA-256 matches the reviewed
manifest value, and copies it with the official reports into the private
evidence directory. A suite update therefore changes its commit, npm version
when necessary, and reviewed lock digest together.

The workflow does not replace the runner's global npm. It downloads the exact
npm tarball URL recorded in the manifest, verifies the recorded registry
SHA-512 integrity before extracting it, and invokes that private `npm-cli.js`
with Node 24. Its Python 3.12 dependencies are likewise installed only from
`requirements/official-py312.lock` with pip hash checking and binary-only
resolution. Regenerate that lock from `official-py312.in` with pip-tools 7.6.0
under Python 3.12, then review the complete diff before merging.

```bash
python scripts/w3c_vc_conformance.py run \
  --suite /opt/vc-data-model-2.0-test-suite \
  --adapter-url https://stack.test.example/__test__/vc-api \
  --stack-manifest /secure/work/stack-manifest.json \
  --output-dir reports/w3c-vc-v2 \
  --install
```

`--stack-manifest` is mandatory for an execution. The helper rejects a manifest
without digest-pinned OCI artifacts and records the release, manifest hash, and
tested image digests in `evidence.json`.

A zero exit code is accepted only when the official report contains passed
ElevenID matrix rows proving all three configured capabilities: issuer, VC
verifier, and VP verifier. The reviewed row markers live with the suite pin;
there is deliberately no fixed total-case count, so upstream may add tests
without weakening or spuriously breaking this evidence guard.

## Certification later

At the pinned OIDF `release-v5.2.0`, the official source labels both the
OID4VP Final verifier plan and the HAIP verifier plan as alpha tests that are
not currently part of the certification program. Passing them is valuable
official-runner interoperability evidence, but it is not an OIDF certificate.
When financing permits, externally managed certificate material and a
registered test deployment can exercise these same production paths. A formal
certificate can be pursued only after OIDF makes the applicable program
available; review and adopt newer runner releases through the monthly updater
when that status changes.

## Manual production-path interoperability workflow

Run **Official interoperability** from the Actions tab to execute one lane or
all four lanes. The workflow downloads the reviewed `marty-ui` release
manifest named in `stack-under-test.json`, checks its independent SHA-256 and
GitHub attestation, verifies each OCI attestation, and checks out the exact
Marty commit recorded by that release. A tag override is accepted only when
its reviewed manifest SHA-256 is supplied in the same dispatch.

Each lane owns separate Compose projects and disposable TLS, truststore,
keystore, operator credentials, fixtures, and output directories. OID4VP Final
and HAIP retain their `planned` profile status while this pre-activation
evidence is collected. The workflow uploads only the sanitized summary;
private configuration, generated keys, cookies, raw logs, and unredacted
official reports remain job-local and expire with the runner.

The EUDI lane also generates a separate disposable HAIP verifier chain. Marty
uses its leaf key and certificate to create the production signed JAR, while
the wallet harness receives only that chain's root through the read-only
`EUDI_OID4VP_TRUST_ANCHOR_FILE` mount. This root is deliberately different
from the disposable TLS CA. The official EUDI OID4VP library must resolve an
`x509_hash` request, validate its `x5c` chain with PKIX, and dispatch an
encrypted `direct_post.jwt` response; a default/DID-only flow does not satisfy
the lane's recorded presentation coverage.

For mdoc issuance, the harness asks the normal gateway API to export the
selected production KMS public key, issues a short-lived document-signer
certificate for that key under a disposable test CA, stores the public chain
through the normal certificate API, and republishes JWKS. The KMS private key
never enters the test process. The independent evidence parser verifies the
resulting COSE signature, X.509 chain, MSO validity, digest coverage, CBOR
types, and issuance claims. An externally managed DSC chain can replace the
disposable chain later without changing the gateway, KMS, issuance, or wallet
paths exercised by the lane.

The public summary is also bound to stable, versioned JUnit evidence IDs for
end-to-end SD-JWT issuance/presentation, cryptographically validated mdoc
issuance, the official HAIP resolve/dispatch path, and the
missing-holder-binding-key negative path. Every claimed coverage value
must map one-to-one to one of these evidence assertions. The runner rejects an
unbound claim or a missing, renamed, duplicated, failed, errored, or skipped
sentinel, and a passing `evidence.json` cannot be written unless all required
assertions appear exactly once and pass. This prevents a suite refactor from
silently deleting the tests behind a published claim.

The stack pin records immutable `marty-ui` release `v1.1.3` as `ready`, with
the independently downloaded `stack-manifest.json` SHA-256 recorded in
`stack-under-test.json`. Execution hard-fails if the released asset, its
attestation, or any digest-pinned component differs from that reviewed pin. A
monthly execution schedule is intentionally deferred until all four manual
lanes pass. The single monthly `official-suite-updates.yml` workflow creates
or refreshes one draft review PR when any official suite has moved. It never
changes a runner pin or dependency lock automatically and never merges.

## EUDI reference interoperability

The EUDI harness runs the existing real-client issuance, presentation, mdoc,
SD-JWT, invalid-request, and replay tests with the gate enabled explicitly.
Point it only at the digest-pinned EUDI containers recorded in
`eudi-reference-interop.json` and the disposable HTTPS Marty deployment.

Start the separate EUDI project with Marty's HAIP overlay and the matching
request-object material. This does not start or join the OIDF runner project;
the existing scoped TLS bridge remains the only cross-project connection.

```bash
python scripts/official_suite_compose.py up \
  --run-id "$OFFICIAL_SUITE_RUN_ID" \
  --marty-ui /opt/marty-ui \
  --eudi --haip --haip-material /secure/work/haip-material
```

```bash
python scripts/eudi_reference_interop.py run \
  --eudi-material "conformance/eudi-material/$OFFICIAL_SUITE_RUN_ID" \
  --stack-manifest path/to/stack-manifest.json \
  --output-dir reports/eudi-reference
```

The runner loads the generated CA, exact endpoints, local hostname resolution,
and public-login gateway from that same private manifest. Explicit endpoint
flags remain available for externally managed certification deployments, but
when combined with `--eudi-material` they must exactly match it.

Run the reference wallet tester and verifier as a separate Compose project
with `conformance/eudi-reference.compose.yml`. It joins only Marty's
`oidf-runner` TLS-proxy bridge; it cannot access Marty's internal Compose
network. The wallet-kit harness is likewise a thin facade over the pinned
official EUDI Wallet Kit Maven libraries, not a mock wallet. The three HTTPS
endpoints above are the TLS boundaries; do not use private container ports
from a host-side conformance run.

The manifest records each library independently: OID4VP 0.12.3, OID4VCI
0.9.1, and SD-JWT 0.18.0, including its Maven coordinate, official source
repository, release tag, and dereferenced commit. The harness build uses
digest-pinned Gradle and Temurin bases, Gradle dependency locking, and strict
SHA-256 dependency verification metadata. The monthly upstream review checks
all three source repositories rather than treating OID4VP as the whole wallet
kit. Updating a coordinate requires regenerating and reviewing both
`gradle.lockfile` and `gradle/verification-metadata.xml`.

It writes JUnit output, the unredacted local runner log, and `evidence.json`
with the exact EUDI component digests, coverage matrix, endpoints, Marty
commit, attested stack-manifest and image digests, exit status, and result-file digests. The wallet-kit harness must use
the Maven coordinate pinned in the same manifest; do not replace it with a
moving upstream release.

The public-safe workflow summary additionally records the locally built
wallet-harness image ID (a `sha256:` content digest) and hashes of its
Dockerfile, Gradle lock, and dependency-verification metadata. The ephemeral
Compose image name, generated keys, passwords, and raw logs are not published.

When certification funding is available, enable the protected certification
environment and run the same command against the registered test deployment.
Attach the pinned runner revision, stack manifest, image digests, sanitized
configuration, exported result JSON, logs, and the commit under test. There is
no second certification-only implementation to drift from daily testing.

## Updating official suites

The monthly `official-suite-updates.yml` workflow checks OIDF, W3C, and every
pinned EUDI source through `scripts/official_suite_updates.py`. When it finds
drift, it creates or refreshes the stable
`automation/official-suite-updates` draft PR with the observed release and
commit revisions. It never silently switches versions, changes immutable
pins, or merges. For OIDF, review an update by changing both the release and
full commit in `oidf-runner.json`, then run the affected profile against the
production-path stack before merging. Expected failures are allowed only in
`expected-failures.json`, with an OIDF test id, issue URL, owner, and expiry
date. Optional OIDF modules that Marty does not claim to support use the
separate `expected-skips.json`, which requires a matching test name,
configuration pattern, rationale, owner, and expiry. The runner fails on a
new skip, or when an expected skip stops occurring, so neither file is a
permanent baseline.
