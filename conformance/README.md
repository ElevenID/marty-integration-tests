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

The `oid4vci-issuer` lane is part of the monthly
`official-interoperability.yml` matrix and is also available through manual
dispatch. It starts the pinned OIDF runner and an attested disposable Marty
stack, provisions the issuer through the public gateway, completes the normal
public OIDC operator login, creates every offer through `POST /v1/issuance`,
and submits no profile, KMS, service, or key selector. Paid certification can
reuse the same lane, runner commit, production images, and evidence format
when financing is approved.

Install and start a pinned copy of the official suite following its upstream
instructions. The runner checkout must be at the commit recorded in
`oidf-runner.json`; the helper refuses a different revision.
The checkout must also remain byte-for-byte clean before and after every lane.
Test selection and Marty configuration use the official runner's supported
external interfaces; no upstream assertion or test implementation is edited,
patched, or locally marked as passing.

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

Marty's public-wallet flow supports `client_auth_type=none`, while the active
official interoperability profile deliberately exercises registered
`private_key_jwt` clients. The disposable organization owns the two official
wallet public keys; Marty rejects missing, invalid, expired, replayed,
wrong-audience, and cross-client assertions. OIDF release-v5.2.2 drives that
normal public issuer path. Three optional capabilities Marty does not advertise
remain explicit, owned, expiring skips. The disposable issuer profile requires
key attestation, trusts only the lane's short-lived attester CA, and advertises
that policy in the production credential-issuer metadata. The unchanged OIDF
runner then creates the valid attestation and corrupts its signature for the
official negative module; ElevenID does not patch the runner or its expected
result.

The attester key belongs to the external test-wallet role because the official
runner has no remote-signing interface. It exists only in the mode-0600 runner
configuration and is destroyed with the disposable lane. It is not a Marty
issuer key: every Marty credential and request-object key remains in managed
custody, and every Marty signature is selected through the tenant issuer
profile and its DID.

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
# Set only for a disposable development issuer TLS endpoint.
export OIDF_ISSUANCE_INSECURE_TLS=1
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
`OIDF_ISSUANCE_INSECURE_TLS=1` is intentionally limited to a disposable local
issuer. The scheduled lane trusts the generated Marty CA and relaxes TLS only
for the isolated local OIDF runner through
`OIDF_CONFORMANCE_INSECURE_TLS=1`.
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
  "request_method": "request_uri_signed"
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

The pinned EUDI verifier endpoint and wallet-kit harness also
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
  --oidf --eudi

# Capture results and logs, then always run:
python scripts/official_suite_compose.py down \
  --marty-ui ../marty-ui \
  --oidf-runner /opt/openid-conformance-suite \
  --eudi-material "conformance/eudi-material/$OFFICIAL_SUITE_RUN_ID" \
  --oidf --eudi
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
the EUDI verifier and wallet-kit harness then
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
  --oidf --eudi
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
discovery endpoint, the verifier Swagger endpoint, and the
wallet-kit health endpoint. Startup fails and unwinds all projects if any real
public path is not ready within the configured timeout.

Add `--haip` with prepared trust material. The lifecycle first starts Marty,
resolves the active verifier issuer profile's public DID key inside the
gateway network, and issues a short-lived certificate for that public key.
Marty signs only through the issuer profile; its private key remains in KMS.

For local and CI HAIP runs, generate new material for every run. The helper
prepares a P-256 disposable root and a separate P-256 credential-signing JWK
for the official mock wallet. After Marty and its migrations are ready, the
lifecycle retrieves only the issuer profile's public JWK from inside the
gateway container, issues the matching leaf, destroys the disposable root
private key, and restarts the flow service in HAIP mode. It writes a ready
`marty-verifier-haip.json`, embeds the root as the official runner's
request-object trust anchor, and stores the leaf-first certificate bundle that
Marty uses for its `x509_hash` and `x5c` request object. The root is omitted
from Marty's JOSE `x5c` header and is trusted independently by the runner.

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
  --output-dir reports/oidf/haip \
  --interaction-script scripts/oidf_marty_verifier.py
```

The default certificate lifetime is 24 hours and is capped at seven days.
Private test-counterparty files are created owner-readable/writable, existing
material is never overwritten, and standard output contains only paths,
public certificate fingerprints, validity, and configuration digests. Do not
commit the generated directory or upload it as an artifact.

For a financed certification run, provision the approved signing key in KMS
custody, bind it to the active issuer profile and DID verification method, and
provide only its externally issued `VERIFIER_X509_CERT_PEM` plus the approved
trust anchor file. The external certificate takes precedence over disposable
issuance, but request objects still traverse the identical issuer-profile and
DID signing path; callers never invoke KMS directly. Direct private-key
environment input is rejected.

```bash
cp conformance/marty-verifier.example.json /secure/work/marty-verifier.json
export CONFORMANCE_SERVER=https://oidf.test.example
# This checked-in deployment adapter starts a normal authenticated gateway flow.
export OIDF_VERIFIER_COMMAND="$PWD/scripts/oidf_marty_start_verification.py"
export OIDF_MARTY_GATEWAY_URL=https://stack.test.example
export OIDF_MARTY_OPERATOR_EMAIL=conformance@elevenid.dev
export OIDF_MARTY_OPERATOR_PASSWORD="$(read_secret oidf-disposable-operator-password)"
export OIDF_MARTY_PRESENTATION_POLICY_ID="$(read_secret oidf-disposable-policy-id)"
export OIDF_VERIFIER_REQUEST_METHOD=request_uri_signed
# Signed request objects use a certificate-bound client identifier.
export OID4VP_CLIENT_ID_PREFIX=x509_hash
python scripts/oidf_conformance.py run \
  --runner /opt/openid-conformance-suite \
  --profile oid4vp-verifier \
  --config /secure/work/marty-verifier.json \
  --stack-manifest /secure/work/stack-manifest.json \
  --output-dir reports/oidf/verifier \
  --interaction-script scripts/oidf_marty_verifier.py
```

The standard verifier plan exercises Marty's native signed `request_uri`
transport with the OIDF runner's `request_uri_signed` and `x509_hash`
variants. The interaction bridge forwards the original public request URI and
client identifier; it never decodes the JAR into a different front-channel
transport. Marty separately supports a signed Request Object passed by value
in the standard `request` parameter. The separate `oid4vp-url-query` lane
exercises the OIDF runner's direct unsigned `url_query` variant with
`client_id_prefix=redirect_uri`; it never relabels or unpacks a signed JAR.
Run
[30509192015](https://github.com/ElevenID/marty-integration-tests/actions/runs/30509192015)
passed all ten official modules against immutable `marty-ui` v1.1.73 with
273 successful conditions, zero failures, zero warnings, and no expected
failures or skips. The pinned OIDF checkout remained unmodified.
The follow-up default-pin
[active run 30509798974](https://github.com/ElevenID/marty-integration-tests/actions/runs/30509798974)
repeated the pass after promotion and records `execution_mode=active`.

The `oid4vp-final` lane also runs an ElevenID-owned released-browser smoke as
separate product-path evidence. It drives the exact released UI through the
applicant catalog, application creation, submission, credential claim, and
verification session. Before opening the browser, the ElevenID-owned bootstrap
creates a disposable DID-bound credential template, linked active application
template, and ordinary application-approved OID4VCI flow through the public
gateway. The smoke selects those exact fixture IDs rather than relying on
ambient demo or seed records. It binds the public credential template's
`organization_id + issuer_did` to the linked application template, rejects
every profile/service/key/KMS selector in public requests and responses, and
records only public IDs, paths, status codes, and whether a credential offer
was produced. Its sanitized result appears under `browser_evidence`; it never
changes an official suite result or compensates for an official failure.

## Run the official ISO mDL verifier plan

The `oid4vp-mdoc` lane uses the pinned OIDF OID4VP Final verifier plan with
`credential_format=iso_mdl`, `response_mode=direct_post`,
`request_method=request_uri_signed`, and `client_id_prefix=x509_hash`. It
provisions an ISO 18013-5 mDL template and presentation policy through the
same authenticated public gateway API as the UI. The disposable profile uses a
managed `mdoc_dsc` signer only while creating the issuer profile; the runtime
request carries only organization and DID identity, never a custody selector.

```bash
cp conformance/marty-verifier-mdoc.example.json /secure/work/marty-verifier-mdoc.json
python scripts/oidf_conformance.py run \
  --runner /opt/openid-conformance-suite \
  --profile oid4vp-mdoc-verifier \
  --config /secure/work/marty-verifier-mdoc.json \
  --stack-manifest /secure/work/stack-manifest.json \
  --output-dir reports/oidf/mdoc-verifier \
  --interaction-script scripts/oidf_marty_verifier.py
```

This is native official **verifier** coverage: the upstream runner creates the
ISO mDL presentation and checks Marty's public OID4VP request, callback, and
verification behavior. It is not an OIDF mdoc issuer certification and must
not be presented as one. Marty mdoc issuance remains covered separately by
the EUDI reference-library lane until upstream provides a suitable issuer plan.

The exact OIDF `release-v5.2.2` source rotates its mdoc
`documentSignerCert`. The reviewed certificate is valid from
`2026-08-03T16:12:01Z` through `2027-08-03T16:12:01Z` and has SHA-256
`6cb412be8d1e78f77b1bce09592b0c88f690034855753b1954d6bcadf3b92b53`.
The rotation fixes time validity but not the certificate profile: the fixture
still has critical `BasicConstraints CA:true` and critical
`KeyUsage keyCertSign,cRLSign`. ISO 18013-5 Table B.3 requires the document
signer usage to be `digitalSignature`; OIDF tracks this in
[conformance-suite#1891](https://gitlab.com/openid/conformance-suite/-/work_items/1891).
A strict verifier must therefore reject the current positive presentations.

The lane reads the certificate from the unchanged, commit-pinned source,
checks its validity, provisions it as an exact issuer pin, and still applies
Marty's document-signer profile validation. Pinning establishes which issuer
the operator trusts; it does not authorize a CA key to act as a document
signer. The lane remains enabled and red so the first reviewed upstream fix is
detected without changing an imported assertion. Do not replace the
certificate, disable time or profile validation, add an expected failure, or
modify/exclude the imported suite to manufacture a pass. Track the fixture and
release-adoption evidence in
[marty-integration-tests#243](https://github.com/ElevenID/marty-integration-tests/issues/243).

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
the same nonce. Other signed-request modules keep GET retrieval.

The EUDI wallet harness receives that request-object root through the read-only
file named by `EUDI_OID4VP_TRUST_ANCHOR_FILE` and validates Marty's JAR `x5c`
with PKIX. It does not infer verifier trust from the HTTPS truststore. Generated
`--haip-material` supplies the root automatically; an externally financed
certification run must supply its approved root file alongside the external
public certificate. The file may contain multiple approved CA certificates, but
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
records the present proof-format boundary. The suite calls Marty's ordinary
authenticated `/v1/vc-api` gateway boundary with a disposable organization-
scoped API key carrying only `credentials:issue` and `credentials:read`.
The canonical official checkout is kept at that exact commit and is never used
as the execution directory. The runner verifies it is byte-for-byte clean,
creates a detached disposable worktree at the same commit, and runs the
upstream suite's own complete test command there. No ElevenID patch, assertion,
expected result, or test selection is applied. Local configuration, the
separately reviewed dependency lock, installed dependencies, and reports exist
only in the disposable worktree. The suite itself rewrites its tracked
`reports/related-resource.json` scratch document; the runner records and allows
only that upstream-owned runtime mutation, rejects a change to any test,
assertion, or other tracked path, removes the disposable worktree, and verifies
the canonical checkout is still clean. An upstream test-runner defect remains a
visible failure until the official repository merges a fix and the reviewed
commit pin advances.
Fixture bootstrap creates separate active credential and presentation
policies through the normal public administration API. Both policies and both
credential templates declare the native W3C VC Data Model v2 Data Integrity
representation. The credential policy omits presentation holder binding; the
presentation policy verifies the official challenge and domain.

The VC-API-shaped issuer endpoint is an adapted interface, but its
implementation is not a synthetic signer. It submits the complete unsigned
credential to Marty's normal issuance transaction, token, nonce, holder-proof,
DID-resolution, issuer-profile, managed-custody, and native marty-core
`eddsa-rdfc-2022` proof path. The verification endpoints forward supported
serialized credentials to the normal Marty presentation-policy evaluator and
never use the inline ad-hoc evaluator.

The official registration uses the product-resolved issuer DID as its issuer
ID and advertises only the `vc2.0` Data Integrity capability. It does not tag
Marty as `EnvelopingProof` or claim JOSE issuance in this lane.
`W3C_VC_API_KEY` is the one-time value returned by the public API-key creation
call during fixture bootstrap; keep it in the private job environment and
never pass it on a command line or upload it as evidence.

```bash
export W3C_VC_API_KEY='<disposable organization-scoped test key>'
python scripts/w3c_vc_conformance.py validate
python scripts/w3c_vc_conformance.py write-local-config \
  --adapter-url https://stack.test.example/v1/vc-api \
  --issuer-id did:web:stack.test.example:orgs:official-w3c \
  --organization-id official-w3c \
  --credential-template-id template-w3c \
  --credential-policy-id policy-credential \
  --presentation-policy-id policy-presentation \
  --output /opt/vc-data-model-2.0-test-suite/localConfig.cjs
```

Run the pinned suite itself (using Node 24 and the exact npm version in the
manifest) only against the disposable HTTPS adapter deployment. `--install`
is explicit because the upstream suite does not publish a lockfile. The helper
recreates that lock, rejects it unless its SHA-256 matches the reviewed
manifest value, and copies it with the official reports into the private
evidence directory. A suite update therefore changes its commit, npm version
when necessary, and reviewed lock digest together.

The official matrix uses the normal production gateway and OID4VCI token
limiters. Their production defaults are not weakened. The disposable W3C stack
receives finite higher budgets because every official issuance redeems a real
pre-authorized token; this prevents infrastructure throttling from being
misclassified as a normative VCDM result.

The manifest also records the exact HTTPS URLs used by the pinned suite's
`relatedResource` fixtures. The lane passes that reviewed list into the
product's fail-closed related-resource validator. This is deployment policy,
not a test patch: issuance still retrieves each resource, computes its digest,
and rejects a mismatch. Ordinary deployments retain the empty fail-closed
default. A monthly suite-pin update must review this URL list explicitly.

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
  --adapter-url https://stack.test.example/v1/vc-api \
  --issuer-id did:web:stack.test.example:orgs:official-w3c \
  --organization-id official-w3c \
  --credential-template-id template-w3c \
  --credential-policy-id policy-credential \
  --presentation-policy-id policy-presentation \
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

The runner never applies an upstream pull request or local compatibility patch.
Monthly updates advance only to a reviewed upstream commit and rerun the
complete suite from a new detached worktree.

## Certification later

At the pinned OIDF `release-v5.2.2`, the official source labels both the
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

The EUDI lane also generates a separate disposable HAIP verifier chain. The
leaf certifies Marty's issuer-profile DID key. The profile and its DID are the
signing interface; the profile internally uses its KMS custody backend to sign
the production JAR, while
the wallet harness receives only that chain's root through the read-only
`EUDI_OID4VP_TRUST_ANCHOR_FILE` mount. This root is deliberately different
from the disposable TLS CA. The official EUDI OID4VP library must resolve an
`x509_hash` request, validate its `x5c` chain with PKIX, and dispatch an
encrypted `direct_post.jwt` response; a default/DID-only flow does not satisfy
the lane's recorded presentation coverage.

For mdoc issuance, the harness asks the normal gateway API for the selected
issuer profile's DID public key, issues a short-lived document-signer
certificate for that key under a disposable test CA, stores the public chain
through the normal issuer-profile certificate API, and republishes JWKS. The
KMS-custodied private key never enters the test process. The independent
evidence parser verifies the resulting COSE signature, X.509 chain, MSO
validity, digest coverage, CBOR types, and issuance claims. An externally
managed DSC chain can replace the disposable chain later without changing the
gateway, issuer-profile, DID, issuance, or wallet paths exercised by the lane.

For mdoc presentation, the wallet harness uses the holder proof key bound into
the issued MSO to construct the ISO DeviceResponse and detached ES256
DeviceAuthentication signature. It follows the OpenID4VP handover implemented
by the EUDI reference wallet's pinned Multipaz dependency. This is a
holder-side operation: issuance remains signed through the selected issuer
profile and its DID, while neither presentation code nor protocol callers can
select an issuer KMS service or key reference.

The public summary is also bound to stable, versioned JUnit evidence IDs for
end-to-end SD-JWT issuance/presentation, cryptographically validated mdoc
issuance and presentation, the official HAIP resolve/dispatch path, and the
missing-holder-binding-key negative path. Every claimed coverage value
must map one-to-one to one of these evidence assertions. The runner rejects an
unbound claim or a missing, renamed, duplicated, failed, errored, or skipped
sentinel, and a passing `evidence.json` cannot be written unless all required
assertions appear exactly once and pass. This prevents a suite refactor from
silently deleting the tests behind a published claim.

The stack pin records immutable `marty-ui` release `v1.1.34` as `ready`, with
the independently downloaded `stack-manifest.json` SHA-256 recorded in
`stack-under-test.json`. Execution hard-fails if the released asset, its
attestation, or any digest-pinned component differs from that reviewed pin.
The official interoperability workflow runs all four lanes monthly on the
eighth day and remains manually dispatchable by lane. The separate monthly
`official-suite-updates.yml` workflow checks upstreams on the first day and
creates or refreshes one draft review PR when any official suite or the
official W3C commit has moved. Neither workflow changes a runner pin or
dependency lock automatically, and the updater never merges.

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

Run the reference verifier and wallet-kit harness as a separate Compose project
with `conformance/eudi-reference.compose.yml`. It joins only Marty's
`oidf-runner` TLS-proxy bridge; it cannot access Marty's internal Compose
network. The wallet-kit harness is likewise a thin facade over pinned official
EUDI Wallet Kit libraries and the OpenWallet Foundation Multipaz mdoc library
used by the EUDI reference wallet, not a mock wallet. The three HTTPS
endpoints above are the TLS boundaries; do not use private container ports
from a host-side conformance run.

The manifest records each library independently: OID4VP 0.15.1, OID4VCI
0.13.0, SD-JWT 0.20.1, and Multipaz 0.100.0, including its Maven coordinate,
official source repository, release tag, and dereferenced commit. The harness build uses
digest-pinned Gradle and Temurin bases, Gradle dependency locking, and strict
SHA-256 dependency verification metadata. The monthly upstream review checks
all four source repositories rather than treating OID4VP as the whole wallet
kit. Updating a coordinate requires regenerating and reviewing both
`gradle.lockfile` and `gradle/verification-metadata.xml`.

OID4VCI 0.13.0 uses key-attestation-bound JWT proofs. Each run creates a
short-lived external wallet-attester chain, mounts its private material only
into the wallet harness, and configures the Marty issuer profile to trust only
that disposable root. Marty issuer keys remain in KMS and all credential
signing continues through the issuer profile and its DID.

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

## DIDComm cross-implementation evidence

The public tenant-boundary lane tests Marty's selected outbound DIDComm
Messaging 2.1 profile against the separately maintained
`notabene-id/go-didcomm` implementation pinned in
`didcomm-interoperability.json`. The workflow checks out the exact reviewed
commit, requires a clean source tree, and builds its command with read-only Go
module resolution and the public checksum database. It does not download a
moving binary or substitute another Marty binding.

After Marty issues through the normal organization-plus-issuer-DID path and
delivers to a fresh X25519 `did:peer:2` holder over CA-validated HTTPS, both
the attested released Marty binding and the independent Go implementation must
decrypt the same JWE to the same plaintext. The independent implementation
must classify the message as encrypted anoncrypt with no authenticated sender;
the plaintext `from` value is not promoted into an authentication result.

This is deliberately a narrow interoperability claim: one recipient, General
JSON JWE, `ECDH-ES+A256KW`, X25519, `A256CBC-HS512`, and the final Issue
Credential 3.0 delivery message. It is not an official DIDComm certification,
full protocol-flow coverage, inbound Marty agent coverage, authcrypt, signed
message, multi-recipient, routing/mediation, DID rotation, or broad DID-method
evidence. Those capabilities require separate production APIs and tests before
they may be claimed.

## Updating official suites

The monthly `official-suite-updates.yml` workflow checks OIDF, W3C, every
pinned EUDI source, and the independent DIDComm implementation through
`scripts/official_suite_updates.py`. When it finds
drift, it creates or refreshes the stable
`automation/official-suite-updates` draft PR with the observed release and
commit revisions. It never silently switches versions, changes immutable
pins, or merges. OIDF and EUDI drift is measured against the latest published
release tag and its dereferenced commit, never an unreleased default-branch
head; W3C remains commit-pinned to its continuously published official suite.
For OIDF, review an update by changing both the release and full commit in
`oidf-runner.json`, then run the affected profile against the production-path
stack before merging. `expected-failures.json` must remain
empty: an official result cannot mask a failing executed test. Optional OIDF
modules that Marty truthfully does not advertise use the
separate `expected-skips.json`, which requires a matching test name,
configuration pattern, rationale, owner, and expiry. The runner fails on a
new skip, or when an expected skip stops occurring, so neither file is a
permanent baseline.
