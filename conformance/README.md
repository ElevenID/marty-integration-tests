# Official OID4VC conformance

This directory runs the OpenID Foundation Conformance Suite against a real
Marty deployment. It is deliberately separate from the mirrored pytest tests:
the official runner is the source of truth, while the local tests provide fast
feedback between official-suite releases.

## Safety and target boundary

The target must be a disposable deployment created from an attested
`marty.stack/v1` manifest. Start it with `make start`; configure the suite with
the gateway-facing issuer or verifier URL. Do not point the suite at an
individual backend container, production customer data, a private service, or
commerce functionality. Test organizations, keys, credential templates, and
wallets are created for each run and discarded afterwards.

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

It must start a normal, authenticated `POST /v1/flows/verify` gateway flow
using the disposable organization and policy, then write JSON containing its
ordinary `authorization_request` (`openid4vp://...?request_uri=...`) or the
HTTPS `request_uri`. The adapter fetches Marty's signed request object and
delivers it to the official mock wallet. The suite then posts its generated
presentation to Marty's actual public callback and determines the result.

```bash
cp conformance/marty-verifier.example.json /secure/work/marty-verifier.json
export CONFORMANCE_SERVER=https://oidf.test.example
# This checked-in deployment adapter starts a normal authenticated gateway flow.
export OIDF_VERIFIER_COMMAND="$PWD/scripts/oidf_marty_start_verification.py"
export OIDF_MARTY_GATEWAY_URL=https://stack.test.example
export OIDF_MARTY_SESSION_ID="$(read_secret oidf-disposable-session-id)"
export OIDF_MARTY_PRESENTATION_POLICY_ID="$(read_secret oidf-disposable-policy-id)"
export OIDF_VERIFIER_REQUEST_METHOD=url_query
# The OID4VP Final baseline uses the standard redirect_uri client-ID prefix.
export OID4VP_CLIENT_ID_PREFIX=redirect_uri
python scripts/oidf_conformance.py run \
  --runner /opt/openid-conformance-suite \
  --profile oid4vp-verifier \
  --config /secure/work/marty-verifier.json \
  --output-dir reports/oidf/verifier \
  --interaction-script scripts/oidf_marty_verifier.py
```

The HAIP profile uses the same command contract but is enabled only after
Marty produces signed `request_uri` requests with `x509_hash`, a fresh
per-request encryption key, and encrypted `direct_post.jwt` handling. Its
configuration additionally supplies the official runner's request-object trust
anchor. No HAIP profile may be marked active merely because a local test
adapter can execute it.

The deployment adapter deliberately requires a real gateway session and active
disposable presentation policy. It rejects HTTP URLs and creates neither an
authentication bypass nor a synthetic verifier flow. For HAIP, set
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

## Certification later

When certification funding is available, enable the protected certification
environment and run the same command against the registered test deployment.
Attach the pinned runner revision, stack manifest, image digests, sanitized
configuration, exported result JSON, logs, and the commit under test. There is
no second certification-only implementation to drift from daily testing.

## Updating the runner

`python scripts/oidf_conformance.py check-update` compares the pinned release
with the latest official GitLab release. The monthly workflow makes an update
visible; it never silently switches versions. Review an update by changing both
the release and full commit in `oidf-runner.json`, then run the active profile
against the production-path stack before merging. Expected failures are allowed
only in `expected-failures.json`, with an OIDF test id, issue URL, owner, and
expiry date. Optional OIDF modules that Marty does not claim to support use
the separate `expected-skips.json`, which requires a matching test name,
configuration pattern, rationale, owner, and expiry. The runner fails on a
new skip, or when an expected skip stops occurring, so neither file is a
permanent baseline.
