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

`run` calls the official `scripts/run-test-plan.py` with the official
`oid4vci-1_0-issuer-test-plan`; it does not simulate protocol calls or swallow
test failures. The official suite URL can be supplied with
`CONFORMANCE_SERVER` when it is not using its normal local default.

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
expiry date; the file is intentionally empty today.
