# Fresh self-host customer journey

`selfhost_customer_journey.py` is an explicit test target. Ordinary OSS smoke
selection does not collect it. It uses the public gateway and Keycloak PKCE
login, creates a synthetic compliance profile, revocation profile, credential
template and presentation policy in the migration-seeded organization, issues
to an in-memory headless wallet through OID4VCI, and requires an `allow`
decision after OID4VP presentation. It revokes that credential and requires a
`deny` decision in a fresh presentation. It confirms both DIDs occur in the
public active profile inventory. It never selects a KMS key directly: public
DIDs resolve through installed profiles. A separate signed installation result
must prove the profiles use non-exportable managed KMS custody; the public DID
inventory deliberately omits custody coordinates. No external CSCA or DSC is
required for this SD-JWT journey.

Run only against a freshly extracted, digest-pinned self-host bundle with
disposable PostgreSQL, Redis, external OpenBao, and scoped secrets. The caller
must first install and start the stack, run its migrations, and provision one
real operator user in the installed Keycloak realm. The operator must be a
member of the seeded organization with public API rights to create profiles,
templates, policies, issue, and verify. This test never creates an internal
plan, injects a session, or uses a demo credential fallback.

Required explicit inputs:

| Variable | Value |
| --- | --- |
| `SELFHOST_GATEWAY_URL` | Host-accessible local edge, for example `http://127.0.0.1:19080` |
| `SELFHOST_KEYCLOAK_URL` | Host-accessible local Keycloak, for example `http://127.0.0.1:18180` |
| `SELFHOST_PUBLIC_DOMAIN` | Domain configured in the extracted bundle's OIDC redirects |
| `SELFHOST_TEST_USERNAME`, `SELFHOST_TEST_PASSWORD` | Disposable operator credentials; supply from files or a secret runner, not a committed env file |
| `SELFHOST_ORG_ID` | Exact migration-seeded organization UUID |
| `SELFHOST_ISSUER_DID` | Public DID of a KMS-backed issuer profile for that organization |
| `SELFHOST_VERIFIER_DID` | Public DID selected by the installed verifier signing profile |

```bash
python -m pytest -q tests/oss_stack/selfhost_customer_journey.py
```

Missing fixture inputs fail the selected test. The test is a business-journey
component, not an installation qualifier by itself. Release evidence must also
bind the test revision and result to the exact ZIP, image lock, source SHA,
installed service graph, migration ledger, KMS custody evidence, clean state,
and owned teardown.
Currently no published self-host bundle provides that evidence.

## Machine API-key component

`selfhost_machine_customer_journey.py` is a separate explicit target. The
existing PKCE test and its assertions remain in place. Both modes share the
same issuance, wallet presentation, verification, credential revocation,
status and revoked-presentation checks.

The machine component requires only these explicit inputs:

| Variable | Value |
| --- | --- |
| `SELFHOST_GATEWAY_URL` | The owned disposable public gateway |
| `SELFHOST_ORG_ID` | Exact provisioned organization UUID |
| `SELFHOST_ISSUER_DID`, `SELFHOST_VERIFIER_DID` | Installed managed public identities |
| `SELFHOST_OPERATOR_API_KEY_FILE` | Absolute private regular file containing an already provisioned organization operator key with `admin:full` |

The operator key configures profiles, policy and template through public APIs and
creates a one-hour test key with explicit `credentials:issue`, `credentials:read`,
`credentials:revoke` and `flows:execute` scopes. The narrower key performs the
credential lifecycle. It must be denied API-key inventory access and access to
another organization on a route it can read in its own organization. The operator
retires the generated key in a `finally` path; a fresh request with that retired
key must return 401. The supplied operator key is not retired by this component.

Gateway requests carry `X-API-Key`; browser cookies and Authorization fallback
are rejected before a request is sent. Redirect following and ambient proxy
configuration are disabled for those requests. Holder protocol authentication
continues to use the existing wallet client and its normal consent/protocol rules.

```bash
python -m pytest -q tests/oss_stack/selfhost_machine_customer_journey.py
```

Missing inputs fail the selected component. This does not provision the initial
tenant or operator key, detect a running console, qualify a published CLI/SDK,
or establish installation support. The release harness must prove approved
bootstrap and console absence, bind the exact runtime/test/client artifacts,
verify real KMS custody and clean start, and complete owned project teardown.
Persisted profiles and credential history follow that disposable project
lifecycle; public retirement of every created configuration remains a separate
acceptance requirement. Hermetic tests of inputs, credential switching and
failure cleanup are not evidence that the live journey passed.

Test migration record: the original 25 assertion obligations are retained in
`exercise_customer_journey` and the original PKCE wrapper, with only the selected
runtime client parameterized. The new component adds key/tenant/scope controls;
no original test, protocol assertion or release qualification is retired.
