# Fresh self-host customer journey

`selfhost_customer_journey.py` is an explicit test target. Ordinary OSS smoke
selection does not collect it. It uses the public gateway and Keycloak PKCE
login, creates a synthetic compliance profile, revocation profile, credential
template and presentation policy in the migration-seeded organization, issues
to an in-memory headless wallet through OID4VCI, and requires an `allow`
decision after OID4VP presentation. It never selects a KMS key directly: the
public issuer DID resolves through the installed issuer profile. No external
CSCA or DSC is required for this SD-JWT journey.

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

```bash
python -m pytest -q tests/oss_stack/selfhost_customer_journey.py
```

Missing fixture inputs fail the selected test. The test is a business-journey
component, not an installation qualifier by itself. Release evidence must also
bind the test revision and result to the exact ZIP, image lock, source SHA,
installed service graph, migration ledger, clean state, and owned teardown.
Currently no published self-host bundle provides that evidence.
