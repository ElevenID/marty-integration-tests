# External connector test boundary

Provider protocols, callbacks, credentials, administration and synchronization
belong to independently owned connectors, including
[canvas-integration](https://github.com/ElevenID/canvas-integration).
The public Common Gateway is their sole platform integration point. Platform
integration tests retain generic authentication, tenant/ownership, application,
evidence, credential issuance and signing contracts. They do not host provider
simulators or require provider administration routes in Marty.

The disposable stack provisions only the five current platform signing-grant
origins. Provider tool signing is connector-owned; existing KMS credential signing
remains platform-owned. External observations confer neither VERIFIED status nor
application approval or signing authority. Connectors receive no platform database,
private service endpoint, internal queue, issuer key or signing grant access.

TODO (connector and platform integration owners): qualify a separately isolated
connector journey through published generic Gateway contracts, using organization
API keys, explicit permissions, canonical ownership and audit/replay checks. Keep
unsupported operations disabled until their public contract exists. Do not revive
provider routes or use direct database writes to fill missing capabilities.
Production adapters, cloud qualification and cutover are separate work. Removing
obsolete tests does not establish deployed interoperability or production readiness.

Historical removed tests remain in Git history. Existing running stacks, tokens,
keys, databases and release evidence are not migrated or removed by this source
change. Adopt the coordinated platform source before running a fresh disposable
stack; older published images may still require their source-bound fixtures.
