# Fixture ownership

The unused `conformance/` corpus and Python generator are retired. Integration's
current tests did not read these files. Its active gateway/issuer interoperability
tests and official-suite runners remain unchanged.

The executable consumers own their hermetic vectors:

- [Core engine tests](https://github.com/ElevenID/marty-core/tree/main/marty-oid4vci/tests/fixtures/conformance)
  retain presentation definition/submission and a verified public VP token;
  dynamic signing cases use the disposable OpenBao Rust helper.
- [Verifier offline adapter tests](https://github.com/ElevenID/marty-verifier/tree/main/src-tauri/tests/fixtures/conformance)
  retain their own three vectors and parsing/result-construction coverage.
- [Authenticator wallet vectors](https://github.com/ElevenID/marty-authenticator/blob/main/test/fixtures/oid4vc_conformance_fixtures.dart)
  retain final/draft issuer metadata, OAuth metadata, inline/reference offers,
  token/nonce and JWT-VC/SD-JWT response cases, an unconsumed mDoc response fixture, Presentation Exchange
  and final DCQL presentation requests, definitions and submissions.

The current parsed presentation definition/submission and trimmed VP token match
Core/Verifier despite formatting differences. Wallet requests now include
DCQL/entity_id and its legacy metadata differs from this historical producer.
Update the owning behavior cases instead of bulk regenerating independent packages.
The mDoc response was a malformed CBOR parser stub and the credential responses
used zero signatures; their exact bytes were not valid-credential requirements.
The removed holder JWK exposed a deterministic synthetic private seed; current
verification vectors retain the public key without needing that seed. No
consumer vectors, parser cases, signing flow or incomplete feature is removed.

Future vector updates belong with the owning behavior tests. Use the maintained
Rust managed-signing facilities when signatures are needed, keep public vectors
only, and run the consumer suite. Local vectors do not establish official OIDF
conformance or cross-language equivalence.
