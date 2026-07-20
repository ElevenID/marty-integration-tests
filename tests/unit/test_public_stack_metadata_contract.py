from __future__ import annotations

from collections.abc import Mapping

import pytest

from tests.oss_stack import test_public_stack as public_stack

ISSUER_METADATA = {
    "credential_issuer": "https://issuer.example.test",
    "credential_endpoint": "https://issuer.example.test/v1/issuance/credential",
    "credential_configurations_supported": {"ExampleCredential": {"format": "dc+sd-jwt"}},
}
AUTHORIZATION_METADATA = {
    "issuer": "https://issuer.example.test",
    "token_endpoint": "https://issuer.example.test/v1/issuance/token",
}


def responses(authorization_metadata: Mapping[str, object]) -> dict[str, Mapping[str, object]]:
    return {
        "/.well-known/openid-credential-issuer": ISSUER_METADATA,
        "/.well-known/oauth-authorization-server": authorization_metadata,
    }


def test_public_stack_uses_oid4vci_final_split_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    metadata = responses(AUTHORIZATION_METADATA)
    monkeypatch.setattr(public_stack, "get_json", lambda path: metadata[path])

    public_stack.test_oid4vci_metadata_is_available()


def test_public_stack_rejects_unbound_authorization_server_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    metadata = responses({**AUTHORIZATION_METADATA, "issuer": "https://attacker.example"})
    monkeypatch.setattr(public_stack, "get_json", lambda path: metadata[path])

    with pytest.raises(AssertionError):
        public_stack.test_oid4vci_metadata_is_available()
