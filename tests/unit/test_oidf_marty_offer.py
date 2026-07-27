from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import oidf_marty_offer as offer


def _authorized_client(name: str) -> dict[str, object]:
    return {
        "client_id": name,
        "jwks": {"keys": [{"kid": f"{name}-key", "kty": "EC"}]},
    }


def test_interrupted_failure_category_emits_only_safe_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        offer,
        "request_json",
        lambda *_args, **_kwargs: (
            200,
            [
                {"result": "SUCCESS", "src": "EarlierCondition"},
                {
                    "result": "FAILURE",
                    "src": "net.openid.conformance.condition.client.GetStaticClientConfiguration",
                    "msg": "contains a disposable secret that must not be emitted",
                },
            ],
        ),
    )

    assert (
        offer.interrupted_failure_category(
            "https://oidf.example",
            "module-1",
            insecure=True,
        )
        == "oidf-invariant-interrupted-getstaticclientconfiguration"
    )


def test_interrupted_failure_category_rejects_unsafe_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        offer,
        "request_json",
        lambda *_args, **_kwargs: (
            200,
            [{"result": "FAILURE", "src": "unsafe source: secret"}],
        ),
    )

    assert (
        offer.interrupted_failure_category(
            "https://oidf.example",
            "module-1",
            insecure=True,
        )
        == "oidf-invariant-interrupted-unknown-source"
    )


def test_command_offer_relaxes_only_conformance_runner_tls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = tmp_path / "request.json"
    request.write_text(
        json.dumps(
            {
                "claims": {"given_name": "Test"},
                "authorized_clients": [_authorized_client("client-1")],
            }
        ),
        encoding="utf-8",
    )
    observed: dict[str, object] = {}
    monkeypatch.setattr(
        offer,
        "parse_args",
        lambda: SimpleNamespace(
            test_id="module-1",
            test_name="issuer-happy-path",
            server="https://oidf.example",
            issuance_url=None,
            api_key=None,
            issuance_command=tmp_path / "public-issuance.py",
            request=request,
            tx_code="000000",
            timeout=30,
            insecure=False,
            conformance_insecure=True,
            issuance_insecure=False,
        ),
    )
    monkeypatch.setattr(
        offer,
        "wait_for_interaction",
        lambda _server, _test_id, *, insecure, timeout: (
            observed.update(
                wait_insecure=insecure,
                timeout=timeout,
            )
            or True
        ),
    )
    monkeypatch.setattr(
        offer,
        "command_credential_offer",
        lambda _command, payload: (
            observed.update(payload=payload) or "openid-credential-offer://?credential_offer=%7B%7D"
        ),
    )
    monkeypatch.setattr(
        offer,
        "deliver_offer",
        lambda _server, _test_id, _uri, _tx_code, *, insecure: observed.update(deliver_insecure=insecure),
    )

    assert offer.main() == 0
    assert observed == {
        "wait_insecure": True,
        "timeout": 30,
        "payload": {
            "claims": {"given_name": "Test"},
            "authorized_client": _authorized_client("client-1"),
        },
        "deliver_insecure": True,
    }


def test_official_multiple_client_module_receives_two_fresh_offers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = tmp_path / "request.json"
    request.write_text(
        json.dumps(
            {
                "claims": {"given_name": "Test"},
                "authorized_clients": [
                    _authorized_client("client-1"),
                    _authorized_client("client-2"),
                ],
            }
        ),
        encoding="utf-8",
    )
    observed: list[str] = []
    payloads: list[dict[str, object]] = []
    monkeypatch.setattr(
        offer,
        "parse_args",
        lambda: SimpleNamespace(
            test_id="module-2",
            test_name="oid4vci-1_0-issuer-happy-flow-multiple-clients",
            server="https://oidf.example",
            issuance_url=None,
            api_key=None,
            issuance_command=tmp_path / "public-issuance.py",
            request=request,
            tx_code="000000",
            timeout=30,
            insecure=False,
            conformance_insecure=True,
            issuance_insecure=False,
        ),
    )
    monkeypatch.setattr(
        offer,
        "wait_for_interaction",
        lambda *_args, **_kwargs: observed.append("wait") or True,
    )
    monkeypatch.setattr(
        offer,
        "command_credential_offer",
        lambda _command, payload: (
            payloads.append(payload)
            or observed.append("create")
            or "openid-credential-offer://?credential_offer=%7B%7D"
        ),
    )
    monkeypatch.setattr(
        offer,
        "deliver_offer",
        lambda *_args, **_kwargs: observed.append("deliver"),
    )

    assert offer.main() == 0
    assert observed == [
        "wait",
        "create",
        "deliver",
        "wait",
        "create",
        "deliver",
    ]
    assert [payload["authorized_client"] for payload in payloads] == [
        _authorized_client("client-1"),
        _authorized_client("client-2"),
    ]


@pytest.mark.parametrize(
    "test_name",
    [
        "oid4vci-1_0-issuer-metadata-test",
        "oid4vci-1_0-issuer-metadata-test-signed",
    ],
)
def test_metadata_modules_do_not_receive_credential_offers(test_name: str) -> None:
    assert offer.required_offer_interactions(test_name) == 0
