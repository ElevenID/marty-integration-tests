from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import oidf_marty_offer as offer


def test_command_offer_relaxes_only_conformance_runner_tls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = tmp_path / "request.json"
    request.write_text(json.dumps({"claims": {"given_name": "Test"}}), encoding="utf-8")
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
        lambda _server, _test_id, *, insecure, timeout: observed.update(
            wait_insecure=insecure,
            timeout=timeout,
        )
        or True,
    )
    monkeypatch.setattr(
        offer,
        "command_credential_offer",
        lambda _command, payload: observed.update(payload=payload)
        or "openid-credential-offer://?credential_offer=%7B%7D",
    )
    monkeypatch.setattr(
        offer,
        "deliver_offer",
        lambda _server, _test_id, _uri, _tx_code, *, insecure: observed.update(
            deliver_insecure=insecure
        ),
    )

    assert offer.main() == 0
    assert observed == {
        "wait_insecure": True,
        "timeout": 30,
        "payload": {"claims": {"given_name": "Test"}},
        "deliver_insecure": True,
    }
