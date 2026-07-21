"""Tests for the official-runner to public-Marty interaction bridge."""

from __future__ import annotations

import importlib.util
from collections.abc import Callable
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("oidf_verifier", ROOT / "scripts" / "oidf_marty_verifier.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load OIDF verifier adapter")
oidf_verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(oidf_verifier)


def test_local_resolver_is_limited_to_the_configured_public_marty_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OIDF_MARTY_GATEWAY_URL", "https://marty-oidf.local:28443")
    monkeypatch.setenv("OIDF_MARTY_RESOLVE_IP", "127.0.0.1")

    assert oidf_verifier.local_marty_resolve("https://marty-oidf.local:28443/v1/request") == [
        "--resolve",
        "marty-oidf.local:28443:127.0.0.1",
    ]
    assert oidf_verifier.local_marty_resolve("https://localhost.emobix.co.uk:8443/test") == []
    assert oidf_verifier.local_marty_resolve("http://marty-oidf.local:28443/v1/request") == []


def test_conformance_resolver_is_limited_to_the_published_runner_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONFORMANCE_SERVER", "https://localhost.emobix.co.uk:8443")
    monkeypatch.setenv("OIDF_CONFORMANCE_RESOLVE_IP", "127.0.0.1")

    assert oidf_verifier.local_conformance_resolve("https://localhost.emobix.co.uk:8443/api/runner/test") == [
        "--resolve",
        "localhost.emobix.co.uk:8443:127.0.0.1",
    ]
    assert oidf_verifier.local_conformance_resolve("https://marty-oidf.local:28443/v1/request") == []
    assert oidf_verifier.local_conformance_resolve("http://localhost.emobix.co.uk:8443/api/runner/test") == []


def test_mock_wallet_tls_exception_never_disables_marty_tls(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, bool]] = []

    def request(
        url: str,
        *,
        headers: dict[str, str] | None = None,
        insecure: bool = False,
    ) -> tuple[int, object]:
        _ = headers
        calls.append((url, insecure))
        if "marty.example" in url:
            return 200, "eyJhbGciOiJFUzI1NiJ9.eyJjbGllbnRfaWQiOiJjbGllbnQifQ.signature"
        return 200, {}

    monkeypatch.setattr(oidf_verifier, "request_json", request)
    oidf_verifier.call_mock_wallet(
        "https://localhost.emobix.co.uk:8443/authorize",
        "https://marty.example/request.jwt",
        request_method="request_uri_signed",
        conformance_insecure=True,
    )
    assert calls[0] == ("https://marty.example/request.jwt", False)
    assert calls[1][1] is True


def test_authorization_request_preserves_signed_transport_outer_parameters() -> None:
    request_uri = "https://marty.example/request.jwt"
    authorization_request = "openid4vp://authorize?" + urlencode(
        {
            "client_id": "x509_hash:abc",
            "request_uri": request_uri,
            "request_uri_method": "post",
        }
    )

    assert oidf_verifier.authorization_request_parameters(authorization_request) == (
        request_uri,
        {"client_id": "x509_hash:abc", "request_uri_method": "post"},
    )


def test_authorization_request_rejects_duplicate_security_parameters() -> None:
    value = (
        "openid4vp://authorize?client_id=first&client_id=second&request_uri=https%3A%2F%2Fmarty.example%2Frequest.jwt"
    )
    with pytest.raises(ValueError, match="duplicate client_id"):
        oidf_verifier.authorization_request_parameters(value)


def test_signed_post_forwards_outer_method_and_leaves_wallet_nonce_to_official_wallet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def request(url: str, **_kwargs: object) -> tuple[int, object]:
        calls.append(url)
        return 200, {}

    monkeypatch.setattr(oidf_verifier, "request_json", request)
    monkeypatch.setattr(
        oidf_verifier,
        "decode_request_object",
        lambda *_args, **_kwargs: pytest.fail("POST-only request_uri must not be fetched with GET"),
    )

    oidf_verifier.call_mock_wallet(
        "https://runner.example/authorize",
        "https://marty.example/request.jwt",
        request_method="request_uri_signed",
        conformance_insecure=False,
        outer_parameters={"client_id": "x509_hash:abc", "request_uri_method": "post"},
    )

    query = parse_qs(urlparse(calls[0]).query)
    assert query == {
        "client_id": ["x509_hash:abc"],
        "request_uri": ["https://marty.example/request.jwt"],
        "request_uri_method": ["post"],
    }
    assert "wallet_nonce" not in query


def test_signed_get_rejects_outer_and_signed_client_id_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        oidf_verifier,
        "decode_request_object",
        lambda *_args, **_kwargs: {"client_id": "signed-client"},
    )
    with pytest.raises(RuntimeError, match="does not match"):
        oidf_verifier.call_mock_wallet(
            "https://runner.example/authorize",
            "https://marty.example/request.jwt",
            request_method="request_uri_signed",
            conformance_insecure=False,
            outer_parameters={"client_id": "outer-client"},
        )


def test_standard_url_query_does_not_inherit_signed_transport_parameters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        oidf_verifier,
        "decode_request_object",
        lambda *_args, **_kwargs: {"client_id": "signed-client", "nonce": "nonce-1"},
    )

    def request(url: str, **_kwargs: object) -> tuple[int, object]:
        calls.append(url)
        return 200, {}

    monkeypatch.setattr(oidf_verifier, "request_json", request)
    oidf_verifier.call_mock_wallet(
        "https://runner.example/authorize",
        "https://marty.example/request.jwt",
        request_method="url_query",
        conformance_insecure=False,
        outer_parameters={"client_id": "outer-client", "request_uri_method": "post"},
    )

    query = parse_qs(urlparse(calls[0]).query)
    assert query == {"client_id": ["signed-client"], "nonce": ["nonce-1"]}
    assert "request_uri_method" not in query


def configure_main(
    monkeypatch: pytest.MonkeyPatch,
    authorization_request: str,
) -> None:
    monkeypatch.setattr(
        oidf_verifier,
        "parse_args",
        lambda: oidf_verifier.argparse.Namespace(
            server="https://runner.example/",
            flow_command=Path("flow-command.py"),
            request_method="request_uri_signed",
            timeout=10,
            insecure=False,
            conformance_insecure=False,
            test_id="module-id",
            test_name="oid4vp-1final-verifier-happy-flow",
        ),
    )
    monkeypatch.setattr(
        oidf_verifier,
        "wait_for_exposed_authorization_endpoint",
        lambda *_args, **_kwargs: "https://runner.example/authorize",
    )
    monkeypatch.setattr(
        oidf_verifier,
        "invoke_flow_command",
        lambda *_args, **_kwargs: authorization_request,
    )


def failed_request(message: str) -> Callable[..., tuple[int, object]]:
    def request(*_args: object, **_kwargs: object) -> tuple[int, object]:
        raise RuntimeError(message)

    return request


def test_finished_module_cannot_suppress_client_id_binding_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    configure_main(
        monkeypatch,
        "openid4vp://authorize?client_id=outer-client&request_uri=https%3A%2F%2Fmarty.example%2Frequest.jwt",
    )
    monkeypatch.setattr(
        oidf_verifier,
        "decode_request_object",
        lambda *_args, **_kwargs: {"client_id": "different-signed-client"},
    )
    monkeypatch.setattr(
        oidf_verifier,
        "module_finished",
        lambda *_args, **_kwargs: pytest.fail("validation failures must not consult finished state"),
    )

    with pytest.raises(RuntimeError, match="does not match"):
        oidf_verifier.main()


def test_finished_module_cannot_suppress_missing_post_client_id(monkeypatch: pytest.MonkeyPatch) -> None:
    configure_main(
        monkeypatch,
        "openid4vp://authorize?request_uri=https%3A%2F%2Fmarty.example%2Frequest.jwt&request_uri_method=post",
    )
    monkeypatch.setattr(
        oidf_verifier,
        "module_finished",
        lambda *_args, **_kwargs: pytest.fail("validation failures must not consult finished state"),
    )

    with pytest.raises(RuntimeError, match="no outer client_id"):
        oidf_verifier.main()


def test_finished_before_official_wallet_submission_transport_race_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_main(
        monkeypatch,
        "openid4vp://authorize?client_id=x509_hash%3Aabc&"
        "request_uri=https%3A%2F%2Fmarty.example%2Frequest.jwt&request_uri_method=post",
    )
    monkeypatch.setattr(
        oidf_verifier,
        "request_json",
        failed_request("runner closed its endpoint"),
    )
    monkeypatch.setattr(oidf_verifier, "module_finished", lambda *_args, **_kwargs: True)

    assert oidf_verifier.main() == 0


def test_active_module_official_wallet_submission_failure_remains_fatal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_main(
        monkeypatch,
        "openid4vp://authorize?client_id=x509_hash%3Aabc&"
        "request_uri=https%3A%2F%2Fmarty.example%2Frequest.jwt&request_uri_method=post",
    )
    monkeypatch.setattr(
        oidf_verifier,
        "request_json",
        failed_request("runner unavailable"),
    )
    monkeypatch.setattr(oidf_verifier, "module_finished", lambda *_args, **_kwargs: False)

    with pytest.raises(oidf_verifier.OfficialWalletSubmissionError, match="runner unavailable"):
        oidf_verifier.main()
