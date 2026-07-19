"""Tests for the pinned official OIDF conformance boundary."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("oidf_conformance", ROOT / "scripts" / "oidf_conformance.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load OIDF conformance helper")
oidf = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(oidf)


def test_pinned_official_runner_manifest_is_valid() -> None:
    manifest = oidf.load_manifest()
    assert manifest["official_runner"]["repository"].startswith("https://gitlab.com/openid/")
    assert manifest["profiles"]["oid4vci-issuer"]["status"] == "active"
    assert "[credential_format=sd_jwt_vc]" in manifest["profiles"]["oid4vci-issuer"]["test_plan"]
    verifier = manifest["profiles"]["oid4vp-verifier"]
    assert verifier["configuration_example"] == "conformance/marty-verifier.example.json"
    assert "oid4vp-1final-verifier-test-plan" in verifier["test_plan"]
    assert "[request_method=url_query]" in verifier["test_plan"]
    haip = manifest["profiles"]["oid4vp-haip-verifier"]
    assert "oid4vp-1final-verifier-haip-test-plan" in haip["test_plan"]
    assert "[response_mode=direct_post.jwt]" in haip["test_plan"]


def test_documented_optional_signed_metadata_skip_is_valid() -> None:
    oidf.validate_expected_failures()


def test_optional_encryption_skip_is_documented_narrowly() -> None:
    skips = json.loads((ROOT / "conformance" / "expected-skips.json").read_text(encoding="utf-8"))
    encryption = next(
        item
        for item in skips
        if item["test-name"] == "oid4vci-1_0-issuer-fail-unsupported-encryption-algorithm"
    )
    assert encryption["variant"] == {"vci_credential_encryption": "plain"}
    assert encryption["expires"] == "2027-01-01"


def test_haip_post_retrieval_module_is_scoped_to_the_required_signed_transport() -> None:
    skips = json.loads((ROOT / "conformance" / "expected-skips.json").read_text(encoding="utf-8"))
    request_uri_post = next(
        item
        for item in skips
        if item["test-name"] == "oid4vp-1final-verifier-request-uri-method-post"
    )
    assert request_uri_post["configuration-filename"] == "*marty-verifier-haip*.json"
    assert request_uri_post["variant"] == {
        "client_id_prefix": "x509_hash",
        "request_method": "request_uri_signed",
        "vp_profile": "haip",
    }


def test_issuer_offer_fixture_has_no_credential_or_secret() -> None:
    payload = json.loads((ROOT / "conformance" / "marty-issuer.offer-request.example.json").read_text(encoding="utf-8"))
    assert payload["claims"]["email"].endswith("@example.test")
    assert "credential_offer" not in payload


def test_runner_relative_path_avoids_windows_drive_letter_grammar(tmp_path: Path) -> None:
    runner = tmp_path / "runner"
    runner.mkdir()
    config = tmp_path / "configuration" / "issuer.json"
    config.parent.mkdir()
    config.write_text("{}", encoding="utf-8")

    result = oidf.runner_relative_path(config, runner)

    assert Path(result).is_absolute() is False
    assert ":" not in result
    assert "\\" not in result


def test_example_configuration_is_rejected(tmp_path: Path) -> None:
    config = tmp_path / "issuer.json"
    example = ROOT / "conformance" / "marty-issuer.example.json"
    config.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.raises(ValueError, match="example values"):
        oidf.validate_config(config)


def test_real_gateway_configuration_is_accepted(tmp_path: Path) -> None:
    config = tmp_path / "issuer.json"
    config.write_text(
        json.dumps(
            {
                "vci": {
                    "credential_issuer_url": "https://conformance.example.test/org/test",
                    "authorization_server": "https://conformance.example.test",
                    "credential_configuration_id": "UniversityDegree_JWT",
                }
            }
        ),
        encoding="utf-8",
    )
    oidf.validate_config(config)


def test_real_verifier_configuration_is_accepted(tmp_path: Path) -> None:
    config = tmp_path / "verifier.json"
    config.write_text(
        json.dumps(
            {
                "credential": {"signing_jwk": {"kty": "EC", "crv": "P-256"}},
                "verifier": {
                    "gateway_url": "https://conformance.example.test",
                    "profile": "oid4vp-1.0-final",
                },
            }
        ),
        encoding="utf-8",
    )
    oidf.validate_config(config, "oid4vp-verifier")


def test_evidence_records_non_secret_provenance(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runner = tmp_path / "runner"
    runner.mkdir()
    (runner / ".git").mkdir()
    config = tmp_path / "config.json"
    config.write_text('{"credential":{"signing_jwk":{"d":"private"}}}', encoding="utf-8")
    output = tmp_path / "report"
    output.mkdir()
    (output / "official-result.json").write_text('{"result":"pass"}', encoding="utf-8")
    stack = tmp_path / "stack.json"
    stack.write_text('{"schema":"marty.stack/v1","release":"marty-ui@1.0.0"}', encoding="utf-8")
    monkeypatch.setattr(oidf, "git_revision", lambda _path: "a" * 40)
    oidf.write_evidence(output, oidf.load_manifest(), "oid4vp-verifier", config, runner, 0, stack, "pre-activation")
    evidence = json.loads((output / "evidence.json").read_text(encoding="utf-8"))
    assert evidence["result"] == {"exit_code": 0, "passed": True}
    assert evidence["execution_mode"] == "pre-activation"
    assert evidence["marty"]["stack_manifest"]["release"] == "marty-ui@1.0.0"
    assert evidence["configuration"]["sha256"].startswith("sha256:")
    assert "private" not in (output / "evidence.json").read_text(encoding="utf-8")


def test_haip_requires_a_runner_trust_anchor(tmp_path: Path) -> None:
    config = tmp_path / "verifier.json"
    config.write_text(
        json.dumps(
            {
                "credential": {"signing_jwk": {"kty": "EC"}},
                "verifier": {
                    "gateway_url": "https://conformance.example.test",
                    "profile": "oid4vp-haip-1.0",
                },
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="request_object_trust_anchor_pem"):
        oidf.validate_config(config, "oid4vp-haip-verifier")


def test_planned_verifier_requires_explicit_attested_pre_activation_run(tmp_path: Path) -> None:
    profile = oidf.load_manifest()["profiles"]["oid4vp-verifier"]
    stack = tmp_path / "stack.json"
    stack.write_text('{"schema":"marty.stack/v1"}', encoding="utf-8")

    with pytest.raises(ValueError, match="not active"):
        oidf.execution_mode("oid4vp-verifier", profile, allow_planned=False, stack_manifest=stack)
    with pytest.raises(ValueError, match="stack-manifest"):
        oidf.execution_mode("oid4vp-verifier", profile, allow_planned=True, stack_manifest=None)
    assert oidf.execution_mode("oid4vp-verifier", profile, allow_planned=True, stack_manifest=stack) == "pre-activation"


def test_active_profile_does_not_need_pre_activation_switch() -> None:
    profile = oidf.load_manifest()["profiles"]["oid4vci-issuer"]

    assert oidf.execution_mode("oid4vci-issuer", profile, allow_planned=False, stack_manifest=None) == "active"


def test_tls_proxy_uses_only_oidf_approved_tls12_ciphers() -> None:
    config = (ROOT / "services" / "tls-proxy" / "nginx.conf").read_text(encoding="utf-8")

    assert "ssl_protocols TLSv1.2 TLSv1.3;" in config
    assert "ECDHE-RSA-AES128-GCM-SHA256" in config
    assert "AES_128_CBC" not in config
    assert "ECDHE-RSA-AES128-SHA" not in config
