"""Tests for the pinned official OIDF conformance boundary."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import zipfile
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
    assert manifest["official_runner"]["source_policy"] == "unmodified"
    issuer = manifest["profiles"]["oid4vci-issuer"]
    assert issuer["status"] == "active"
    assert "[credential_format=sd_jwt_vc]" in issuer["test_plan"]
    assert "[client_auth_type=private_key_jwt]" in issuer["test_plan"]
    assert "not an OIDF certification claim" in issuer["qualification"]
    assert "private_key_jwt clients end to end" in issuer["qualification"]
    verifier = manifest["profiles"]["oid4vp-verifier"]
    assert verifier["status"] == "active"
    assert "not currently a certifiable" in verifier["qualification"]
    assert verifier["configuration_example"] == "conformance/marty-verifier.example.json"
    assert "oid4vp-1final-verifier-test-plan" in verifier["test_plan"]
    assert "[request_method=request_uri_signed]" in verifier["test_plan"]
    assert "[client_id_prefix=x509_hash]" in verifier["test_plan"]
    url_query = manifest["profiles"]["oid4vp-url-query-verifier"]
    assert url_query["status"] == "active"
    assert "[request_method=url_query]" in url_query["test_plan"]
    assert "[client_id_prefix=redirect_uri]" in url_query["test_plan"]
    assert "Exact unmodified OIDF release-v5.2.2 evidence" in url_query["qualification"]
    assert "distinct from Marty's signed by-value Request Object" in url_query["qualification"]
    mdoc = manifest["profiles"]["oid4vp-mdoc-verifier"]
    assert mdoc["status"] == "active"
    assert "[credential_format=iso_mdl]" in mdoc["test_plan"]
    assert "[response_mode=direct_post]" in mdoc["test_plan"]
    assert "not certification" in mdoc["qualification"]
    assert "strict Marty releases correctly reject" in mdoc["qualification"]
    fixture = mdoc["upstream_fixture_review"]
    assert fixture["tracking_issue"].endswith("/issues/243")
    assert fixture["upstream_profile_issue"].endswith("/work_items/1891")
    assert fixture["runner_release"] == manifest["official_runner"]["release"]
    assert fixture["certificate_not_before"] == "2026-08-03T16:12:01+00:00"
    assert fixture["certificate_not_after"] == "2027-08-03T16:12:01+00:00"
    assert fixture["certificate_sha256"] == "6cb412be8d1e78f77b1bce09592b0c88f690034855753b1954d6bcadf3b92b53"
    assert fixture["iso_18013_5_document_signer_profile"] == "nonconformant"
    assert fixture["observed_basic_constraints_ca"] is True
    assert fixture["observed_key_usage"] == ["keyCertSign", "cRLSign"]
    assert fixture["required_key_usage"] == ["digitalSignature"]
    assert fixture["expected_marty_behavior"] == "reject"
    assert fixture["latest_execution"].endswith("/31193237615")
    assert "exact unmodified runner" in fixture["policy"]
    assert "Never replace" in fixture["policy"]
    haip = manifest["profiles"]["oid4vp-haip-verifier"]
    assert haip["status"] == "active"
    assert "oid4vp-1final-verifier-haip-test-plan" in haip["test_plan"]
    assert "[response_mode=direct_post.jwt]" in haip["test_plan"]


def test_official_oidf_evidence_has_no_expected_failures() -> None:
    oidf.validate_expected_failures()
    expected_failures = json.loads((ROOT / "conformance" / "expected-failures.json").read_text(encoding="utf-8"))
    assert expected_failures == []


def test_official_oidf_evidence_rejects_expected_failure_masking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conformance = tmp_path / "conformance"
    conformance.mkdir()
    (conformance / "expected-failures.json").write_text(
        '[{"test-id":"would-hide-a-failure"}]\n',
        encoding="utf-8",
    )
    (conformance / "expected-skips.json").write_text("[]\n", encoding="utf-8")
    monkeypatch.setattr(oidf, "ROOT", tmp_path)

    with pytest.raises(ValueError, match="must not accept expected failures"):
        oidf.validate_expected_failures()


def test_official_runner_rejects_untracked_local_test_shims(tmp_path: Path) -> None:
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.name", "Compliance Test"],
        cwd=tmp_path,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "compliance@example.test"],
        cwd=tmp_path,
        check=True,
    )
    runner_script = tmp_path / "scripts" / "run-test-plan.py"
    runner_script.parent.mkdir()
    runner_script.write_text("raise SystemExit(0)\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "commit", "-m", "official fixture"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    commit = oidf.git_revision(tmp_path)
    manifest = {"official_runner": {"commit": commit}}

    oidf.validate_runner(tmp_path, manifest)
    (tmp_path / "local-pass-shim.py").write_text(
        "assert True\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="byte-for-byte clean"):
        oidf.validate_runner(tmp_path, manifest)


def test_optional_encryption_skip_is_documented_narrowly() -> None:
    skips = json.loads((ROOT / "conformance" / "expected-skips.json").read_text(encoding="utf-8"))
    encryption = next(
        item for item in skips if item["test-name"] == "oid4vci-1_0-issuer-fail-unsupported-encryption-algorithm"
    )
    assert encryption["variant"] == {"vci_credential_encryption": "plain"}
    assert encryption["expires"] == "2027-01-01"


def test_invalid_key_attestation_signature_is_not_expected_to_skip() -> None:
    skips = json.loads((ROOT / "conformance" / "expected-skips.json").read_text(encoding="utf-8"))
    key_attestation = [
        item for item in skips if item["test-name"] == "oid4vci-1_0-issuer-fail-invalid-key-attestation-signature"
    ]
    assert key_attestation == []


def test_haip_post_retrieval_module_is_not_expected_to_skip() -> None:
    skips = json.loads((ROOT / "conformance" / "expected-skips.json").read_text(encoding="utf-8"))
    request_uri_post = [
        item
        for item in skips
        if item["test-name"] == "oid4vp-1final-verifier-request-uri-method-post"
        and item["configuration-filename"] == "*marty-verifier-haip*.json"
    ]
    assert request_uri_post == []


def test_request_uri_post_retrieval_is_not_expected_to_skip() -> None:
    skips = json.loads((ROOT / "conformance" / "expected-skips.json").read_text(encoding="utf-8"))
    request_uri_post = [item for item in skips if item["test-name"] == "oid4vp-1final-verifier-request-uri-method-post"]
    assert request_uri_post == []


def test_expected_skips_do_not_start_racy_product_interactions() -> None:
    expected_skips = [
        {
            "test-name": "optional-module",
            "configuration-filename": "*marty-issuer*.json",
        }
    ]

    assert oidf.requires_interaction_hook("active-module", expected_skips) is True
    assert oidf.requires_interaction_hook("optional-module", expected_skips) is False
    assert oidf.requires_interaction_hook("unexpected-skipped-module", expected_skips) is True


def test_official_runner_always_emits_actionable_failure_detail() -> None:
    source = (ROOT / "scripts" / "oidf_conformance.py").read_text(encoding="utf-8")
    assert '"--no-parallel",\n        "--verbose",' in source


def test_failure_diagnostics_extract_only_allowlisted_public_facts(tmp_path: Path) -> None:
    output = tmp_path / "results"
    output.mkdir()
    exported = {
        "testInfo": {"testName": "oid4vci-1_0-issuer-happy-flow", "testId": "secret-id"},
        "results": [
            {
                "src": "-START-BLOCK-",
                "startBlock": True,
                "blockId": "block-1",
                "msg": "Verify Credential Endpoint Response",
            },
            {
                "src": "EnsureHttpStatusCodeIsAnyOf",
                "result": "FAILURE",
                "blockId": "block-1",
                "msg": "must not be copied",
                "args": {
                    "http_status": 400,
                    "expected_status_codes": [200, 202],
                    "body": {"access_token": "must-not-leak"},
                    "error_description": "Key attestation nonce does not match issuance nonce: must-not-leak",
                },
            },
            {
                "src": "VCIValidateCredentialErrorResponse",
                "result": "FAILURE",
                "blockId": "block-1",
                "args": {
                    "error": "invalid_proof",
                    "expected_error": "invalid_nonce",
                    "credential": "must-not-leak",
                },
            },
        ],
    }
    with zipfile.ZipFile(output / "official.zip", "w") as archive:
        archive.writestr("module.json", json.dumps(exported))

    diagnostics = oidf.write_failure_diagnostics(output)

    assert diagnostics == [
        {
            "module": "oid4vci-1_0-issuer-happy-flow",
            "condition": "EnsureHttpStatusCodeIsAnyOf",
            "block": "Verify Credential Endpoint Response",
            "http_status": 400,
            "expected_status_codes": [200, 202],
            "error_category": "key-attestation-nonce",
        },
        {
            "module": "oid4vci-1_0-issuer-happy-flow",
            "condition": "VCIValidateCredentialErrorResponse",
            "block": "Verify Credential Endpoint Response",
            "error": "invalid_proof",
            "expected_error": "invalid_nonce",
            "error_category": "key-attestation-nonce",
        },
    ]
    serialized = (output / "failure-diagnostics.json").read_text(encoding="utf-8")
    assert "must-not-leak" not in serialized
    assert "secret-id" not in serialized


def test_failure_diagnostics_classify_module_response_without_copying_description(tmp_path: Path) -> None:
    output = tmp_path / "results"
    output.mkdir()
    exported = {
        "testInfo": {"testName": "oid4vci-1_0-issuer-happy-flow"},
        "results": [
            {
                "src": "CallProtectedResource",
                "result": "INFO",
                "args": {
                    "response": {
                        "error_description": (
                            "Key-attestation-bound proof has no resolved tenant issuer policy: must-not-leak"
                        )
                    }
                },
            },
            {
                "src": "EnsureHttpStatusCodeIsAnyOf",
                "result": "FAILURE",
                "args": {"http_status": 400, "expected_status_codes": [200, 202]},
            },
        ],
    }
    with zipfile.ZipFile(output / "official.zip", "w") as archive:
        archive.writestr("module.json", json.dumps(exported))

    diagnostics = oidf.write_failure_diagnostics(output)

    assert diagnostics[0]["error_category"] == "key-attestation-policy-unresolved"
    assert "must-not-leak" not in (output / "failure-diagnostics.json").read_text(encoding="utf-8")


def test_browser_diagnostics_report_only_allowlisted_lifecycle_facts(tmp_path: Path) -> None:
    output = tmp_path / "results"
    output.mkdir()
    exported = {
        "testInfo": {
            "testName": "oid4vp-1final-verifier-happy-flow",
            "testId": "must-not-leak-id",
            "status": "WAITING",
            "result": "UNKNOWN",
        },
        "results": [
            {
                "src": "WebRunner",
                "msg": "Scripted browser HTTP request",
                "args": {"request_uri": "https://must-not-leak.example/secret"},
            },
            {
                "src": "WebRunner",
                "msg": "Scripted browser HTTP response",
                "args": {"response_content": "must-not-leak-credential"},
            },
            {"src": "WebRunner", "msg": "Waiting"},
            {
                "src": "WebRunner",
                "msg": "TLS failure at https://must-not-leak.example",
                "result": "FAILURE",
                "current_dom": "must-not-leak-dom",
            },
        ],
    }
    with zipfile.ZipFile(output / "official.zip", "w") as archive:
        archive.writestr("module.json", json.dumps(exported))

    diagnostics = oidf.write_browser_automation_diagnostics(output)

    assert diagnostics == [
        {
            "module": "oid4vp-1final-verifier-happy-flow",
            "events": [
                "browser-runner-failure",
                "request-started",
                "response-received",
                "wait-started",
            ],
            "status": "WAITING",
            "result": "UNKNOWN",
        }
    ]
    serialized = (output / "browser-automation-diagnostics.json").read_text(encoding="utf-8")
    assert "must-not-leak" not in serialized


def test_browser_diagnostics_distinguish_missing_automation_from_unrelated_modules(tmp_path: Path) -> None:
    output = tmp_path / "results"
    output.mkdir()
    waiting = {
        "testInfo": {
            "testName": "oid4vp-1final-verifier-minimal-cnf-jwk",
            "status": "WAITING",
            "result": "UNKNOWN",
        },
        "results": [],
    }
    finished = {
        "testInfo": {
            "testName": "oid4vp-1final-verifier-invalid-signature",
            "status": "FINISHED",
            "result": "PASSED",
        },
        "results": [],
    }
    with zipfile.ZipFile(output / "official.zip", "w") as archive:
        archive.writestr("waiting.json", json.dumps(waiting))
        archive.writestr("finished.json", json.dumps(finished))

    diagnostics = oidf.write_browser_automation_diagnostics(output)

    assert diagnostics == [
        {
            "module": "oid4vp-1final-verifier-minimal-cnf-jwk",
            "events": ["automation-not-observed"],
            "status": "WAITING",
            "result": "UNKNOWN",
        }
    ]


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
                "alias": oidf.OIDF_VERIFIER_ALIAS,
                "credential": {"signing_jwk": {"kty": "EC", "crv": "P-256"}},
                "verifier": {
                    "gateway_url": "https://conformance.example.test",
                    "profile": "oid4vp-1.0-final",
                },
                "browser": oidf.VERIFICATION_EVIDENCE_BROWSER_AUTOMATION,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="complete private EC JWK"):
        oidf.validate_config(config, "oid4vp-verifier")

    config.write_text(
        json.dumps(
            {
                "alias": oidf.OIDF_VERIFIER_ALIAS,
                "credential": {"signing_jwk": {"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "d": "d"}},
                "client": {"request_object_trust_anchor_pem": "test-root"},
                "verifier": {
                    "gateway_url": "https://conformance.example.test",
                    "profile": "oid4vp-1.0-final",
                },
                "browser": oidf.VERIFICATION_EVIDENCE_BROWSER_AUTOMATION,
            }
        ),
        encoding="utf-8",
    )
    oidf.validate_config(config, "oid4vp-verifier")


def test_verifier_configuration_profile_must_match_the_official_plan(tmp_path: Path) -> None:
    config = tmp_path / "verifier.json"
    config.write_text(
        json.dumps(
            {
                "alias": oidf.OIDF_VERIFIER_ALIAS,
                "credential": {"signing_jwk": {"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "d": "d"}},
                "verifier": {
                    "gateway_url": "https://conformance.example.test",
                    "profile": "oid4vp-haip-1.0",
                },
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="mismatched profile"):
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


def test_signed_request_uri_requires_a_runner_trust_anchor(tmp_path: Path) -> None:
    config = tmp_path / "verifier.json"
    config.write_text(
        json.dumps(
            {
                "alias": oidf.OIDF_VERIFIER_ALIAS,
                "credential": {"signing_jwk": {"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "d": "d"}},
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


def test_direct_url_query_does_not_require_a_request_object_trust_anchor(
    tmp_path: Path,
) -> None:
    config = tmp_path / "verifier.json"
    config.write_text(
        json.dumps(
            {
                "alias": oidf.OIDF_VERIFIER_ALIAS,
                "credential": {
                    "signing_jwk": {
                        "kty": "EC",
                        "crv": "P-256",
                        "x": "x",
                        "y": "y",
                        "d": "d",
                    }
                },
                "verifier": {
                    "gateway_url": "https://conformance.example.test",
                    "profile": "oid4vp-1.0-final",
                },
                "browser": oidf.VERIFICATION_EVIDENCE_BROWSER_AUTOMATION,
            }
        ),
        encoding="utf-8",
    )

    oidf.validate_config(config, "oid4vp-url-query-verifier")


def test_verifier_configuration_requires_reviewed_screenshot_automation(
    tmp_path: Path,
) -> None:
    config = tmp_path / "verifier.json"
    config.write_text(
        json.dumps(
            {
                "alias": oidf.OIDF_VERIFIER_ALIAS,
                "credential": {
                    "signing_jwk": {
                        "kty": "EC",
                        "crv": "P-256",
                        "x": "x",
                        "y": "y",
                        "d": "d",
                    }
                },
                "client": {"request_object_trust_anchor_pem": "test-root"},
                "verifier": {
                    "gateway_url": "https://conformance.example.test",
                    "profile": "oid4vp-1.0-final",
                },
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="reviewed OIDF verification-evidence"):
        oidf.validate_config(config, "oid4vp-verifier")


def test_verifier_configuration_requires_browser_compatible_alias(tmp_path: Path) -> None:
    config = tmp_path / "verifier.json"
    config.write_text(
        json.dumps(
            {
                "credential": {
                    "signing_jwk": {
                        "kty": "EC",
                        "crv": "P-256",
                        "x": "x",
                        "y": "y",
                        "d": "d",
                    }
                },
                "client": {"request_object_trust_anchor_pem": "test-root"},
                "verifier": {
                    "gateway_url": "https://conformance.example.test",
                    "profile": "oid4vp-1.0-final",
                },
                "browser": oidf.VERIFICATION_EVIDENCE_BROWSER_AUTOMATION,
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="configuration alias"):
        oidf.validate_config(config, "oid4vp-verifier")


def test_planned_verifier_requires_explicit_attested_pre_activation_run(tmp_path: Path) -> None:
    profile = dict(oidf.load_manifest()["profiles"]["oid4vp-verifier"])
    profile["status"] = "planned"
    stack = tmp_path / "stack.json"
    stack.write_text('{"schema":"marty.stack/v1"}', encoding="utf-8")

    with pytest.raises(ValueError, match="not active"):
        oidf.execution_mode("oid4vp-verifier", profile, allow_planned=False, stack_manifest=stack)
    with pytest.raises(ValueError, match="stack-manifest"):
        oidf.execution_mode("oid4vp-verifier", profile, allow_planned=True, stack_manifest=None)
    assert oidf.execution_mode("oid4vp-verifier", profile, allow_planned=True, stack_manifest=stack) == "pre-activation"


def test_activated_issuer_profile_no_longer_needs_pre_activation_switch() -> None:
    profile = oidf.load_manifest()["profiles"]["oid4vci-issuer"]

    assert (
        oidf.execution_mode(
            "oid4vci-issuer",
            profile,
            allow_planned=False,
            stack_manifest=None,
        )
        == "active"
    )


@pytest.mark.parametrize(
    "profile_name",
    [
        "oid4vp-verifier",
        "oid4vp-url-query-verifier",
        "oid4vp-mdoc-verifier",
        "oid4vp-haip-verifier",
    ],
)
def test_activated_verifier_profiles_no_longer_need_pre_activation_switch(
    profile_name: str,
) -> None:
    profile = oidf.load_manifest()["profiles"][profile_name]

    assert (
        oidf.execution_mode(
            profile_name,
            profile,
            allow_planned=False,
            stack_manifest=None,
        )
        == "active"
    )


def test_verifier_interaction_environment_matches_the_official_plan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OIDF_MARTY_VERIFIER_PROFILE", "standard")
    monkeypatch.setenv("OIDF_VERIFIER_REQUEST_METHOD", "request_uri_signed")
    oidf.validate_verifier_interaction_environment("oid4vp-verifier")

    oidf.validate_verifier_interaction_environment("oid4vp-mdoc-verifier")

    monkeypatch.setenv("OIDF_VERIFIER_REQUEST_METHOD", "url_query")
    oidf.validate_verifier_interaction_environment("oid4vp-url-query-verifier")

    monkeypatch.setenv("OIDF_MARTY_VERIFIER_PROFILE", "haip")
    monkeypatch.setenv("OIDF_VERIFIER_REQUEST_METHOD", "request_uri_signed")
    oidf.validate_verifier_interaction_environment("oid4vp-haip-verifier")

    monkeypatch.setenv("OIDF_VERIFIER_REQUEST_METHOD", "url_query")
    with pytest.raises(ValueError, match="request_uri_signed"):
        oidf.validate_verifier_interaction_environment("oid4vp-haip-verifier")


def test_tls_proxy_uses_only_oidf_approved_tls12_ciphers() -> None:
    config = (ROOT / "services" / "tls-proxy" / "nginx.conf").read_text(encoding="utf-8")

    assert "ssl_protocols TLSv1.2 TLSv1.3;" in config
    assert "ECDHE-RSA-AES128-GCM-SHA256" in config
    assert "AES_128_CBC" not in config
    assert "ECDHE-RSA-AES128-SHA" not in config
