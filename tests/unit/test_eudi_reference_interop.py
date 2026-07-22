from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("eudi_reference_interop", ROOT / "scripts" / "eudi_reference_interop.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load EUDI reference interop helper")
eudi = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(eudi)


def test_eudi_reference_components_are_immutable_and_complete() -> None:
    manifest = eudi.load_manifest()
    assert "@sha256:" in manifest["components"]["wallet_tester"]["image"]
    assert "@sha256:" in manifest["components"]["verifier_endpoint"]["image"]
    assert manifest["coverage"]["issuance"] == ["sd_jwt_vc", "mso_mdoc"]
    assert manifest["coverage"]["presentation"] == ["sd_jwt_vc"]
    assert manifest["coverage"]["request_object_trust"] == ["signed_jar_x509_hash_pkix"]
    assert manifest["coverage"]["response_mode"] == ["direct_post.jwt"]
    assert manifest["coverage"]["negative"] == ["missing_holder_binding_key"]
    assert set(manifest["required_evidence"]) == set(eudi.REQUIRED_EVIDENCE_CLAIMS)
    assert manifest["compatibility_only"]["presentation"] == ["mso_mdoc"]
    assert "replayed_response" in manifest["planned_coverage"]["negative"]
    assert manifest["limitations"]["mso_mdoc_presentation"]["status"] == "not_officially_exercised"
    libraries = manifest["components"]["wallet_kit"]["libraries"]
    assert {name: value["version"] for name, value in libraries.items()} == {
        "oid4vp": "0.12.3",
        "oid4vci": "0.9.1",
        "sd_jwt": "0.18.0",
    }
    assert all(value["maven_coordinate"].endswith(value["version"]) for value in libraries.values())
    build = manifest["components"]["wallet_kit"]["build"]
    assert "@sha256:" in build["builder_image"]
    assert "@sha256:" in build["runtime_image"]
    assert "@sha256:" in build["public_url_bridge_image"]
    gradle = (ROOT / "services" / "eudi-wallet-harness" / "build.gradle.kts").read_text(encoding="utf-8")
    lock = (ROOT / "services" / "eudi-wallet-harness" / "gradle.lockfile").read_text(encoding="utf-8")
    verification = (ROOT / "services" / "eudi-wallet-harness" / "gradle" / "verification-metadata.xml").read_text(
        encoding="utf-8"
    )
    for library in libraries.values():
        coordinate = library["maven_coordinate"]
        assert f'implementation("{coordinate}")' in gradle
        assert coordinate + "=" in lock
    assert "lockAllConfigurations()" in gradle
    assert "<verify-metadata>true</verify-metadata>" in verification
    assert '<sha256 value="' in verification

    presentation_source = (
        ROOT
        / "services"
        / "eudi-wallet-harness"
        / "src"
        / "main"
        / "kotlin"
        / "com"
        / "elevenid"
        / "marty"
        / "wallet"
        / "WalletPresentationService.kt"
    ).read_text(encoding="utf-8")
    assert "openId4Vp.resolveRequestUri" in presentation_source
    assert "openId4Vp.dispatch" in presentation_source
    assert "ECKeyGenerator" not in presentation_source
    assert "holderKeyFor(credentialCompact)" in presentation_source
    assert "EncryptionMethod.A256GCM" in presentation_source
    issuance_source = (
        ROOT
        / "services"
        / "eudi-wallet-harness"
        / "src"
        / "main"
        / "kotlin"
        / "com"
        / "elevenid"
        / "marty"
        / "wallet"
        / "WalletIssuanceService.kt"
    ).read_text(encoding="utf-8")
    assert 'System.getProperty("javax.net.ssl.trustStore")' in issuance_source
    assert "TrustManagerFactory.getDefaultAlgorithm()" in issuance_source
    assert "sslContext(tlsContext)" in issuance_source
    official_tests = "\n".join(
        (ROOT / "tests" / "integration" / "gateway" / path).read_text(encoding="utf-8")
        for path in ("test_eudi_wallet_kit.py", "test_eudi_wallet_kit_vp.py")
    )
    assert all(evidence_id in official_tests for evidence_id in eudi.REQUIRED_EVIDENCE_CLAIMS)


def test_eudi_manifest_cannot_claim_coverage_without_stable_evidence() -> None:
    manifest = eudi.load_manifest()
    manifest["coverage"]["issuance"].append("jwt_vc_json")
    path = Mock(spec=Path)
    path.read_text.return_value = json.dumps(manifest)

    with pytest.raises(ValueError, match="must be a bijection.*unbound coverage: issuance:jwt_vc_json"):
        eudi.load_manifest(path)


def test_eudi_manifest_cannot_claim_presentation_without_haip_trust_evidence(tmp_path: Path) -> None:
    manifest = eudi.load_manifest()
    manifest["coverage"].pop("request_object_trust")
    path = tmp_path / "eudi-reference-interop.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="x509_hash PKIX"):
        eudi.load_manifest(path)


def test_eudi_evidence_records_pinned_components(tmp_path: Path) -> None:
    output = tmp_path / "report"
    output.mkdir()
    (output / "junit.xml").write_text("<testsuites/>", encoding="utf-8")
    endpoints = {
        "gateway": "https://marty.test",
        "wallet_tester": "http://wallet:5050",
        "verifier": "http://verifier:8090",
        "wallet_kit": "http://kit:9090",
    }
    observed = {
        evidence_id: {"status": "passed", "classname": "suite", "testcase": evidence_id}
        for evidence_id in eudi.REQUIRED_EVIDENCE_CLAIMS
    }
    eudi.write_evidence(
        output,
        eudi.load_manifest(),
        endpoints,
        0,
        observed_evidence=observed,
    )
    evidence = json.loads((output / "evidence.json").read_text(encoding="utf-8"))
    assert evidence["result"] == {"exit_code": 0, "passed": True, "skipped": 0}
    assert evidence["components"]["wallet_tester"]["image"].startswith("ghcr.io/")
    assert evidence["observed_evidence"] == observed


def test_eudi_stack_manifest_records_immutable_marty_images(tmp_path: Path) -> None:
    manifest = tmp_path / "stack-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": "marty.stack/v1",
                "release": "marty-ui@1.0.0",
                "components": [
                    {
                        "name": "marty",
                        "artifacts": [
                            {
                                "type": "oci",
                                "uri": "ghcr.io/elevenid/marty",
                                "digest": "sha256:" + "a" * 64,
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    metadata = eudi.stack_manifest_metadata(manifest)
    assert metadata["release"] == "marty-ui@1.0.0"
    assert metadata["images"][0]["digest"] == "sha256:" + "a" * 64


def test_eudi_junit_skip_count_is_visible(tmp_path: Path) -> None:
    report = tmp_path / "junit.xml"
    report.write_text('<testsuites><testsuite tests="2" skipped="1"/></testsuites>', encoding="utf-8")
    assert eudi.junit_skip_count(report) == 1


def _junit_document(cases: list[tuple[str | None, str | None]]) -> str:
    rendered: list[str] = []
    for index, (evidence_id, outcome) in enumerate(cases):
        properties = (
            f'<properties><property name="evidence_id" value="{evidence_id}"/></properties>'
            if evidence_id is not None
            else ""
        )
        result = f"<{outcome}/>" if outcome is not None else ""
        rendered.append(f'<testcase classname="eudi" name="case-{index}">{properties}{result}</testcase>')
    return "<testsuites><testsuite>" + "".join(rendered) + "</testsuite></testsuites>"


def _passing_evidence_cases() -> list[tuple[str, None]]:
    return [(evidence_id, None) for evidence_id in eudi.REQUIRED_EVIDENCE_CLAIMS]


def test_eudi_junit_requires_each_stable_evidence_id_exactly_once(tmp_path: Path) -> None:
    report = tmp_path / "junit.xml"
    report.write_text(_junit_document(_passing_evidence_cases()), encoding="utf-8")

    observed = eudi.junit_required_evidence(
        report,
        set(eudi.REQUIRED_EVIDENCE_CLAIMS),
    )

    assert set(observed) == set(eudi.REQUIRED_EVIDENCE_CLAIMS)
    assert all(record["status"] == "passed" for record in observed.values())


def test_eudi_junit_failure_summary_exposes_no_failure_text(tmp_path: Path) -> None:
    report = tmp_path / "junit.xml"
    report.write_text(
        '<testsuites><testsuite><testcase classname="eudi.wallet" name="test_public_path">'
        '<failure message="secret-bearing detail">private response body</failure>'
        "</testcase></testsuite></testsuites>",
        encoding="utf-8",
    )

    assert eudi.junit_failure_summary(report) == [
        {
            "classname": "eudi.wallet",
            "testcase": "test_public_path",
            "outcomes": ["failure"],
            "categories": ["unclassified"],
        }
    ]
    assert "secret" not in json.dumps(eudi.junit_failure_summary(report))


def test_eudi_junit_failure_summary_emits_only_fixed_actionable_categories(
    tmp_path: Path,
) -> None:
    report = tmp_path / "junit.xml"
    report.write_text(
        '<testsuites><testsuite><testcase classname="eudi.wallet" name="test_offer">'
        '<failure message="HTTP 422 while resolving credential_offer">'
        "issuer profile DID resolution failed; token=must-not-escape"
        "</failure></testcase></testsuite></testsuites>",
        encoding="utf-8",
    )

    summary = eudi.junit_failure_summary(report)
    assert summary == [
        {
            "classname": "eudi.wallet",
            "testcase": "test_offer",
            "outcomes": ["failure"],
            "categories": [
                "http-422",
                "credential-offer",
                "issuer-profile-or-did",
            ],
        }
    ]
    serialized = json.dumps(summary)
    assert "must-not-escape" not in serialized
    assert "token" not in serialized


def test_eudi_failure_categories_recognize_gateway_client_status() -> None:
    categories = eudi.classify_eudi_failure_text(
        "POST /v1/signing-keys/config/resolve failed with 422: private detail"
    )

    assert categories == ["http-422", "signing-service-resolution"]


def test_eudi_failure_categories_identify_verifier_contract_without_values() -> None:
    categories = eudi.classify_eudi_failure_text(
        "HTTP 400 invalid_request: DCQL vct_values did not match; token=must-not-be-reported"
    )

    assert categories == [
        "http-400",
        "verifier-invalid-request",
        "verifier-dcql",
        "verifier-vct",
    ]


@pytest.mark.parametrize(
    ("diagnostic", "category"),
    [
        ("offer-json-invalid", "offer-document-invalid"),
        ("issuer-metadata-json-invalid", "issuer-metadata-json-invalid"),
        ("issuer-metadata-credential-configurations-empty", "issuer-metadata-configurations-empty"),
        ("authorization-server-metadata-resolution-failed", "authorization-server-metadata-failed"),
        ("issuer-metadata-tls-certificate-path-untrusted", "wallet-tls-certificate-path-untrusted"),
        ("issuer-metadata-tls-certificate-validity-failed", "wallet-tls-certificate-validity-failed"),
        ("issuer-metadata-tls-hostname-mismatch", "wallet-tls-hostname-mismatch"),
        ("issuer-metadata-tls-truststore-empty", "wallet-tls-truststore-empty"),
        ("issuer-metadata-tls-handshake-failed", "wallet-tls-handshake-failed"),
        ("issuer-metadata-hostname-resolution-failed", "wallet-hostname-resolution-failed"),
        ("issuer-metadata-connection-failed", "wallet-connection-failed"),
    ],
)
def test_eudi_failure_categories_recognize_public_safe_wallet_codes(
    diagnostic: str,
    category: str,
) -> None:
    categories = eudi.classify_eudi_failure_text(diagnostic)

    assert category in categories


def test_eudi_junit_failure_summary_classifies_safe_oid4vci_error_codes(
    tmp_path: Path,
) -> None:
    report = tmp_path / "junit.xml"
    report.write_text(
        '<testsuites><testsuite><testcase classname="eudi.wallet" name="test_issue">'
        '<failure message="OID4VCI credential failed: status=400 error=invalid_proof"/>'
        "</testcase></testsuite></testsuites>",
        encoding="utf-8",
    )

    assert eudi.junit_failure_summary(report) == [
        {
            "classname": "eudi.wallet",
            "testcase": "test_issue",
            "outcomes": ["failure"],
            "categories": ["http-400", "invalid-proof"],
        }
    ]


def test_eudi_junit_failure_summary_classifies_safe_operation_only(
    tmp_path: Path,
) -> None:
    report = tmp_path / "junit.xml"
    report.write_text(
        '<testsuites><testsuite><testcase classname="suite" name="case">'
        '<error message="POST /v1/signing-keys/issuer-profiles failed: secret=private"/>'
        "</testcase></testsuite></testsuites>",
        encoding="utf-8",
    )

    summary = eudi.junit_failure_summary(report)

    assert summary[0]["categories"] == [
        "issuer-profile-or-did",
        "issuer-profile-provisioning",
    ]
    assert "private" not in json.dumps(summary)


@pytest.mark.parametrize(
    ("cases", "message"),
    [
        ([], "missing required evidence_id"),
        (
            [("eudi.renamed.v1", None), *_passing_evidence_cases()],
            "undeclared evidence_id",
        ),
        (
            [*_passing_evidence_cases(), (eudi.EUDI_HAIP_EVIDENCE_ID, None)],
            "duplicate evidence_id",
        ),
        (
            [
                (eudi.EUDI_HAIP_EVIDENCE_ID, "failure"),
                (eudi.EUDI_HOLDER_BINDING_EVIDENCE_ID, None),
            ],
            "did not pass: failure",
        ),
        (
            [
                (eudi.EUDI_HAIP_EVIDENCE_ID, "error"),
                (eudi.EUDI_HOLDER_BINDING_EVIDENCE_ID, None),
            ],
            "did not pass: error",
        ),
        (
            [
                (eudi.EUDI_HAIP_EVIDENCE_ID, "skipped"),
                (eudi.EUDI_HOLDER_BINDING_EVIDENCE_ID, None),
            ],
            "did not pass: skipped",
        ),
    ],
)
def test_eudi_junit_rejects_missing_renamed_duplicate_or_nonpassing_evidence(
    tmp_path: Path,
    cases: list[tuple[str | None, str | None]],
    message: str,
) -> None:
    report = tmp_path / "junit.xml"
    report.write_text(_junit_document(cases), encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        eudi.junit_required_evidence(
            report,
            set(eudi.REQUIRED_EVIDENCE_CLAIMS),
        )


def test_eudi_writer_cannot_publish_a_green_summary_without_sentinels(
    tmp_path: Path,
) -> None:
    output = tmp_path / "report"
    output.mkdir()

    with pytest.raises(ValueError, match="every stable evidence assertion"):
        eudi.write_evidence(output, eudi.load_manifest(), {}, 0)


def test_eudi_haip_evidence_binds_a_request_root_separate_from_tls(tmp_path: Path) -> None:
    request_root = tmp_path / "request-root.pem"
    tls_root = tmp_path / "tls-root.pem"
    request_root.write_text("request-object-root", encoding="ascii")
    tls_root.write_text("tls-root", encoding="ascii")

    metadata = eudi.request_object_trust_metadata(
        {
            eudi.OID4VP_TRUST_ANCHOR_FILE_ENV: str(request_root),
            "SSL_CERT_FILE": str(tls_root),
        }
    )

    assert metadata["profile"] == "haip"
    assert metadata["client_id_prefix"] == "x509_hash"
    assert metadata["response_mode"] == "direct_post.jwt"
    assert metadata["separate_from_tls"] is True
    assert metadata["anchor_sha256"] != metadata["tls_ca_sha256"]


def test_eudi_haip_evidence_rejects_reusing_the_tls_root(tmp_path: Path) -> None:
    root = tmp_path / "shared-root.pem"
    root.write_text("shared-root", encoding="ascii")

    with pytest.raises(ValueError, match="independent from TLS"):
        eudi.request_object_trust_metadata(
            {
                eudi.OID4VP_TRUST_ANCHOR_FILE_ENV: str(root),
                "SSL_CERT_FILE": str(root),
            }
        )


def test_run_environment_loads_material_trust_and_public_login_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated = {
        "OIDF_PUBLIC_BASE_URL": "https://marty-oidf.test:8443",
        "EUDI_WALLET_TESTER_PUBLIC_URL": "https://marty-oidf.test:25051",
        "EUDI_VERIFIER_PUBLIC_URL": "https://marty-oidf.test:28091",
        "EUDI_WALLET_KIT_URL": "http://127.0.0.1:29090",
        "SSL_CERT_FILE": str(tmp_path / "root-ca.pem"),
        "OIDF_MARTY_RESOLVE_IP": "127.0.0.1",
    }
    monkeypatch.setattr(eudi, "merged_material_environment", lambda *_args: ("generated", dict(generated)))
    monkeypatch.setattr(eudi, "validate_environment", lambda *_args, **_kwargs: {})
    args = argparse.Namespace(
        eudi_material=tmp_path,
        gateway_url=None,
        wallet_tester_url=None,
        verifier_url=None,
        wallet_kit_url=None,
    )

    environment, endpoints = eudi.run_environment(args)

    assert endpoints["gateway"] == generated["OIDF_PUBLIC_BASE_URL"]
    assert environment["OIDF_MARTY_GATEWAY_URL"] == generated["OIDF_PUBLIC_BASE_URL"]
    assert environment["SSL_CERT_FILE"] == generated["SSL_CERT_FILE"]
    assert environment["OIDF_MARTY_RESOLVE_IP"] == "127.0.0.1"


def test_explicit_endpoint_cannot_deviate_from_material(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated = {
        "OIDF_PUBLIC_BASE_URL": "https://marty-oidf.test:8443",
        "EUDI_WALLET_TESTER_PUBLIC_URL": "https://marty-oidf.test:25051",
        "EUDI_VERIFIER_PUBLIC_URL": "https://marty-oidf.test:28091",
        "EUDI_WALLET_KIT_URL": "http://127.0.0.1:29090",
    }
    monkeypatch.setattr(eudi, "merged_material_environment", lambda *_args: ("generated", generated))
    monkeypatch.setattr(eudi, "validate_environment", lambda *_args, **_kwargs: {})
    args = argparse.Namespace(
        eudi_material=tmp_path,
        gateway_url="https://different.test:8443",
        wallet_tester_url=None,
        verifier_url=None,
        wallet_kit_url=None,
    )

    with pytest.raises(ValueError, match="gateway URL must match"):
        eudi.run_environment(args)
