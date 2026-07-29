from __future__ import annotations

import base64
import importlib.util
import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "oidf_mdoc_binding_audit", ROOT / "scripts" / "oidf_mdoc_binding_audit.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load OIDF mdoc binding audit helper")
audit_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit_module)


def _write_export(
    export_dir: Path,
    *,
    test_name: str,
    flow_id: str,
    transcript: bytes,
    nonce: str = "nonce-1",
) -> dict[str, str]:
    client_id = "x509_hash:client"
    response_uri = f"https://verifier.example/v1/flows/instances/{flow_id}/submit"
    presentation = (
        base64.urlsafe_b64encode(b"official-device-response").rstrip(b"=").decode()
    )
    payload = {
        "testInfo": {"testName": test_name},
        "results": [
            {
                "session_transcript_b64": base64.b64encode(transcript).decode(),
                "session_transcript_input": {
                    "client_id": client_id,
                    "nonce": nonce,
                    "response_uri": response_uri,
                    "jwkThumbprint_b64": "<null>",
                },
            },
            {"vp_token": {"credential-query": [presentation]}},
        ],
    }
    export_dir.mkdir()
    with zipfile.ZipFile(export_dir / "official.zip", "w") as archive:
        archive.writestr(f"test-log-{test_name}-id.json", json.dumps(payload))
    return {
        "flow": audit_module.digest(flow_id),
        "transcript": audit_module.digest(transcript),
        "client_id": audit_module.digest(client_id),
        "nonce": audit_module.digest(nonce),
        "response_uri": audit_module.digest(response_uri),
        "response_key": "none",
        "presentation": audit_module.digest(presentation),
        "device_response": audit_module.digest(
            audit_module.decode_b64(presentation)
        ),
    }


def _write_log(path: Path, values: dict[str, str]) -> None:
    path.write_text(
        "flow | OID4VP mdoc binding "
        f"flow_instance_sha256={values['flow']} "
        f"transcript_sha256={values['transcript']} "
        f"client_id_sha256={values['client_id']} "
        f"nonce_sha256={values['nonce']} "
        f"response_uri_sha256={values['response_uri']} "
        f"response_key_thumbprint_sha256={values['response_key']} "
        f"presentation_sha256={values['presentation']}\n"
        "presentation-policy | mDoc verification binding "
        f"transcript_sha256={values['transcript']} "
        f"device_response_sha256={values['device_response']} "
        "issuer_signature_valid=True issuer_trusted=True "
        "device_authentication_valid=True\n",
        encoding="utf-8",
    )


def test_positive_official_binding_matches_product_without_raw_values(tmp_path: Path) -> None:
    values = _write_export(
        tmp_path / "export",
        test_name="oid4vp-1final-verifier-happy-flow",
        flow_id="flow-1",
        transcript=b"official-transcript",
    )
    compose_log = tmp_path / "compose.log"
    _write_log(compose_log, values)

    report = audit_module.audit(tmp_path / "export", compose_log)

    module = report["modules"][0]
    assert report["source_policy"] == "unmodified"
    assert module["status"] == "expected-binding-observed"
    assert all(module["binding_matches"].values())
    assert module["product_transcript_forwarded"] is True
    serialized = json.dumps(report)
    assert "official-transcript" not in serialized
    assert "x509_hash:client" not in serialized
    assert "nonce-1" not in serialized


def test_negative_official_transcript_mismatch_is_expected(tmp_path: Path) -> None:
    values = _write_export(
        tmp_path / "export",
        test_name="oid4vp-1final-verifier-invalid-session-transcript",
        flow_id="flow-2",
        transcript=b"wallet-manipulated-transcript",
    )
    values["transcript"] = audit_module.digest(b"verifier-owned-transcript")
    compose_log = tmp_path / "compose.log"
    _write_log(compose_log, values)

    report = audit_module.audit(tmp_path / "export", compose_log)

    module = report["modules"][0]
    assert module["status"] == "expected-binding-observed"
    assert module["binding_matches"]["transcript"] is False
    assert module["product_transcript_forwarded"] is True
