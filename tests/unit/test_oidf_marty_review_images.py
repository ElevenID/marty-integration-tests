from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("oidf_marty_review_images", ROOT / "scripts/oidf_marty_review_images.py")
assert SPEC
assert SPEC.loader
review = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(review)
from oidf_marty_start_verification import PRIVATE_FLOW_AUDIT_SCHEMA, private_flow_audit_path  # noqa: E402

FLOW = "12345678-1234-1234-1234-123456789abc"
NAME = "oid4vp-1final-verifier-happy-flow"


def fixture_case(tmp_path: Path) -> tuple[list[dict], dict, Path, Path]:
    images, audit = tmp_path / "images", tmp_path / "audit"
    images.mkdir()
    audit.mkdir()
    digest = hashlib.sha256(NAME.encode()).hexdigest()
    pixels = b"\x89PNG\r\n\x1a\nunit-test-only"
    (images / (digest + ".png")).write_bytes(pixels)
    (images / (digest + ".json")).write_text(
        json.dumps({"instance_id": FLOW, "status": "COMPLETED", "result": "passed", "decision": "allow"})
    )
    callback = hashlib.sha256(f"test1\0{FLOW}".encode()).hexdigest()
    (audit / (callback + ".json")).write_text(
        json.dumps({"schema": PRIVATE_FLOW_AUDIT_SCHEMA, "test_name": NAME, "flow_instance_id": FLOW})
    )
    infos = [
        {
            "testName": NAME,
            "testId": "test1",
            "_id": "test1",
            "planId": "plan1",
            "status": "FINISHED",
            "result": "REVIEW",
        }
    ]
    capture = {
        "official_results_modified": False,
        "review_pending": [NAME],
        "modules": [
            {
                "test_name": NAME,
                "capture_status": "CAPTURED",
                **review.SUCCESS,
                "screenshot": {"private_file": digest + ".png", "sha256": hashlib.sha256(pixels).hexdigest()},
            }
        ],
    }
    return infos, capture, images, audit


def test_capture_binding_requires_the_exact_test_callback_and_pixels(tmp_path: Path) -> None:
    infos, capture, images, audit = fixture_case(tmp_path)
    cases = review.captured_cases(infos, capture, images, audit)
    assert len(cases) == 1
    assert cases[0]["test_id"] == "test1"
    assert cases[0]["flow_id"] == FLOW
    infos[0]["testId"] = infos[0]["_id"] = "anotherattempt"
    with pytest.raises(FileNotFoundError):
        review.captured_cases(infos, capture, images, audit)


def test_haip_image_uses_exact_variant_label_and_retains_base_module_name(tmp_path: Path) -> None:
    infos, capture, images, audit = fixture_case(tmp_path)
    label = NAME + "[client_id_prefix=x509_hash][request_method=request_uri_signed][vp_profile=haip]"
    infos[0]["interaction_name"] = label
    callback = private_flow_audit_path(audit, "test1", FLOW)
    callback.write_text(json.dumps({"schema": PRIVATE_FLOW_AUDIT_SCHEMA, "test_name": label, "flow_instance_id": FLOW}))
    assert review.captured_cases(infos, capture, images, audit)[0]["test_name"] == NAME
    infos[0]["interaction_name"] = label.replace("haip", "other")
    with pytest.raises(ValueError, match="exact official test"):
        review.captured_cases(infos, capture, images, audit)


@pytest.mark.parametrize("mutation", ["result", "hash", "path", "size", "outcome", "module"])
def test_stale_failed_or_unbound_captures_cannot_be_attached(tmp_path: Path, mutation: str) -> None:
    infos, capture, images, audit = fixture_case(tmp_path)
    row = capture["modules"][0]
    if mutation == "result":
        infos[0]["result"] = "FAILED"
    elif mutation == "hash":
        row["screenshot"]["sha256"] = "0" * 64
    elif mutation == "path":
        row["screenshot"]["private_file"] = "../../private.png"
    elif mutation == "size":
        (images / row["screenshot"]["private_file"]).write_bytes(b"\x89PNG\r\n\x1a\n" + b"x" * review.MAX_IMAGE_BYTES)
    elif mutation == "outcome":
        row["decision"] = "deny"
    else:
        row["test_name"] = "another-module"
    with pytest.raises(ValueError, match="review|capture"):
        review.captured_cases(infos, capture, images, audit)


@pytest.mark.parametrize("url", ["https://remote.example", "http://localhost", "https://user:secret@localhost"])
def test_automatic_attachment_is_limited_to_the_local_runner(url: str) -> None:
    with pytest.raises(ValueError, match="local|HTTPS|credentials"):
        review.local_server(url)


@pytest.mark.parametrize("result", ["PASSED", "WARNING", "FAILED"])
def test_upload_never_reclassifies_another_outcome_as_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    result: str,
) -> None:
    infos, capture, images, audit = fixture_case(tmp_path)
    case = review.captured_cases(infos, capture, images, audit)[0]
    methods = []

    def request(_url: str, **kwargs: object) -> tuple[int, dict]:
        methods.append(kwargs.get("method", "GET"))
        return 200, {**infos[0], "result": result}

    monkeypatch.setattr(review, "request_json", request)
    with pytest.raises(ValueError, match="exact finished REVIEW"):
        review.attach_image("https://localhost:8443", {}, case)
    assert methods == ["GET"]


def test_real_image_upload_is_read_back_and_idempotent_without_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    infos, capture, images, audit = fixture_case(tmp_path)
    case = review.captured_cases(infos, capture, images, audit)[0]
    logs: list[dict] = []
    uploads = []

    def request(url: str, **kwargs: object) -> tuple[int, object]:
        if "/api/info/" in url:
            return 200, infos[0]
        if kwargs.get("method") == "POST":
            encoded = kwargs["body"].decode()
            assert encoded.startswith(review.PNG_PREFIX)
            assert base64.b64decode(encoded[len(review.PNG_PREFIX) :]) == case["image"].read_bytes()
            uploads.append(True)
            # Match stock ImageAPI: an ordinary image log entry has no result.
            logs.append({"testId": "test1", "img": encoded, "src": "_image-api"})
            return 200, logs[-1]
        assert url.endswith("/api/log/test1")
        return 200, logs

    monkeypatch.setattr(review, "request_json", request)
    first = review.attach_image("https://localhost:8443", {}, case)
    second = review.attach_image("https://localhost:8443", {}, case)
    assert len(uploads) == 1
    assert first["readback_hash_matched"] is True
    assert first["review_status"] == "PENDING"
    assert second["reused_existing_image"] is True
    assert infos[0]["result"] == "REVIEW"
