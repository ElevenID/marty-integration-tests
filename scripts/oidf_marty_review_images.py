#!/usr/bin/env python3
"""Attach real Marty UI evidence to the local stock OIDF server; never approve REVIEW."""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import re
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

from official_fixture_bootstrap import write_private_json  # noqa: E402
from oidf_conformance import (  # noqa: E402
    exported_module_documents,
    exported_module_info,
    finalize_evidence_artifacts,
    load_manifest,
    official_plan_coverage,
    validate_runner,
)
from oidf_marty_public_login import public_origin, required_env  # noqa: E402
from oidf_marty_start_verification import gateway_session_id, read_private_flow_audit  # noqa: E402
from oidf_marty_verification_evidence import outcome_projection, read_flow_evidence  # noqa: E402
from oidf_marty_verifier import request_json  # noqa: E402
from oidf_sd_jwt_diagnostic_audit import FLOW_ID  # noqa: E402

IDENTITY = re.compile(r"[A-Za-z0-9]{1,180}\Z")
PNG_PREFIX = "data:image/png;base64,"
MAX_IMAGE_BYTES = 500 * 1024  # Stock ImageAPI's limit, before base64 encoding.
SUCCESS = {"status": "completed", "result": "passed", "decision": "allow"}


def local_server(value: str) -> str:
    server = public_origin(value)
    parsed = urlsplit(server)
    if parsed.hostname not in {"localhost", "localhost.emobix.co.uk", "127.0.0.1", "::1"}:
        raise ValueError("automatic image attachment is limited to the owned local OIDF server")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("official server credentials must not be embedded in URLs")
    return server


def captured_cases(
    infos: list[dict],
    capture: dict,
    images: Path,
    flow_audit: Path,
) -> list[dict]:
    """Bind pixels to the exact official test, private callback and successful result."""
    names = [info.get("testName") for info in infos]
    if len(set(names)) != len(names):
        raise ValueError("ambiguous official module export")
    review = {info["testName"] for info in infos if info.get("result") == "REVIEW"}
    if capture.get("official_results_modified") is not False or set(capture.get("review_pending", [])) != review:
        raise ValueError("capture does not match the official review modules")
    rows = capture.get("modules")
    if not isinstance(rows, list) or len(rows) != len(infos) or {row.get("test_name") for row in rows} != set(names):
        raise ValueError("capture does not cover the exact official module set")
    cases = []
    for info in infos:
        name = info["testName"]
        if name not in review:
            continue
        test_id, plan_id = info.get("testId"), info.get("planId")
        if (
            not isinstance(test_id, str)
            or not IDENTITY.fullmatch(test_id)
            or not isinstance(plan_id, str)
            or not IDENTITY.fullmatch(plan_id)
            or info.get("_id") != test_id
            or info.get("status") != "FINISHED"
        ):
            raise ValueError("review module lacks a finished, exact official identity")
        row = next(row for row in rows if row["test_name"] == name)
        if row.get("capture_status") != "CAPTURED" or {key: row.get(key) for key in SUCCESS} != SUCCESS:
            raise ValueError("review image lacks a real completed allow outcome")
        digest = hashlib.sha256(name.encode()).hexdigest()
        image = images / (digest + ".png")
        if image.is_symlink() or not image.is_file() or not image.resolve().is_relative_to(images.resolve()):
            raise ValueError("review image is not an owned capture file")
        pixels = image.read_bytes()
        if not pixels.startswith(b"\x89PNG\r\n\x1a\n") or len(pixels) > MAX_IMAGE_BYTES:
            raise ValueError("review image violates the stock image contract")
        screenshot = row.get("screenshot", {})
        sha = hashlib.sha256(pixels).hexdigest()
        if screenshot.get("private_file") != image.name or screenshot.get("sha256") != sha:
            raise ValueError("review image hash does not match the actual capture")
        raw = json.loads((images / (digest + ".json")).read_text(encoding="utf-8"))
        flow_id = raw.get("instance_id")
        if (
            not isinstance(flow_id, str)
            or not FLOW_ID.fullmatch(flow_id)
            or outcome_projection(raw, flow_id) != SUCCESS
        ):
            raise ValueError("review image lacks its exact public result")
        read_private_flow_audit(flow_audit, test_id, flow_id, info.get("interaction_name", name))
        cases.append(
            {
                "test_name": name,
                "test_id": test_id,
                "plan_id": plan_id,
                "flow_id": flow_id,
                "image": image,
                "sha256": sha,
            }
        )
    return cases


def image_hash(encoded: object) -> str | None:
    if not isinstance(encoded, str) or not encoded.startswith(PNG_PREFIX):
        return None
    return hashlib.sha256(base64.b64decode(encoded[len(PNG_PREFIX) :], validate=True)).hexdigest()


def attach_image(server: str, headers: dict[str, str], case: dict, *, insecure: bool = False) -> dict:
    server = local_server(server)
    test_id = case["test_id"]

    def checked_info() -> None:
        status, info = request_json(f"{server}/api/info/{test_id}", headers=headers, insecure=insecure)
        if (
            status != 200
            or not isinstance(info, dict)
            or any(
                info.get(key) != value
                for key, value in {
                    "testId": test_id,
                    "testName": case["test_name"],
                    "planId": case["plan_id"],
                    "status": "FINISHED",
                    "result": "REVIEW",
                }.items()
            )
        ):
            raise ValueError("live official module is not the exact finished REVIEW case")

    def images() -> list[dict]:
        # The finished-test upload endpoint creates a new ordinary log entry.
        # Read the complete log: ImageService filters only condition REVIEW
        # entries and would omit a newly uploaded image without that field.
        status, rows = request_json(f"{server}/api/log/{test_id}", headers=headers, insecure=insecure)
        if (
            status != 200
            or not isinstance(rows, list)
            or any(not isinstance(row, dict) or row.get("testId") != test_id for row in rows)
        ):
            raise ValueError("official image readback failed its module binding")
        return [row for row in rows if "img" in row]

    checked_info()  # ImageAPI changes result to REVIEW: never call it for FAILED/WARNING/PASSED.
    existing = images()
    reused = any(image_hash(row.get("img")) == case["sha256"] for row in existing)
    if not reused:
        if sum("img" in row for row in existing) >= 2:
            raise ValueError("official module already has its permitted images")
        payload = PNG_PREFIX + base64.b64encode(case["image"].read_bytes()).decode()
        status, stored = request_json(
            f"{server}/api/log/{test_id}/images?description=Actual%20Marty%20verifier%20UI%20-%20review%20required",
            method="POST",
            body=payload.encode(),
            headers={**headers, "Content-Type": "text/plain"},
            insecure=insecure,
        )
        if (
            status != 200
            or not isinstance(stored, dict)
            or stored.get("testId") != test_id
            or image_hash(stored.get("img")) != case["sha256"]
        ):
            raise ValueError("official image upload was rejected")
    if not any(image_hash(row.get("img")) == case["sha256"] for row in images()):
        raise ValueError("official persisted image differs from the actual capture")
    checked_info()
    return {
        "test_name": case["test_name"],
        "screenshot_sha256": case["sha256"],
        "readback_hash_matched": True,
        "reused_existing_image": reused,
        "review_status": "PENDING",
    }


async def export_plan(
    runner: Path, server: str, token: str | None, plan_id: str, destination: Path, *, insecure: bool
) -> Path:
    # Reuse the exact unmodified upstream exporter; never create/publish a certification package.
    sys.path.insert(0, str(runner / "scripts"))
    from conformance import Conformance

    client = Conformance(server, token, verify_ssl=not insecure)
    try:
        return Path(await client.exportjson(plan_id, str(destination)))
    finally:
        await client.httpclient.aclose()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in [
        "official-output",
        "capture-report",
        "private-images",
        "flow-audit-dir",
        "private-export",
        "oidf-runner",
        "output",
    ]:
        parser.add_argument("--" + flag, type=Path, required=True)
    parser.add_argument("--profile", required=True)
    args = parser.parse_args()
    receipt: dict = {"schema": "elevenid.official-real-ui-images/v1", "state": "FAILED", "review_status": "PENDING"}
    try:
        manifest = load_manifest()
        validate_runner(args.oidf_runner, manifest)
        server = local_server(required_env("CONFORMANCE_SERVER"))
        infos = exported_module_info(args.official_output)
        coverage = official_plan_coverage(args.official_output, manifest["profiles"][args.profile]["test_plan"])
        if not coverage["complete"]:
            raise ValueError("official plan coverage is not complete")
        capture = json.loads(args.capture_report.read_text(encoding="utf-8"))
        labels = {row["test_name"]: row["interaction_name"] for row in coverage["module_bindings"]}
        bound_infos = [dict(info, interaction_name=labels[info["testName"]]) for info in infos]
        cases = captured_cases(bound_infos, capture, args.private_images, args.flow_audit_dir)
        originals = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in args.official_output.glob("*.zip")
        }
        rows = []
        receipt["modules"] = rows
        if cases:
            base_url = public_origin(required_env("OIDF_MARTY_GATEWAY_URL"))
            session = gateway_session_id()
            token = os.environ.get("CONFORMANCE_TOKEN")
            headers = {"Authorization": "Bearer " + token} if token else {}
            insecure = "CONFORMANCE_DEV_MODE" in os.environ or "DISABLE_SSL_VERIFY" in os.environ
            for case in cases:
                _, outcome, _ = read_flow_evidence(base_url, session, case["flow_id"], review_required=True)
                if outcome != SUCCESS:
                    raise ValueError("Marty verification result no longer matches its capture")
                rows.append(attach_image(server, headers, case, insecure=insecure))
            args.private_export.mkdir(mode=0o700, parents=True, exist_ok=False)
            log_path = args.private_export / "stock-export-private.log"
            log_path.touch(mode=0o600, exist_ok=False)
            with log_path.open("w", encoding="utf-8") as log, redirect_stdout(log), redirect_stderr(log):
                exported = asyncio.run(export_plan(
                    args.oidf_runner, server, token, cases[0]["plan_id"], args.private_export, insecure=insecure
                ))
            if not exported.resolve().is_relative_to(args.private_export.resolve()):
                raise ValueError("official exporter returned an unexpected path")
            exported.chmod(0o600)
            refreshed = exported_module_info(args.private_export)
            fields = ["testId", "testName", "planId", "status", "result", "variant"]

            def project(values: list[dict]) -> list[str]:
                return sorted(json.dumps({k: info.get(k) for k in fields}, sort_keys=True) for info in values)

            if project(refreshed) != project(infos):
                raise ValueError("official module outcomes changed during evidence attachment")
            exported_images = {
                doc["testInfo"]["testName"]: {
                    image_hash(row.get("img")) for row in doc.get("results", []) if isinstance(row, dict)
                }
                for doc in exported_module_documents(args.private_export)
            }
            if any(case["sha256"] not in exported_images.get(case["test_name"], set()) for case in cases):
                raise ValueError("official re-export is missing an actual verifier image")
            receipt["official_export_sha256"] = hashlib.sha256(exported.read_bytes()).hexdigest()
        if originals != {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in args.official_output.glob("*.zip")
        }:
            raise ValueError("original official exports changed")
        validate_runner(args.oidf_runner, manifest)
        receipt.update(
            state="ATTACHED" if cases else "NO_REVIEW_IMAGES_REQUIRED",
            modules=rows,
            original_exports_unchanged=True,
            module_outcomes_unchanged=True,
            plan_binding_sha256=coverage["binding_sha256"],
        )
    except Exception as error:  # noqa: BLE001 - keep private API/configuration data out of public output
        receipt["error_class"] = type(error).__name__
        write_private_json(
            args.private_images.parent / (args.output.stem + "-private-error.json"),
            {"error_class": type(error).__name__, "error": str(error)},
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if receipt["state"] != "FAILED":
        try:
            finalize_evidence_artifacts(args.official_output)
        except Exception as error:  # noqa: BLE001 - no private paths/API data in public diagnostics
            receipt.update(state="FAILED", error_class=type(error).__name__)
            args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            write_private_json(args.private_images.parent / (args.output.stem + "-inventory-private-error.json"),
                               {"error_class": type(error).__name__, "error": str(error)})
    print(
        json.dumps({"state": receipt["state"], "images": len(receipt.get("modules", [])), "review_status": "PENDING"})
    )
    return 2 if receipt["state"] == "FAILED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
