#!/usr/bin/env python3
"""Encrypt bound private review inputs, or open their exact images for review.

This is transport, never approval. Original reports are read-only. The standard
age tool receives the private identity only during local decryption; CI uses a
public native age recipient. No plaintext export is uploaded or written by the
viewer. Candidate qualification remains the independent product Rust gate.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import io
import json
import os
import re
import subprocess
import tarfile
from pathlib import Path, PurePosixPath

from official_review_crypto import MAX_ARCHIVE, read_regular
from sanitize_official_evidence import pending_review_request

SCHEMA = "elevenid.private-official-review/v1"
DELIVERY_SCHEMA = "elevenid.official-review-delivery/v1"
RECIPIENT = re.compile(r"age1[0-9a-z]{58}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
EXECUTION_ID = re.compile(r"[A-Za-z0-9._-]{1,180}\Z")
IMAGE_PATH = re.compile(r"images/[0-9a-f]{64}\.png\Z")


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def safe_path(name: str) -> str:
    path = PurePosixPath(name)
    if (
        not name
        or path.is_absolute()
        or "\\" in name
        or ":" in name
        or any(part in {".", ".."} for part in path.parts)
        or str(path) != name
    ):
        raise ValueError("private review archive contains an unsafe path")
    return name


def summary_input(path: Path) -> tuple[bytes, dict]:
    raw = read_regular(path, 8 * 1024 * 1024)
    summary = json.loads(raw)
    if (
        not isinstance(summary, dict)
        or summary.get("schema") != "elevenid.sanitized-official-interop/v1"
        or not isinstance(summary.get("review_requests"), list)
    ):
        raise ValueError("private review requires the exact current public summary")
    return raw, summary


def delivery_scope(summary: dict, execution_id: str, attempt: int) -> str:
    local = summary.get("local_runtime_binding")
    if local is not None and (
        not isinstance(local, dict) or local.get("runId") != execution_id or local.get("releaseQualified") is not False
    ):
        raise ValueError("private local review origin does not match its actual runtime")
    trusted_actions = (
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("GITHUB_REPOSITORY") in {"ElevenID/marty-ui", "ElevenID/marty-integration-tests"}
        and os.environ.get("GITHUB_REF") == "refs/heads/main"
        and execution_id == f"{summary['lane']}-{os.environ.get('GITHUB_RUN_ID')}-{attempt}"
        and os.environ.get("GITHUB_RUN_ATTEMPT") == str(attempt)
    )
    return "OFFICIAL_RUN_REVIEW_ONLY" if local is None and trusted_actions else "LOCAL_DEVELOPER_FEEDBACK"


def encrypt(args: argparse.Namespace) -> dict:
    summary_bytes, summary = summary_input(args.summary)
    if not RECIPIENT.fullmatch(args.recipient) or not EXECUTION_ID.fullmatch(args.execution_id) or args.attempt <= 0:
        raise ValueError("private review recipient/origin is invalid")
    scope = delivery_scope(summary, args.execution_id, args.attempt)
    if not summary["review_requests"]:
        return {"schema": DELIVERY_SCHEMA, "state": "NO_REVIEW_INPUTS", "release_qualified": False}
    if args.output.exists() or args.output.is_symlink():
        raise ValueError("private review delivery destination already exists")
    members: dict[str, bytes] = {}

    def add(name: str, value: bytes, expected: str | None = None) -> None:
        safe_path(name)
        if expected is not None and digest(value) != expected:
            raise ValueError("private review input differs from its public binding")
        if name in members and members[name] != value:
            raise ValueError("private review archive has conflicting members")
        members[name] = value
        if sum(map(len, members.values())) > MAX_ARCHIVE:
            raise ValueError("private review archive exceeds its size limit")

    add("summary.json", summary_bytes)
    exports = [(path, read_regular(path)) for path in sorted(args.private_exports.glob("*.zip"))]
    for request in summary["review_requests"]:
        source = safe_path(request["source"])
        evidence_path = args.raw / source
        if not evidence_path.resolve().is_relative_to(args.raw.resolve()):
            raise ValueError("private review evidence is outside its owned directory")
        evidence_bytes = read_regular(evidence_path)
        evidence = json.loads(evidence_bytes)
        if not isinstance(evidence, dict):
            raise ValueError("private review original evidence is malformed")
        projected = pending_review_request(evidence_path, evidence)
        if projected is None or {"source": source, **projected} != request:
            raise ValueError("private review inventory differs from the actual original evidence")
        add("raw/" + source, evidence_bytes, request["original_evidence_sha256"])
        parent = str(PurePosixPath(source).parent)
        receipt = evidence_path.parent / "official-real-ui-images.json"
        add(f"raw/{parent}/official-real-ui-images.json", read_regular(receipt), request["capture_receipt_sha256"])
        original = {row["path"]: row["sha256"] for row in evidence["artifacts"]}
        for path in sorted(evidence_path.parent.glob("*.zip")):
            add(f"raw/{parent}/{path.name}", read_regular(path), original[path.name])
        enriched = [(path, value) for path, value in exports if digest(value) == request["official_export_sha256"]]
        if len(enriched) != 1:
            raise ValueError("private review has no unique unchanged stock re-export")
        add(f"private/{request['official_export_sha256'][7:]}.zip", enriched[0][1], request["official_export_sha256"])
        for module in request["modules"]:
            image = args.private_images / (hashlib.sha256(module["test_name"].encode()).hexdigest() + ".png")
            pixels = read_regular(image, 500 * 1024)
            if not pixels.startswith(b"\x89PNG\r\n\x1a\n") or not DIGEST.fullmatch(module["screenshot_sha256"]):
                raise ValueError("private review image violates the actual capture contract")
            add("images/" + module["screenshot_sha256"][7:] + ".png", pixels, module["screenshot_sha256"])
    manifest = {
        "schema": SCHEMA,
        "execution_id": args.execution_id,
        "attempt": args.attempt,
        "lane": summary["lane"],
        "scope": scope,
        "summary_sha256": digest(summary_bytes),
        "review_requests": summary["review_requests"],
        "release_qualified": False,
        "members": {name: {"sha256": digest(value), "size": len(value)} for name, value in sorted(members.items())},
    }
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w", format=tarfile.PAX_FORMAT) as output:
        payloads = {"manifest.json": json.dumps(manifest, sort_keys=True).encode(), **members}
        for name, value in sorted(payloads.items()):
            entry = tarfile.TarInfo(name)
            entry.mode, entry.size = 0o600, len(value)
            output.addfile(entry, io.BytesIO(value))
    if len(archive.getvalue()) > MAX_ARCHIVE:
        raise ValueError("private review plaintext exceeds its size limit")
    args.output.mkdir(parents=True, exist_ok=False)
    encrypted = args.output / "review.tar.age"
    result = subprocess.run(
        [str(args.age), "--encrypt", "--recipient", args.recipient, "--output", str(encrypted)],
        input=archive.getvalue(),
        capture_output=True,
        timeout=120,
        check=False,
    )
    if result.returncode:
        raise ValueError("standard review encryption failed")
    ciphertext = read_regular(encrypted, MAX_ARCHIVE + 1024 * 1024)
    if not ciphertext.startswith(b"age-encryption.org/v1\n"):
        raise ValueError("review output is not a native age encrypted file")
    receipt = {
        "schema": DELIVERY_SCHEMA,
        "state": "ENCRYPTED",
        "scope": manifest["scope"],
        "execution_id": args.execution_id,
        "attempt": args.attempt,
        "lane": summary["lane"],
        "recipient": args.recipient,
        "summary_sha256": digest(summary_bytes),
        "ciphertext_sha256": digest(ciphertext),
        "ciphertext_bytes": len(ciphertext),
        "image_count": sum(len(r["modules"]) for r in summary["review_requests"]),
        "release_qualified": False,
    }
    (args.output / "review-delivery.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return receipt


def unpack(value: bytes) -> dict[str, bytes]:
    if len(value) > MAX_ARCHIVE:
        raise ValueError("decrypted review archive exceeds its size limit")
    result = {}
    with tarfile.open(fileobj=io.BytesIO(value), mode="r:") as source:
        for entry in source:
            name = safe_path(entry.name)
            if not entry.isfile() or name in result or entry.size > MAX_ARCHIVE or len(result) > 1024:
                raise ValueError("private review archive has invalid or duplicate members")
            stream = source.extractfile(entry)
            if stream is None:
                raise ValueError("private review archive member is unavailable")
            result[name] = stream.read(MAX_ARCHIVE + 1)
            if len(result[name]) != entry.size or sum(map(len, result.values())) > MAX_ARCHIVE:
                raise ValueError("private review archive member size is invalid")
    return result


def open_review(args: argparse.Namespace) -> dict:
    summary_bytes, summary = summary_input(args.summary)
    receipt = json.loads(read_regular(args.artifact / "review-delivery.json"))
    ciphertext = read_regular(args.artifact / "review.tar.age", MAX_ARCHIVE + 1024 * 1024)
    if (
        not isinstance(receipt, dict)
        or receipt.get("schema") != DELIVERY_SCHEMA
        or receipt.get("state") != "ENCRYPTED"
        or receipt.get("summary_sha256") != digest(summary_bytes)
        or receipt.get("ciphertext_sha256") != digest(ciphertext)
        or receipt.get("ciphertext_bytes") != len(ciphertext)
        or receipt.get("release_qualified") is not False
    ):
        raise ValueError("encrypted review delivery does not match the exact public summary")
    result = subprocess.run(
        [str(args.age), "--decrypt", "--identity", str(args.identity), str(args.artifact / "review.tar.age")],
        capture_output=True,
        timeout=120,
        check=False,
    )
    if result.returncode:
        raise ValueError("private review decryption failed; no images were opened")
    members = unpack(result.stdout)
    manifest = json.loads(members.pop("manifest.json"))
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema") != SCHEMA
        or manifest.get("summary_sha256") != digest(summary_bytes)
        or manifest.get("review_requests") != summary["review_requests"]
        or manifest.get("release_qualified") is not False
        or manifest.get("members")
        != {name: {"sha256": digest(value), "size": len(value)} for name, value in sorted(members.items())}
        or members.get("summary.json") != summary_bytes
        or manifest.get("lane") != summary["lane"]
        or (summary.get("local_runtime_binding") is not None and manifest.get("scope") != "LOCAL_DEVELOPER_FEEDBACK")
        or any(manifest.get(key) != receipt.get(key) for key in ["scope", "execution_id", "attempt"])
    ):
        raise ValueError("decrypted review manifest or members differ from their bound evidence")
    images = {}
    cards = []
    friendly = {
        "happy-flow": "Happy path",
        "minimal-cnf-jwk": "Minimal holder key",
        "request-uri-method-post": "Request URI using POST",
        "request-uri-fetched-twice": "Request URI fetched twice",
    }
    for request in summary["review_requests"]:
        for module in request["modules"]:
            image = "images/" + module["screenshot_sha256"][7:] + ".png"
            if (
                not IMAGE_PATH.fullmatch(image)
                or image not in members
                or digest(members[image]) != module["screenshot_sha256"]
                or not members[image].startswith(b"\x89PNG\r\n\x1a\n")
            ):
                raise ValueError("private review image differs from its exact official case")
            images[image] = members[image]
            short = module["test_name"].removeprefix("oid4vp-1final-verifier-")
            title = html.escape(friendly.get(short, short.replace("-", " ").capitalize()))
            detail = html.escape(json.dumps(module, indent=2))
            cards.append(
                f'<article><h2>{title}</h2><a href="{image}">'
                f'<img src="{image}" alt="Actual verifier result for {title}"></a>'
                f"<details><summary>Case reference and image binding</summary><pre>{detail}</pre></details></article>"
            )
    if not cards or receipt.get("image_count") != len(cards):
        raise ValueError("private review does not cover its exact case count")
    if args.output.exists() or args.output.is_symlink():
        raise ValueError("private review viewer destination already exists")
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "images").mkdir()
    for name, value in images.items():
        (args.output / name).write_bytes(value)
    title = html.escape(summary["lane"] + " â€” review required")
    context = html.escape(manifest["scope"] + ": " + manifest["execution_id"])
    page = (
        '<!doctype html><html lang="en"><meta charset="utf-8"><title>' + title + "</title>"
        "<style>body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:0 24px;"
        "color:#19324b;background:#f5f7fa}"
        "article{background:white;padding:24px;margin:28px 0;border-radius:12px}"
        "img{width:100%;height:auto}pre{white-space:pre-wrap;overflow-wrap:anywhere}"
        "details{margin-top:16px}h1{margin-bottom:8px}</style><h1>" + title + "</h1><p>" + context + "</p>"
        "<p>Actual bound screenshots. Review remains pending; original official results are unchanged.</p>"
        + "".join(cards)
        + "</html>"
    )
    (args.output / "index.html").write_text(page, encoding="utf-8")
    opened = {
        "schema": "elevenid.private-review-opened/v1",
        "state": "DECRYPTED_FOR_REVIEW",
        "summary_sha256": digest(summary_bytes),
        "images_verified": len(cards),
        "review_status": "PENDING",
        "release_qualified": False,
        "plaintext_exports_written": False,
    }
    (args.output / "review-readback.json").write_text(json.dumps(opened, indent=2) + "\n", encoding="utf-8")
    return opened


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    encryptor = sub.add_parser("encrypt")
    encryptor.add_argument("--raw", type=Path, required=True)
    encryptor.add_argument("--private-images", type=Path, required=True)
    encryptor.add_argument("--private-exports", type=Path, required=True)
    encryptor.add_argument("--recipient", required=True)
    encryptor.add_argument("--execution-id", required=True)
    encryptor.add_argument("--attempt", type=int, required=True)
    viewer = sub.add_parser("open")
    viewer.add_argument("--artifact", type=Path, required=True)
    viewer.add_argument("--identity", type=Path, required=True)
    for command in [encryptor, viewer]:
        command.add_argument("--summary", type=Path, required=True)
        command.add_argument("--age", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        receipt = encrypt(args) if args.operation == "encrypt" else open_review(args)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError):
        print("Private review delivery failed its encryption, origin or evidence checks.")
        return 1
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
