#!/usr/bin/env python3
"""Deliver a real Marty credential offer to one official OIDF test module.

This is intentionally an adapter, not a test runner.  The OpenID Foundation
suite remains responsible for all protocol assertions.  It is suitable for a
local stack, a staging deployment, and a future certification environment:
the target issuance API and its credentials are supplied at runtime.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urljoin
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REQUEST = ROOT / "conformance" / "marty-issuer.offer-request.example.json"
SAFE_FAILURE_SOURCE = re.compile(r"^[A-Za-z][A-Za-z0-9_$]{0,99}$")
SAFE_HTTP_STATUS_MIN = 100
SAFE_HTTP_STATUS_MAX = 599
OFFER_INTERACTION_COUNTS = {
    # The official module obtains one credential for each of two independent
    # wallet clients and returns to WAITING before the second flow.
    "oid4vci-1_0-issuer-happy-flow-multiple-clients": 2,
}


def interrupted_failure_category(
    server: str,
    test_id: str,
    *,
    insecure: bool,
) -> str:
    """Return a bounded, non-secret category for an interrupted OIDF module."""
    status, entries = request_json(
        urljoin(server, f"api/log/{test_id}"),
        insecure=insecure,
    )
    if status != 200 or not isinstance(entries, list):
        return "oidf-invariant-interrupted-log-unavailable"
    for entry in reversed(entries):
        if not isinstance(entry, dict) or entry.get("result") != "FAILURE":
            continue
        source = entry.get("src")
        if isinstance(source, str):
            source = source.rsplit(".", 1)[-1]
            if SAFE_FAILURE_SOURCE.fullmatch(source):
                slug = re.sub(r"[^a-z0-9]+", "-", source.lower()).strip("-")
                category = f"oidf-invariant-interrupted-{slug}"
                actual = entry.get("actual")
                if (
                    isinstance(actual, int)
                    and not isinstance(actual, bool)
                    and SAFE_HTTP_STATUS_MIN <= actual <= SAFE_HTTP_STATUS_MAX
                ):
                    return f"{category}-http-{actual}"
                return category
        return "oidf-invariant-interrupted-unknown-source"
    return "oidf-invariant-interrupted-no-failure-entry"


def request_json(
    url: str,
    *,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    insecure: bool = False,
) -> tuple[int, Any]:
    request = Request(url, data=body, headers=headers or {}, method=method)
    context = ssl._create_unverified_context() if insecure else None  # nosec B323: explicit local option
    try:
        with urlopen(request, timeout=15, context=context) as response:  # nosec B310: operator-supplied endpoint
            raw = response.read().decode("utf-8")
            if not raw:
                return response.status, None
            try:
                return response.status, json.loads(raw)
            except json.JSONDecodeError:
                return response.status, raw
    except HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(raw) if raw else None
        except json.JSONDecodeError:
            return exc.code, raw
    except URLError as exc:
        raise RuntimeError(f"request to {url} failed: {exc.reason}") from exc


def wait_for_interaction(server: str, test_id: str, *, insecure: bool, timeout: int) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status, info = request_json(urljoin(server, f"api/info/{test_id}"), insecure=insecure)
        if status == 200 and isinstance(info, dict):
            state = info.get("status")
            if state == "WAITING":
                return True
            if state == "INTERRUPTED":
                try:
                    print(
                        interrupted_failure_category(
                            server,
                            test_id,
                            insecure=insecure,
                        )
                    )
                except (OSError, RuntimeError, ValueError):
                    print("oidf-invariant-interrupted-diagnostic-unavailable")
                return False
            if state == "FINISHED":
                return False
        time.sleep(1)
    raise RuntimeError(f"OIDF module {test_id} did not reach WAITING within {timeout} seconds")


def required_offer_interactions(test_name: str) -> int:
    """Return the official module's number of issuer-driven offer phases."""
    if test_name in {
        "oid4vci-1_0-issuer-metadata-test",
        "oid4vci-1_0-issuer-metadata-test-signed",
    }:
        return 0
    return OFFER_INTERACTION_COUNTS.get(test_name, 1)


def offer_payload_for_interaction(
    payload: dict[str, Any],
    interaction: int,
) -> dict[str, Any]:
    """Bind each fresh offer to the official wallet client that will redeem it."""

    clients = payload.get("authorized_clients")
    if not isinstance(clients, list) or len(clients) < interaction:
        raise ValueError(f"issuance request has no authorized client for interaction {interaction}")
    client = clients[interaction - 1]
    if not isinstance(client, dict):
        raise ValueError(f"authorized client {interaction} must be an object")
    effective = {key: value for key, value in payload.items() if key != "authorized_clients"}
    effective["authorized_client"] = client
    return effective


def credential_offer_uri(issuance_url: str, api_key: str, payload: dict[str, Any], *, insecure: bool) -> str:
    status, response = request_json(
        issuance_url,
        method="POST",
        body=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
        insecure=insecure,
    )
    if status not in {200, 201, 202} or not isinstance(response, dict):
        raise RuntimeError(f"Marty issuance API returned HTTP {status}")
    uri = response.get("credential_offer_uri")
    if not isinstance(uri, str) or not uri:
        raise RuntimeError("Marty issuance API response has no credential_offer_uri")
    return uri


def command_credential_offer(command: Path, payload: dict[str, Any]) -> str:
    """Run a deployment-owned issuance transport without exposing its network."""
    if not command.is_file():
        raise ValueError(f"issuance command is missing: {command}")
    completed = subprocess.run(
        [sys.executable, str(command.resolve())],
        input=json.dumps(payload).encode("utf-8"),
        capture_output=True,
        check=False,
    )
    if completed.returncode:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"issuance command failed with exit code {completed.returncode}: {detail[:200]}")
    try:
        response = json.loads(completed.stdout.decode("utf-8"))
    except json.JSONDecodeError as exc:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"issuance command did not return JSON: {detail[:200]}") from exc
    uri = response.get("credential_offer_uri") if isinstance(response, dict) else None
    if not isinstance(uri, str) or not uri:
        raise RuntimeError("issuance command response has no credential_offer_uri")
    return uri


def deliver_offer(server: str, test_id: str, offer_uri: str, tx_code: str, *, insecure: bool) -> None:
    marker = "credential_offer="
    if marker not in offer_uri:
        raise RuntimeError("Marty issuance response has no inline credential_offer")
    offer = unquote(offer_uri.split(marker, 1)[1])
    offer_url = urljoin(server, f"test/{test_id}/credential_offer?credential_offer={quote(offer, safe='')}")
    status, _ = request_json(offer_url, insecure=insecure)
    if status not in {200, 201, 202, 204}:
        raise RuntimeError(f"OIDF credential_offer endpoint returned HTTP {status}")
    # The official suite may reject tx_code for profiles that do not need one.
    # Delivering it is harmless; the suite remains authoritative about the result.
    request_json(urljoin(server, f"test/{test_id}/tx_code?code={quote(tx_code, safe='')}"), insecure=insecure)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test-id", required=True)
    parser.add_argument("--test-name", required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("--issuance-url", default=os.environ.get("OIDF_ISSUANCE_URL"))
    parser.add_argument("--api-key", default=os.environ.get("OIDF_ISSUANCE_API_KEY"))
    parser.add_argument("--issuance-command", type=Path, default=os.environ.get("OIDF_ISSUANCE_COMMAND"))
    parser.add_argument("--request", type=Path, default=Path(os.environ.get("OIDF_ISSUANCE_REQUEST", DEFAULT_REQUEST)))
    parser.add_argument("--tx-code", default=os.environ.get("OIDF_TX_CODE", "000000"))
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--insecure", action="store_true", default=os.environ.get("OIDF_INSECURE_TLS") == "1")
    parser.add_argument(
        "--conformance-insecure",
        action="store_true",
        default=os.environ.get("OIDF_CONFORMANCE_INSECURE_TLS") == "1",
        help="skip TLS verification only for the isolated upstream runner",
    )
    parser.add_argument(
        "--issuance-insecure",
        action="store_true",
        default=os.environ.get("OIDF_ISSUANCE_INSECURE_TLS") == "1",
        help="skip TLS verification only for a disposable issuer endpoint",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.issuance_command is None and (not args.issuance_url or not args.api_key):
        raise ValueError("OIDF_ISSUANCE_URL and OIDF_ISSUANCE_API_KEY, or OIDF_ISSUANCE_COMMAND, are required")
    if not args.server:
        raise ValueError("CONFORMANCE_SERVER must be set")
    if not args.request.is_file():
        raise ValueError(f"issuance request is missing: {args.request}")
    conformance_insecure = args.insecure or args.conformance_insecure
    issuance_insecure = args.insecure or args.issuance_insecure
    interaction_count = required_offer_interactions(args.test_name)
    if interaction_count == 0:
        print(f"OIDF module {args.test_id} ({args.test_name}) requires no issuer interaction")
        return 0
    payload = json.loads(args.request.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("issuance request must be a JSON object")
    for interaction in range(1, interaction_count + 1):
        if not wait_for_interaction(
            args.server,
            args.test_id,
            insecure=conformance_insecure,
            timeout=args.timeout,
        ):
            if interaction == 1:
                print(f"OIDF module {args.test_id} ({args.test_name}) finished without issuer interaction")
                return 0
            raise RuntimeError(
                f"OIDF module {args.test_id} finished before issuer interaction {interaction} of {interaction_count}"
            )
        interaction_payload = offer_payload_for_interaction(payload, interaction)
        offer_uri = (
            command_credential_offer(args.issuance_command, interaction_payload)
            if args.issuance_command is not None
            else credential_offer_uri(
                args.issuance_url,
                args.api_key,
                interaction_payload,
                insecure=issuance_insecure,
            )
        )
        deliver_offer(
            args.server,
            args.test_id,
            offer_uri,
            args.tx_code,
            insecure=conformance_insecure,
        )
        print(
            f"Delivered Marty credential offer {interaction}/{interaction_count} "
            f"to OIDF module {args.test_id} ({args.test_name})"
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"OIDF issuer interaction failed: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
