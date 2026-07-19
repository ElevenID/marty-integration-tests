#!/usr/bin/env python3
"""Local browser adapter for the official OIDF runner's front-channel tests.

The OpenID Foundation suite owns the test state and assertions. This adapter
only implements the local Docker networking needed to visit an issuer URL and
execute the suite's callback JavaScript handoff. Certification deployments use
a real browser instead and do not invoke this file.
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
from urllib.parse import urlencode, urljoin
from urllib.error import HTTPError
from urllib.request import Request, urlopen


TARGET_TEST = "oid4vci-1_0-issuer-happy-flow-multiple-clients"


def request_json(url: str, *, method: str = "GET", body: bytes | None = None) -> tuple[int, object]:
    request = Request(url, data=body, method=method)
    context = ssl._create_unverified_context()  # nosec B323: local disposable runner only
    try:
        with urlopen(request, timeout=15, context=context) as response:  # nosec B310: local runner URL
            raw = response.read().decode("utf-8")
            return response.status, json.loads(raw) if raw else None
    except HTTPError as exc:
        return exc.code, None


def docker_curl(args: list[str]) -> str:
    container = os.environ.get("OIDF_CONFORMANCE_CONTAINER", "oidf-conformance-suite-release-v520-server-1")
    completed = subprocess.run(
        ["docker", "exec", container, "curl", "-ksS", *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError("local browser transport failed")
    return completed.stdout


def latest_implicit_submission(server: str, test_id: str) -> str | None:
    _, entries = request_json(urljoin(server, f"api/log/{test_id}"))
    if not isinstance(entries, list):
        return None
    for entry in reversed(entries):
        if isinstance(entry, dict) and entry.get("src") == "CreateRandomImplicitSubmitUrl":
            implicit = entry.get("implicit_submit")
            if isinstance(implicit, dict) and isinstance(implicit.get("fullUrl"), str):
                return implicit["fullUrl"]
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test-id", required=True)
    parser.add_argument("--test-name", required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument(
        "--offer-refresh-script",
        default=os.environ.get("OIDF_BROWSER_OFFER_REFRESH_SCRIPT", "scripts/oidf_marty_offer.py"),
        help="deployment-owned command that creates the second, one-time credential offer",
    )
    args = parser.parse_args()
    if args.test_name != TARGET_TEST:
        return 0

    deadline = time.monotonic() + args.timeout
    visited: set[str] = set()
    while time.monotonic() < deadline:
        status, browser = request_json(urljoin(args.server, f"api/runner/browser/{args.test_id}"))
        if status != 200:
            time.sleep(0.5)
            continue
        urls = browser.get("urls", []) if isinstance(browser, dict) else []
        pending = [url for url in urls if isinstance(url, str) and url not in visited]
        if not pending:
            time.sleep(0.5)
            continue
        for url in pending:
            # The official multiple-client module uses two wallet clients. A
            # fresh offer keeps Marty pre-authorized codes single-use while
            # exercising the real issuance initiation path for client two.
            refresh = subprocess.run(
                [
                    sys.executable, args.offer_refresh_script, "--test-id", args.test_id,
                    "--test-name", args.test_name, "--server", args.server,
                ],
                check=False,
            )
            if refresh.returncode:
                raise RuntimeError("second credential offer delivery failed")
            headers = docker_curl(["-D", "-", "-o", "/dev/null", "--max-time", "15", url])
            match = re.search(r"(?im)^location:\s*(\S+)", headers)
            if not match:
                raise RuntimeError("issuer authorization endpoint did not return a redirect")
            callback = match.group(1)
            docker_curl([
                "--connect-to", "localhost.emobix.co.uk:8443:host.docker.internal:8443",
                "-o", "/dev/null", "--max-time", "15", callback,
            ])
            implicit = None
            for _ in range(20):
                implicit = latest_implicit_submission(args.server, args.test_id)
                if implicit:
                    break
                time.sleep(0.25)
            if not implicit:
                raise RuntimeError("OIDF callback did not create an implicit submission URL")
            docker_curl([
                "--connect-to", "localhost.emobix.co.uk:8443:host.docker.internal:8443",
                "-X", "POST", "-H", "Content-Type: text/plain", "-o", "/dev/null",
                "--max-time", "15", implicit,
            ])
            request_json(
                urljoin(args.server, f"api/runner/browser/{args.test_id}/visit?{urlencode({'url': url})}"),
                method="POST",
            )
            visited.add(url)
            print(f"Completed local browser handoff for OIDF module {args.test_id}")
            return 0
    raise RuntimeError(f"OIDF module {args.test_id} did not expose a browser URL")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"OIDF browser interaction failed: {exc}", file=os.sys.stderr)
        raise SystemExit(2) from exc
