"""Stage generated official-suite hostnames on its disposable Linux runner."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

HOST = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\Z")


def append_host_aliases(address: str, aliases: list[str]) -> None:
    address = str(ipaddress.ip_address(address))
    if not aliases or any(not HOST.fullmatch(host) or len(host) > 253 for host in aliases):
        raise ValueError("disposable runner host alias is invalid")
    with subprocess.Popen(["sudo", "tee", "-a", "/etc/hosts"], stdin=subprocess.PIPE,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as writer:
        # Docker-generated hosts files can lack an EOF newline.
        writer.communicate(f"\n{address} {' '.join(aliases)}\n".encode("ascii"), timeout=10)
        if writer.returncode:
            raise RuntimeError("runner cannot stage disposable host aliases")


def material_aliases(report: dict) -> list[str]:
    if (report.get("schema") != "elevenid.eudi-test-material-report/v1"
            or not isinstance(report.get("urls"), dict) or "gateway" not in report["urls"]):
        raise ValueError("disposable runner requires its generated material report")
    hosts = {"localhost.emobix.co.uk"}
    for value in report["urls"].values():
        if not isinstance(value, str) or any(c.isspace() for c in value):
            raise ValueError("generated material URL is invalid")
        url = urlsplit(value)
        host = url.hostname
        if url.scheme not in {"http", "https"} or not host or url.username is not None or url.password is not None:
            raise ValueError("generated material URL is invalid")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if host != "localhost":
                if not HOST.fullmatch(host) or len(host) > 253:
                    raise ValueError("generated material hostname is invalid") from None
                hosts.add(host)
    return sorted(hosts)


def missing_aliases(existing: str, aliases: list[str]) -> list[str]:
    records = [line.partition("#")[0].split() for line in existing.splitlines()]
    pending = []
    for host in aliases:
        addresses = {record[0] for record in records if len(record) > 1 and host in record[1:]}
        if addresses - {"127.0.0.1"}:
            raise ValueError("disposable runner hostname has a conflicting existing address")
        if not addresses:
            pending.append(host)
    return pending


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--material-report", type=Path, required=True)
    parser.add_argument("--install", action="store_true")
    args = parser.parse_args()
    aliases = material_aliases(json.loads(args.material_report.read_text(encoding="utf-8")))
    if args.install:
        if os.name != "posix":
            raise RuntimeError("disposable runner host installation requires Linux")
        pending = missing_aliases(Path("/etc/hosts").read_text(encoding="utf-8"), aliases)
        if pending:
            append_host_aliases("127.0.0.1", pending)
    else:
        print("127.0.0.1 " + " ".join(aliases))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
