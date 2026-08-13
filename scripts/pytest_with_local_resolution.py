#!/usr/bin/env python3
"""Run pytest with exact disposable hostnames resolved to a local address."""

from __future__ import annotations

import argparse

import pytest
from local_hostname_resolution import resolve_hosts_to


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resolve-address", required=True)
    parser.add_argument("--resolve-host", action="append", default=[])
    args, pytest_args = parser.parse_known_args(argv)
    if pytest_args[:1] == ["--"]:
        pytest_args = pytest_args[1:]
    if not args.resolve_host:
        parser.error("at least one --resolve-host is required")
    if not pytest_args:
        parser.error("pytest arguments are required after --")
    with resolve_hosts_to(args.resolve_address, set(args.resolve_host)):
        return int(pytest.main(pytest_args))


if __name__ == "__main__":
    raise SystemExit(main())
