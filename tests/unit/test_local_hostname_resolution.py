from __future__ import annotations

import importlib.util
import socket
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "local_hostname_resolution",
    ROOT / "scripts" / "local_hostname_resolution.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load local hostname resolution helper")
resolution = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(resolution)


def test_resolve_hosts_to_is_exact_and_restores_dns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[object] = []

    def original(host: object, *_args: object, **_kwargs: object) -> object:
        calls.append(host)
        return host

    monkeypatch.setattr(socket, "getaddrinfo", original)

    with resolution.resolve_hosts_to("127.0.0.1", {"Marty-OIDF.test"}):
        assert socket.getaddrinfo(b"marty-oidf.test", 443) == "127.0.0.1"
        assert socket.getaddrinfo("attacker.test", 443) == "attacker.test"

    assert socket.getaddrinfo is original
    assert calls == ["127.0.0.1", "attacker.test"]
