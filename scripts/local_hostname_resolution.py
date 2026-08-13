"""Scoped hostname resolution for disposable local interoperability endpoints."""

from __future__ import annotations

import socket
from collections.abc import Iterator
from contextlib import contextmanager


def _normalized_host(value: str | bytes | None) -> str | None:
    if isinstance(value, bytes):
        try:
            value = value.decode("idna")
        except UnicodeError:
            return None
    return value.rstrip(".").casefold() if isinstance(value, str) else None


@contextmanager
def resolve_hosts_to(address: str, hosts: set[str]) -> Iterator[None]:
    """Resolve an exact hostname allowlist to one address, then restore DNS."""
    normalized_address = address.strip()
    normalized_hosts = {
        normalized
        for host in hosts
        if (normalized := _normalized_host(host.strip()))
    }
    if not normalized_address or not normalized_hosts:
        yield
        return

    original_getaddrinfo = socket.getaddrinfo

    def _getaddrinfo(
        host: str | bytes | None,
        port: str | bytes | int | None,
        family: int = 0,
        type: int = 0,  # noqa: A002 - mirrors socket.getaddrinfo's public API
        proto: int = 0,
        flags: int = 0,
    ) -> object:
        resolved_host = (
            normalized_address
            if _normalized_host(host) in normalized_hosts
            else host
        )
        return original_getaddrinfo(
            resolved_host,
            port,
            family,
            type,
            proto,
            flags,
        )

    socket.getaddrinfo = _getaddrinfo  # type: ignore[assignment]
    try:
        yield
    finally:
        socket.getaddrinfo = original_getaddrinfo
