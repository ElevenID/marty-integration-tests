"""Real expiry remains gated by the server clock across backward corrections."""
import asyncio
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from types import SimpleNamespace

import httpx
import pytest

from tests.integration.gateway.helpers import eudi_expiry


EPOCH = datetime(2026, 10, 26, 12, tzinfo=timezone.utc)


def response(seconds: int, *, date: bool = True) -> httpx.Response:
    return httpx.Response(200, request=httpx.Request("GET", "https://marty.test/health"),
                          headers={"Date": format_datetime(EPOCH + timedelta(seconds=seconds), usegmt=True)} if date else {})


def test_backward_public_clock_correction_does_not_satisfy_expiry(monkeypatch):
    replies = iter(response(n) for n in (59, 57, 61, 63))
    calls = []
    async def get(path, **kwargs):
        calls.append(path)
        return next(replies)
    async def sleep(_):
        pass
    monkeypatch.setattr(eudi_expiry.asyncio, "sleep", sleep)
    observed = asyncio.run(eudi_expiry.wait_for_public_expiry(
        SimpleNamespace(client=SimpleNamespace(get=get)), (EPOCH + timedelta(seconds=60)).isoformat()))
    assert observed == EPOCH + timedelta(seconds=63)
    assert calls == ["/health"] * 4


def test_missing_public_clock_fails_instead_of_claiming_expiry():
    async def get(*args, **kwargs):
        return response(80, date=False)
    with pytest.raises(ValueError, match="HTTP clock"):
        asyncio.run(eudi_expiry.wait_for_public_expiry(SimpleNamespace(client=SimpleNamespace(get=get)), EPOCH.isoformat()))


def test_expiry_wait_is_bounded_by_monotonic_time(monkeypatch):
    ticks = iter((0, 0, 121))
    monkeypatch.setattr(eudi_expiry, "monotonic", lambda: next(ticks))
    async def get(*args, **kwargs):
        return response(10)
    async def sleep(_):
        pass
    monkeypatch.setattr(eudi_expiry.asyncio, "sleep", sleep)
    with pytest.raises(TimeoutError, match="declared request expiry"):
        asyncio.run(eudi_expiry.wait_for_public_expiry(SimpleNamespace(client=SimpleNamespace(get=get)), (EPOCH + timedelta(seconds=60)).isoformat()))
