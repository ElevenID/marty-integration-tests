"""Observe actual public-server expiry without assuming the host clock is steady."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from time import monotonic

from .gateway_client import GatewayClient


async def wait_for_public_expiry(gateway: GatewayClient, expires_at: str) -> datetime:
    """Bound the wait monotonically; qualify expiry using the public HTTP clock."""
    expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    if expiry.tzinfo is None or expiry.utcoffset() != timedelta(0):
        raise ValueError("verification expiry must be an explicit UTC timestamp")
    deadline = monotonic() + 120
    while monotonic() < deadline:
        # Date has whole-second precision. The small margin also avoids probing
        # the exact request expiry while the public edge and backend schedule.
        response = await gateway.client.get("/health", headers={"Cache-Control": "no-cache"}, timeout=10)
        response.raise_for_status()
        value = response.headers.get("Date")
        if not value:
            raise ValueError("public server did not expose its HTTP clock")
        observed = parsedate_to_datetime(value)
        if observed.tzinfo is None or observed.utcoffset() != timedelta(0):
            raise ValueError("public HTTP clock is not UTC")
        if observed >= expiry + timedelta(seconds=2):
            return observed.astimezone(timezone.utc)
        await asyncio.sleep(1)
    raise TimeoutError("public server has not crossed the declared request expiry")
