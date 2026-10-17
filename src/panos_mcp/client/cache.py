"""Small async-safe TTL cache for config subtree reads, keyed by (action, xpath)."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from datetime import datetime
from xml.etree.ElementTree import Element

from panos_mcp.models.common import now_utc

CacheKey = tuple[str, str]


class TTLCache:
    def __init__(self, ttl: float, clock: Callable[[], float] = time.monotonic) -> None:
        self.ttl = ttl
        self._clock = clock
        self._entries: dict[CacheKey, tuple[float, datetime, Element]] = {}
        self._locks: dict[CacheKey, asyncio.Lock] = {}

    async def get_or_fetch(
        self, key: CacheKey, fetch: Callable[[], Awaitable[Element]]
    ) -> tuple[datetime, Element]:
        """Return `(retrieved_at, element)`, fetching when missing or expired."""
        if self.ttl <= 0:
            return now_utc(), await fetch()
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            hit = self._entries.get(key)
            if hit is not None and self._clock() - hit[0] < self.ttl:
                return hit[1], hit[2]
            element = await fetch()
            retrieved_at = now_utc()
            self._entries[key] = (self._clock(), retrieved_at, element)
            return retrieved_at, element

    def clear(self) -> None:
        self._entries.clear()
