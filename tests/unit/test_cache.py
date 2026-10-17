from __future__ import annotations

from xml.etree.ElementTree import Element

import pytest

from panos_mcp.client.cache import TTLCache

pytestmark = pytest.mark.anyio


async def test_ttl_hit_and_expiry() -> None:
    now = [0.0]
    cache = TTLCache(30, clock=lambda: now[0])
    calls = 0

    async def fetch() -> Element:
        nonlocal calls
        calls += 1
        return Element("result", {"n": str(calls)})

    t1, e1 = await cache.get_or_fetch(("show", "/x"), fetch)
    now[0] = 10
    t2, e2 = await cache.get_or_fetch(("show", "/x"), fetch)
    assert calls == 1 and e1 is e2 and t1 == t2
    await cache.get_or_fetch(("get", "/x"), fetch)
    assert calls == 2
    now[0] = 31
    _, e3 = await cache.get_or_fetch(("show", "/x"), fetch)
    assert calls == 3 and e3.get("n") == "3"


async def test_ttl_zero_disables() -> None:
    cache = TTLCache(0)
    calls = 0

    async def fetch() -> Element:
        nonlocal calls
        calls += 1
        return Element("result")

    await cache.get_or_fetch(("show", "/x"), fetch)
    await cache.get_or_fetch(("show", "/x"), fetch)
    assert calls == 2
