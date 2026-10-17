from __future__ import annotations

from datetime import datetime

import pytest

from panos_mcp.models.common import ErrorCode, ToolError
from panos_mcp.models.logs import LogType
from panos_mcp.services.logs import LogFilters, LogService, build_query, validate_advanced_filter
from tests.conftest import ClientFactory

NOW = datetime(2026, 10, 16, 9, 0, 0)


def test_structured_filters() -> None:
    q = build_query(
        LogFilters(
            source="10.1.1.5",
            destination="192.0.2.0/24",
            port=443,
            application="ssl",
            action="deny",
            rule="Allow Web",
            device_serial="900000000001",
            severity="high",
            since="1h",
            until="2026-10-16T08:30:00",
        ),
        NOW,
    )
    assert q == (
        "( addr.src in 10.1.1.5 ) and ( addr.dst in 192.0.2.0/24 ) and ( port.dst eq 443 ) and "
        "( app eq ssl ) and ( action eq deny ) and ( rule eq 'Allow Web' ) and "
        "( serial eq 900000000001 ) and ( severity eq high ) and "
        "( receive_time geq '2026/10/16 08:00:00' ) and ( receive_time leq '2026/10/16 08:30:00' )"
    )
    assert build_query(LogFilters(since="24h"), NOW) == "( receive_time geq '2026/10/15 09:00:00' )"
    assert build_query(LogFilters(), NOW) == ""


@pytest.mark.parametrize(
    "f",
    [
        LogFilters(source="10.1.1.999"),
        LogFilters(destination="not-an-ip"),
        LogFilters(port=0),
        LogFilters(port=70000),
        LogFilters(rule="it's"),
        LogFilters(since="yesterday-ish"),
        LogFilters(device_serial="bad serial"),
    ],
)
def test_invalid_structured_filters(f: LogFilters) -> None:
    with pytest.raises(ToolError) as info:
        build_query(f, NOW)
    assert info.value.code is ErrorCode.INVALID_INPUT


@pytest.mark.parametrize(
    "value",
    [
        "( zone.src eq trust ) and ( port.dst eq 443 )",
        "( addr.src in 10.0.0.0/8 ) or not ( app eq 'web-browsing' )",
        '( rule eq "Allow Web" )',
    ],
)
def test_advanced_filter_accepted(value: str) -> None:
    assert validate_advanced_filter(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "( zone.src eq 'trust )",
        "( app eq ssl",
        "app eq ssl )",
        "( bogus eq 1 )",
        "( app eq )",
        "( app eq ssl )\n( x )",
        "x" * 1001,
    ],
)
def test_advanced_filter_rejected(value: str) -> None:
    with pytest.raises(ToolError) as info:
        validate_advanced_filter(value)
    assert info.value.code is ErrorCode.INVALID_INPUT


@pytest.mark.anyio
async def test_limit_bounds(replay_client: ClientFactory) -> None:
    client, _ = replay_client(log_limit_max=50)
    svc = LogService(client)
    with pytest.raises(ToolError) as info:
        await svc.query(LogType.TRAFFIC, LogFilters(), 51)
    assert info.value.code is ErrorCode.INVALID_INPUT
    result = await svc.query(LogType.TRAFFIC, LogFilters(), 3)
    assert len(result.entries) == 3 and result.truncated


@pytest.mark.anyio
async def test_timeout_with_fake_clock(replay_client: ClientFactory) -> None:
    client, transport = replay_client("log-timeout", query_timeout=2)
    clock = [0.0]

    async def fake_sleep(seconds: float) -> None:
        clock[0] += seconds

    svc = LogService(client, monotonic=lambda: clock[0], sleep=fake_sleep)
    with pytest.raises(ToolError) as info:
        await svc.query(LogType.TRAFFIC, LogFilters(since="1h"), 10)
    assert info.value.code is ErrorCode.TIMEOUT and "time range" in info.value.info.hint
    assert clock[0] <= 2.0
    polls = [r for r in transport.requests if r.params.get("action") == "get"]
    assert 2 <= len(polls) <= 5  # bounded polling with backoff
