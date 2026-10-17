"""Contract tests for query_logs / test_security_policy_match (contracts/mcp-tools.md §12-13)."""

from __future__ import annotations

import re
from typing import Any

import pytest

from tests.contract.conftest import HarnessFactory

pytestmark = pytest.mark.anyio

ALLOW = {
    "device_serial": "900000000001",
    "from_zone": "trust",
    "to_zone": "dmz",
    "source": "10.10.1.5",
    "destination": "10.20.1.10",
    "protocol": "tcp",
    "destination_port": 443,
    "application": "ssl",
}
DENY = {
    "device_serial": "900000000001",
    "from_zone": "trust",
    "to_zone": "untrust",
    "source": "10.10.1.5",
    "destination": "192.0.2.66",
    "protocol": 6,
    "destination_port": 23,
}
NO_MATCH = {
    "device_serial": "900000000001",
    "from_zone": "dmz",
    "to_zone": "trust",
    "source": "10.20.1.10",
    "destination": "10.10.1.5",
    "protocol": "udp",
    "destination_port": 161,
}
TOOLS: dict[str, dict[str, Any]] = {
    "query_logs": {"log_type": "traffic"},
    "test_security_policy_match": ALLOW,
}


async def test_schemas(harness: HarnessFactory) -> None:
    tools = {t.name: t for t in await harness().server.list_tools()}
    assert set(tools["query_logs"].input_schema["properties"]) == {
        "log_type",
        "since",
        "until",
        "source",
        "destination",
        "port",
        "application",
        "action",
        "rule",
        "device_serial",
        "severity",
        "advanced_filter",
        "limit",
    }
    assert set(tools["test_security_policy_match"].input_schema["required"]) == {
        "device_serial",
        "from_zone",
        "to_zone",
        "source",
        "destination",
        "protocol",
    }
    for name in TOOLS:
        annotations = tools[name].annotations
        assert annotations is not None and annotations.read_only_hint is True


async def test_query_logs_us3_1(harness: HarnessFactory) -> None:
    h = harness()
    data = await h.ok(
        "query_logs",
        log_type="traffic",
        destination="192.0.2.10",
        action="deny",
        since="1h",
        limit=2,
    )
    start = next(r for r in h.transport.requests if r.params.get("log-type") == "traffic")
    assert re.fullmatch(
        r"\( addr\.dst in 192\.0\.2\.10 \) and \( action eq deny \) and "
        r"\( receive_time geq '\d{4}/\d\d/\d\d \d\d:\d\d:\d\d' \)",
        start.params["query"],
    )
    assert start.params["nlogs"] == "3"  # limit + 1 to detect truncation
    items = data["items"]
    assert len(items) == 2 and data["truncated"] is True and data["narrowing_hint"]
    assert items[0]["receive_time"] >= items[1]["receive_time"]
    assert data["warnings"]  # relative-time note


@pytest.mark.parametrize("log_type", ["threat", "url", "system", "config"])
async def test_other_log_types(harness: HarnessFactory, log_type: str) -> None:
    data = await harness().ok("query_logs", log_type=log_type)
    assert data["returned"] >= 3 and data["truncated"] is False
    assert all(e["log_type"] == log_type for e in data["items"])


async def test_timeout_us3_3(harness: HarnessFactory) -> None:
    error = await harness("log-timeout", query_timeout=1).error("query_logs", log_type="traffic")
    assert error["code"] == "timeout" and "time range" in error["hint"]


async def test_policy_match_us3_2(harness: HarnessFactory) -> None:
    h = harness()
    allow = (await h.ok("test_security_policy_match", **ALLOW))["items"]
    assert (
        allow["matched"] and allow["rule_name"] == "Allow-Admin-Web" and allow["action"] == "allow"
    )
    deny = (await h.ok("test_security_policy_match", **DENY))["items"]
    assert deny["rule_name"] == "Block-Known-Bad" and deny["action"] == "deny"
    none = (await h.ok("test_security_policy_match", **NO_MATCH))["items"]
    assert none["matched"] is False and "default" in none["note"]


async def test_policy_match_disconnected(harness: HarnessFactory) -> None:
    args = {**ALLOW, "device_serial": "900000000003"}
    error = await harness("disconnected-device").error("test_security_policy_match", **args)
    assert error["code"] == "device_unavailable"


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("query_logs", {"log_type": "traffic", "source": "10.1.1.999"}),
        ("query_logs", {"log_type": "traffic", "port": 0}),
        ("query_logs", {"log_type": "traffic", "advanced_filter": "( bogus eq 1 )"}),
        ("test_security_policy_match", {**ALLOW, "source": "not-an-ip"}),
        ("test_security_policy_match", {**ALLOW, "protocol": 300}),
    ],
)
async def test_invalid_input(harness: HarnessFactory, tool: str, args: dict[str, Any]) -> None:
    assert (await harness().error(tool, **args))["code"] == "invalid_input"


@pytest.mark.parametrize("tool", list(TOOLS))
async def test_unknown_serial(harness: HarnessFactory, tool: str) -> None:
    args = {**TOOLS[tool], "device_serial": "900000000009"}
    error = await harness().error(tool, **args)
    assert error["code"] == "not_found" and error["suggestions"]


@pytest.mark.parametrize("tool", list(TOOLS))
async def test_auth_and_permission(harness: HarnessFactory, tool: str) -> None:
    assert (await harness("auth-failure").error(tool, **TOOLS[tool]))["code"] == "auth_failed"
    error = await harness("permission-denied").error(tool, **TOOLS[tool])
    assert error["code"] == "permission_denied"


async def test_policy_match_single_result(harness: HarnessFactory) -> None:
    data = await harness().ok("test_security_policy_match", **ALLOW)
    assert data["returned"] == 1 and data["next_offset"] is None  # truncation N/A


async def test_log_get_only_for_own_jobs(harness: HarnessFactory) -> None:
    h = harness()
    await h.ok("query_logs", log_type="system")
    gets = [r for r in h.transport.requests if r.params.get("action") == "get"]
    assert gets and all(int(r.params["job-id"]) in h.client.started_log_jobs for r in gets)
