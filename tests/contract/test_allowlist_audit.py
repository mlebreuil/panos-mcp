"""Constitution I / SC-005: across every scenario and tool, only allow-listed reads are sent."""

from __future__ import annotations

from typing import Any

import pytest

from panos_mcp.client.commands import TOOL_REQUESTS
from panos_mcp.samples.scenarios import list_scenarios
from tests.conftest import SAMPLES
from tests.contract.conftest import HarnessFactory

pytestmark = pytest.mark.anyio

INPUTS: dict[str, dict[str, Any]] = {
    "get_panorama_info": {},
    "list_managed_devices": {"device_group": "Branch-DG"},
    "list_device_groups": {},
    "list_templates": {},
    "list_jobs": {},
    "get_job": {"job_id": 102},
    "get_security_rules": {"scope": "Branch-DG", "effective": True, "destination": "10.20.0.0/16"},
    "get_nat_rules": {"scope": "Branch-DG", "effective": True},
    "get_objects": {"kind": "address", "include_inherited": True, "scope": "Branch-DG"},
    "find_object_references": {"name": "web-srv-01", "kind": "address"},
    "resolve_address_group": {"name": "dyn-web", "device_serial": "900000000001"},
    "query_logs": {"log_type": "traffic", "since": "1h", "device_serial": "900000000001"},
    "test_security_policy_match": {
        "device_serial": "900000000001",
        "from_zone": "trust",
        "to_zone": "dmz",
        "source": "10.10.1.5",
        "destination": "10.20.1.10",
        "protocol": "tcp",
        "destination_port": 443,
        "application": "ssl",
    },
}
SCENARIOS = [s for s in list_scenarios(SAMPLES) if s != "large-estate"]


def test_inputs_cover_every_tool() -> None:
    assert set(INPUTS) == set(TOOL_REQUESTS)


async def test_every_tool_is_read_only(harness: HarnessFactory) -> None:
    tools = await harness().server.list_tools()
    assert {t.name for t in tools} == set(TOOL_REQUESTS)
    for tool in tools:
        assert tool.annotations is not None
        assert tool.annotations.read_only_hint is True
        assert tool.annotations.destructive_hint is False


@pytest.mark.parametrize("scenario", SCENARIOS)
async def test_scenario_requests_are_allow_listed(harness: HarnessFactory, scenario: str) -> None:
    h = harness(scenario, query_timeout=0.01)
    for tool, args in INPUTS.items():
        await h.call(tool, **args)  # Harness.call audits each request (allow-list + declared)
    assert h.transport.requests, scenario
    for recorded in h.transport.requests:
        assert recorded.params["type"] in ("op", "config", "log")
        assert recorded.params.get("action") in (None, "get", "show")
