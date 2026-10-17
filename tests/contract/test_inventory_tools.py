"""Contract tests for the US1 tools (contracts/mcp-tools.md §1-6)."""

from __future__ import annotations

import pytest
from mcp.server.mcpserver.exceptions import ToolError as McpToolError

from tests.contract.conftest import HarnessFactory

pytestmark = pytest.mark.anyio

US1_TOOLS = [
    "get_panorama_info",
    "list_managed_devices",
    "list_device_groups",
    "list_templates",
    "list_jobs",
    "get_job",
]


async def test_registered_read_only_with_schemas(harness: HarnessFactory) -> None:
    tools = {t.name: t for t in await harness().server.list_tools()}
    for name in US1_TOOLS:
        tool = tools[name]
        assert tool.annotations is not None and tool.annotations.read_only_hint is True
        assert tool.annotations.destructive_hint is False
        assert tool.description and tool.output_schema
    props = tools["list_managed_devices"].input_schema["properties"]
    assert set(props) == {
        "device_group",
        "template_stack",
        "connected",
        "config_sync",
        "model",
        "sw_version",
        "limit",
        "offset",
    }
    assert props["limit"]["maximum"] == 500
    assert set(tools["get_job"].input_schema["required"]) == {"job_id"}


async def test_panorama_info(harness: HarnessFactory) -> None:
    data = await harness().ok("get_panorama_info")
    info = data["items"]
    assert info["hostname"] == "panorama-lab-01" and info["ha_state"] == "standalone"
    assert [lic["feature"] for lic in info["licenses"] if lic["expired"]] == ["Premium Support"]
    assert data["next_offset"] is None and data["truncated"] is False  # not-found/truncation N/A


async def test_panorama_info_partial_when_licenses_denied(harness: HarnessFactory) -> None:
    data = await harness("license-denied").ok("get_panorama_info")
    assert data["items"]["licenses"] == []
    assert any("license" in w for w in data["warnings"])


async def test_passive_peer_warning(harness: HarnessFactory) -> None:
    data = await harness("ha-passive").ok("get_panorama_info")
    assert data["items"]["ha_state"] == "passive"
    assert any("passive" in w for w in data["warnings"])


async def test_list_devices_baseline(harness: HarnessFactory) -> None:
    data = await harness().ok("list_managed_devices")
    assert data["total"] == 4
    hq = next(d for d in data["items"] if d["serial"] == "900000000001")
    assert hq["device_group"] == "Region-A-DG" and hq["template_stack"] == "Stack-A"


async def test_disconnected_device(harness: HarnessFactory) -> None:
    data = await harness("disconnected-device").ok("list_managed_devices", connected=False)
    assert [d["serial"] for d in data["items"]] == ["900000000003"]


async def test_out_of_sync(harness: HarnessFactory) -> None:
    data = await harness("out-of-sync").ok("list_managed_devices", config_sync="out_of_sync")
    assert {d["hostname"] for d in data["items"]} == {"fw-hq-02", "fw-dc-01"}


async def test_filters(harness: HarnessFactory) -> None:
    h = harness()
    assert (await h.ok("list_managed_devices", sw_version="10.2"))["total"] == 1
    assert (await h.ok("list_managed_devices", device_group="Region-A-DG"))["total"] == 2
    assert (await h.ok("list_managed_devices", template_stack="Stack-B"))["total"] == 1
    assert (await h.ok("list_managed_devices", model="pa-440"))["total"] == 1


@pytest.mark.parametrize(
    ("tool", "args", "suggestion"),
    [
        ("list_managed_devices", {"device_group": "Region-A-GD"}, "Region-A-DG"),
        ("list_managed_devices", {"template_stack": "Stack-AA"}, "Stack-A"),
        ("list_device_groups", {"root": "Branch-GD"}, "Branch-DG"),
        ("list_templates", {"name": "T-Bse"}, "T-Base"),
    ],
)
async def test_not_found_with_suggestions(
    harness: HarnessFactory, tool: str, args: dict[str, str], suggestion: str
) -> None:
    error = await harness().error(tool, **args)
    assert error["code"] == "not_found" and suggestion in error["suggestions"]


async def test_list_jobs_no_match_is_empty(harness: HarnessFactory) -> None:
    data = await harness().ok("list_jobs", job_type="NoSuchType")
    assert data["items"] == [] and data["total"] == 0


async def test_get_job(harness: HarnessFactory) -> None:
    h = harness()
    job = (await h.ok("get_job", job_id=102))["items"]
    assert job["result"] == "fail" and job["devices"][0]["result"] == "fail"
    error = await h.error("get_job", job_id=999999)
    assert error["code"] == "not_found"


async def test_get_job_schema_rejects_zero(harness: HarnessFactory) -> None:
    # Schema violations are rejected by the MCP SDK before the tool runs (contract note);
    # in-process it raises, on the wire it becomes an isError result naming the argument.
    with pytest.raises(McpToolError, match="job_id"):
        await harness().server.call_tool("get_job", {"job_id": 0})


async def test_truncation(harness: HarnessFactory) -> None:
    h = harness()
    for tool, args in [
        ("list_managed_devices", {"limit": 2}),
        ("list_device_groups", {"limit": 2}),
        ("list_templates", {"limit": 1}),
        ("list_jobs", {"limit": 2}),
    ]:
        data = await h.ok(tool, **args)
        assert data["truncated"] is True and data["narrowing_hint"], tool
        assert data["next_offset"] == args["limit"], tool
    job = await h.ok("get_job", job_id=102, max_devices=2)
    assert job["truncated"] is True and job["total"] == 3 and len(job["items"]["devices"]) == 2
    assert job["items"]["devices"][0]["result"] == "fail" and job["narrowing_hint"]


async def test_jobs_newest_first(harness: HarnessFactory) -> None:
    data = await harness().ok("list_jobs")
    assert [j["id"] for j in data["items"]] == [106, 105, 104, 103, 102, 101]


@pytest.mark.parametrize("tool", US1_TOOLS)
async def test_auth_failure(harness: HarnessFactory, tool: str) -> None:
    args = {"job_id": 102} if tool == "get_job" else {}
    error = await harness("auth-failure").error(tool, **args)
    assert error["code"] == "auth_failed"


@pytest.mark.parametrize("tool", US1_TOOLS)
async def test_permission_denied(harness: HarnessFactory, tool: str) -> None:
    args = {"job_id": 102} if tool == "get_job" else {}
    error = await harness("permission-denied").error(tool, **args)
    assert error["code"] == "permission_denied"
    assert "XML API" in error["hint"]


async def test_baseline_11_2(harness: HarnessFactory) -> None:
    h = harness("baseline-11-2")
    assert (await h.ok("get_panorama_info"))["items"]["sw_version"].startswith("11.2")
    assert (await h.ok("list_managed_devices"))["total"] == 4
