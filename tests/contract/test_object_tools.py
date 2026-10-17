"""Contract tests for get_objects / find_object_references / resolve_address_group (§9-11)."""

from __future__ import annotations

import pytest

from tests.contract.conftest import HarnessFactory

pytestmark = pytest.mark.anyio
TOOLS = {
    "get_objects": {"kind": "address"},
    "find_object_references": {"name": "web-srv-01", "kind": "address"},
    "resolve_address_group": {"name": "all-servers"},
}


async def test_schemas(harness: HarnessFactory) -> None:
    tools = {t.name: t for t in await harness().server.list_tools()}
    assert set(tools["get_objects"].input_schema["properties"]) == {
        "kind",
        "scope",
        "name",
        "name_contains",
        "value_contains",
        "include_inherited",
        "config_source",
        "limit",
        "offset",
    }
    assert set(tools["find_object_references"].input_schema["properties"]) == {
        "name",
        "kind",
        "scope",
        "config_source",
        "limit",
        "offset",
    }
    assert set(tools["resolve_address_group"].input_schema["properties"]) == {
        "name",
        "scope",
        "device_serial",
        "config_source",
        "max_addresses",
    }
    for name in TOOLS:
        annotations = tools[name].annotations
        assert annotations is not None and annotations.read_only_hint is True


async def test_references_us2_2(harness: HarnessFactory) -> None:
    data = await harness().ok("find_object_references", name="web-srv-01", kind="address")
    refs = {(r["referrer_kind"], r["referrer_name"], r["scope"]) for r in data["items"]}
    assert ("address_group", "web-servers", "shared") in refs
    assert ("security_rule", "Allow-Admin-Web", "Region-A-DG") in refs
    assert any("Branch-DG" in w for w in data["warnings"])


async def test_expansion_us2_3(harness: HarnessFactory) -> None:
    data = await harness().ok("resolve_address_group", name="all-servers")
    group = data["items"]
    assert group["nested_groups"] == ["web-servers"]
    assert sorted(a["name"] for a in group["addresses"]) == [
        "db-srv-01",
        "web-srv-01",
        "web-srv-02",
    ]


async def test_override_flagged_effective(harness: HarnessFactory) -> None:
    data = await harness().ok(
        "get_objects", kind="address", scope="Branch-DG", name="web-srv-01", include_inherited=True
    )
    flags = {o["scope"]: o["effective"] for o in data["items"]}
    assert flags == {"Branch-DG": True, "shared": False}


async def test_cycle(harness: HarnessFactory) -> None:
    data = await harness("address-group-cycle").ok("resolve_address_group", name="grp-a")
    assert data["items"]["cycles_detected"] == ["grp-a -> grp-b -> grp-a"]


async def test_dynamic_group_needs_serial(harness: HarnessFactory) -> None:
    h = harness()
    data = await h.ok("resolve_address_group", name="dyn-web")
    assert data["items"]["kind"] == "dynamic" and data["warnings"]
    data = await h.ok("resolve_address_group", name="dyn-web", device_serial="900000000001")
    assert len(data["items"]["addresses"]) == 3


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("get_objects", {"kind": "address", "name": "web-srv-1"}),
        ("get_objects", {"kind": "address", "scope": "Nope-DG"}),
        ("find_object_references", {"name": "web-srv-1", "kind": "address"}),
        ("resolve_address_group", {"name": "web-servrs"}),
    ],
)
async def test_not_found(harness: HarnessFactory, tool: str, args: dict[str, str]) -> None:
    error = await harness().error(tool, **args)
    assert error["code"] == "not_found" and error["suggestions"]


@pytest.mark.parametrize("tool", list(TOOLS))
async def test_auth_and_permission(harness: HarnessFactory, tool: str) -> None:
    assert (await harness("auth-failure").error(tool, **TOOLS[tool]))["code"] == "auth_failed"
    error = await harness("permission-denied").error(tool, **TOOLS[tool])
    assert error["code"] == "permission_denied"


async def test_truncation(harness: HarnessFactory) -> None:
    h = harness()
    data = await h.ok("get_objects", kind="address", limit=2)
    assert data["truncated"] and data["next_offset"] == 2
    data = await h.ok("find_object_references", name="web-srv-01", kind="address", limit=2)
    assert data["truncated"] and data["next_offset"] == 2 and data["total"] >= 3
    data = await h.ok("resolve_address_group", name="all-servers", max_addresses=2)
    assert data["truncated"] and data["total"] == 3 and len(data["items"]["addresses"]) == 2
    assert data["narrowing_hint"] and data["next_offset"] is None


async def test_invalid_name_input(harness: HarnessFactory) -> None:
    error = await harness().error("get_objects", kind="address", name="bad\nname")
    assert error["code"] == "invalid_input"
