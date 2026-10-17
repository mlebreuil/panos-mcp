"""Contract tests for get_security_rules / get_nat_rules (contracts/mcp-tools.md §7-8)."""

from __future__ import annotations

import pytest

from tests.contract.conftest import HarnessFactory

pytestmark = pytest.mark.anyio
TOOLS = ["get_security_rules", "get_nat_rules"]


async def test_schemas(harness: HarnessFactory) -> None:
    tools = {t.name: t for t in await harness().server.list_tools()}
    sec = tools["get_security_rules"].input_schema["properties"]
    assert {
        "scope",
        "rulebase",
        "effective",
        "name_contains",
        "tag",
        "from_zone",
        "to_zone",
        "source",
        "destination",
        "application",
        "service",
        "action",
        "disabled",
        "config_source",
        "limit",
        "offset",
    } == set(sec)
    nat = tools["get_nat_rules"].input_schema["properties"]
    assert "application" not in nat and "action" not in nat
    for name in TOOLS:
        annotations = tools[name].annotations
        assert annotations is not None and annotations.read_only_hint is True


async def test_effective_rulebase_us2_1(harness: HarnessFactory) -> None:
    data = await harness().ok("get_security_rules", scope="Branch-DG", effective=True)
    assert data["config_source"] == "running"
    items = data["items"]
    assert items[0]["scope"] == "shared" and items[0]["position"] == "pre"
    assert items[-1]["scope"] == "shared" and items[-1]["position"] == "post"
    assert [r["order"] for r in items] == list(range(1, len(items) + 1))


async def test_filters_us2_4(harness: HarnessFactory) -> None:
    data = await harness().ok(
        "get_security_rules",
        scope="Branch-DG",
        effective=True,
        rulebase="pre",
        destination="10.20.0.0/16",
        action="allow",
    )
    names = [r["name"] for r in data["items"]]
    assert "Allow-Web-In" in names and "Allow-DNS" not in names


async def test_candidate_us2_5(harness: HarnessFactory) -> None:
    h = harness("candidate-differs")
    running = await h.ok("get_security_rules", scope="Branch-DG", rulebase="pre")
    candidate = await h.ok(
        "get_security_rules", scope="Branch-DG", rulebase="pre", config_source="candidate"
    )
    assert candidate["config_source"] == "candidate"
    assert "Allow-New-App" in [r["name"] for r in candidate["items"]]
    assert "Allow-New-App" not in [r["name"] for r in running["items"]]
    result = await h.call("get_security_rules", scope="Branch-DG", config_source="candidate")
    assert "candidate config" in result.content[0].text  # type: ignore[union-attr]


async def test_nat(harness: HarnessFactory) -> None:
    data = await harness().ok("get_nat_rules", scope="Branch-DG", effective=True)
    dnat = next(r for r in data["items"] if r["name"] == "DNAT-Web-8443")
    assert dnat["destination_translation"] == {
        "address": "web-srv-01",
        "port": 443,
        "dynamic": False,
    }


@pytest.mark.parametrize("tool", TOOLS)
async def test_unknown_scope(harness: HarnessFactory, tool: str) -> None:
    error = await harness().error(tool, scope="Brnch-DG")
    assert error["code"] == "not_found" and "Branch-DG" in error["suggestions"]


@pytest.mark.parametrize("tool", TOOLS)
async def test_auth_and_permission(harness: HarnessFactory, tool: str) -> None:
    assert (await harness("auth-failure").error(tool))["code"] == "auth_failed"
    assert (await harness("permission-denied").error(tool))["code"] == "permission_denied"


@pytest.mark.parametrize("tool", TOOLS)
async def test_truncation(harness: HarnessFactory, tool: str) -> None:
    data = await harness().ok(tool, scope="Branch-DG", effective=True, limit=2)
    assert data["truncated"] is True and data["next_offset"] == 2 and data["narrowing_hint"]
    nxt = await harness().ok(tool, scope="Branch-DG", effective=True, limit=2, offset=2)
    assert nxt["items"][0]["order"] == 3
