from __future__ import annotations

import pytest

from panos_mcp.models.common import ConfigSource, ErrorCode, ToolError
from panos_mcp.models.objects import Address, ObjectKind
from panos_mcp.services.objects import ObjectService
from tests.conftest import ClientFactory

pytestmark = pytest.mark.anyio
RUN = ConfigSource.RUNNING


async def test_nearest_scope_wins(replay_client: ClientFactory) -> None:
    client, _ = replay_client()
    items, _ = await ObjectService(client).get_objects(
        ObjectKind.ADDRESS, "Branch-DG", RUN, name="web-srv-01", include_inherited=True
    )
    by_scope = {o.scope: o for o in items}
    assert set(by_scope) == {"Branch-DG", "shared"}
    assert by_scope["Branch-DG"].effective is True and by_scope["shared"].effective is False
    branch = by_scope["Branch-DG"]
    assert isinstance(branch, Address) and branch.value == "10.30.1.10/32"


async def test_where_used(replay_client: ClientFactory) -> None:
    client, _ = replay_client()
    refs, warnings, _ = await ObjectService(client).find_references(
        "web-srv-01", ObjectKind.ADDRESS, "shared", RUN
    )
    found = {(r.referrer_kind.value, r.referrer_name, r.scope) for r in refs}
    assert ("address_group", "web-servers", "shared") in found
    assert ("security_rule", "Allow-LB", "Global-DG") in found
    assert ("security_rule", "Allow-Admin-Web", "Region-A-DG") in found
    assert ("nat_rule", "Static-Web-01", "shared") in found
    # Branch-DG defines its own web-srv-01: its references are shadowed, reported as warning
    assert not any(r.scope == "Branch-DG" for r in refs)
    assert any("Branch-DG" in w for w in warnings)


async def test_where_used_tag(replay_client: ClientFactory) -> None:
    client, _ = replay_client()
    refs, _, _ = await ObjectService(client).find_references("web", ObjectKind.TAG, "shared", RUN)
    found = {(r.referrer_kind.value, r.referrer_name) for r in refs}
    assert {
        ("address", "web-srv-01"),
        ("address", "web-srv-02"),
        ("dynamic_address_group_filter", "dyn-web"),
        ("security_rule", "Allow-Web-In"),
        ("address_group", "web-servers"),
    } <= found


async def test_where_used_profile_group(replay_client: ClientFactory) -> None:
    client, _ = replay_client()
    refs, _, _ = await ObjectService(client).find_references(
        "strict-profiles", ObjectKind.SECURITY_PROFILE_GROUP, "shared", RUN
    )
    assert [(r.referrer_name, r.field) for r in refs] == [("Allow-Web-In", "profile_group")]


async def test_where_used_not_defined(replay_client: ClientFactory) -> None:
    client, _ = replay_client()
    with pytest.raises(ToolError) as info:
        await ObjectService(client).find_references("web-srv-1", ObjectKind.ADDRESS, "shared", RUN)
    assert info.value.code is ErrorCode.NOT_FOUND and "web-srv-01" in info.value.info.suggestions


async def test_static_expansion_nested_and_deduplicated(replay_client: ClientFactory) -> None:
    client, _ = replay_client()
    group, _ = await ObjectService(client).resolve_address_group("all-servers", "shared", RUN, None)
    assert group.kind == "static" and group.nested_groups == ["web-servers"]
    assert sorted(a.name for a in group.addresses) == ["db-srv-01", "web-srv-01", "web-srv-02"]
    assert group.cycles_detected == []


async def test_cycle_reported(replay_client: ClientFactory) -> None:
    client, _ = replay_client("address-group-cycle")
    group, _ = await ObjectService(client).resolve_address_group("grp-a", "shared", RUN, None)
    assert group.cycles_detected == ["grp-a -> grp-b -> grp-a"]
    assert sorted(a.name for a in group.addresses) == ["db-srv-01", "web-srv-01"]


async def test_dynamic_without_and_with_serial(replay_client: ClientFactory) -> None:
    client, _ = replay_client()
    svc = ObjectService(client)
    group, _ = await svc.resolve_address_group("dyn-web", "shared", RUN, None)
    assert group.kind == "dynamic" and group.dynamic_filter == "'web' and 'prod'"
    assert group.addresses == [] and group.resolved_on is None
    group, _ = await svc.resolve_address_group("dyn-web", "shared", RUN, "900000000001")
    assert group.resolved_on == "900000000001"
    assert [a.value for a in group.addresses] == ["10.20.1.10", "10.20.1.11", "10.20.1.12"]


async def test_candidate_config(replay_client: ClientFactory) -> None:
    client, transport = replay_client("candidate-differs")
    items, _ = await ObjectService(client).get_objects(
        ObjectKind.ADDRESS, "shared", ConfigSource.CANDIDATE, name="db-srv-01"
    )
    assert isinstance(items[0], Address) and items[0].value == "10.20.2.20/32"
    assert all(
        r.params.get("action") == "get" for r in transport.requests if r.params["type"] == "config"
    )
