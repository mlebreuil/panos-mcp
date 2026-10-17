"""Every tool once against a lab Panorama; configuration must be unchanged afterwards."""

from __future__ import annotations

import pytest

from panos_mcp.samples.capture import snapshot
from tests.integration.live.conftest import LiveServer

pytestmark = pytest.mark.anyio


async def test_all_tools_read_only(live: LiveServer) -> None:
    before = await snapshot(live.client)

    info = await live.data("get_panorama_info")
    assert info["items"]["hostname"]
    devices = await live.data("list_managed_devices")
    groups = await live.data("list_device_groups")
    await live.data("list_templates")
    jobs = await live.data("list_jobs", limit=5)
    if jobs["items"]:
        await live.data("get_job", job_id=jobs["items"][0]["id"])
    scope = groups["items"][0]["name"] if groups["items"] else "shared"
    await live.data("get_security_rules", scope=scope, effective=True, limit=20)
    await live.data("get_nat_rules", scope=scope, effective=True, limit=20)
    addresses = await live.data("get_objects", kind="address", scope="shared", limit=5)
    if addresses["items"]:
        name = addresses["items"][0]["name"]
        await live.data("find_object_references", name=name, kind="address", scope="shared")
    address_groups = await live.data("get_objects", kind="address_group", limit=5)
    if address_groups["items"]:
        await live.data("resolve_address_group", name=address_groups["items"][0]["name"])
    await live.data("query_logs", log_type="system", since="1h", limit=5)
    connected = [d for d in devices["items"] if d["connected"]]
    if connected:
        result = await live.call(
            "test_security_policy_match",
            device_serial=connected[0]["serial"],
            from_zone="trust",
            to_zone="untrust",
            source="192.0.2.1",
            destination="198.51.100.1",
            protocol="tcp",
            destination_port=443,
        )
        # a zone may not exist on that firewall; any structured answer is fine, never a write
        assert result.structured_content is not None

    assert await snapshot(live.client) == before, "configuration changed during the session"
