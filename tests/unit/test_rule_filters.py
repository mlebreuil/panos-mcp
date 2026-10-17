from __future__ import annotations

from typing import Literal

import pytest

from panos_mcp.models.common import ConfigSource
from panos_mcp.models.policy import RuleAction
from panos_mcp.services.policy import PolicyService, RuleFilters
from tests.conftest import ClientFactory

pytestmark = pytest.mark.anyio


async def names(
    replay_client: ClientFactory,
    scope: str,
    f: RuleFilters,
    effective: bool = True,
    rule_type: Literal["security", "nat"] = "security",
) -> list[str]:
    client, _ = replay_client()
    rules, _ = await PolicyService(client).rules(
        rule_type,
        scope,
        "both",
        effective,
        f,
        ConfigSource.RUNNING,
    )
    return [r.name for r in rules]


async def test_destination_cidr_matches_resolved_addresses(replay_client: ClientFactory) -> None:
    got = await names(
        replay_client,
        "Region-A-DG",
        RuleFilters(destination="10.20.0.0/16", action=RuleAction.ALLOW),
    )
    # direct object (web-srv-01), nested group (all-servers), group (web-servers), "any"
    assert {"Allow-Web-In", "Allow-LB", "Allow-Admin-Web", "Allow-Partners"} <= set(got)
    assert "Allow-DNS" not in got  # 10.1.1.53 is outside 10.20/16


async def test_branch_override_changes_resolution(replay_client: ClientFactory) -> None:
    got = await names(
        replay_client, "Branch-DG", RuleFilters(destination="10.20.1.10"), effective=False
    )
    assert "Allow-Branch-To-Web01" not in got  # web-srv-01 resolves to 10.30.1.10 in Branch-DG
    got = await names(
        replay_client, "Branch-DG", RuleFilters(destination="10.30.1.10"), effective=False
    )
    assert "Allow-Branch-To-Web01" in got


async def test_name_filters_through_groups(replay_client: ClientFactory) -> None:
    got = await names(replay_client, "Region-A-DG", RuleFilters(destination="db-srv-01"))
    assert "Allow-Partners" in got  # all-servers contains db-srv-01
    got = await names(replay_client, "Region-A-DG", RuleFilters(application="ssl"))
    assert {"Allow-Web-In", "Allow-LB", "Allow-Partners"} <= set(got)  # web-apps contains ssl
    got = await names(replay_client, "Region-A-DG", RuleFilters(service="svc-tcp-8443"))
    assert "Allow-Admin-Web" in got  # web-svcs contains svc-tcp-8443


async def test_simple_filters_and_combination(replay_client: ClientFactory) -> None:
    assert await names(replay_client, "Global-DG", RuleFilters(disabled=True)) == ["Legacy-FTP"]
    got = await names(replay_client, "Branch-DG", RuleFilters(tag="web", from_zone="trust"))
    assert got == ["Allow-Branch-Web"]
    got = await names(replay_client, "Branch-DG", RuleFilters(name_contains="cleanup"))
    assert got == ["Branch-Cleanup", "Global-Cleanup"]
    got = await names(replay_client, "shared", RuleFilters(to_zone="dmz"), effective=False)
    assert "Allow-Web-In" in got and "Allow-DNS" not in got
    assert "Block-Known-Bad" in got  # "any" matches every zone


async def test_negated_source(replay_client: ClientFactory) -> None:
    got = await names(
        replay_client, "Region-A-DG", RuleFilters(source="192.0.2.1"), effective=False
    )
    assert "Deny-Not-Corp" in got  # negated corp-net: outside addresses match
    got = await names(replay_client, "Region-A-DG", RuleFilters(source="10.1.2.3"), effective=False)
    assert "Deny-Not-Corp" not in got


async def test_nat_filters(replay_client: ClientFactory) -> None:
    order = await names(replay_client, "Branch-DG", RuleFilters(), rule_type="nat")
    assert order == [
        "SNAT-Outbound",
        "Static-Web-01",
        "DNAT-Web-8443",
        "Branch-SNAT-Pool",
        "Branch-No-NAT-VPN",
    ]
    got = await names(
        replay_client, "Branch-DG", RuleFilters(service="svc-tcp-8443"), rule_type="nat"
    )
    assert "DNAT-Web-8443" in got  # exact service; the others use "any"
    got = await names(
        replay_client, "Branch-DG", RuleFilters(service="service-http"), rule_type="nat"
    )
    assert "DNAT-Web-8443" not in got and "SNAT-Outbound" in got
    got = await names(
        replay_client, "Branch-DG", RuleFilters(destination="corp-net"), rule_type="nat"
    )
    assert "Branch-No-NAT-VPN" in got
