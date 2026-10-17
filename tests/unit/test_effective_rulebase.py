from __future__ import annotations

import pytest

from panos_mcp.models.common import ConfigSource
from panos_mcp.services.policy import PolicyService, RuleFilters
from tests.conftest import ClientFactory

pytestmark = pytest.mark.anyio


async def test_effective_order_for_branch(replay_client: ClientFactory) -> None:
    client, _ = replay_client()
    rules, _ = await PolicyService(client).rules(
        "security", "Branch-DG", "both", True, RuleFilters(), ConfigSource.RUNNING
    )
    blocks: list[tuple[str, str]] = []
    for r in rules:
        key = (r.scope, r.position.value)
        if not blocks or blocks[-1] != key:
            blocks.append(key)
    assert blocks == [
        ("shared", "pre"),
        ("Global-DG", "pre"),
        ("Region-A-DG", "pre"),
        ("Branch-DG", "pre"),
        ("Branch-DG", "post"),
        ("Global-DG", "post"),
        ("shared", "post"),
    ]
    assert [r.order for r in rules] == list(range(1, len(rules) + 1))
    assert rules[0].name == "Block-Known-Bad" and rules[-1].name == "Log-And-Deny-All"


async def test_non_effective_is_own_scope_only(replay_client: ClientFactory) -> None:
    client, _ = replay_client()
    rules, _ = await PolicyService(client).rules(
        "security", "Branch-DG", "pre", False, RuleFilters(), ConfigSource.RUNNING
    )
    assert {r.scope for r in rules} == {"Branch-DG"} and len(rules) == 3


async def test_effective_post_only(replay_client: ClientFactory) -> None:
    client, _ = replay_client()
    rules, _ = await PolicyService(client).rules(
        "security", "Branch-DG", "post", True, RuleFilters(), ConfigSource.RUNNING
    )
    assert [r.name for r in rules] == ["Branch-Cleanup", "Global-Cleanup", "Log-And-Deny-All"]
