"""Scale budget (SC-003): typical lookups < 5 s at 500 firewalls / 10,000 rules.

Network latency of a real Panorama is excluded (research.md known gaps).
"""

from __future__ import annotations

import shutil
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from mcp_types import CallToolResult

from panos_mcp.client.replay import ReplayTransport
from panos_mcp.client.xmlapi import PanoramaClient
from panos_mcp.samples.generate import generate_large_estate
from panos_mcp.server import build_server
from tests.conftest import SAMPLES, offline_settings

pytestmark = [pytest.mark.benchmark, pytest.mark.anyio]
BUDGET_S = 5.0


@pytest.fixture(scope="module")
def estate(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("samples")
    shutil.copytree(SAMPLES, root, dirs_exist_ok=True)
    generate_large_estate(root, devices=500, rules=10000, seed=42)
    return root


@pytest.fixture
async def call(estate: Path) -> AsyncIterator[Any]:
    settings = offline_settings(samples_scenario="large-estate")
    client = PanoramaClient(settings, transport=ReplayTransport(estate, "large-estate"))
    server, _ = build_server(client, settings)

    async def run(tool: str, **args: Any) -> tuple[dict[str, Any], float]:
        start = time.perf_counter()
        result = await server.call_tool(tool, args)
        elapsed = time.perf_counter() - start
        assert isinstance(result, CallToolResult) and not result.is_error, result
        assert result.structured_content is not None
        return result.structured_content, elapsed

    yield run
    await client.aclose()


async def test_list_devices(call: Any) -> None:
    data, elapsed = await call("list_managed_devices")
    assert data["total"] == 504 and data["truncated"] and data["narrowing_hint"]
    assert elapsed < BUDGET_S, elapsed


async def test_effective_rules_with_ip_filter(call: Any) -> None:
    data, elapsed = await call(
        "get_security_rules", scope="Branch-DG", effective=True, destination="10.100.3.7"
    )
    assert data["total"] > 0 and data["truncated"] and data["narrowing_hint"]
    assert elapsed < BUDGET_S, elapsed


async def test_where_used(call: Any) -> None:
    data, elapsed = await call("find_object_references", name="gen-host-0007", kind="address")
    assert data["total"] > 0
    assert elapsed < BUDGET_S, elapsed
