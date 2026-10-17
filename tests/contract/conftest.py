"""Contract-test harness: the real MCP server on a replay scenario."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from typing import Any

import pytest
from mcp.server.mcpserver import MCPServer
from mcp_types import CallToolResult

from panos_mcp.client.allowlist import check_request
from panos_mcp.client.commands import TOOL_REQUESTS
from panos_mcp.client.replay import ReplayTransport
from panos_mcp.client.xmlapi import PanoramaClient
from panos_mcp.server import build_server
from tests.conftest import SAMPLES, offline_settings


@dataclass
class Harness:
    server: MCPServer
    client: PanoramaClient
    transport: ReplayTransport

    async def call(self, tool: str, **arguments: Any) -> CallToolResult:
        start = len(self.transport.requests)
        result = await self.server.call_tool(tool, arguments)
        assert isinstance(result, CallToolResult)
        self.audit(tool, start)
        return result

    async def ok(self, tool: str, **arguments: Any) -> dict[str, Any]:
        result = await self.call(tool, **arguments)
        assert not result.is_error, result.content
        assert result.structured_content is not None
        data: dict[str, Any] = result.structured_content
        return data

    async def error(self, tool: str, **arguments: Any) -> dict[str, Any]:
        result = await self.call(tool, **arguments)
        assert result.is_error, result.structured_content
        assert result.structured_content is not None
        error: dict[str, Any] = result.structured_content["error"]
        return error

    def audit(self, tool: str, start: int) -> None:
        """Every request is allow-listed and declared for this tool in TOOL_REQUESTS."""
        templates = TOOL_REQUESTS[tool]
        for recorded in self.transport.requests[start:]:
            check_request(recorded.params, self.client.started_log_jobs)
            assert any(t.matches(recorded.params) for t in templates), (
                f"{tool} issued an undeclared request: {recorded.key}"
            )


HarnessFactory = Callable[..., Harness]


@pytest.fixture
async def harness() -> AsyncIterator[HarnessFactory]:
    created: list[Harness] = []

    def make(scenario: str = "baseline", **overrides: Any) -> Harness:
        settings = offline_settings(samples_scenario=scenario, **overrides)
        transport = ReplayTransport(SAMPLES, scenario)
        client = PanoramaClient(settings, transport=transport)
        server, _ = build_server(client, settings)
        h = Harness(server, client, transport)
        created.append(h)
        return h

    yield make
    for h in created:
        await h.client.aclose()
