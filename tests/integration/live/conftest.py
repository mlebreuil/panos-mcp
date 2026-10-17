"""Opt-in live tests against a LAB Panorama (PANOS_MCP_LIVE=1). Never run in CI."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from typing import Any

import pytest
from mcp.server.mcpserver import MCPServer
from mcp_types import CallToolResult

from panos_mcp.client.xmlapi import PanoramaClient
from panos_mcp.config import Settings
from panos_mcp.server import build_server

LIVE = os.environ.get("PANOS_MCP_LIVE") == "1"


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if "integration/live" in str(item.fspath):
            item.add_marker(pytest.mark.live)
            if not LIVE:
                item.add_marker(pytest.mark.skip(reason="set PANOS_MCP_LIVE=1 to run live tests"))


class LiveServer:
    def __init__(self, server: MCPServer, client: PanoramaClient) -> None:
        self.server = server
        self.client = client

    async def call(self, tool: str, **args: Any) -> CallToolResult:
        result = await self.server.call_tool(tool, args)
        assert isinstance(result, CallToolResult)
        return result

    async def data(self, tool: str, **args: Any) -> dict[str, Any]:
        result = await self.call(tool, **args)
        assert not result.is_error, result.content
        assert result.structured_content is not None
        out: dict[str, Any] = result.structured_content
        return out


@pytest.fixture
async def live() -> AsyncIterator[LiveServer]:
    settings = Settings()
    client = PanoramaClient(settings)
    await client.keygen()
    server, _ = build_server(client, settings)
    yield LiveServer(server, client)
    await client.aclose()


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
