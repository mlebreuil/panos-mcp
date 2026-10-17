from __future__ import annotations

import json

import pytest
from mcp.server.mcpserver import MCPServer
from mcp_types import CallToolResult

from panos_mcp.client.xmlapi import PanoramaClient
from panos_mcp.logging import configure_logging
from panos_mcp.models.common import ErrorCode, ToolError, ToolResult
from panos_mcp.server import AppContext, readonly_tool
from tests.conftest import offline_settings

pytestmark = pytest.mark.anyio


def make_server() -> MCPServer:
    settings = offline_settings()
    server = MCPServer(name="t")
    app = AppContext(client=PanoramaClient(settings), settings=settings)
    tool = readonly_tool(server, app, lambda r: "ok")

    @tool
    async def crashes(path: str = "/secret/file.py") -> ToolResult[list[str]]:
        """Always crashes."""
        raise KeyError(path)

    @tool
    async def anticipated() -> ToolResult[list[str]]:
        """Raises a ToolError."""
        raise ToolError(ErrorCode.NOT_FOUND, "nope", "try again", ["near"])

    @tool
    async def works() -> ToolResult[list[str]]:
        """Works."""
        return ToolResult[list[str]](items=["a"], returned=1)

    return server


async def call(server: MCPServer, name: str) -> CallToolResult:
    result = await server.call_tool(name, {})
    assert isinstance(result, CallToolResult)
    return result


async def test_unexpected_exception_is_generic_error(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO")
    server = make_server()
    result = await call(server, "crashes")
    assert result.is_error
    text = json.dumps(result.model_dump(mode="json"))
    assert "Traceback" not in text and "/secret/file.py" not in text and "KeyError" not in text
    assert (result.structured_content or {})["error"]["code"] == "panorama_error"
    assert "Traceback" in capsys.readouterr().err


async def test_tool_error_is_structured() -> None:
    result = await call(make_server(), "anticipated")
    assert result.is_error
    assert (result.structured_content or {})["error"] == {
        "code": "not_found",
        "message": "nope",
        "hint": "try again",
        "suggestions": ["near"],
    }


async def test_success_and_annotations() -> None:
    server = make_server()
    result = await call(server, "works")
    assert not result.is_error
    assert (result.structured_content or {})["items"] == ["a"]
    tools = {t.name: t for t in await server.list_tools()}
    annotations = tools["works"].annotations
    assert annotations is not None
    assert annotations.read_only_hint is True
    assert annotations.destructive_hint is False
    assert tools["works"].output_schema is not None
