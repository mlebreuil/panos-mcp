"""MCP server: registers read-only tools and renders results/errors (contracts/mcp-tools.md)."""

from __future__ import annotations

import functools
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp_types import CallToolResult, TextContent, ToolAnnotations

from panos_mcp.client.allowlist import ReadOnlyViolation
from panos_mcp.client.xmlapi import PanoramaClient
from panos_mcp.config import Settings
from panos_mcp.logging import get_logger
from panos_mcp.models.common import ErrorCode, ToolError, ToolErrorInfo, ToolResult

log = get_logger("server")

READ_ONLY = ToolAnnotations(
    read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=True
)

INSTRUCTIONS = """\
Read-only access to one Palo Alto Networks Panorama: managed firewalls, device groups,
templates, jobs, security/NAT policy, objects, logs and policy-match tests.

This server cannot change anything: it has no tools to create, edit, delete, commit, push,
revert or reboot. If the user asks for a change, say that this server is read-only.

Tips: scope policy and object queries with `scope` ("shared" or a device-group name);
use list_device_groups to discover names. Results state whether they come from the running
or candidate configuration. When a result is truncated, follow its narrowing_hint.
"""

UNEXPECTED = ToolErrorInfo(
    code=ErrorCode.PANORAMA_ERROR,
    message="Unexpected error while processing the Panorama response.",
    hint="Retry; if it persists, run with PANOS_MCP_LOG_LEVEL=DEBUG and report the log "
    "(it contains no secrets).",
)


@dataclass
class AppContext:
    client: PanoramaClient
    settings: Settings
    global_warnings: list[str] = field(default_factory=list)


def error_result(info: ToolErrorInfo) -> CallToolResult:
    payload = {"error": info.model_dump(mode="json")}
    text = f"Error ({info.code.value}): {info.message} Hint: {info.hint}"
    if info.suggestions:
        text += f" Did you mean: {', '.join(info.suggestions)}?"
    return CallToolResult(
        content=[TextContent(type="text", text=text)],
        structured_content=payload,
        is_error=True,
    )


def success_result(result: ToolResult[Any], summary: str) -> CallToolResult:
    data = result.model_dump(mode="json")
    body = json.dumps(data, separators=(",", ":"), default=str)
    return CallToolResult(
        content=[TextContent(type="text", text=f"{summary}\n{body}")],
        structured_content=data,
    )


ToolFn = Callable[..., Awaitable[ToolResult[Any]]]
Summarizer = Callable[[Any], str]


def readonly_tool(
    server: MCPServer, app: AppContext, summarize: Summarizer
) -> Callable[[ToolFn], ToolFn]:
    """Register `fn` as a read-only tool with structured results and errors."""

    def decorator(fn: ToolFn) -> ToolFn:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> CallToolResult:
            try:
                result = await fn(*args, **kwargs)
            except ToolError as exc:
                return error_result(exc.info)
            except ReadOnlyViolation as exc:
                log.error("blocked non-allow-listed request: %s", exc)
                return error_result(
                    ToolErrorInfo(
                        code=ErrorCode.READ_ONLY_VIOLATION,
                        message="The request was blocked because this server is read-only.",
                        hint="This server can only read from Panorama.",
                    )
                )
            except Exception:
                log.exception("unexpected error in tool %s", fn.__name__)
                return error_result(UNEXPECTED)
            for warning in app.global_warnings:
                if warning not in result.warnings:
                    result.warnings.append(warning)
            return success_result(result, summarize(result))

        server.add_tool(
            wrapper,
            name=fn.__name__,
            description=fn.__doc__,
            annotations=READ_ONLY,
            structured_output=True,
        )
        return fn

    return decorator


def build_server(client: PanoramaClient, settings: Settings) -> tuple[MCPServer, AppContext]:
    from panos_mcp.tools import inventory, objects, policy, troubleshooting

    server = MCPServer(name="panorama", instructions=INSTRUCTIONS, version="0.1.0")
    app = AppContext(client=client, settings=settings)
    tls_warning = settings.tls_warning()
    if tls_warning:
        app.global_warnings.append(tls_warning)
    for module in (inventory, policy, objects, troubleshooting):
        module.register(server, app)
    return server, app
