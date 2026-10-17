"""US2 tools: objects, where-used, address-group expansion."""

from __future__ import annotations

from typing import Annotated, cast

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from panos_mcp.models.common import (
    DEFAULT_LIMIT,
    ConfigSource,
    Limit,
    Offset,
    ToolResult,
    paginate,
)
from panos_mcp.models.objects import AnyObject, ObjectKind, ObjectReference, ResolvedAddressGroup
from panos_mcp.server import AppContext, readonly_tool
from panos_mcp.services.objects import ObjectService

Scope = Annotated[str, Field(description='"shared" or a device-group name')]
Source = Annotated[
    ConfigSource, Field(description="running (committed) or candidate (uncommitted) config")
]


def register(server: MCPServer, app: AppContext) -> None:
    svc = ObjectService(app.client)

    @readonly_tool(server, app, lambda r: f"{r.total} object(s) match; showing {r.returned}.")
    async def get_objects(
        kind: Annotated[ObjectKind, Field(description="Object kind")],
        scope: Scope = "shared",
        name: Annotated[str | None, Field(description="Exact object name")] = None,
        name_contains: Annotated[str | None, Field(description="Substring of the name")] = None,
        value_contains: Annotated[
            str | None, Field(description="Substring of an address value or service port")
        ] = None,
        include_inherited: Annotated[
            bool, Field(description="Also list objects from shared and ancestor device groups")
        ] = False,
        config_source: Source = ConfigSource.RUNNING,
        limit: Limit = DEFAULT_LIMIT,
        offset: Offset = 0,
    ) -> ToolResult[list[AnyObject]]:
        """Objects of one kind (addresses, address groups, services, service groups,
        application groups, tags, security profile groups) defined in a scope. Each object
        states its defining scope; with include_inherited, `effective` marks the definition
        that applies when the same name exists in several scopes. Read-only."""
        items, when = await svc.get_objects(
            kind,
            scope,
            config_source,
            name=name,
            name_contains=name_contains,
            value_contains=value_contains,
            include_inherited=include_inherited,
        )
        page = paginate(items, limit, offset, "Filter by name_contains or value_contains.")
        return ToolResult[list[AnyObject]](
            items=cast(list[AnyObject], page.items),
            total=page.total,
            returned=page.returned,
            truncated=page.truncated,
            next_offset=page.next_offset,
            narrowing_hint=page.narrowing_hint,
            config_source=config_source,
            retrieved_at=when,
        )

    @readonly_tool(server, app, lambda r: f"{r.total} reference(s) found; showing {r.returned}.")
    async def find_object_references(
        name: Annotated[str, Field(description="Object name")],
        kind: Annotated[ObjectKind, Field(description="Object kind")],
        scope: Annotated[str, Field(description="Scope where the object is defined")] = "shared",
        config_source: Source = ConfigSource.RUNNING,
        limit: Limit = DEFAULT_LIMIT,
        offset: Offset = 0,
    ) -> ToolResult[list[ObjectReference]]:
        """Where an object is used: security/NAT rules, groups, tagged objects and dynamic
        group filters, in its defining scope and all descendant device groups. References
        that resolve to a nearer same-name object are excluded and reported in warnings.
        Read-only."""
        refs, warnings, when = await svc.find_references(name, kind, scope, config_source)
        page = paginate(refs, limit, offset, "Page with offset to see more references.")
        return ToolResult[list[ObjectReference]](
            items=page.items,
            total=page.total,
            returned=page.returned,
            truncated=page.truncated,
            next_offset=page.next_offset,
            narrowing_hint=page.narrowing_hint,
            config_source=config_source,
            retrieved_at=when,
            warnings=warnings,
        )

    def expand_summary(r: ToolResult[ResolvedAddressGroup]) -> str:
        g = r.items
        text = f"{g.group} ({g.kind}) expands to {r.total} address(es); showing {r.returned}."
        if g.cycles_detected:
            text += f" Cycles: {'; '.join(g.cycles_detected)}."
        return text

    @readonly_tool(server, app, expand_summary)
    async def resolve_address_group(
        name: Annotated[str, Field(description="Address group name")],
        scope: Scope = "shared",
        device_serial: Annotated[
            str | None,
            Field(description="Firewall serial; required to resolve dynamic group members"),
        ] = None,
        config_source: Source = ConfigSource.RUNNING,
        max_addresses: Annotated[
            int, Field(ge=1, le=1000, description="Maximum addresses to return")
        ] = 200,
    ) -> ToolResult[ResolvedAddressGroup]:
        """Expand an address group to concrete addresses, flattening nested groups and
        reporting cycles. Dynamic groups return their filter, and their current members when
        device_serial is given (resolved on that firewall). Read-only."""
        group, when = await svc.resolve_address_group(name, scope, config_source, device_serial)
        warnings = []
        if group.kind == "dynamic" and group.resolved_on is None:
            warnings.append(
                "Dynamic group: members depend on registered IPs; pass device_serial to "
                "resolve them on a firewall."
            )
        total = len(group.addresses)
        truncated = total > max_addresses
        group.addresses = group.addresses[:max_addresses]
        return ToolResult[ResolvedAddressGroup](
            items=group,
            total=total,
            returned=len(group.addresses),
            truncated=truncated,
            narrowing_hint="Expand one of the nested groups instead, or raise max_addresses."
            if truncated
            else None,
            config_source=config_source,
            retrieved_at=when,
            warnings=warnings,
        )
