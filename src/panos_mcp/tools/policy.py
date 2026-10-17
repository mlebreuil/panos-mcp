"""US2 tools: security and NAT rules, per scope or effective (inherited)."""

from __future__ import annotations

from typing import Annotated, Literal, cast

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
from panos_mcp.models.policy import NatRule, RuleAction, SecurityRule
from panos_mcp.server import AppContext, readonly_tool
from panos_mcp.services.policy import PolicyService, RuleFilters

Scope = Annotated[str, Field(description='"shared" or a device-group name')]
RulebaseArg = Annotated[
    Literal["pre", "post", "both"], Field(description="Pre-rules, post-rules or both")
]
Effective = Annotated[
    bool,
    Field(
        description="Include rules inherited from shared and ancestor device groups, in "
        "firewall evaluation order"
    ),
]
Source = Annotated[
    ConfigSource, Field(description="running (committed) or candidate (uncommitted) config")
]
Opt = Annotated[str | None, Field(description="Filter (exact member, or IP/CIDR for addresses)")]

HINT = "Add filters (zones, source, destination, application, tag) or page with offset."


def _summary(kind: str):  # type: ignore[no-untyped-def]
    def summarize(r: ToolResult[list[SecurityRule]] | ToolResult[list[NatRule]]) -> str:
        source = r.config_source.value if r.config_source else "running"
        return f"{r.total} {kind} rule(s) match ({source} config); showing {r.returned}."

    return summarize


def register(server: MCPServer, app: AppContext) -> None:
    svc = PolicyService(app.client)

    @readonly_tool(server, app, _summary("security"))
    async def get_security_rules(
        scope: Scope = "shared",
        rulebase: RulebaseArg = "both",
        effective: Effective = False,
        name_contains: Annotated[
            str | None, Field(description="Substring of the rule name")
        ] = None,
        tag: Annotated[str | None, Field(description="Rule tag")] = None,
        from_zone: Annotated[str | None, Field(description="Source zone")] = None,
        to_zone: Annotated[str | None, Field(description="Destination zone")] = None,
        source: Opt = None,
        destination: Opt = None,
        application: Annotated[str | None, Field(description="Application or group")] = None,
        service: Annotated[str | None, Field(description="Service or service group")] = None,
        action: Annotated[RuleAction | None, Field(description="Rule action")] = None,
        disabled: Annotated[bool | None, Field(description="Only disabled/enabled rules")] = None,
        config_source: Source = ConfigSource.RUNNING,
        limit: Limit = DEFAULT_LIMIT,
        offset: Offset = 0,
    ) -> ToolResult[list[SecurityRule]]:
        """Security rules of a scope, or the effective rulebase a device group's firewalls
        evaluate (shared and ancestor rules included, labeled with their scope and pre/post
        position, numbered in evaluation order). Filters are AND-combined; an IP/CIDR
        source/destination matches rules whose resolved addresses overlap it. Read-only."""
        filters = RuleFilters(
            name_contains,
            tag,
            from_zone,
            to_zone,
            source,
            destination,
            application,
            service,
            action,
            disabled,
        )
        rules, when = await svc.rules(
            "security", scope, rulebase, effective, filters, config_source
        )
        page = paginate(rules, limit, offset, HINT)
        return ToolResult[list[SecurityRule]](
            items=cast(list[SecurityRule], page.items),
            total=page.total,
            returned=page.returned,
            truncated=page.truncated,
            next_offset=page.next_offset,
            narrowing_hint=page.narrowing_hint,
            config_source=config_source,
            retrieved_at=when,
        )

    @readonly_tool(server, app, _summary("NAT"))
    async def get_nat_rules(
        scope: Scope = "shared",
        rulebase: RulebaseArg = "both",
        effective: Effective = False,
        name_contains: Annotated[
            str | None, Field(description="Substring of the rule name")
        ] = None,
        tag: Annotated[str | None, Field(description="Rule tag")] = None,
        from_zone: Annotated[str | None, Field(description="Source zone")] = None,
        to_zone: Annotated[str | None, Field(description="Destination zone")] = None,
        source: Opt = None,
        destination: Opt = None,
        service: Annotated[str | None, Field(description="Service or service group")] = None,
        disabled: Annotated[bool | None, Field(description="Only disabled/enabled rules")] = None,
        config_source: Source = ConfigSource.RUNNING,
        limit: Limit = DEFAULT_LIMIT,
        offset: Offset = 0,
    ) -> ToolResult[list[NatRule]]:
        """NAT rules of a scope, or the effective NAT rulebase of a device group (inherited
        rules included, in evaluation order), with source/destination translations.
        Read-only."""
        filters = RuleFilters(
            name_contains,
            tag,
            from_zone,
            to_zone,
            source,
            destination,
            None,
            service,
            None,
            disabled,
        )
        rules, when = await svc.rules("nat", scope, rulebase, effective, filters, config_source)
        page = paginate(rules, limit, offset, HINT)
        return ToolResult[list[NatRule]](
            items=cast(list[NatRule], page.items),
            total=page.total,
            returned=page.returned,
            truncated=page.truncated,
            next_offset=page.next_offset,
            narrowing_hint=page.narrowing_hint,
            config_source=config_source,
            retrieved_at=when,
        )
