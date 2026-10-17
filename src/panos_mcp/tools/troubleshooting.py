"""US3 tools: log queries and security policy match tests."""

from __future__ import annotations

from typing import Annotated, Literal

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from panos_mcp.models.common import ToolResult
from panos_mcp.models.logs import LogEntry, LogType, PolicyMatchQuery, PolicyMatchResult
from panos_mcp.server import AppContext, readonly_tool
from panos_mcp.services.logs import LogFilters, LogService, invalid, parse_ip

TIME_NOTE = (
    "Relative times (since/until) are computed from this machine's clock; Panorama interprets "
    "them in its own time zone."
)


def register(server: MCPServer, app: AppContext) -> None:
    svc = LogService(app.client)

    def logs_summary(r: ToolResult[list[LogEntry]]) -> str:
        more = " (more available; narrow the query)" if r.truncated else ""
        return f"{r.returned} log entr{'y' if r.returned == 1 else 'ies'}, newest first{more}."

    @readonly_tool(server, app, logs_summary)
    async def query_logs(
        log_type: Annotated[LogType, Field(description="traffic, threat, url, system or config")],
        since: Annotated[
            str | None, Field(description="Start: relative (30m, 1h, 24h, 7d) or timestamp")
        ] = None,
        until: Annotated[str | None, Field(description="End: relative or timestamp")] = None,
        source: Annotated[str | None, Field(description="Source IP or CIDR")] = None,
        destination: Annotated[str | None, Field(description="Destination IP or CIDR")] = None,
        port: Annotated[int | None, Field(description="Destination port (1-65535)")] = None,
        application: Annotated[str | None, Field(description="Application name")] = None,
        action: Annotated[str | None, Field(description="Action, e.g. allow, deny, drop")] = None,
        rule: Annotated[str | None, Field(description="Security rule name")] = None,
        device_serial: Annotated[
            str | None, Field(description="Only logs from this firewall")
        ] = None,
        severity: Annotated[str | None, Field(description="Threat/system severity")] = None,
        advanced_filter: Annotated[
            str | None,
            Field(description="Extra PAN-OS log filter, e.g. ( zone.src eq trust )"),
        ] = None,
        limit: Annotated[int, Field(ge=1, description="Maximum entries to return")] = 100,
    ) -> ToolResult[list[LogEntry]]:
        """Search traffic, threat, URL, system or config logs collected by Panorama. Filters
        are AND-combined; results are newest first and bounded by limit. Long queries stop at
        the configured timeout with a hint to narrow the time range. Read-only."""
        filters = LogFilters(
            since,
            until,
            source,
            destination,
            port,
            application,
            action,
            rule,
            device_serial,
            severity,
            advanced_filter,
        )
        result = await svc.query(log_type, filters, limit)
        warnings = [TIME_NOTE] if since or until else []
        return ToolResult[list[LogEntry]](
            items=result.entries,
            returned=len(result.entries),
            truncated=result.truncated,
            narrowing_hint="Narrow the time range or add filters (source, destination, port, "
            "rule) to see the rest."
            if result.truncated
            else None,
            warnings=warnings,
        )

    def match_summary(r: ToolResult[PolicyMatchResult]) -> str:
        return r.items.note

    @readonly_tool(server, app, match_summary)
    async def test_security_policy_match(
        device_serial: Annotated[str, Field(description="Firewall serial (list_managed_devices)")],
        from_zone: Annotated[str, Field(description="Source zone")],
        to_zone: Annotated[str, Field(description="Destination zone")],
        source: Annotated[str, Field(description="Source IP address")],
        destination: Annotated[str, Field(description="Destination IP address")],
        protocol: Annotated[
            int | Literal["tcp", "udp", "icmp"], Field(description="IP protocol name or number")
        ],
        destination_port: Annotated[
            int | None, Field(ge=1, le=65535, description="Destination port")
        ] = None,
        application: Annotated[str | None, Field(description="Application name")] = None,
        source_user: Annotated[str | None, Field(description="Source user")] = None,
        vsys: Annotated[str, Field(description="Virtual system")] = "vsys1",
    ) -> ToolResult[PolicyMatchResult]:
        """Ask a managed firewall which security rule would match a traffic flow (the
        firewall evaluates its running policy; nothing is changed). Read-only."""
        number = (
            protocol if isinstance(protocol, int) else {"tcp": 6, "udp": 17, "icmp": 1}[protocol]
        )
        if not 0 <= number <= 255:
            raise invalid(
                "protocol must be tcp, udp, icmp or a number 0-255.",
                "Use tcp, udp or icmp, or an IP protocol number.",
            )
        query = PolicyMatchQuery(
            device_serial=device_serial,
            vsys=vsys,
            from_zone=from_zone,
            to_zone=to_zone,
            source=parse_ip(source, "Source"),
            destination=parse_ip(destination, "Destination"),
            protocol=number,
            destination_port=destination_port,
            application=application,
            source_user=source_user,
        )
        result = await svc.policy_match(query)
        warnings = []
        if vsys != "vsys1":
            warnings.append(
                "The XML API test is evaluated in the firewall's default target vsys; the vsys "
                "argument is recorded but not applied."
            )
        return ToolResult[PolicyMatchResult](items=result, returned=1, warnings=warnings)
