"""Log queries (filter builder/validator, job polling) and policy-match tests (US3)."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from panos_mcp.client import commands
from panos_mcp.client.xmlapi import PanoramaClient
from panos_mcp.models.common import ErrorCode, ToolError
from panos_mcp.models.logs import LogEntry, LogType, PolicyMatchQuery, PolicyMatchResult
from panos_mcp.parsers.logs import parse_job_status, parse_log_entries, parse_policy_match
from panos_mcp.services.inventory import InventoryService

MAX_NLOGS = 5000
BACKOFF = (0.5, 1.0, 2.0, 4.0)
_RELATIVE_RE = re.compile(r"^(\d+)\s*([mhd])$")
_UNITS = {"m": "minutes", "h": "hours", "d": "days"}

FILTER_FIELDS = frozenset(
    {
        "addr.src",
        "addr.dst",
        "addr",
        "port.src",
        "port.dst",
        "app",
        "action",
        "rule",
        "zone.src",
        "zone.dst",
        "user.src",
        "user.dst",
        "receive_time",
        "time_generated",
        "severity",
        "subtype",
        "threatid",
        "category",
        "url",
        "device_name",
        "serial",
        "vsys",
        "eventid",
        "admin",
        "cmd",
        "result",
        "proto",
        "session_end_reason",
        "direction",
    }
)
FILTER_OPERATORS = frozenset({"eq", "neq", "in", "notin", "geq", "leq", "gt", "lt", "contains"})
LOGICAL = frozenset({"and", "or", "not"})
_TOKEN_RE = re.compile(r"'[^']*'|\"[^\"]*\"|\(|\)|[^\s()]+")
PANORAMA_TIME = "%Y/%m/%d %H:%M:%S"


def invalid(message: str, hint: str) -> ToolError:
    return ToolError(ErrorCode.INVALID_INPUT, message, hint)


def validate_advanced_filter(value: str) -> str:
    """Check PAN-OS log filter syntax: balanced quotes/parentheses, known fields/operators."""
    if len(value) > 1000 or re.search(r"[\x00-\x1f\x7f]", value):
        raise invalid(
            "The advanced filter is too long or has control characters.",
            "Keep the filter on one line and under 1000 characters.",
        )
    if value.count("'") % 2 or value.count('"') % 2:
        raise invalid("The advanced filter has unbalanced quotes.", "Close every quote.")
    depth = 0
    for ch in re.sub(r"'[^']*'|\"[^\"]*\"", "", value):
        depth += ch == "("
        depth -= ch == ")"
        if depth < 0:
            break
    if depth != 0:
        raise invalid(
            "The advanced filter has unbalanced parentheses.",
            "Each term looks like ( field operator value ).",
        )
    tokens = [t for t in _TOKEN_RE.findall(value) if t not in ("(", ")")]
    for i, token in enumerate(tokens):
        if token.lower() in FILTER_OPERATORS:
            if i == 0 or tokens[i - 1].lower() not in FILTER_FIELDS:
                field = tokens[i - 1] if i else ""
                raise invalid(
                    f"Unknown log filter field {field!r}.",
                    "Use fields such as addr.src, addr.dst, port.dst, app, action, rule, "
                    "zone.src, zone.dst, receive_time, severity.",
                )
            if i + 1 >= len(tokens) or tokens[i + 1].lower() in LOGICAL:
                raise invalid(f"Operator {token!r} has no value.", "Use ( field op value ).")
    return value


def parse_ip(value: str, what: str) -> str:
    try:
        return (
            str(ipaddress.ip_network(value, strict=False))
            if "/" in value
            else str(ipaddress.ip_address(value))
        )
    except ValueError:
        raise invalid(
            f"{what} {value!r} is not a valid IP address or CIDR.",
            "Use an address such as 10.1.1.5 or a prefix such as 10.1.0.0/16.",
        ) from None


def _quoted(value: str, what: str) -> str:
    commands.validate_name(value, what)
    if "'" in value:
        raise invalid(f"The {what} cannot contain a single quote.", f"Check the {what}.")
    return f"'{value}'" if re.search(r"[\s()]", value) else value


def parse_when(value: str, now: datetime) -> datetime:
    rel = _RELATIVE_RE.match(value.strip().lower())
    if rel:
        return now - timedelta(**{_UNITS[rel.group(2)]: int(rel.group(1))})
    for fmt in (
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%d",
        PANORAMA_TIME,
    ):
        try:
            return datetime.strptime(value.strip().rstrip("Z"), fmt)
        except ValueError:
            continue
    raise invalid(
        f"Time {value!r} is not understood.",
        "Use a relative time such as 1h, 30m, 7d, or a timestamp 2026-10-16T08:00:00.",
    )


@dataclass
class LogFilters:
    since: str | None = None
    until: str | None = None
    source: str | None = None
    destination: str | None = None
    port: int | None = None
    application: str | None = None
    action: str | None = None
    rule: str | None = None
    device_serial: str | None = None
    severity: str | None = None
    advanced_filter: str | None = None


def build_query(f: LogFilters, now: datetime) -> str:
    terms: list[str] = []
    if f.source:
        terms.append(f"( addr.src in {parse_ip(f.source, 'Source')} )")
    if f.destination:
        terms.append(f"( addr.dst in {parse_ip(f.destination, 'Destination')} )")
    if f.port is not None:
        if not 1 <= f.port <= 65535:
            raise invalid("Port must be between 1 and 65535.", "Check the port number.")
        terms.append(f"( port.dst eq {f.port} )")
    if f.application:
        terms.append(f"( app eq {_quoted(f.application, 'application')} )")
    if f.action:
        terms.append(f"( action eq {_quoted(f.action, 'action')} )")
    if f.rule:
        terms.append(f"( rule eq {_quoted(f.rule, 'rule name')} )")
    if f.device_serial:
        terms.append(f"( serial eq {commands.validate_serial(f.device_serial)} )")
    if f.severity:
        terms.append(f"( severity eq {_quoted(f.severity, 'severity')} )")
    if f.since:
        terms.append(f"( receive_time geq '{parse_when(f.since, now):{PANORAMA_TIME}}' )")
    if f.until:
        terms.append(f"( receive_time leq '{parse_when(f.until, now):{PANORAMA_TIME}}' )")
    if f.advanced_filter:
        terms.append(f"( {validate_advanced_filter(f.advanced_filter)} )")
    return " and ".join(terms)


@dataclass
class LogQueryResult:
    entries: list[LogEntry]
    truncated: bool
    query: str


class LogService:
    def __init__(
        self,
        client: PanoramaClient,
        *,
        clock: Callable[[], datetime] = datetime.now,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.client = client
        self.inventory = InventoryService(client)
        self.clock = clock
        self.monotonic = monotonic
        self.sleep = sleep

    async def query(self, log_type: LogType, filters: LogFilters, limit: int) -> LogQueryResult:
        max_limit = self.client.settings.log_limit_max
        if not 1 <= limit <= max_limit:
            raise invalid(
                f"limit must be between 1 and {max_limit}.",
                "Lower the limit, or ask the operator to raise PANOS_MCP_LOG_LIMIT_MAX.",
            )
        query = build_query(filters, self.clock())
        if filters.device_serial:
            await self.inventory.require_device(filters.device_serial)
        nlogs = min(limit + 1, MAX_NLOGS)
        job_id = await self.client.log_start(log_type.value, query, nlogs)
        timeout = self.client.settings.query_timeout
        started = self.monotonic()
        attempt = 0
        while True:
            result = await self.client.log_get(job_id)
            if parse_job_status(result) == "FIN":
                entries = parse_log_entries(result, log_type)
                return LogQueryResult(entries[:limit], len(entries) > limit, query)
            if self.monotonic() - started >= timeout:
                raise ToolError(
                    ErrorCode.TIMEOUT,
                    f"The {log_type.value} log query did not finish within {timeout:g} seconds.",
                    "Narrow the time range (since/until) or add filters, then retry.",
                )
            delay = BACKOFF[min(attempt, len(BACKOFF) - 1)]
            await self.sleep(min(delay, max(0.0, timeout - (self.monotonic() - started))))
            attempt += 1

    async def policy_match(self, q: PolicyMatchQuery) -> PolicyMatchResult:
        fw = await self.inventory.require_device(q.device_serial)
        if not fw.connected:
            raise ToolError(
                ErrorCode.DEVICE_UNAVAILABLE,
                f"Firewall {fw.hostname} ({fw.serial}) is not connected to Panorama.",
                "Check the firewall's connectivity with list_managed_devices, then retry.",
            )
        cmd = commands.test_security_policy_match(
            from_zone=q.from_zone,
            to_zone=q.to_zone,
            source=q.source,
            destination=q.destination,
            protocol=q.protocol,
            destination_port=q.destination_port,
            application=q.application,
            source_user=q.source_user,
        )
        match = parse_policy_match(await self.client.op(cmd, target=q.device_serial))
        if match is None:
            return PolicyMatchResult(
                device_serial=q.device_serial,
                vsys=q.vsys,
                query=q,
                matched=False,
                note="No match: no security rule matches; the intrazone/interzone default rule "
                "applies (interzone traffic is denied by default).",
            )
        rule, action = match
        return PolicyMatchResult(
            device_serial=q.device_serial,
            vsys=q.vsys,
            query=q,
            matched=True,
            rule_name=rule,
            action=action,
            note=f"First matching rule: {rule} ({action or 'action unknown'}).",
        )
