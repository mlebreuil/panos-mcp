"""Parsers for log query results and security-policy-match responses."""

from __future__ import annotations

import re
from datetime import datetime
from xml.etree.ElementTree import Element

from panos_mcp.models.logs import LogEntry, LogType
from panos_mcp.parsers import name_of, text

# XML field -> LogEntry attribute
FIELD_MAP = {
    "receive_time": "receive_time",
    "serial": "device_serial",
    "device_name": "device_name",
    "vsys": "vsys",
    "src": "src",
    "dst": "dst",
    "sport": "sport",
    "dport": "dport",
    "proto": "proto",
    "app": "app",
    "rule": "rule",
    "action": "action",
    "from": "from_zone",
    "to": "to_zone",
    "srcuser": "src_user",
    "bytes": "bytes",
    "session_end_reason": "session_end_reason",
    "severity": "severity",
    "direction": "direction",
    "category": "category",
    "eventid": "event_id",
    "opaque": "description",
    "admin": "admin",
    "cmd": "command",
    "path": "path",
    "result": "result",
}
INT_FIELDS = {"sport", "dport", "bytes"}
SKIP = {"domain", "seqno", "time_generated", "type", "logid"}
_THREAT_RE = re.compile(r"^(?P<name>.*)\((?P<id>\d+)\)$")


def _time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y/%m/%d %H:%M:%S")
    except ValueError:
        return None


def parse_job_status(result: Element) -> str:
    return (text(result, "job/status", "") or "").upper()


def parse_log_entries(result: Element, log_type: LogType) -> list[LogEntry]:
    entries: list[LogEntry] = []
    for node in result.findall("log/logs/entry"):
        data: dict[str, object] = {"log_type": log_type}
        extra: dict[str, str] = {}
        for child in node:
            value = (child.text or "").strip()
            if not value or child.tag in SKIP:
                continue
            attr = FIELD_MAP.get(child.tag)
            if attr == "receive_time":
                data[attr] = _time(value)
            elif attr in INT_FIELDS and attr is not None:
                data[attr] = int(value) if value.isdigit() else None
            elif attr:
                data[attr] = value
            elif child.tag == "threatid":
                match = _THREAT_RE.match(value)
                data["threat_name"] = match.group("name").strip() if match else value
                data["threat_id"] = match.group("id") if match else None
            elif child.tag == "misc":
                data["url"] = value.strip('"')
            else:
                extra[child.tag] = value
        data["extra"] = extra
        entries.append(LogEntry.model_validate(data))
    entries.sort(key=lambda e: e.receive_time or datetime.min, reverse=True)
    return entries


def parse_policy_match(result: Element) -> tuple[str, str | None] | None:
    """(rule name, action) of the first matching rule, or None when nothing matches."""
    for entry in result.findall("rules/entry"):
        name = name_of(entry)
        if name:
            return name, text(entry, "action")
    return None
