"""Typed builders for allow-listed requests, input validation, and the tool->request registry.

User values never reach a command or xpath by string formatting of raw input:
`cmd` XML is built with ElementTree (which escapes text), and values inside xpath
predicates go through `xpath_literal`.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Literal

from panos_mcp.models.common import SHARED, ErrorCode, ToolError

PANORAMA_ENTRY = "/config/devices/entry[@name='localhost.localdomain']"
SHARED_XPATH = "/config/shared"

MAX_NAME_LENGTH = 63
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
SERIAL_RE = re.compile(r"^[0-9A-Za-z]{8,20}$")

RuleType = Literal["security", "nat"]
Position = Literal["pre", "post"]

OBJECT_XPATH_NODE: dict[str, str] = {
    "address": "address",
    "address_group": "address-group",
    "service": "service",
    "service_group": "service-group",
    "application_group": "application-group",
    "tag": "tag",
    "security_profile_group": "profile-group",
}


# --------------------------------------------------------------------------- validation


def validate_name(value: str, what: str = "name") -> str:
    """Reject only what PAN-OS names can never contain; everything else is quoted safely."""
    if not value or not value.strip():
        raise ToolError(ErrorCode.INVALID_INPUT, f"The {what} is empty.", f"Provide a {what}.")
    if len(value) > MAX_NAME_LENGTH:
        raise ToolError(
            ErrorCode.INVALID_INPUT,
            f"The {what} is longer than {MAX_NAME_LENGTH} characters.",
            f"PAN-OS names are at most {MAX_NAME_LENGTH} characters; check the {what}.",
        )
    if _CONTROL_RE.search(value):
        raise ToolError(
            ErrorCode.INVALID_INPUT,
            f"The {what} contains control characters or line breaks.",
            f"Remove line breaks and control characters from the {what}.",
        )
    return value


def validate_serial(value: str) -> str:
    if not SERIAL_RE.match(value):
        raise ToolError(
            ErrorCode.INVALID_INPUT,
            "The firewall serial number is not valid.",
            "Serial numbers are 8-20 letters or digits; use list_managed_devices to find it.",
        )
    return value


def xpath_literal(value: str) -> str:
    """Quote `value` as an XPath 1.0 string literal, whatever quotes it contains."""
    if "'" not in value:
        return f"'{value}'"
    if '"' not in value:
        return f'"{value}"'
    parts = value.split("'")
    pieces: list[str] = []
    for i, part in enumerate(parts):
        if part:
            pieces.append(f"'{part}'")
        if i < len(parts) - 1:
            pieces.append('"\'"')
    return "concat(" + ", ".join(pieces) + ")"


# --------------------------------------------------------------------------- xpaths


def scope_xpath(scope: str) -> str:
    if scope == SHARED:
        return SHARED_XPATH
    validate_name(scope, "device group name")
    return f"{PANORAMA_ENTRY}/device-group/entry[@name={xpath_literal(scope)}]"


def rulebase_xpath(scope: str, rule_type: RuleType, position: Position) -> str:
    return f"{scope_xpath(scope)}/{position}-rulebase/{rule_type}/rules"


def object_xpath(scope: str, kind: str) -> str:
    return f"{scope_xpath(scope)}/{OBJECT_XPATH_NODE[kind]}"


def template_stack_xpath() -> str:
    return f"{PANORAMA_ENTRY}/template-stack"


# --------------------------------------------------------------------------- op commands


def _cmd(
    *path: str, leaf_text: str | None = None, leaf_children: dict[str, str] | None = None
) -> str:
    root = ET.Element(path[0])
    node = root
    for tag in path[1:]:
        node = ET.SubElement(node, tag)
    if leaf_text is not None:
        node.text = leaf_text
    for tag, text in (leaf_children or {}).items():
        ET.SubElement(node, tag).text = text
    return ET.tostring(root, encoding="unicode", short_empty_elements=False)


def show_system_info() -> str:
    return _cmd("show", "system", "info")


def show_ha_state() -> str:
    return _cmd("show", "high-availability", "state")


def request_license_info() -> str:
    return _cmd("request", "license", "info")


def show_devices_all() -> str:
    return _cmd("show", "devices", "all")


def show_devicegroups() -> str:
    return _cmd("show", "devicegroups")


def show_dg_hierarchy() -> str:
    return _cmd("show", "dg-hierarchy")


def show_templates() -> str:
    return _cmd("show", "templates")


def show_jobs_all() -> str:
    return _cmd("show", "jobs", "all")


def show_job(job_id: int) -> str:
    return _cmd("show", "jobs", "id", leaf_text=str(int(job_id)))


def check_pending_changes() -> str:
    return _cmd("check", "pending-changes")


def show_dynamic_address_group(name: str | None = None) -> str:
    if name is None:
        return _cmd("show", "object", "dynamic-address-group", "all")
    validate_name(name, "address group name")
    return _cmd("show", "object", "dynamic-address-group", "name", leaf_text=name)


PROTOCOL_NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1}


def test_security_policy_match(
    *,
    from_zone: str,
    to_zone: str,
    source: str,
    destination: str,
    protocol: int,
    destination_port: int | None = None,
    application: str | None = None,
    source_user: str | None = None,
) -> str:
    children: dict[str, str] = {
        "from": validate_name(from_zone, "source zone"),
        "to": validate_name(to_zone, "destination zone"),
        "source": source,
        "destination": destination,
        "protocol": str(int(protocol)),
    }
    if destination_port is not None:
        children["destination-port"] = str(int(destination_port))
    if application is not None:
        children["application"] = validate_name(application, "application")
    if source_user is not None:
        children["source-user"] = validate_name(source_user, "source user")
    return _cmd("test", "security-policy-match", leaf_children=children)


# --------------------------------------------------------------------------- registry


@dataclass(frozen=True)
class RequestTemplate:
    """A request shape a tool may issue. `pattern` is a regex over the op command path,
    the config xpath, or the log type."""

    type: Literal["op", "config", "log"]
    pattern: str
    description: str

    def matches(self, params: dict[str, str]) -> bool:
        from panos_mcp.client.allowlist import command_path, parse_cmd

        if params.get("type") != self.type:
            return False
        if self.type == "op":
            subject = command_path(parse_cmd(params.get("cmd", "")))
        elif self.type == "config":
            subject = params.get("xpath", "")
        else:
            subject = params.get("log-type", "") if "action" not in params else "job"
        return re.fullmatch(self.pattern, subject) is not None


_DG = re.escape(PANORAMA_ENTRY) + r"/device-group/entry\[@name=.+\]"
_SCOPE = rf"(?:{re.escape(SHARED_XPATH)}|{_DG})"
_HIERARCHY = RequestTemplate("op", "show/dg-hierarchy", "device-group hierarchy")
_DEVICES = RequestTemplate("op", "show/devices/all", "managed firewalls")


def _rules(rule_type: str) -> RequestTemplate:
    return RequestTemplate(
        "config", rf"{_SCOPE}/(?:pre|post)-rulebase/{rule_type}/rules", f"{rule_type} rulebase"
    )


_OBJECTS = RequestTemplate(
    "config",
    rf"{_SCOPE}/(?:{'|'.join(re.escape(v) for v in OBJECT_XPATH_NODE.values())})",
    "objects",
)

TOOL_REQUESTS: dict[str, list[RequestTemplate]] = {
    "get_panorama_info": [
        RequestTemplate("op", "show/system/info", "system info"),
        RequestTemplate("op", "show/high-availability/state", "HA state"),
        RequestTemplate("op", "request/license/info", "licenses"),
    ],
    "list_managed_devices": [
        _DEVICES,
        _HIERARCHY,
        RequestTemplate("op", "show/devicegroups", "group membership"),
        RequestTemplate("config", re.escape(template_stack_xpath()), "template stacks"),
    ],
    "list_device_groups": [_HIERARCHY, RequestTemplate("op", "show/devicegroups", "groups")],
    "list_templates": [
        RequestTemplate("op", "show/templates", "templates"),
        RequestTemplate("config", re.escape(template_stack_xpath()), "template stacks"),
    ],
    "list_jobs": [RequestTemplate("op", "show/jobs/all", "jobs")],
    "get_job": [RequestTemplate("op", "show/jobs/id", "one job")],
    "get_security_rules": [_HIERARCHY, _rules("security"), _OBJECTS],
    "get_nat_rules": [_HIERARCHY, _rules("nat"), _OBJECTS],
    "get_objects": [_HIERARCHY, _OBJECTS],
    "find_object_references": [_HIERARCHY, _OBJECTS, _rules("security"), _rules("nat")],
    "resolve_address_group": [
        _HIERARCHY,
        _OBJECTS,
        RequestTemplate("op", "show/object/dynamic-address-group(?:/.*)?", "DAG members"),
    ],
    "query_logs": [
        _DEVICES,
        RequestTemplate("log", "traffic|threat|url|system|config", "log query start"),
        RequestTemplate("log", "job", "log query result"),
    ],
    "test_security_policy_match": [
        _DEVICES,
        RequestTemplate("op", "test/security-policy-match", "policy match"),
    ],
}

# Requests issued outside tools (capture safety checks).
SAFETY_REQUESTS: list[RequestTemplate] = [
    RequestTemplate("op", "check/pending-changes", "pending changes"),
    RequestTemplate("op", "show/jobs/all", "jobs"),
]
