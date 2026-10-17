from __future__ import annotations

import re

import pytest
from defusedxml import ElementTree as SafeET

from panos_mcp.client import commands
from panos_mcp.client.allowlist import check_request
from panos_mcp.models.common import ErrorCode, ToolError


def literal_value(literal: str) -> str:
    """Evaluate an XPath 1.0 string literal / concat() produced by xpath_literal."""
    if literal.startswith("concat("):
        parts = re.findall(r"'([^']*)'|\"([^\"]*)\"", literal[7:-1])
        return "".join(a or b for a, b in parts)
    return literal[1:-1]


@pytest.mark.parametrize("value", ["plain", "it's", 'say "hi"', "both ' and \"", "x' or '1'='1"])
def test_xpath_literal_round_trip(value: str) -> None:
    assert literal_value(commands.xpath_literal(value)) == value


@pytest.mark.parametrize("name", ["x' or '1'='1", "]/..", 'a"b', "_leading", "Branch DG.1"])
def test_injection_style_names_are_quoted_not_rejected(name: str) -> None:
    xpath = commands.scope_xpath(name)
    predicate = xpath.rsplit("[@name=", 1)[1][:-1]
    assert literal_value(predicate) == name


@pytest.mark.parametrize("name", ["", "   ", "a" * 64, "line\nbreak", "tab\tx"])
def test_impossible_names_rejected(name: str) -> None:
    with pytest.raises(ToolError) as info:
        commands.validate_name(name)
    assert info.value.code is ErrorCode.INVALID_INPUT


def test_builders_produce_xml_with_escaped_values() -> None:
    cmd = commands.show_dynamic_address_group("a<b&c")
    root = SafeET.fromstring(cmd)
    assert root.findtext("object/dynamic-address-group/name") == "a<b&c"
    for builder in (
        commands.show_system_info,
        commands.show_devices_all,
        commands.request_license_info,
    ):
        SafeET.fromstring(builder())


def test_every_tool_has_allowlisted_templates() -> None:
    assert len(commands.TOOL_REQUESTS) == 13
    samples = {
        "op": lambda path: {
            "type": "op",
            "cmd": "".join(f"<{p}>" for p in path.split("/"))
            + "".join(f"</{p}>" for p in reversed(path.split("/"))),
        },
    }
    for tool, templates in commands.TOOL_REQUESTS.items():
        assert templates, tool
        for template in templates:
            if template.type == "op":
                path = template.pattern.split("(")[0]
                check_request(samples["op"](path))


def test_serial_validation() -> None:
    assert commands.validate_serial("900000000001") == "900000000001"
    with pytest.raises(ToolError):
        commands.validate_serial("bad serial!")
