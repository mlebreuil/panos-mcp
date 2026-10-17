"""Leak checks (research.md R8).

Layer 1 (`check_originals`): at sanitize time, no original sensitive value may remain.
Layer 2 (`lint`): in CI, without the mapping, committed samples must only contain
values from forged/documentation ranges.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from xml.etree.ElementTree import Element

from defusedxml import ElementTree as SafeET

from panos_mcp.samples.sanitize.classify import (
    EMAIL_RE,
    FQDN_TAGS,
    IPV4_TOKEN_RE,
    MAC_RE,
    SECRET_TAGS,
    SERIAL_TAGS,
    looks_like_domain,
)
from panos_mcp.samples.sanitize.forge import (
    DOC_MAC_PREFIX,
    DOC_V4,
    DOC_V6,
    EXAMPLE_DOMAINS,
    REDACTED,
    _looks_like_mask,
)

_IPV6_TOKEN_RE = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?:/\d{1,3})?")


@dataclass(frozen=True)
class Finding:
    rule: str
    value: str
    where: str

    def __str__(self) -> str:
        return f"{self.rule}: {self.value!r} ({self.where})"


def _values(text: str) -> str:
    """Text and attribute values only (element names are not data)."""
    try:
        root: Element = SafeET.fromstring(text)
    except SafeET.ParseError:
        return text
    parts: list[str] = []
    for node in root.iter():
        parts.extend(node.attrib.values())
        if node.text:
            parts.append(node.text)
    return "\n".join(parts)


def check_originals(text: str, originals: Iterable[str]) -> list[str]:
    """Return original values still present in the data of `text` (token match, len >= 3)."""
    text = _values(text)
    leaks = []
    for value in sorted(set(originals)):
        if len(value) < 3:
            continue
        pattern = r"(?<![\w.:-])" + re.escape(value) + r"(?![\w:-]|\.\w)"
        if re.search(pattern, text):
            leaks.append(value)
    return leaks


def _domain_ok(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    return d.endswith(EXAMPLE_DOMAINS) or d.endswith(".test") or d in EXAMPLE_DOMAINS


def lint(text: str) -> list[Finding]:
    """Check sanitized XML for values outside forged/documentation ranges."""
    findings: list[Finding] = []
    root: Element = SafeET.fromstring(text)
    for node in root.iter():
        values = [("text", node.text or "")] + [(f"@{k}", v) for k, v in node.attrib.items()]
        for where_kind, value in values:
            if not value.strip():
                continue
            where = f"<{node.tag}> {where_kind}"
            findings.extend(_lint_value(node.tag, where_kind, value.strip(), where))
    return findings


def _lint_value(tag: str, where_kind: str, value: str, where: str) -> list[Finding]:
    out: list[Finding] = []
    if where_kind == "text" and tag in SECRET_TAGS and value != REDACTED:
        out.append(Finding("secret-not-redacted", value[:12] + "...", where))
    if where_kind == "text" and tag in SERIAL_TAGS and not value.startswith("9"):
        out.append(Finding("serial-not-forged", value, where))
    if (
        where_kind == "text"
        and tag in FQDN_TAGS
        and looks_like_domain(value)
        and not _domain_ok(value)
    ):
        out.append(Finding("domain-not-example", value, where))
    for match in IPV4_TOKEN_RE.finditer(value):
        base = match.group(0).split("/")[0]
        try:
            addr = ipaddress.IPv4Address(base)
        except ValueError:
            continue
        if _looks_like_mask(base) or not addr.is_global:
            continue
        if not any(addr in net for net in DOC_V4):
            out.append(Finding("public-ipv4-not-documentation", match.group(0), where))
    for match in _IPV6_TOKEN_RE.finditer(value):
        try:
            addr6 = ipaddress.IPv6Address(match.group(0).split("/")[0])
        except ValueError:
            continue
        if addr6.is_global and addr6 not in DOC_V6:
            out.append(Finding("public-ipv6-not-documentation", match.group(0), where))
    for match in EMAIL_RE.finditer(value):
        if not _domain_ok(match.group(0).rsplit("@", 1)[-1]):
            out.append(Finding("email-not-example", match.group(0), where))
    for match in MAC_RE.finditer(value):
        if not match.group(0).lower().startswith(DOC_MAC_PREFIX):
            out.append(Finding("mac-not-documentation", match.group(0), where))
    return out
