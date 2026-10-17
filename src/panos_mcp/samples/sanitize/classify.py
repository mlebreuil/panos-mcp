"""Classify XML values by element/attribute context and by parsing (research.md R8)."""

from __future__ import annotations

import ipaddress
import re
from enum import StrEnum


class Kind(StrEnum):
    SECRET = "secret"  # noqa: S105 - a value kind, not a password
    IP = "ip"  # address, prefix, range or wildcard
    FQDN = "fqdn"
    NAME = "name"
    HOSTNAME = "hostname"
    SERIAL = "serial"
    MAC = "mac"
    USER = "user"
    EMAIL = "email"
    TEXT = "text"
    URL = "url"
    KEEP = "keep"
    SCAN = "scan"  # unclassified text: scan for embedded IPs/emails/MACs
    FILTER = "filter"  # dynamic-group match expression: quoted tag names


SECRET_TAGS = frozenset(
    {
        "phash",
        "key",
        "password",
        "private-key",
        "pre-shared-key",
        "community",
        "community-string",
        "secret",
        "passphrase",
        "authentication-key",
        "bind-password",
        "api-key",
        "auth-password",
        "priv-password",
        "certificate-pem",
        "private-key-pem",
    }
)
IP_TAGS = frozenset(
    {
        "ip-netmask",
        "ip-range",
        "ip-wildcard",
        "ip-address",
        "ipv6-address",
        "mgmt-ip",
        "ip",
        "src",
        "dst",
        "natsrc",
        "natdst",
        "default-gateway",
        "peer-ip",
        "ipv6-default-gateway",
        "translated-address",
        "source-ip",
        "destination-ip",
    }
)
FQDN_TAGS = frozenset({"fqdn", "domain"})
HOSTNAME_TAGS = frozenset({"hostname", "devicename", "device-name", "device_name", "peer-name"})
SERIAL_TAGS = frozenset(
    {"serial", "serial-num", "serial-no", "serialno", "peer-serial", "device-serial"}
)
MAC_TAGS = frozenset({"mac", "mac-address", "macaddr", "peer-mac"})
USER_TAGS = frozenset({"admin", "user", "srcuser", "dstuser", "src-user", "source-user", "owner"})
TEXT_TAGS = frozenset({"description", "comment", "comments", "opaque", "msg-detail"})
URL_TAGS = frozenset({"url", "misc"})
NAME_REF_TAGS = frozenset(
    {
        "member",
        "parent-dg",
        "device-group",
        "template-stack",
        "template",
        "from",
        "to",
        "from_zone",
        "to_zone",
        "zone",
        "app",
        "application",
        "rule",
        "rule-name",
    }
)
KEEP_TAGS = frozenset(
    {
        "sw-version",
        "app-version",
        "av-version",
        "threat-version",
        "wildfire-version",
        "url-filtering-version",
        "model",
        "family",
        "uptime",
        "time",
        "receive_time",
        "time_generated",
        "start",
        "status",
        "result",
        "progress",
        "type",
        "action",
        "protocol",
        "proto",
        "port",
        "sport",
        "dport",
        "destination-port",
        "severity",
        "subtype",
        "category",
        "netmask",
        "vsys",
        "rule_uuid",
        "id",
        "job",
        "tenq",
        "tdeq",
        "tfin",
        "expires",
        "issued",
        "feature",
        "expired",
        "authcode",
        "base-license-name",
        "connected",
        "ha",
        "state",
        "enabled",
        "mode",
        "count",
        "total-count",
        "bytes",
        "packets",
        "session_end_reason",
        "direction",
        "threatid",
        "eventid",
    }
)

MAC_RE = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")
IPV4_TOKEN_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\d.])")
URL_RE = re.compile(r"\bhttps?://[^\s<>\"']+")


DOMAIN_RE = re.compile(r"^(\*\.)?([A-Za-z0-9-]+\.)+[A-Za-z]{2,}\.?$")


def looks_like_domain(value: str) -> bool:
    return DOMAIN_RE.match(value.strip()) is not None


def parse_ip_like(value: str) -> bool:
    """True for an IPv4/IPv6 address, prefix, `a-b` range or `addr/mask` wildcard."""
    candidate = value.strip()
    if not candidate:
        return False
    if "-" in candidate and candidate.count("-") == 1:
        left, right = candidate.split("-")
        return _is_addr(left) and _is_addr(right)
    try:
        ipaddress.ip_network(candidate, strict=False)
        return True
    except ValueError:
        pass
    if "/" in candidate:
        addr, mask = candidate.split("/", 1)
        return _is_addr(addr) and _is_addr(mask)
    return False


def _is_addr(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def classify_element(tag: str, text: str) -> Kind:
    """Classify the text of an element named `tag`."""
    if tag in SECRET_TAGS:
        return Kind.SECRET
    if tag == "filter":
        return Kind.FILTER
    if tag in IP_TAGS:
        return Kind.IP if parse_ip_like(text) else Kind.SCAN
    if tag in FQDN_TAGS:
        return Kind.FQDN if looks_like_domain(text) else Kind.SCAN
    if tag in HOSTNAME_TAGS:
        return Kind.HOSTNAME
    if tag in SERIAL_TAGS:
        return Kind.SERIAL
    if tag in MAC_TAGS:
        return Kind.MAC
    if tag in USER_TAGS:
        return Kind.EMAIL if EMAIL_RE.fullmatch(text.strip()) else Kind.USER
    if tag in TEXT_TAGS:
        return Kind.TEXT
    if tag in URL_TAGS:
        return Kind.URL
    if tag in NAME_REF_TAGS:
        return Kind.IP if parse_ip_like(text) else Kind.NAME
    if tag in KEEP_TAGS:
        return Kind.SCAN
    return Kind.SCAN
