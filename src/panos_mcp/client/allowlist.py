"""Request allow-list: the server's read-only guarantee.

Every request to the Panorama XML API passes through `check_request` before any
transport is used. Only the request shapes listed in research.md R4 are allowed;
everything else raises `ReadOnlyViolation`.

Changes to this file require explicit reviewer sign-off (constitution Principle I).
"""

from __future__ import annotations

from collections.abc import Mapping
from xml.etree.ElementTree import Element

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException


class ReadOnlyViolation(Exception):
    """A request that is not on the read-only allow-list."""


# Operational command paths (root -> leaf of the parsed `cmd`, see `command_path`).
# Prefix entries also allow deeper paths below them (e.g. `.../all`, `.../name/X`).
OP_PREFIXES: frozenset[str] = frozenset(
    {
        "show/system/info",
        "show/high-availability/state",
        "show/devices/all",
        "show/devicegroups",
        "show/dg-hierarchy",
        "show/templates",
        "show/jobs/all",
        "show/jobs/id",
        "check/pending-changes",
        "show/object/dynamic-address-group",
        "test/security-policy-match",
    }
)
# Exact-only paths: `request/*` is otherwise forbidden (research.md R4).
OP_EXACT: frozenset[str] = frozenset({"request/license/info"})

CONFIG_ACTIONS: frozenset[str] = frozenset({"get", "show"})
LOG_TYPES: frozenset[str] = frozenset({"traffic", "threat", "url", "system", "config"})

_ALLOWED_KEYS: Mapping[str, frozenset[str]] = {
    "keygen": frozenset({"type", "user", "password"}),
    "op": frozenset({"type", "cmd", "target"}),
    "config": frozenset({"type", "action", "xpath", "target"}),
    "log": frozenset({"type", "log-type", "query", "nlogs", "skip", "dir", "action", "job-id"}),
}


def parse_cmd(cmd: str) -> Element:
    try:
        root: Element = SafeET.fromstring(cmd)
    except (SafeET.ParseError, DefusedXmlException) as exc:
        raise ReadOnlyViolation(f"op command is not well-formed XML: {exc}") from None
    return root


def command_path(root: Element) -> str:
    """Root-to-leaf element path, descending while an element has exactly one child.

    `<show><jobs><id>5</id></jobs></show>` -> `show/jobs/id`;
    `<test><security-policy-match><from>a</from><to>b</to>...` -> `test/security-policy-match`.
    """
    parts = [root.tag]
    node = root
    while True:
        children = list(node)
        if len(children) != 1:
            break
        node = children[0]
        parts.append(node.tag)
    return "/".join(parts)


def is_allowed_op_path(path: str) -> bool:
    if path in OP_EXACT:
        return True
    return any(path == p or path.startswith(p + "/") for p in OP_PREFIXES)


def check_request(
    params: Mapping[str, str],
    started_log_jobs: set[int] | frozenset[int] = frozenset(),
    *,
    allow_keygen: bool = False,
) -> None:
    """Raise `ReadOnlyViolation` unless `params` is an allow-listed read request."""
    req_type = params.get("type", "")
    if req_type not in _ALLOWED_KEYS:
        raise ReadOnlyViolation(f"request type {req_type!r} is not allowed")
    extra = set(params) - _ALLOWED_KEYS[req_type]
    if extra:
        raise ReadOnlyViolation(f"parameters not allowed for type={req_type}: {sorted(extra)}")

    if req_type == "keygen":
        if not allow_keygen:
            raise ReadOnlyViolation("key generation is only allowed at startup")
        return

    if req_type == "op":
        cmd = params.get("cmd", "")
        path = command_path(parse_cmd(cmd))
        if not is_allowed_op_path(path):
            raise ReadOnlyViolation(f"operational command {path!r} is not allowed")
        return

    if req_type == "config":
        action = params.get("action")
        if action not in CONFIG_ACTIONS:
            raise ReadOnlyViolation(f"config action {action!r} is not allowed (only get/show)")
        xpath = params.get("xpath", "")
        if not xpath.startswith("/config/"):
            raise ReadOnlyViolation("config xpath must start with /config/")
        return

    # type=log
    action = params.get("action")
    if action is None:
        if params.get("log-type") not in LOG_TYPES:
            raise ReadOnlyViolation(f"log type {params.get('log-type')!r} is not allowed")
        if "job-id" in params:
            raise ReadOnlyViolation("job-id is only valid with action=get")
        return
    if action != "get":
        raise ReadOnlyViolation(f"log action {action!r} is not allowed")
    try:
        job_id = int(params.get("job-id", ""))
    except ValueError:
        raise ReadOnlyViolation("log action=get requires a numeric job-id") from None
    if job_id not in started_log_jobs:
        raise ReadOnlyViolation(f"log job {job_id} was not started by this process")
