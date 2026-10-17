"""Parsers for object config responses (address, groups, services, tags, profile groups)."""

from __future__ import annotations

from xml.etree.ElementTree import Element

from panos_mcp.client.commands import OBJECT_XPATH_NODE
from panos_mcp.models.objects import (
    Address,
    AddressGroup,
    AddressType,
    ApplicationGroup,
    ObjectBase,
    ObjectKind,
    SecurityProfileGroup,
    Service,
    ServiceGroup,
    Tag,
)
from panos_mcp.parsers import members, name_of, text


def _entries(result: Element, kind: ObjectKind) -> list[Element]:
    container = result.find(OBJECT_XPATH_NODE[kind.value])
    return container.findall("entry") if container is not None else []


def _common(entry: Element, scope: str) -> dict[str, object]:
    return {
        "name": name_of(entry),
        "scope": scope,
        "description": text(entry, "description"),
        "tags": members(entry, "tag"),
    }


def _address(entry: Element, scope: str) -> Address | None:
    for kind in AddressType:
        value = text(entry, kind.value)
        if value:
            return Address.model_validate({**_common(entry, scope), "type": kind, "value": value})
    return None


def _address_group(entry: Element, scope: str) -> AddressGroup:
    dynamic = text(entry, "dynamic/filter")
    if dynamic is not None:
        return AddressGroup.model_validate({**_common(entry, scope), "dynamic_filter": dynamic})
    return AddressGroup.model_validate(
        {**_common(entry, scope), "static_members": members(entry, "static")}
    )


def _service(entry: Element, scope: str) -> Service | None:
    proto = entry.find("protocol")
    if proto is None or len(proto) == 0:
        return None
    node = proto[0]
    if node.tag not in ("tcp", "udp", "sctp"):
        return None
    return Service.model_validate(
        {
            **_common(entry, scope),
            "protocol": node.tag,
            "destination_port": text(node, "port", ""),
            "source_port": text(node, "source-port"),
        }
    )


def _profile_group(entry: Element, scope: str) -> SecurityProfileGroup:
    profiles = {
        child.tag: (members(entry, child.tag) or [""])[0]
        for child in entry
        if child.find("member") is not None and child.tag != "tag"
    }
    return SecurityProfileGroup.model_validate({**_common(entry, scope), "profiles": profiles})


def parse_objects(result: Element, kind: ObjectKind, scope: str) -> list[ObjectBase]:
    out: list[ObjectBase] = []
    for entry in _entries(result, kind):
        obj: ObjectBase | None
        match kind:
            case ObjectKind.ADDRESS:
                obj = _address(entry, scope)
            case ObjectKind.ADDRESS_GROUP:
                obj = _address_group(entry, scope)
            case ObjectKind.SERVICE:
                obj = _service(entry, scope)
            case ObjectKind.SERVICE_GROUP:
                obj = ServiceGroup.model_validate(
                    {**_common(entry, scope), "members": members(entry, "members")}
                )
            case ObjectKind.APPLICATION_GROUP:
                obj = ApplicationGroup.model_validate(
                    {**_common(entry, scope), "members": members(entry, "members")}
                )
            case ObjectKind.TAG:
                obj = Tag.model_validate(
                    {
                        **_common(entry, scope),
                        "color": text(entry, "color"),
                        "comments": text(entry, "comments"),
                    }
                )
            case ObjectKind.SECURITY_PROFILE_GROUP:
                obj = _profile_group(entry, scope)
        if obj is not None:
            out.append(obj)
    return out


def parse_dag_members(result: Element) -> list[str]:
    """Registered IPs of a dynamic address group from `show object dynamic-address-group`."""
    return [name_of(e) for e in result.iter("entry") if e.get("type") and name_of(e)]
