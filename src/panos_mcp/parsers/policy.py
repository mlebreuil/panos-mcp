"""Parsers for security and NAT rulebase config responses."""

from __future__ import annotations

from xml.etree.ElementTree import Element

from panos_mcp.models.policy import (
    DestinationTranslation,
    NatRule,
    NatType,
    Position,
    RuleAction,
    RuleTarget,
    SecurityRule,
    SourceTranslation,
    SourceTranslationKind,
)
from panos_mcp.parsers import members, name_of, text, yes


def _entries(result: Element) -> list[Element]:
    rules = result.find("rules")
    return rules.findall("entry") if rules is not None else []


def _target(entry: Element) -> RuleTarget | None:
    target = entry.find("target")
    if target is None:
        return None
    return RuleTarget(
        devices=[name_of(d) for d in target.findall("devices/entry") if name_of(d)],
        negate=yes(text(target, "negate")),
    )


def _action(value: str | None) -> RuleAction:
    try:
        return RuleAction(value or "allow")
    except ValueError:
        return RuleAction.DENY


def parse_security_rules(result: Element, scope: str, position: Position) -> list[SecurityRule]:
    out = []
    for entry in _entries(result):
        profiles_node = entry.find("profile-setting/profiles")
        profiles = None
        if profiles_node is not None:
            profiles = {
                child.tag: (members(profiles_node, child.tag) or [""])[0] for child in profiles_node
            }
        groups = members(entry, "profile-setting/group")
        out.append(
            SecurityRule(
                name=name_of(entry),
                uuid=entry.get("uuid"),
                scope=scope,
                position=position,
                disabled=yes(text(entry, "disabled")),
                description=text(entry, "description"),
                tags=members(entry, "tag"),
                target=_target(entry),
                from_zones=members(entry, "from"),
                to_zones=members(entry, "to"),
                sources=members(entry, "source"),
                destinations=members(entry, "destination"),
                source_users=members(entry, "source-user"),
                applications=members(entry, "application"),
                services=members(entry, "service"),
                categories=members(entry, "category"),
                negate_source=yes(text(entry, "negate-source")),
                negate_destination=yes(text(entry, "negate-destination")),
                action=_action(text(entry, "action")),
                profile_group=groups[0] if groups else None,
                profiles=profiles,
                log_start=yes(text(entry, "log-start")),
                log_end=text(entry, "log-end", "yes") != "no",
                log_setting=text(entry, "log-setting"),
                schedule=text(entry, "schedule"),
            )
        )
    return out


def _source_translation(entry: Element) -> SourceTranslation | None:
    node = entry.find("source-translation")
    if node is None or len(node) == 0:
        return None
    kind_node = node[0]
    try:
        kind = SourceTranslationKind(kind_node.tag)
    except ValueError:
        return None
    addresses = members(kind_node, "translated-address")
    single = text(kind_node, "translated-address")
    if not addresses and single:
        addresses = [single]
    return SourceTranslation(
        kind=kind,
        addresses=addresses,
        interface=text(kind_node, "interface-address/interface"),
        bidirectional=yes(text(kind_node, "bi-directional")),
    )


def _destination_translation(entry: Element) -> DestinationTranslation | None:
    for tag, dynamic in (
        ("destination-translation", False),
        ("dynamic-destination-translation", True),
    ):
        node = entry.find(tag)
        if node is not None:
            port = text(node, "translated-port")
            return DestinationTranslation(
                address=text(node, "translated-address"),
                port=int(port) if port and port.isdigit() else None,
                dynamic=dynamic,
            )
    return None


def parse_nat_rules(result: Element, scope: str, position: Position) -> list[NatRule]:
    out = []
    for entry in _entries(result):
        to_zones = members(entry, "to")
        try:
            nat_type = NatType(text(entry, "nat-type", "ipv4"))
        except ValueError:
            nat_type = NatType.IPV4
        out.append(
            NatRule(
                name=name_of(entry),
                uuid=entry.get("uuid"),
                scope=scope,
                position=position,
                disabled=yes(text(entry, "disabled")),
                description=text(entry, "description"),
                tags=members(entry, "tag"),
                target=_target(entry),
                from_zones=members(entry, "from"),
                to_zone=to_zones[0] if to_zones else None,
                to_interface=text(entry, "to-interface"),
                sources=members(entry, "source"),
                destinations=members(entry, "destination"),
                service=text(entry, "service", "any"),
                nat_type=nat_type,
                source_translation=_source_translation(entry),
                destination_translation=_destination_translation(entry),
            )
        )
    return out
