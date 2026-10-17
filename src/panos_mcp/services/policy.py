"""Policy service: rulebases per scope, effective (inherited) order, rule filters (US2)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from panos_mcp.client.xmlapi import PanoramaClient
from panos_mcp.models.common import SHARED, ConfigSource
from panos_mcp.models.objects import ObjectKind
from panos_mcp.models.policy import NatRule, Position, RuleAction, SecurityRule
from panos_mcp.services.hierarchy import DeviceGroupTree
from panos_mcp.services.objects import ObjectService, Resolver, ip_range, overlaps

Rulebase = Literal["pre", "post", "both"]
ADDRESS_KINDS = (
    ObjectKind.ADDRESS,
    ObjectKind.ADDRESS_GROUP,
    ObjectKind.SERVICE,
    ObjectKind.SERVICE_GROUP,
    ObjectKind.APPLICATION_GROUP,
)


@dataclass
class RuleFilters:
    name_contains: str | None = None
    tag: str | None = None
    from_zone: str | None = None
    to_zone: str | None = None
    source: str | None = None
    destination: str | None = None
    application: str | None = None
    service: str | None = None
    action: RuleAction | None = None
    disabled: bool | None = None

    def needs_objects(self) -> bool:
        return any((self.source, self.destination, self.application, self.service))


def evaluation_order(
    tree: DeviceGroupTree, scope: str, rulebase: Rulebase, effective: bool
) -> list[tuple[str, Position]]:
    """(scope, position) pairs in firewall evaluation order (research.md R5)."""
    if effective and scope != SHARED:
        top_down = [*reversed(tree.ancestors(scope)), scope]  # shared ... scope
    else:
        top_down = [scope]
    pre = [(s, Position.PRE) for s in top_down]
    post = [(s, Position.POST) for s in reversed(top_down)]
    if rulebase == "pre":
        return pre
    if rulebase == "post":
        return post
    return pre + post


def _member_matches(
    resolver: Resolver, values: list[str], query: str, kind: ObjectKind, negate: bool = False
) -> bool:
    if "any" in values:
        return not negate
    query_range = ip_range(query)
    if query_range is not None and kind in (ObjectKind.ADDRESS, ObjectKind.ADDRESS_GROUP):
        hit = any(overlaps(query_range, r) for v in values for r in resolver.address_ranges(v))
    else:
        hit = any(v == query or resolver.group_contains(kind, v, query) for v in values)
    return hit != negate


def security_matches(rule: SecurityRule, f: RuleFilters, resolver: Resolver) -> bool:
    if f.name_contains and f.name_contains.lower() not in rule.name.lower():
        return False
    if f.tag and f.tag not in rule.tags:
        return False
    if f.from_zone and not ({f.from_zone, "any"} & set(rule.from_zones)):
        return False
    if f.to_zone and not ({f.to_zone, "any"} & set(rule.to_zones)):
        return False
    if f.action and rule.action is not f.action:
        return False
    if f.disabled is not None and rule.disabled != f.disabled:
        return False
    if f.source and not _member_matches(
        resolver, rule.sources, f.source, ObjectKind.ADDRESS, rule.negate_source
    ):
        return False
    if f.destination and not _member_matches(
        resolver, rule.destinations, f.destination, ObjectKind.ADDRESS, rule.negate_destination
    ):
        return False
    if f.application and not _member_matches(
        resolver, rule.applications, f.application, ObjectKind.APPLICATION_GROUP
    ):
        return False
    return not (
        f.service
        and not _member_matches(resolver, rule.services, f.service, ObjectKind.SERVICE_GROUP)
    )


def nat_matches(rule: NatRule, f: RuleFilters, resolver: Resolver) -> bool:
    if f.name_contains and f.name_contains.lower() not in rule.name.lower():
        return False
    if f.tag and f.tag not in rule.tags:
        return False
    if f.from_zone and not ({f.from_zone, "any"} & set(rule.from_zones)):
        return False
    if f.to_zone and rule.to_zone not in (f.to_zone, "any"):
        return False
    if f.disabled is not None and rule.disabled != f.disabled:
        return False
    if f.source and not _member_matches(resolver, rule.sources, f.source, ObjectKind.ADDRESS):
        return False
    if f.destination and not _member_matches(
        resolver, rule.destinations, f.destination, ObjectKind.ADDRESS
    ):
        return False
    return not (
        f.service
        and not _member_matches(resolver, [rule.service], f.service, ObjectKind.SERVICE_GROUP)
    )


class PolicyService:
    def __init__(self, client: PanoramaClient) -> None:
        self.client = client
        self.objects = ObjectService(client)

    async def rules(
        self,
        rule_type: Literal["security", "nat"],
        scope: str,
        rulebase: Rulebase,
        effective: bool,
        filters: RuleFilters,
        source: ConfigSource,
    ) -> tuple[list[SecurityRule] | list[NatRule], datetime]:
        tree = await self.objects.tree()
        scope = tree.resolve_scope(scope)
        order = evaluation_order(tree, scope, rulebase, effective)
        rule_scopes = list(dict.fromkeys(s for s, _ in order))
        loaded = await self.objects.load(rule_scopes, [], source, rule_types=(rule_type,))
        if filters.needs_objects():
            object_scopes = [scope, *tree.ancestors(scope)]
            objects = await self.objects.load(object_scopes, ADDRESS_KINDS, source)
            loaded.objects = objects.objects
            loaded.retrieved_at = min(loaded.retrieved_at, objects.retrieved_at)
        resolver = Resolver(tree, loaded, scope)

        out_sec: list[SecurityRule] = []
        out_nat: list[NatRule] = []
        position = 0
        for s, pos in order:
            if rule_type == "security":
                for rule in loaded.security.get((s, pos), []):
                    position += 1
                    rule.order = position
                    if security_matches(rule, filters, resolver):
                        out_sec.append(rule)
            else:
                for nat in loaded.nat.get((s, pos), []):
                    position += 1
                    nat.order = position
                    if nat_matches(nat, filters, resolver):
                        out_nat.append(nat)
        return (out_sec if rule_type == "security" else out_nat), loaded.retrieved_at
