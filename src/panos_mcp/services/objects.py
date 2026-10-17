"""Object service: lookup with scope inheritance, where-used, address-group expansion (US2)."""

from __future__ import annotations

import asyncio
import difflib
import ipaddress
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime

from panos_mcp.client import commands
from panos_mcp.client.xmlapi import PanoramaClient
from panos_mcp.models.common import SHARED, ConfigSource, ErrorCode, ToolError, now_utc
from panos_mcp.models.objects import (
    Address,
    AddressGroup,
    AddressType,
    ApplicationGroup,
    ObjectBase,
    ObjectKind,
    ObjectReference,
    ReferrerKind,
    ResolvedAddressGroup,
    Service,
    ServiceGroup,
)
from panos_mcp.models.policy import NatRule, Position, SecurityRule
from panos_mcp.parsers.objects import parse_dag_members, parse_objects
from panos_mcp.parsers.policy import parse_nat_rules, parse_security_rules
from panos_mcp.services.hierarchy import DeviceGroupTree, load_tree

IpRange = tuple[int, int, int]  # (version, low, high)

# Names in one namespace: addresses and address groups share names in PAN-OS.
NAMESPACES: dict[ObjectKind, tuple[ObjectKind, ...]] = {
    ObjectKind.ADDRESS: (ObjectKind.ADDRESS, ObjectKind.ADDRESS_GROUP),
    ObjectKind.ADDRESS_GROUP: (ObjectKind.ADDRESS, ObjectKind.ADDRESS_GROUP),
    ObjectKind.SERVICE: (ObjectKind.SERVICE, ObjectKind.SERVICE_GROUP),
    ObjectKind.SERVICE_GROUP: (ObjectKind.SERVICE, ObjectKind.SERVICE_GROUP),
    ObjectKind.APPLICATION_GROUP: (ObjectKind.APPLICATION_GROUP,),
    ObjectKind.TAG: (ObjectKind.TAG,),
    ObjectKind.SECURITY_PROFILE_GROUP: (ObjectKind.SECURITY_PROFILE_GROUP,),
}


def ip_range(value: str) -> IpRange | None:
    """Address range for an IP, CIDR or `a-b` range; None for FQDN/wildcard/names."""
    value = value.strip()
    try:
        if "-" in value and value.count("-") == 1:
            lo, hi = (ipaddress.ip_address(v.strip()) for v in value.split("-"))
            return (lo.version, int(lo), int(hi))
        net = ipaddress.ip_network(value, strict=False)
        return (net.version, int(net.network_address), int(net.broadcast_address))
    except ValueError:
        return None


def overlaps(a: IpRange, b: IpRange) -> bool:
    return a[0] == b[0] and a[1] <= b[2] and b[1] <= a[2]


@dataclass
class Loaded:
    """Objects (and optionally rules) loaded for a set of scopes."""

    objects: dict[tuple[str, ObjectKind], list[ObjectBase]] = field(default_factory=dict)
    security: dict[tuple[str, Position], list[SecurityRule]] = field(default_factory=dict)
    nat: dict[tuple[str, Position], list[NatRule]] = field(default_factory=dict)
    retrieved_at: datetime = field(default_factory=now_utc)

    _index: dict[tuple[str, ObjectKind], dict[str, ObjectBase]] = field(default_factory=dict)

    def defined(self, scope: str, kind: ObjectKind) -> list[ObjectBase]:
        return self.objects.get((scope, kind), [])

    def find(self, scope: str, kind: ObjectKind, name: str) -> ObjectBase | None:
        """O(1) lookup of an object defined in `scope` (first definition wins)."""
        key = (scope, kind)
        index = self._index.get(key)
        if index is None:
            index = {}
            for obj in self.defined(scope, kind):
                index.setdefault(obj.name, obj)
            self._index[key] = index
        return index.get(name)


class Resolver:
    """Resolve names from a context scope: nearest definition wins (scope -> ancestors)."""

    def __init__(self, tree: DeviceGroupTree, loaded: Loaded, context: str) -> None:
        self.tree = tree
        self.loaded = loaded
        self.context = context
        self.chain = [context, *tree.ancestors(context)] if context != SHARED else [SHARED]

    def lookup(self, kind: ObjectKind, name: str) -> ObjectBase | None:
        for scope in self.chain:
            obj = self.loaded.find(scope, kind, name)
            if obj is not None:
                return obj
        return None

    def lookup_namespace(self, kind: ObjectKind, name: str) -> ObjectBase | None:
        for scope in self.chain:
            for k in NAMESPACES[kind]:
                obj = self.loaded.find(scope, k, name)
                if obj is not None:
                    return obj
        return None

    def address_ranges(self, member: str, seen: frozenset[str] = frozenset()) -> list[IpRange]:
        """IP ranges a rule/group member stands for (empty for any/fqdn/unknown)."""
        literal = ip_range(member)
        if literal is not None:
            return [literal]
        obj = self.lookup_namespace(ObjectKind.ADDRESS, member)
        if isinstance(obj, Address):
            if obj.type in (AddressType.IP_NETMASK, AddressType.IP_RANGE):
                found = ip_range(obj.value)
                return [found] if found else []
            return []
        if isinstance(obj, AddressGroup) and obj.static_members and member not in seen:
            out: list[IpRange] = []
            for child in obj.static_members:
                out.extend(self.address_ranges(child, seen | {member}))
            return out
        return []

    def group_contains(
        self, kind: ObjectKind, group: str, name: str, seen: frozenset[str] = frozenset()
    ) -> bool:
        """True if `group` (an address/service/application group) transitively includes `name`."""
        if group in seen:
            return False
        obj = self.lookup_namespace(kind, group)
        children: Sequence[str] = ()
        if isinstance(obj, AddressGroup) and obj.static_members:
            children = obj.static_members
        elif isinstance(obj, ServiceGroup | ApplicationGroup):
            children = obj.members
        for child in children:
            if child == name or self.group_contains(kind, child, name, seen | {group}):
                return True
        return False

    def expand(self, group: str) -> tuple[list[Address], list[str], list[str]]:
        """Flatten a static group: (addresses, nested groups in traversal order, cycles)."""
        addresses: dict[str, Address] = {}
        nested: list[str] = []
        cycles: list[str] = []

        def walk(name: str, path: tuple[str, ...]) -> None:
            obj = self.lookup_namespace(ObjectKind.ADDRESS_GROUP, name)
            if isinstance(obj, AddressGroup):
                if name in path:
                    cycles.append(" -> ".join([*path[path.index(name) :], name]))
                    return
                if path:
                    nested.append(name)
                for child in obj.static_members or []:
                    walk(child, (*path, name))
            elif isinstance(obj, Address):
                addresses.setdefault(obj.value + "|" + obj.name, obj)
            elif ip_range(name) is not None:
                addresses.setdefault(
                    name,
                    Address(name=name, scope=self.context, type=AddressType.IP_NETMASK, value=name),
                )

        walk(group, ())
        return list(addresses.values()), nested, cycles


ALL_KINDS = tuple(ObjectKind)
POSITIONS = (Position.PRE, Position.POST)


class ObjectService:
    def __init__(self, client: PanoramaClient) -> None:
        self.client = client

    async def tree(self) -> DeviceGroupTree:
        return await load_tree(self.client)

    async def load(
        self,
        scopes: Iterable[str],
        kinds: Iterable[ObjectKind],
        source: ConfigSource,
        *,
        rule_types: Sequence[str] = (),
    ) -> Loaded:
        loaded = Loaded()
        scopes = list(dict.fromkeys(scopes))
        kinds = list(kinds)
        times: list[datetime] = []

        async def objects(scope: str, kind: ObjectKind) -> None:
            when, result = await self.client.config(
                commands.object_xpath(scope, kind.value), source
            )
            times.append(when)
            loaded.objects[(scope, kind)] = parse_objects(result, kind, scope)

        async def rulebase(scope: str, pos: Position, rule_type: str) -> None:
            xpath = commands.rulebase_xpath(scope, rule_type, pos.value)  # type: ignore[arg-type]
            when, result = await self.client.config(xpath, source)
            times.append(when)
            if rule_type == "security":
                loaded.security[(scope, pos)] = parse_security_rules(result, scope, pos)
            else:
                loaded.nat[(scope, pos)] = parse_nat_rules(result, scope, pos)

        jobs = [objects(s, k) for s in scopes for k in kinds]
        jobs += [rulebase(s, p, t) for s in scopes for p in POSITIONS for t in rule_types]
        await asyncio.gather(*jobs)
        loaded.retrieved_at = min(times) if times else now_utc()
        return loaded

    # ------------------------------------------------------------------ get_objects

    async def get_objects(
        self,
        kind: ObjectKind,
        scope: str,
        source: ConfigSource,
        *,
        name: str | None = None,
        name_contains: str | None = None,
        value_contains: str | None = None,
        include_inherited: bool = False,
    ) -> tuple[list[ObjectBase], datetime]:
        tree = await self.tree()
        scope = tree.resolve_scope(scope)
        chain = [scope, *tree.ancestors(scope)] if include_inherited else [scope]
        loaded = await self.load(chain, [kind], source)
        resolver = Resolver(tree, loaded, scope)
        items: list[ObjectBase] = []
        for s in chain:
            for obj in loaded.defined(s, kind):
                obj.effective = resolver.lookup(kind, obj.name) is obj
                items.append(obj)
        if name is not None:
            commands.validate_name(name, "object name")
            matches = [o for o in items if o.name == name]
            if not matches:
                raise ToolError(
                    ErrorCode.NOT_FOUND,
                    f"No {kind.value.replace('_', ' ')} named {name!r} in scope {scope!r}"
                    + (" or its ancestors." if include_inherited else "."),
                    "Check the name and scope, or set include_inherited=true to include "
                    "shared and parent device groups.",
                    difflib.get_close_matches(name, [o.name for o in items], n=3, cutoff=0.5),
                )
            items = matches
        if name_contains:
            items = [o for o in items if name_contains.lower() in o.name.lower()]
        if value_contains:
            needle = value_contains.lower()
            items = [o for o in items if needle in _object_value(o).lower()]
        return items, loaded.retrieved_at

    # ------------------------------------------------------------------ where-used

    async def find_references(
        self, name: str, kind: ObjectKind, scope: str, source: ConfigSource
    ) -> tuple[list[ObjectReference], list[str], datetime]:
        commands.validate_name(name, "object name")
        tree = await self.tree()
        scope = tree.resolve_scope(scope)
        search = [scope, *tree.descendants(scope)]
        load_scopes = [*tree.ancestors(scope), *search]
        kinds = (
            *NAMESPACES[kind],
            ObjectKind.ADDRESS,
            ObjectKind.ADDRESS_GROUP,
            ObjectKind.SERVICE,
            ObjectKind.SERVICE_GROUP,
            ObjectKind.APPLICATION_GROUP,
            ObjectKind.SECURITY_PROFILE_GROUP,
        )
        loaded = await self.load(
            load_scopes, dict.fromkeys(kinds), source, rule_types=("security", "nat")
        )

        defined_here = [o for o in loaded.defined(scope, kind) if o.name == name]
        if not defined_here:
            names = [o.name for o in loaded.defined(scope, kind)]
            raise ToolError(
                ErrorCode.NOT_FOUND,
                f"No {kind.value.replace('_', ' ')} named {name!r} is defined in {scope!r}.",
                "Check the defining scope with get_objects (include_inherited=true).",
                difflib.get_close_matches(name, names, n=3, cutoff=0.5),
            )

        refs: list[ObjectReference] = []
        warnings: list[str] = []
        for s in search:
            resolved = Resolver(tree, loaded, s).lookup_namespace(kind, name)
            if resolved is not None and resolved.scope != scope:
                warnings.append(
                    f"References to {name!r} in {s} resolve to the object defined in "
                    f"{resolved.scope} and are not listed."
                )
                continue
            refs.extend(_references_in_scope(loaded, s, kind, name))
        return refs, warnings, loaded.retrieved_at

    # ------------------------------------------------------------------ group expansion

    async def resolve_address_group(
        self, name: str, scope: str, source: ConfigSource, device_serial: str | None
    ) -> tuple[ResolvedAddressGroup, datetime]:
        commands.validate_name(name, "address group name")
        tree = await self.tree()
        scope = tree.resolve_scope(scope)
        chain = [scope, *tree.ancestors(scope)]
        loaded = await self.load(chain, [ObjectKind.ADDRESS, ObjectKind.ADDRESS_GROUP], source)
        resolver = Resolver(tree, loaded, scope)
        group = resolver.lookup(ObjectKind.ADDRESS_GROUP, name)
        if not isinstance(group, AddressGroup):
            names = [o.name for s in chain for o in loaded.defined(s, ObjectKind.ADDRESS_GROUP)]
            raise ToolError(
                ErrorCode.NOT_FOUND,
                f"No address group named {name!r} is visible from {scope!r}.",
                "Use get_objects with kind=address_group and include_inherited=true.",
                difflib.get_close_matches(name, names, n=3, cutoff=0.5),
            )
        if group.dynamic_filter is not None:
            resolved = ResolvedAddressGroup(
                group=name, scope=group.scope, kind="dynamic", dynamic_filter=group.dynamic_filter
            )
            if device_serial:
                commands.validate_serial(device_serial)
                result = await self.client.op(
                    commands.show_dynamic_address_group(name), target=device_serial
                )
                resolved.resolved_on = device_serial
                resolved.addresses = [
                    Address(name=ip, scope=group.scope, type=AddressType.IP_NETMASK, value=ip)
                    for ip in parse_dag_members(result)
                ]
            return resolved, loaded.retrieved_at
        addresses, nested, cycles = resolver.expand(name)
        return (
            ResolvedAddressGroup(
                group=name,
                scope=group.scope,
                kind="static",
                addresses=addresses,
                nested_groups=nested,
                cycles_detected=cycles,
            ),
            loaded.retrieved_at,
        )


def _object_value(obj: ObjectBase) -> str:
    if isinstance(obj, Address):
        return obj.value
    if isinstance(obj, Service):
        return f"{obj.protocol}/{obj.destination_port}"
    return ""


def _references_in_scope(
    loaded: Loaded, scope: str, kind: ObjectKind, name: str
) -> list[ObjectReference]:
    refs: list[ObjectReference] = []

    def add(rk: ReferrerKind, referrer: str, fld: str, pos: Position | None = None) -> None:
        refs.append(
            ObjectReference(
                referrer_kind=rk,
                referrer_name=referrer,
                scope=scope,
                position=pos.value if pos in POSITIONS else None,  # type: ignore[arg-type]
                field=fld,
            )
        )

    address_like = kind in (ObjectKind.ADDRESS, ObjectKind.ADDRESS_GROUP)
    service_like = kind in (ObjectKind.SERVICE, ObjectKind.SERVICE_GROUP)
    for pos in POSITIONS:
        for sec in loaded.security.get((scope, pos), []):
            fields: dict[str, list[str]] = {}
            if address_like:
                fields = {"source": sec.sources, "destination": sec.destinations}
            elif service_like:
                fields = {"service": sec.services}
            elif kind is ObjectKind.APPLICATION_GROUP:
                fields = {"application": sec.applications}
            elif kind is ObjectKind.TAG:
                fields = {"tag": sec.tags}
            elif kind is ObjectKind.SECURITY_PROFILE_GROUP:
                fields = {"profile_group": [sec.profile_group] if sec.profile_group else []}
            for fld, values in fields.items():
                if name in values:
                    add(ReferrerKind.SECURITY_RULE, sec.name, fld, pos)
        for nat in loaded.nat.get((scope, pos), []):
            nat_fields: dict[str, list[str]] = {}
            if address_like:
                translated = []
                if nat.source_translation:
                    translated += nat.source_translation.addresses
                if nat.destination_translation and nat.destination_translation.address:
                    translated.append(nat.destination_translation.address)
                nat_fields = {
                    "source": nat.sources,
                    "destination": nat.destinations,
                    "translated_address": translated,
                }
            elif service_like:
                nat_fields = {"service": [nat.service]}
            elif kind is ObjectKind.TAG:
                nat_fields = {"tag": nat.tags}
            for fld, values in nat_fields.items():
                if name in values:
                    add(ReferrerKind.NAT_RULE, nat.name, fld, pos)

    for obj in loaded.defined(scope, ObjectKind.ADDRESS_GROUP):
        if not isinstance(obj, AddressGroup):
            continue
        if address_like and name in (obj.static_members or []):
            add(ReferrerKind.ADDRESS_GROUP, obj.name, "members")
        if kind is ObjectKind.TAG and obj.dynamic_filter and f"'{name}'" in obj.dynamic_filter:
            add(ReferrerKind.DYNAMIC_ADDRESS_GROUP_FILTER, obj.name, "filter")
    if service_like:
        for obj in loaded.defined(scope, ObjectKind.SERVICE_GROUP):
            if isinstance(obj, ServiceGroup) and name in obj.members:
                add(ReferrerKind.SERVICE_GROUP, obj.name, "members")
    if kind is ObjectKind.APPLICATION_GROUP:
        for obj in loaded.defined(scope, ObjectKind.APPLICATION_GROUP):
            if isinstance(obj, ApplicationGroup) and name in obj.members:
                add(ReferrerKind.APPLICATION_GROUP, obj.name, "members")
    if kind is ObjectKind.TAG:
        tagged_kinds = (
            (ObjectKind.ADDRESS, ReferrerKind.ADDRESS),
            (ObjectKind.ADDRESS_GROUP, ReferrerKind.ADDRESS_GROUP),
            (ObjectKind.SERVICE, ReferrerKind.SERVICE),
            (ObjectKind.SERVICE_GROUP, ReferrerKind.SERVICE_GROUP),
            (ObjectKind.SECURITY_PROFILE_GROUP, ReferrerKind.SECURITY_PROFILE_GROUP),
        )
        for obj_kind, rk in tagged_kinds:
            for obj in loaded.defined(scope, obj_kind):
                if name in obj.tags:
                    add(rk, obj.name, "tag")
    return refs
