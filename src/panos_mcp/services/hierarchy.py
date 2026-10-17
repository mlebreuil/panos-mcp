"""Device-group tree from `show dg-hierarchy`: ancestry, descendants, name resolution."""

from __future__ import annotations

import difflib
from xml.etree.ElementTree import Element

from panos_mcp.client import commands
from panos_mcp.client.xmlapi import PanoramaClient
from panos_mcp.models.common import SHARED, ErrorCode, ToolError


class DeviceGroupTree:
    def __init__(self, parents: dict[str, str]) -> None:
        self.parents = parents  # device group -> parent ("shared" for top level)
        self.children: dict[str, list[str]] = {SHARED: []}
        for dg in parents:
            self.children.setdefault(dg, [])
        for dg, parent in parents.items():
            self.children.setdefault(parent, []).append(dg)

    @classmethod
    def from_xml(cls, result: Element) -> DeviceGroupTree:
        parents: dict[str, str] = {}

        def walk(node: Element, parent: str) -> None:
            for child in node.findall("dg"):
                name = child.get("name")
                if name:
                    parents[name] = parent
                    walk(child, name)

        container = result.find("dg-hierarchy")
        walk(container if container is not None else result, SHARED)
        return cls(parents)

    @property
    def names(self) -> list[str]:
        return list(self.parents)

    def exists(self, name: str) -> bool:
        return name == SHARED or name in self.parents

    def ancestors(self, dg: str) -> list[str]:
        """Parents from nearest to `shared` (inclusive); empty for `shared`."""
        chain: list[str] = []
        current = dg
        while current != SHARED:
            current = self.parents[current]
            chain.append(current)
        return chain

    def descendants(self, dg: str) -> list[str]:
        out: list[str] = []
        stack = list(reversed(self.children.get(dg, [])))
        while stack:
            node = stack.pop()
            out.append(node)
            stack.extend(reversed(self.children.get(node, [])))
        return out

    def depth_first(self, root: str = SHARED) -> list[str]:
        return [root, *self.descendants(root)] if root != SHARED else self.descendants(SHARED)

    def close_matches(self, name: str) -> list[str]:
        return difflib.get_close_matches(name, [SHARED, *self.names], n=3, cutoff=0.5)

    def resolve_scope(self, name: str) -> str:
        if self.exists(name):
            return name
        raise ToolError(
            ErrorCode.NOT_FOUND,
            f"Device group {name!r} does not exist.",
            "Use list_device_groups to see the available device groups.",
            self.close_matches(name),
        )


async def load_tree(client: PanoramaClient) -> DeviceGroupTree:
    return DeviceGroupTree.from_xml(await client.op(commands.show_dg_hierarchy()))
