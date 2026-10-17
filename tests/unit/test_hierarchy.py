from __future__ import annotations

from pathlib import Path

import pytest
from defusedxml import ElementTree as SafeET

from panos_mcp.models.common import ErrorCode, ToolError
from panos_mcp.services.hierarchy import DeviceGroupTree


@pytest.fixture
def tree(samples_root: Path) -> DeviceGroupTree:
    xml = (samples_root / "11.1/op/show-dg-hierarchy/baseline.xml").read_bytes()
    result = SafeET.fromstring(xml).find("result")
    assert result is not None
    return DeviceGroupTree.from_xml(result)


def test_ancestors_and_descendants(tree: DeviceGroupTree) -> None:
    assert tree.ancestors("Branch-DG") == ["Region-A-DG", "Global-DG", "shared"]
    assert tree.ancestors("shared") == []
    assert tree.descendants("Global-DG") == ["Region-A-DG", "Branch-DG", "Region-B-DG"]
    assert tree.depth_first() == ["Global-DG", "Region-A-DG", "Branch-DG", "Region-B-DG"]
    assert tree.exists("shared") and not tree.exists("Nope-DG")


def test_resolve_scope_not_found_with_suggestions(tree: DeviceGroupTree) -> None:
    assert tree.resolve_scope("Branch-DG") == "Branch-DG"
    with pytest.raises(ToolError) as info:
        tree.resolve_scope("Branch-GD")
    assert info.value.code is ErrorCode.NOT_FOUND
    assert "Branch-DG" in info.value.info.suggestions
