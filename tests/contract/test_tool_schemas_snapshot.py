"""Constitution III: tool names and input schemas are a public contract.

Any change fails this test until the snapshot is intentionally regenerated with
`PANOS_MCP_UPDATE_SNAPSHOTS=1 uv run pytest tests/contract/test_tool_schemas_snapshot.py`
(and the change is reviewed as a potential breaking change: MAJOR release).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from tests.contract.conftest import HarnessFactory

pytestmark = pytest.mark.anyio
SNAPSHOT = Path(__file__).parent / "snapshots" / "tools.json"


async def test_tool_contract_unchanged(harness: HarnessFactory) -> None:
    tools = await harness().server.list_tools()
    current = {t.name: t.input_schema for t in sorted(tools, key=lambda t: t.name)}
    assert len(current) == 13
    rendered = json.dumps(current, indent=2, sort_keys=True) + "\n"
    if os.environ.get("PANOS_MCP_UPDATE_SNAPSHOTS") == "1":
        SNAPSHOT.parent.mkdir(exist_ok=True)
        SNAPSHOT.write_text(rendered)
    assert SNAPSHOT.exists(), "snapshot missing; regenerate with PANOS_MCP_UPDATE_SNAPSHOTS=1"
    assert rendered == SNAPSHOT.read_text(), (
        "tool names or input schemas changed; review the contract change, then regenerate"
    )
