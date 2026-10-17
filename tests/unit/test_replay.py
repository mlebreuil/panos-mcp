from __future__ import annotations

import json
from pathlib import Path

import pytest

from panos_mcp.client import commands
from panos_mcp.client.allowlist import ReadOnlyViolation
from panos_mcp.client.replay import ReplayMiss, ReplayTransport
from panos_mcp.client.xmlapi import PanoramaClient
from panos_mcp.models.common import ErrorCode, ToolError
from panos_mcp.samples.scenarios import ScenarioError
from tests.conftest import offline_settings

pytestmark = pytest.mark.anyio

SYS = '<response status="success"><result><system><hostname>{}</hostname></system></result></response>'
DENIED = '<response status="error" code="403"><result><msg>not authorized</msg></result></response>'
LOG_START = '<response status="success"><result><msg><line>query job enqueued</line></msg><job>1</job></result></response>'
LOG_RESULT = '<response status="success"><result><job><status>FIN</status></job><log><logs count="0" progress="100"/></log></result></response>'


def write(root: Path, sample_id: str, body: str) -> None:
    path = root / f"{sample_id}.xml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)


def scenario(root: Path, name: str, **data: object) -> None:
    folder = root / "scenarios"
    folder.mkdir(parents=True, exist_ok=True)
    body = {"name": name, "description": "test scenario", "panos_version": "11.1", **data}
    (folder / f"{name}.json").write_text(json.dumps(body))


SYS_REQ = {"type": "op", "cmd": commands.show_system_info()}
HA_REQ = {"type": "op", "cmd": commands.show_ha_state()}


@pytest.fixture
def lib(tmp_path: Path) -> Path:
    write(tmp_path, "11.1/op/show-system-info/base", SYS.format("base"))
    write(tmp_path, "11.1/op/show-system-info/child", SYS.format("child"))
    write(tmp_path, "any/op/error-403/role-denied", DENIED)
    write(tmp_path, "11.1/log/traffic/start", LOG_START)
    write(tmp_path, "11.1/log/traffic/result", LOG_RESULT)
    scenario(
        tmp_path,
        "base",
        responses=[
            {"request": SYS_REQ, "sample": "11.1/op/show-system-info/base"},
            {
                "request": {"type": "log", "log_type": "traffic", "log_phase": "start"},
                "sample": "11.1/log/traffic/start",
            },
            {
                "request": {"type": "log", "log_type": "traffic", "log_phase": "result"},
                "sample": "11.1/log/traffic/result",
            },
        ],
    )
    scenario(
        tmp_path,
        "child",
        extends="base",
        responses=[{"request": SYS_REQ, "sample": "11.1/op/show-system-info/child"}],
    )
    scenario(tmp_path, "denied", default_response="any/op/error-403/role-denied")
    scenario(tmp_path, "strict", extends="base", default_on_miss="fail_test")
    scenario(tmp_path, "loop-a", extends="loop-b")
    scenario(tmp_path, "loop-b", extends="loop-a")
    return tmp_path


def client(root: Path, name: str) -> tuple[PanoramaClient, ReplayTransport]:
    transport = ReplayTransport(root, name)
    return PanoramaClient(offline_settings(samples_scenario=name), transport=transport), transport


async def test_serves_mapped_sample(lib: Path) -> None:
    c, t = client(lib, "base")
    assert (await c.op(commands.show_system_info())).findtext("system/hostname") == "base"
    assert t.requests[0].sample == "11.1/op/show-system-info/base"
    await c.aclose()


async def test_extends_overrides_and_inherits(lib: Path) -> None:
    c, _ = client(lib, "child")
    assert (await c.op(commands.show_system_info())).findtext("system/hostname") == "child"
    job = await c.log_start("traffic", "", 5)
    assert job >= 1001
    result = await c.log_get(job)
    assert result.findtext("job/status") == "FIN"
    await c.aclose()


async def test_default_response_answers_everything(lib: Path) -> None:
    c, _ = client(lib, "denied")
    for cmd in (commands.show_system_info(), commands.show_devices_all()):
        with pytest.raises(ToolError) as info:
            await c.op(cmd)
        assert info.value.code is ErrorCode.PERMISSION_DENIED
    await c.aclose()


async def test_miss_modes(lib: Path) -> None:
    c, _ = client(lib, "base")
    with pytest.raises(ToolError) as info:
        await c.op(commands.show_ha_state())
    assert info.value.code is ErrorCode.NOT_FOUND
    await c.aclose()
    strict, _ = client(lib, "strict")
    with pytest.raises(ReplayMiss):
        await strict.op(commands.show_ha_state())
    await strict.aclose()


async def test_allowlist_in_front_of_replay(lib: Path) -> None:
    c, t = client(lib, "base")
    with pytest.raises(ReadOnlyViolation):
        await c.op("<commit></commit>")
    assert t.requests == []
    await c.aclose()


def test_inheritance_cycle_and_unknown_parent(lib: Path) -> None:
    with pytest.raises(ScenarioError, match="cycle"):
        ReplayTransport(lib, "loop-a")
    scenario(lib, "orphan", extends="nope")
    with pytest.raises(ScenarioError, match="unknown scenario"):
        ReplayTransport(lib, "orphan")
