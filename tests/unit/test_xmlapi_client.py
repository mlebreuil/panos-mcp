from __future__ import annotations

import asyncio
from urllib.parse import parse_qsl

import httpx
import pytest

from panos_mcp.client import commands
from panos_mcp.client.allowlist import ReadOnlyViolation
from panos_mcp.models.common import ErrorCode, ToolError
from tests.conftest import mock_client, xml_response

pytestmark = pytest.mark.anyio

OK = (
    '<response status="success"><result><system><hostname>p</hostname></system></result></response>'
)


async def test_post_with_header_and_no_key_in_url() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return xml_response(OK)(request)

    client = mock_client(handler, samples_scenario=None, host="p.example.com", api_key="KEY123")
    result = await client.op(commands.show_system_info())
    assert result.findtext("system/hostname") == "p"
    req = seen[0]
    assert req.method == "POST"
    assert req.url.path == "/api/"
    assert req.headers["X-PAN-KEY"] == "KEY123"
    assert "KEY123" not in str(req.url)
    params = dict(parse_qsl(req.content.decode()))
    assert "key" not in params
    assert params["type"] == "op"
    await client.aclose()


async def test_allowlist_runs_before_transport() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return xml_response(OK)(request)

    client = mock_client(handler)
    with pytest.raises(ReadOnlyViolation):
        await client.op("<commit></commit>")
    assert calls == 0
    await client.aclose()


async def test_billion_laughs_rejected() -> None:
    bomb = (
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
        '<!ENTITY lol2 "&lol;&lol;&lol;&lol;">]><response status="success">'
        "<result>&lol2;</result></response>"
    )
    client = mock_client(xml_response(bomb))
    with pytest.raises(ToolError) as info:
        await client.op(commands.show_system_info())
    assert info.value.code is ErrorCode.PANORAMA_ERROR
    await client.aclose()


async def test_error_response_mapped() -> None:
    body = '<response status="error" code="403"><result><msg>Invalid key</msg></result></response>'
    client = mock_client(xml_response(body, status=403))
    with pytest.raises(ToolError) as info:
        await client.op(commands.show_system_info())
    assert info.value.code is ErrorCode.AUTH_FAILED
    await client.aclose()


async def test_bounded_concurrency() -> None:
    in_flight = 0
    peak = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0.01)
        in_flight -= 1
        return httpx.Response(200, content=OK.encode(), request=request)

    client = mock_client(handler, max_concurrency=2)
    await asyncio.gather(*(client.op(commands.show_system_info()) for _ in range(8)))
    assert peak == 2
    await client.aclose()


async def test_keygen_once_at_startup() -> None:
    seen: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        params = dict(parse_qsl(request.content.decode()))
        seen.append(params)
        if params["type"] == "keygen":
            body = '<response status="success"><result><key>NEWKEY</key></result></response>'
            return httpx.Response(200, content=body.encode(), request=request)
        assert request.headers["X-PAN-KEY"] == "NEWKEY"
        return xml_response(OK)(request)

    client = mock_client(
        handler, samples_scenario=None, host="p.example.com", username="admin", password="pw"
    )
    await client.keygen()
    await client.op(commands.show_system_info())
    assert [p["type"] for p in seen] == ["keygen", "op"]
    await client.aclose()


async def test_missing_config_node_is_empty() -> None:
    body = '<response status="error" code="7"><msg><line>No such node</line></msg></response>'
    client = mock_client(xml_response(body))
    _, result = await client.config("/config/shared/address")
    assert len(result) == 0
    await client.aclose()
