"""Shared fixtures. No test may reach the network (constitution Principle IV)."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from panos_mcp.client.replay import ReplayTransport
from panos_mcp.client.xmlapi import PanoramaClient
from panos_mcp.config import Settings

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest) -> None:
    if request.node.get_closest_marker("live"):
        return

    async def blocked(self: Any, request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"network access in tests: {request.url}")

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", blocked)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def samples_root() -> Path:
    return SAMPLES


def offline_settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "samples_scenario": "baseline",
        "cache_ttl": 0,
        "query_timeout": 5,
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def settings_offline() -> Settings:
    return offline_settings()


ClientFactory = Callable[..., tuple[PanoramaClient, ReplayTransport]]


@pytest.fixture
async def replay_client() -> AsyncIterator[ClientFactory]:
    created: list[PanoramaClient] = []

    def make(
        scenario: str = "baseline", **overrides: Any
    ) -> tuple[PanoramaClient, ReplayTransport]:
        settings = offline_settings(samples_scenario=scenario, **overrides)
        transport = ReplayTransport(SAMPLES, scenario)
        client = PanoramaClient(settings, transport=transport)
        created.append(client)
        return client, transport

    yield make
    for client in created:
        await client.aclose()


def mock_client(handler: Callable[[httpx.Request], Any], **overrides: Any) -> PanoramaClient:
    settings = offline_settings(**overrides)
    return PanoramaClient(settings, transport=httpx.MockTransport(handler))


def xml_response(body: str, status: int = 200) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, content=body.encode(), request=request)

    return handler


@pytest.fixture
def tmp_mapping(tmp_path: Path) -> Iterator[Path]:
    yield tmp_path / "mapping"
