"""FR-002 / SC-004: secrets never appear in tool output, errors or logs (DEBUG included)."""

from __future__ import annotations

import json
import logging

import pytest
from pydantic import SecretStr

from panos_mcp.client.replay import ReplayTransport
from panos_mcp.client.xmlapi import PanoramaClient
from panos_mcp.config import Settings
from panos_mcp.logging import configure_logging
from panos_mcp.samples.scenarios import list_scenarios
from panos_mcp.server import build_server
from tests.conftest import SAMPLES
from tests.contract.test_allowlist_audit import INPUTS

pytestmark = pytest.mark.anyio
KEY = "TESTKEY-DO-NOT-LEAK"
PASSWORD = "PW-DO-NOT-LEAK"
SCENARIOS = [s for s in list_scenarios(SAMPLES) if s != "large-estate"]


@pytest.mark.parametrize("scenario", SCENARIOS)
async def test_no_secret_anywhere(scenario: str, capsys: pytest.CaptureFixture[str]) -> None:
    settings = Settings(
        host="panorama.example.com",
        api_key=SecretStr(KEY),
        username="admin",
        password=SecretStr(PASSWORD),
        cache_ttl=0,
        query_timeout=0.01,
        log_level="DEBUG",
    )
    configure_logging("DEBUG", settings.secrets())
    logging.getLogger("panos_mcp").debug("settings loaded: %r key=%s", settings, KEY)
    client = PanoramaClient(settings, transport=ReplayTransport(SAMPLES, scenario))
    server, _ = build_server(client, settings)
    outputs = []
    for tool, args in INPUTS.items():
        result = await server.call_tool(tool, args)
        outputs.append(json.dumps(result.model_dump(mode="json"), default=str))
    await client.aclose()
    captured = capsys.readouterr()
    for text in (*outputs, captured.out, captured.err):
        assert KEY not in text and PASSWORD not in text
