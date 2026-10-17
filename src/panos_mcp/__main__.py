"""Entry point: `panos-mcp` runs the MCP server over stdio (no network listener)."""

from __future__ import annotations

import sys

import anyio

from panos_mcp.client.replay import ReplayTransport
from panos_mcp.client.xmlapi import PanoramaClient
from panos_mcp.config import Settings, load_settings
from panos_mcp.logging import configure_logging
from panos_mcp.models.common import ToolError
from panos_mcp.samples.layout import default_samples_dir
from panos_mcp.server import build_server


def build_client(settings: Settings) -> PanoramaClient:
    if settings.samples_scenario:
        root = settings.samples_dir or default_samples_dir()
        transport = ReplayTransport(root, settings.samples_scenario)
        return PanoramaClient(settings, transport=transport)
    return PanoramaClient(settings)


async def _run(settings: Settings) -> None:
    client = build_client(settings)
    try:
        if not settings.offline:
            await client.keygen()
        server, _ = build_server(client, settings)
        await server.run_stdio_async()
    finally:
        await client.aclose()


def main() -> None:
    settings = load_settings()
    log = configure_logging(settings.log_level, settings.secrets())
    if settings.offline:
        log.info("offline demo mode: scenario %s", settings.samples_scenario)
    warning = settings.tls_warning()
    if warning:
        log.warning(warning)
    try:
        anyio.run(_run, settings)
    except ToolError as exc:
        print(f"panos-mcp: {exc.info.message} {exc.info.hint}", file=sys.stderr)
        raise SystemExit(1) from None
    except KeyboardInterrupt:  # pragma: no cover
        pass


if __name__ == "__main__":
    main()
