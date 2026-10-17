"""Opt-in live capture is safe by construction (research.md R9), tested offline."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from panos_mcp.client.replay import ReplayTransport
from panos_mcp.client.xmlapi import PanoramaClient
from panos_mcp.samples import capture
from panos_mcp.samples.cli import main
from panos_mcp.samples.library import SampleError, validate_library
from panos_mcp.samples.metadata import read_meta
from panos_mcp.samples.sanitize.forge import MappingStore
from tests.conftest import SAMPLES, offline_settings

KEY = b"c" * 32


def test_refuses_without_live_opt_in(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("PANOS_MCP_LIVE", raising=False)
    plan = tmp_path / "plan.json"
    plan.write_text("{}")
    code = main(
        [
            "--samples-dir",
            str(tmp_path),
            "capture",
            "--plan",
            str(plan),
            "--version",
            "11.2",
            "--variant",
            "lab",
        ]
    )
    assert code == 3


def test_write_plan_is_offline(tmp_path: Path) -> None:
    out = tmp_path / "plan.json"
    assert main(["capture", "--write-plan", str(out)]) == 0
    plan = json.loads(out.read_text())
    assert {"op", "config", "log"} <= set(plan)


class FlippingTransport(ReplayTransport):
    """Replay, but pending-changes turns to 'yes' after the first check (simulated change)."""

    checks = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        body = (await request.aread()).decode()
        if "pending-changes" in body:
            self.checks += 1
            if self.checks > 1:
                xml = '<response status="success"><result>yes</result></response>'
                return httpx.Response(200, content=xml.encode(), request=request)
        return await super().handle_async_request(request)


def client_for(transport: ReplayTransport) -> PanoramaClient:
    return PanoramaClient(offline_settings(), transport=transport)


def written(root: Path) -> list[Path]:
    return list(root.rglob("*.meta.json"))


@pytest.mark.anyio
async def test_state_change_writes_nothing(tmp_path: Path) -> None:
    client = client_for(FlippingTransport(SAMPLES, "baseline"))
    code, ids, _ = await capture.run_capture(
        client, capture.build_plan(), tmp_path, "11.2", "lab", MappingStore.ephemeral(KEY)
    )
    await client.aclose()
    assert code == 3 and ids == [] and written(tmp_path) == []


@pytest.mark.anyio
async def test_leak_check_failure_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def leak(*args: object, **kwargs: object) -> None:
        raise SampleError("leak check failed, original values still present: ['x']")

    monkeypatch.setattr(capture, "sanitize_xml", leak)
    client = client_for(ReplayTransport(SAMPLES, "baseline"))
    code, ids, _ = await capture.run_capture(
        client, capture.build_plan(), tmp_path, "11.2", "lab", MappingStore.ephemeral(KEY)
    )
    await client.aclose()
    assert code == 1 and ids == [] and written(tmp_path) == []


@pytest.mark.anyio
async def test_capture_writes_sanitized_lab_samples(tmp_path: Path) -> None:
    transport = ReplayTransport(SAMPLES, "baseline")
    client = client_for(transport)
    code, ids, report = await capture.run_capture(
        client, capture.build_plan(), tmp_path, "11.2", "lab", MappingStore.ephemeral(KEY)
    )
    await client.aclose()
    assert code == 0 and len(ids) > 30
    meta = read_meta(tmp_path / "11.2/op/show-devices-all/lab.meta.json")
    assert meta.provenance.source == "lab-capture" and meta.status == "unverified"
    assert meta.provenance.captured_at is not None
    assert validate_library(tmp_path) == []  # every captured sample passes the lint
    # full-mode sanitization forged the (fictional) names and private addresses too
    text = (tmp_path / "11.2/op/show-devices-all/lab.xml").read_text()
    assert "fw-hq-01" not in text and "10.10.0.11" not in text
    # only allow-listed reads were issued; no config writes, no commits
    assert all(r.params["type"] in ("op", "config", "log") for r in transport.requests)
    assert all(r.params.get("action") in (None, "get", "show") for r in transport.requests)
    assert any("not_found" in s for s in report.skipped)  # e.g. empty Region-B-DG rulebases


def test_mark_verified(tmp_path: Path) -> None:
    sample = tmp_path / "11.1/op/show-system-info"
    sample.mkdir(parents=True)
    for suffix in (".xml", ".meta.json"):
        src = SAMPLES / "11.1/op/show-system-info" / f"baseline{suffix}"
        (sample / f"baseline{suffix}").write_text(src.read_text())
    assert (
        main(
            [
                "--samples-dir",
                str(tmp_path),
                "capture",
                "--mark-verified",
                "11.1/op/show-system-info/baseline",
            ]
        )
        == 0
    )
    assert read_meta(sample / "baseline.meta.json").status == "verified"
