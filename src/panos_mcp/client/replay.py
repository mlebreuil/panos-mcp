"""Replay transport: answers XML API requests from the sample library (no network).

Used by tests and by offline demo mode (`PANOS_MCP_SAMPLES_SCENARIO`). The production
client is unchanged; only its httpx transport is swapped, so the allow-list still runs
before every request.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl
from xml.etree.ElementTree import Element, tostring

import httpx
from defusedxml import ElementTree as SafeET

from panos_mcp.samples.layout import SampleId, key_for_params
from panos_mcp.samples.scenarios import ResolvedScenario

MISS_RESPONSE = (
    '<response status="error" code="7"><msg><line>'
    "No such node (replay: no sample for this request in scenario {name})"
    "</line></msg></response>"
)


class ReplayMiss(AssertionError):
    """Raised for an unmatched request when the scenario uses `default_on_miss: fail_test`."""


@dataclass
class RecordedRequest:
    params: dict[str, str]
    key: str
    sample: str | None


@dataclass
class ReplayTransport(httpx.AsyncBaseTransport):
    root: Path
    scenario_name: str
    requests: list[RecordedRequest] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.scenario = ResolvedScenario(self.root, self.scenario_name)
        self._job_ids = itertools.count(1001)
        self._job_types: dict[int, str] = {}

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        body = await request.aread()
        params = dict(parse_qsl(body.decode("utf-8"), keep_blank_values=True))
        log_type: str | None = None
        if params.get("type") == "log" and params.get("action") == "get":
            log_type = self._job_types.get(int(params.get("job-id", "0")))
        key = key_for_params(params, log_type)
        sample_id = self.scenario.lookup(key)
        self.requests.append(RecordedRequest(params=params, key=key, sample=sample_id))

        if sample_id is None:
            if self.scenario.default_on_miss == "fail_test":
                raise ReplayMiss(f"scenario {self.scenario_name!r} has no sample for {key}")
            text = MISS_RESPONSE.format(name=self.scenario_name)
            return httpx.Response(200, content=text.encode(), request=request)

        content = SampleId.parse(sample_id).xml_path(self.root).read_bytes()
        if params.get("type") == "log" and params.get("action") is None:
            content = self._assign_job(content, params["log-type"])
        return httpx.Response(200, content=content, request=request)

    def _assign_job(self, content: bytes, log_type: str) -> bytes:
        """Give each log query start a fresh deterministic job id."""
        root: Element = SafeET.fromstring(content)
        job = root.find("result/job")
        if job is None or root.get("status") != "success":
            return content
        job_id = next(self._job_ids)
        job.text = str(job_id)
        self._job_types[job_id] = log_type
        data: bytes = tostring(root, encoding="utf-8")
        return data
