"""Async Panorama XML API client. Every request passes the read-only allow-list first."""

from __future__ import annotations

import asyncio
import re
from datetime import datetime
from xml.etree.ElementTree import Element

import httpx
from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from panos_mcp.client import allowlist, errors
from panos_mcp.client.cache import TTLCache
from panos_mcp.config import Settings
from panos_mcp.logging import get_logger
from panos_mcp.models.common import ConfigSource, ErrorCode, ToolError, now_utc

log = get_logger("xmlapi")
_JOB_RE = re.compile(r"jobid\s+(\d+)", re.IGNORECASE)


class PanoramaClient:
    def __init__(
        self,
        settings: Settings,
        transport: httpx.AsyncBaseTransport | None = None,
        *,
        base_url: str | None = None,
    ) -> None:
        self.settings = settings
        verify: bool | str = settings.verify_tls
        if settings.verify_tls and settings.ca_bundle:
            verify = str(settings.ca_bundle)
        host = settings.host or "panorama.offline.invalid"
        self._http = httpx.AsyncClient(
            base_url=base_url or f"https://{host}",
            transport=transport,
            verify=verify,
            timeout=settings.timeout,
        )
        self._key: str | None = (
            settings.api_key.get_secret_value() if settings.api_key is not None else None
        )
        self._semaphore = asyncio.Semaphore(settings.max_concurrency)
        self._cache = TTLCache(settings.cache_ttl)
        self.started_log_jobs: set[int] = set()

    async def aclose(self) -> None:
        await self._http.aclose()

    # ------------------------------------------------------------------ core

    async def _request(self, params: dict[str, str], *, keygen: bool = False) -> Element:
        allowlist.check_request(params, self.started_log_jobs, allow_keygen=keygen)
        headers = {} if keygen or self._key is None else {"X-PAN-KEY": self._key}
        async with self._semaphore:
            response = await self._send(params, headers)
        root = self._parse(response)
        if root.get("status") != "success":
            raise errors.from_error_response(root, keygen=keygen)
        return root

    async def _send(self, params: dict[str, str], headers: dict[str, str]) -> httpx.Response:
        for attempt in (1, 2):
            try:
                return await self._http.post("/api/", data=params, headers=headers)
            except httpx.ConnectError as exc:
                if attempt == 2:
                    raise errors.from_exception(exc) from None
                log.info("connect error, retrying once")
            except httpx.HTTPError as exc:
                raise errors.from_exception(exc) from None
        raise AssertionError("unreachable")  # pragma: no cover

    @staticmethod
    def _parse(response: httpx.Response) -> Element:
        try:
            root: Element = SafeET.fromstring(response.content)
        except (SafeET.ParseError, DefusedXmlException):
            if response.status_code in (401, 403):
                raise errors.from_exception(
                    httpx.HTTPStatusError("auth", request=response.request, response=response)
                ) from None
            raise ToolError(
                ErrorCode.PANORAMA_ERROR,
                "Panorama returned a response that is not valid XML.",
                "Check that PANOS_MCP_HOST points to Panorama's management interface.",
            ) from None
        if root.tag != "response":
            raise ToolError(
                ErrorCode.PANORAMA_ERROR,
                "Panorama returned an unexpected response.",
                "Check that PANOS_MCP_HOST points to Panorama's management interface.",
            )
        return root

    @staticmethod
    def _result(root: Element) -> Element:
        result = root.find("result")
        return result if result is not None else Element("result")

    # ------------------------------------------------------------------ public API

    async def request(self, params: dict[str, str]) -> Element:
        """Raw allow-listed request returning the whole `<response>` (sample capture)."""
        return await self._request(params)

    async def keygen(self) -> None:
        """Exchange username/password for an API key (startup only)."""
        s = self.settings
        if not s.username or s.password is None:
            return
        root = await self._request(
            {"type": "keygen", "user": s.username, "password": s.password.get_secret_value()},
            keygen=True,
        )
        key = root.findtext("result/key")
        if not key:
            raise ToolError(
                ErrorCode.AUTH_FAILED,
                "Panorama did not return an API key.",
                "Check the username and password.",
            )
        self._key = key

    async def op(self, cmd: str, target: str | None = None) -> Element:
        params = {"type": "op", "cmd": cmd}
        if target:
            params["target"] = target
        return self._result(await self._request(params))

    async def config(
        self, xpath: str, source: ConfigSource = ConfigSource.RUNNING, *, missing_ok: bool = True
    ) -> tuple[datetime, Element]:
        """Read a config subtree (`show` = running, `get` = candidate), cached by TTL.

        With `missing_ok`, a node that does not exist yields an empty `<result/>`.
        """
        action = "show" if source is ConfigSource.RUNNING else "get"

        async def fetch() -> Element:
            try:
                return self._result(
                    await self._request({"type": "config", "action": action, "xpath": xpath})
                )
            except ToolError as exc:
                if missing_ok and exc.code is ErrorCode.NOT_FOUND:
                    return Element("result")
                raise

        return await self._cache.get_or_fetch((action, xpath), fetch)

    async def log_start(self, log_type: str, query: str, nlogs: int, skip: int = 0) -> int:
        params = {"type": "log", "log-type": log_type, "nlogs": str(nlogs)}
        if query:
            params["query"] = query
        if skip:
            params["skip"] = str(skip)
        root = await self._request(params)
        job_text = root.findtext("result/job") or ""
        if not job_text.strip().isdigit():
            match = _JOB_RE.search("".join(root.itertext()))
            job_text = match.group(1) if match else ""
        if not job_text.strip().isdigit():
            raise ToolError(
                ErrorCode.PANORAMA_ERROR,
                "Panorama did not return a log query job id.",
                "Retry the query.",
            )
        job_id = int(job_text)
        self.started_log_jobs.add(job_id)
        return job_id

    async def log_get(self, job_id: int) -> Element:
        return self._result(
            await self._request({"type": "log", "action": "get", "job-id": str(job_id)})
        )

    @staticmethod
    def now() -> datetime:
        return now_utc()
