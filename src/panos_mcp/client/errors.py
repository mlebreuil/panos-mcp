"""Map transport failures and Panorama error responses to `ToolError` (data-model.md §B)."""

from __future__ import annotations

import ssl
from xml.etree.ElementTree import Element

import httpx

from panos_mcp.models.common import ErrorCode, ToolError

_AUTH_MARKERS = ("invalid credential", "invalid key", "key expired", "expired", "api key")


def error_message(root: Element) -> str:
    """Collect the human-readable message(s) from an error response."""
    texts: list[str] = []
    for tag in ("msg", "line"):
        for node in root.iter(tag):
            text = "".join(node.itertext()).strip()
            if text and text not in texts:
                texts.append(text)
    return "; ".join(texts) or "no message"


def from_error_response(root: Element, *, keygen: bool = False) -> ToolError:
    """Translate `<response status="error" code="...">` into a ToolError."""
    code = root.get("code", "")
    message = error_message(root)
    lower = message.lower()
    if code == "403" or "forbidden" in lower or "unauthorized" in lower:
        if keygen or any(marker in lower for marker in _AUTH_MARKERS):
            return ToolError(
                ErrorCode.AUTH_FAILED,
                "Panorama rejected the credentials.",
                "Check that PANOS_MCP_API_KEY (or username/password) is valid and not expired.",
            )
        return ToolError(
            ErrorCode.PERMISSION_DENIED,
            "Panorama denied this request for the configured admin account.",
            "Ask your Panorama administrator to grant the admin role XML API read access "
            "(configuration, operational requests and logs) for this operation.",
        )
    if code == "7":
        return ToolError(
            ErrorCode.NOT_FOUND,
            "Panorama reports that the requested object is not present.",
            "Check the name and scope; list the available items first.",
        )
    if code == "12":
        return ToolError(
            ErrorCode.INVALID_INPUT,
            "Panorama reports that the request refers to an invalid object.",
            "Check the names and values in the request.",
        )
    return ToolError(
        ErrorCode.PANORAMA_ERROR,
        f"Panorama returned an error (code {code or 'none'}): {message}",
        "Retry; if it persists, check the request parameters and the Panorama system log.",
    )


def from_exception(exc: Exception) -> ToolError:
    """Translate an httpx / TLS exception into a ToolError (never echoes request data)."""
    if isinstance(exc, httpx.TimeoutException):
        return ToolError(
            ErrorCode.TIMEOUT,
            "Panorama did not answer in time.",
            "Retry, narrow the query, or raise PANOS_MCP_TIMEOUT.",
        )
    if isinstance(exc, ssl.SSLError) or _caused_by_ssl(exc):
        return ToolError(
            ErrorCode.TLS_ERROR,
            "The TLS certificate of Panorama could not be verified.",
            "Install the issuing CA via PANOS_MCP_CA_BUNDLE, or fix the certificate on Panorama.",
        )
    if isinstance(exc, httpx.ConnectError | httpx.NetworkError):
        return ToolError(
            ErrorCode.UNREACHABLE,
            "Panorama could not be reached.",
            "Check PANOS_MCP_HOST, network connectivity and that the management interface "
            "allows HTTPS.",
        )
    if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code in (401, 403):
        return ToolError(
            ErrorCode.AUTH_FAILED,
            "Panorama rejected the credentials.",
            "Check that PANOS_MCP_API_KEY (or username/password) is valid and not expired.",
        )
    return ToolError(
        ErrorCode.PANORAMA_ERROR,
        "Unexpected error while talking to Panorama.",
        "Retry; if it persists, run with PANOS_MCP_LOG_LEVEL=DEBUG and report the log.",
    )


def _caused_by_ssl(exc: BaseException) -> bool:
    seen: BaseException | None = exc
    while seen is not None:
        if isinstance(seen, ssl.SSLError):
            return True
        if "CERTIFICATE_VERIFY_FAILED" in str(seen):
            return True
        seen = seen.__cause__ or seen.__context__
    return False
