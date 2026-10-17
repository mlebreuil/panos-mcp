"""Shared models: result envelope, errors, scope, config source, pagination."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, Field, model_validator

SHARED = "shared"

Scope = str
"""`"shared"` or a device-group name."""

Limit = Annotated[int, Field(ge=1, le=500, description="Maximum number of items to return")]
Offset = Annotated[int, Field(ge=0, description="Number of items to skip")]
DEFAULT_LIMIT = 50


class ConfigSource(StrEnum):
    RUNNING = "running"
    CANDIDATE = "candidate"


class ErrorCode(StrEnum):
    NOT_FOUND = "not_found"
    INVALID_INPUT = "invalid_input"
    PERMISSION_DENIED = "permission_denied"
    AUTH_FAILED = "auth_failed"
    UNREACHABLE = "unreachable"
    TLS_ERROR = "tls_error"
    TIMEOUT = "timeout"
    PANORAMA_ERROR = "panorama_error"
    READ_ONLY_VIOLATION = "read_only_violation"
    DEVICE_UNAVAILABLE = "device_unavailable"


class ToolErrorInfo(BaseModel):
    """Structured error returned to the MCP client (never contains secrets)."""

    code: ErrorCode
    message: str
    hint: str
    suggestions: list[str] = Field(default_factory=list)


class ToolError(Exception):
    """Raised by services/tools for anticipated failures; rendered as `ToolErrorInfo`."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        hint: str,
        suggestions: Sequence[str] = (),
    ) -> None:
        super().__init__(message)
        self.info = ToolErrorInfo(
            code=code, message=message, hint=hint, suggestions=list(suggestions)
        )

    @property
    def code(self) -> ErrorCode:
        return self.info.code


def now_utc() -> datetime:
    return datetime.now(UTC)


class ToolResult[T](BaseModel):
    """Envelope for every tool response."""

    items: T
    total: int | None = None
    returned: int
    truncated: bool = False
    next_offset: int | None = None
    narrowing_hint: str | None = None
    config_source: ConfigSource | None = None
    retrieved_at: datetime = Field(default_factory=now_utc)
    warnings: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _hint_when_truncated(self) -> ToolResult[T]:
        if self.truncated and not self.narrowing_hint:
            raise ValueError("narrowing_hint is required when truncated")
        return self


class Page[T](BaseModel):
    items: list[T]
    total: int
    returned: int
    truncated: bool
    next_offset: int | None
    narrowing_hint: str | None


def paginate[T](items: Sequence[T], limit: int, offset: int, hint: str) -> Page[T]:
    """Slice `items` and compute truncation metadata."""
    total = len(items)
    window = list(items[offset : offset + limit])
    end = offset + len(window)
    truncated = end < total
    return Page[T](
        items=window,
        total=total,
        returned=len(window),
        truncated=truncated,
        next_offset=end if truncated else None,
        narrowing_hint=hint if truncated else None,
    )
