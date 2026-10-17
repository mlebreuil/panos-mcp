"""Sample metadata sidecars (`<variant>.meta.json`) and their JSON Schema validation."""

from __future__ import annotations

import json
from datetime import datetime
from importlib import resources
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_RESOURCE = "sample-metadata.schema.json"


class SampleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["op", "config", "log"]
    cmd: str | None = None
    action: Literal["get", "show"] | None = None
    xpath: str | None = None
    log_type: Literal["traffic", "threat", "url", "system", "config"] | None = None
    log_phase: Literal["start", "result"] | None = None
    query: str | None = None
    target: str | None = None


class Provenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: Literal["documentation", "synthetic", "lab-capture"]
    url: str | None = None
    captured_at: datetime | None = None
    generator: str | None = None
    notes: str | None = None


class SanitizationRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_version: str
    sanitized_at: datetime
    leak_check: Literal["passed"]


class SampleMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    request: SampleRequest
    panos_version: str
    description: str
    provenance: Provenance
    sanitization: SanitizationRecord
    status: Literal["unverified", "verified"] = "unverified"
    tags: list[str] = Field(default_factory=list)

    def to_json(self) -> str:
        data = self.model_dump(mode="json", exclude_none=True)
        if not data.get("tags"):
            data.pop("tags", None)
        return json.dumps(data, indent=2, sort_keys=False) + "\n"


def load_schema() -> dict[str, Any]:
    text = resources.files("panos_mcp.samples").joinpath(SCHEMA_RESOURCE).read_text("utf-8")
    schema: dict[str, Any] = json.loads(text)
    return schema


def schema_errors(data: dict[str, Any]) -> list[str]:
    """Validate a metadata dict against the JSON Schema; returns error messages."""
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover - dev dependency
        raise RuntimeError("jsonschema is required: uv sync --all-extras") from exc
    validator = jsonschema.Draft202012Validator(
        load_schema(), format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER
    )
    return [
        f"{'/'.join(str(p) for p in err.absolute_path) or '<root>'}: {err.message}"
        for err in sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path))
    ]


def read_meta(path: Path) -> SampleMeta:
    return SampleMeta.model_validate_json(path.read_text("utf-8"))
