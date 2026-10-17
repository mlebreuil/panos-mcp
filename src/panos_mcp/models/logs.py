"""Log and policy-match models (data-model.md §A)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, field_validator

EXTRA_MAX_KEYS = 50


class LogType(StrEnum):
    TRAFFIC = "traffic"
    THREAT = "threat"
    URL = "url"
    SYSTEM = "system"
    CONFIG = "config"


class LogEntry(BaseModel):
    log_type: LogType
    receive_time: datetime | None = None
    device_serial: str | None = None
    device_name: str | None = None
    vsys: str | None = None
    # traffic / threat / url
    src: str | None = None
    dst: str | None = None
    sport: int | None = None
    dport: int | None = None
    proto: str | None = None
    app: str | None = None
    rule: str | None = None
    action: str | None = None
    from_zone: str | None = None
    to_zone: str | None = None
    src_user: str | None = None
    bytes: int | None = None
    session_end_reason: str | None = None
    # threat
    threat_name: str | None = None
    threat_id: str | None = None
    severity: str | None = None
    direction: str | None = None
    # url
    url: str | None = None
    category: str | None = None
    # system
    event_id: str | None = None
    description: str | None = None
    # config
    admin: str | None = None
    command: str | None = None
    path: str | None = None
    result: str | None = None
    extra: dict[str, str] = Field(default_factory=dict)

    @field_validator("extra")
    @classmethod
    def _bounded(cls, value: dict[str, str]) -> dict[str, str]:
        return dict(list(value.items())[:EXTRA_MAX_KEYS])


class PolicyMatchQuery(BaseModel):
    device_serial: str
    vsys: str
    from_zone: str
    to_zone: str
    source: str
    destination: str
    protocol: int
    destination_port: int | None = None
    application: str | None = None
    source_user: str | None = None


class PolicyMatchResult(BaseModel):
    device_serial: str
    vsys: str
    query: PolicyMatchQuery
    matched: bool
    rule_name: str | None = None
    action: str | None = None
    note: str
