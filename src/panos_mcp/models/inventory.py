"""Inventory models (data-model.md §A): Panorama, firewalls, device groups, templates, jobs."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class HAState(StrEnum):
    STANDALONE = "standalone"
    ACTIVE = "active"
    PASSIVE = "passive"
    SUSPENDED = "suspended"
    UNKNOWN = "unknown"


class ConfigSync(StrEnum):
    IN_SYNC = "in_sync"
    OUT_OF_SYNC = "out_of_sync"
    UNKNOWN = "unknown"


class License(BaseModel):
    feature: str
    description: str | None = None
    issued: str | None = None
    expires: str | None = None
    expired: bool = False


class PanoramaInfo(BaseModel):
    hostname: str
    model: str
    serial: str
    sw_version: str
    ha_state: HAState
    ha_peer_state: str | None = None
    uptime: str | None = None
    mgmt_ip: str | None = None
    licenses: list[License] = Field(default_factory=list)
    content_versions: dict[str, str] = Field(default_factory=dict)
    tls_verification: bool = True


class HAStatus(BaseModel):
    local_state: str
    peer_serial: str | None = None


class ManagedFirewall(BaseModel):
    serial: str
    hostname: str
    model: str
    mgmt_ip: str | None = None
    sw_version: str
    content_versions: dict[str, str] = Field(default_factory=dict)
    device_group: str | None = None
    template_stack: str | None = None
    connected: bool
    config_sync: ConfigSync = ConfigSync.UNKNOWN
    ha: HAStatus | None = None
    vsys: list[str] = Field(default_factory=list)


class DeviceGroup(BaseModel):
    name: str
    parent: str
    children: list[str] = Field(default_factory=list)
    members: list[str] = Field(default_factory=list, description="Firewall serials")
    description: str | None = None


class TemplateKind(StrEnum):
    TEMPLATE = "template"
    TEMPLATE_STACK = "template_stack"


class Template(BaseModel):
    name: str
    kind: TemplateKind
    templates: list[str] = Field(default_factory=list, description="Stack members, in order")
    members: list[str] = Field(default_factory=list, description="Firewall serials")
    description: str | None = None


class JobStatus(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    FINISHED = "finished"


class JobResult(StrEnum):
    OK = "ok"
    FAIL = "fail"
    PENDING = "pending"
    UNKNOWN = "unknown"


class JobDeviceResult(BaseModel):
    serial: str
    device_name: str | None = None
    status: JobStatus
    result: JobResult
    messages: list[str] = Field(default_factory=list)


class Job(BaseModel):
    id: int
    type: str
    status: JobStatus
    result: JobResult
    progress: int = Field(ge=0, le=100)
    user: str | None = None
    description: str | None = None
    queued_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    details: list[str] = Field(default_factory=list)
    devices: list[JobDeviceResult] = Field(default_factory=list)
