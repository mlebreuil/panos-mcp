"""Parsers for inventory responses (system info, HA, licenses, devices, groups, templates, jobs)."""

from __future__ import annotations

from datetime import datetime
from xml.etree.ElementTree import Element

from panos_mcp.models.inventory import (
    ConfigSync,
    HAState,
    HAStatus,
    Job,
    JobDeviceResult,
    JobResult,
    JobStatus,
    License,
    ManagedFirewall,
    Template,
    TemplateKind,
)
from panos_mcp.parsers import lines, members, name_of, text, yes

CONTENT_FIELDS = {
    "app-version": "app_threat",
    "threat-version": "threat",
    "av-version": "antivirus",
    "wildfire-version": "wildfire",
    "url-filtering-version": "url_filtering",
}


def content_versions(node: Element) -> dict[str, str]:
    out = {}
    for tag, key in CONTENT_FIELDS.items():
        value = text(node, tag)
        if value and value != "0":
            out[key] = value
    return out


def parse_system_info(result: Element) -> dict[str, object]:
    system = result.find("system")
    node = system if system is not None else result
    return {
        "hostname": text(node, "hostname", "unknown"),
        "model": text(node, "model", "unknown"),
        "serial": text(node, "serial", "unknown"),
        "sw_version": text(node, "sw-version", "unknown"),
        "uptime": text(node, "uptime"),
        "mgmt_ip": text(node, "ip-address"),
        "content_versions": content_versions(node),
    }


def ha_state_from(value: str | None) -> HAState:
    v = (value or "").lower()
    if "suspended" in v:
        return HAState.SUSPENDED
    if "passive" in v:
        return HAState.PASSIVE
    if "active" in v:
        return HAState.ACTIVE
    return HAState.UNKNOWN


def parse_ha(result: Element) -> tuple[HAState, str | None]:
    if not yes(text(result, "enabled")):
        return HAState.STANDALONE, None
    return ha_state_from(text(result, "local-info/state")), text(result, "peer-info/state")


def parse_licenses(result: Element) -> list[License]:
    return [
        License(
            feature=text(e, "feature", "unknown") or "unknown",
            description=text(e, "description"),
            issued=text(e, "issued"),
            expires=text(e, "expires"),
            expired=yes(text(e, "expired")),
        )
        for e in result.iter("entry")
        if e.find("feature") is not None
    ]


def _config_sync(entry: Element) -> ConfigSync:
    statuses = [
        (s.text or "").strip().lower()
        for s in entry.iter("shared-policy-status")
        if (s.text or "").strip()
    ]
    if any("out of sync" in s for s in statuses):
        return ConfigSync.OUT_OF_SYNC
    if statuses and all(s == "in sync" for s in statuses):
        return ConfigSync.IN_SYNC
    return ConfigSync.UNKNOWN


def parse_devices(result: Element) -> list[ManagedFirewall]:
    container = result.find("devices")
    if container is None:
        return []
    firewalls = []
    for entry in container.findall("entry"):
        serial = text(entry, "serial") or name_of(entry)
        ha_state = text(entry, "ha/state")
        ip = text(entry, "ip-address")
        firewalls.append(
            ManagedFirewall(
                serial=serial,
                hostname=text(entry, "hostname", serial) or serial,
                model=text(entry, "model", "unknown") or "unknown",
                mgmt_ip=ip if ip and ip != "unknown" else None,
                sw_version=text(entry, "sw-version", "unknown") or "unknown",
                content_versions=content_versions(entry),
                connected=yes(text(entry, "connected")),
                config_sync=_config_sync(entry),
                ha=HAStatus(local_state=ha_state, peer_serial=text(entry, "ha/peer/serial"))
                if ha_state
                else None,
                vsys=[v.get("name", "") for v in entry.findall("vsys/entry") if v.get("name")],
            )
        )
    return firewalls


def parse_devicegroup_members(result: Element) -> dict[str, list[str]]:
    container = result.find("devicegroups")
    out: dict[str, list[str]] = {}
    if container is None:
        return out
    for entry in container.findall("entry"):
        name = entry.get("name")
        if name:
            out[name] = [text(d, "serial") or name_of(d) for d in entry.findall("devices/entry")]
    return out


def parse_templates(result: Element) -> list[Template]:
    container = result.find("templates")
    if container is None:
        return []
    return [
        Template(
            name=entry.get("name", ""),
            kind=TemplateKind.TEMPLATE,
            members=[text(d, "serial") or name_of(d) for d in entry.findall("devices/entry")],
            description=text(entry, "description"),
        )
        for entry in container.findall("entry")
        if entry.get("name")
    ]


def parse_template_stacks(result: Element) -> list[Template]:
    container = result.find("template-stack")
    if container is None:
        return []
    return [
        Template(
            name=entry.get("name", ""),
            kind=TemplateKind.TEMPLATE_STACK,
            templates=members(entry, "templates"),
            members=[d.get("name", "") for d in entry.findall("devices/entry") if d.get("name")],
            description=text(entry, "description"),
        )
        for entry in container.findall("entry")
        if entry.get("name")
    ]


_STATUS = {"FIN": JobStatus.FINISHED, "ACT": JobStatus.ACTIVE, "PEND": JobStatus.PENDING}
_RESULT = {"OK": JobResult.OK, "FAIL": JobResult.FAIL, "PEND": JobResult.PENDING}


def _when(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y/%m/%d %H:%M:%S")
    except ValueError:
        return None


def _status(value: str | None) -> JobStatus:
    return _STATUS.get((value or "").upper(), JobStatus.PENDING)


def _result(value: str | None) -> JobResult:
    return _RESULT.get((value or "").upper(), JobResult.UNKNOWN)


def parse_job(node: Element) -> Job:
    queued = _when(text(node, "tenq"))
    started = None
    tdeq = text(node, "tdeq")
    if queued and tdeq:
        started = _when(f"{queued:%Y/%m/%d} {tdeq}")
    progress_text = text(node, "progress", "0") or "0"
    progress = int(progress_text) if progress_text.isdigit() else 0
    devices = [
        JobDeviceResult(
            serial=text(d, "serial-no") or text(d, "serial") or "unknown",
            device_name=text(d, "devicename"),
            status=_status(text(d, "status")),
            result=_result(text(d, "result")),
            messages=lines(d.find("details")),
        )
        for d in node.findall("devices/entry")
    ]
    return Job(
        id=int(text(node, "id", "0") or 0),
        type=text(node, "type", "unknown") or "unknown",
        status=_status(text(node, "status")),
        result=_result(text(node, "result")),
        progress=max(0, min(100, progress)),
        user=text(node, "user"),
        description=text(node, "description"),
        queued_at=queued,
        started_at=started,
        finished_at=_when(text(node, "tfin")),
        details=lines(node.find("details")),
        devices=devices,
    )


def parse_jobs(result: Element) -> list[Job]:
    return [parse_job(j) for j in result.findall("job")]
