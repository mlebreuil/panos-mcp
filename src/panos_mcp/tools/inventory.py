"""US1 tools: Panorama info, managed firewalls, device groups, templates, jobs."""

from __future__ import annotations

from typing import Annotated

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from panos_mcp.models.common import DEFAULT_LIMIT, Limit, Offset, ToolResult, paginate
from panos_mcp.models.inventory import (
    ConfigSync,
    DeviceGroup,
    Job,
    JobResult,
    JobStatus,
    ManagedFirewall,
    PanoramaInfo,
    Template,
    TemplateKind,
)
from panos_mcp.server import AppContext, readonly_tool
from panos_mcp.services.inventory import DeviceFilters, InventoryService


def _page_result[T](
    items: list[T], limit: int, offset: int, hint: str, warnings: list[str] | None = None
) -> ToolResult[list[T]]:
    page = paginate(items, limit, offset, hint)
    return ToolResult[list[T]](
        items=page.items,
        total=page.total,
        returned=page.returned,
        truncated=page.truncated,
        next_offset=page.next_offset,
        narrowing_hint=page.narrowing_hint,
        warnings=warnings or [],
    )


def _devices_summary(r: ToolResult[list[ManagedFirewall]]) -> str:
    down = [f"{d.hostname} ({d.serial})" for d in r.items if not d.connected]
    text = f"{r.total} firewall(s) match; showing {r.returned}."
    if down:
        text += f" Disconnected: {', '.join(down)}."
    return text


def register(server: MCPServer, app: AppContext) -> None:
    svc = InventoryService(app.client)

    def info_summary(r: ToolResult[PanoramaInfo]) -> str:
        i = r.items
        expired = [lic.feature for lic in i.licenses if lic.expired]
        text = f"Panorama {i.hostname} ({i.model}, {i.sw_version}), HA: {i.ha_state.value}."
        if expired:
            text += f" Expired licenses: {', '.join(expired)}."
        return text

    @readonly_tool(server, app, info_summary)
    async def get_panorama_info() -> ToolResult[PanoramaInfo]:
        """Panorama's own system information: hostname, model, software and content versions,
        uptime, HA state and licenses. Read-only. Use it to check which Panorama this server
        is connected to and its health."""
        info, warnings = await svc.panorama_info()
        return ToolResult[PanoramaInfo](items=info, returned=1, warnings=warnings)

    @readonly_tool(server, app, _devices_summary)
    async def list_managed_devices(
        device_group: Annotated[
            str | None, Field(description="Only firewalls in this device group")
        ] = None,
        template_stack: Annotated[
            str | None, Field(description="Only firewalls in this template stack")
        ] = None,
        connected: Annotated[
            bool | None, Field(description="true = connected only, false = disconnected only")
        ] = None,
        config_sync: Annotated[
            ConfigSync | None, Field(description="Filter by policy sync state with Panorama")
        ] = None,
        model: Annotated[str | None, Field(description="Exact model, e.g. PA-3420")] = None,
        sw_version: Annotated[
            str | None, Field(description="Software version prefix, e.g. 11.1")
        ] = None,
        limit: Limit = DEFAULT_LIMIT,
        offset: Offset = 0,
    ) -> ToolResult[list[ManagedFirewall]]:
        """List firewalls managed by Panorama with serial, hostname, model, management IP,
        software/content versions, device group, template stack, connection status, config
        sync state, HA state and vsys. Read-only. Use filters to answer questions such as
        "which firewalls are disconnected?" or "which firewalls run 10.2?"."""
        items = await svc.list_devices(
            DeviceFilters(device_group, template_stack, connected, config_sync, model, sw_version)
        )
        return _page_result(
            items, limit, offset, "Filter by device_group, connected or sw_version, or page."
        )

    @readonly_tool(server, app, lambda r: f"{r.total} device group(s); showing {r.returned}.")
    async def list_device_groups(
        root: Annotated[
            str | None, Field(description="Only this device group and its descendants")
        ] = None,
        include_members: Annotated[
            bool, Field(description="Include member firewall serials")
        ] = True,
        limit: Limit = DEFAULT_LIMIT,
        offset: Offset = 0,
    ) -> ToolResult[list[DeviceGroup]]:
        """Device-group hierarchy (parent, children) with member firewalls, depth-first from
        the top. Read-only. Use it to discover device-group names for scope parameters."""
        items = await svc.device_groups(root, include_members)
        return _page_result(items, limit, offset, "Pass root to list one branch, or page.")

    @readonly_tool(server, app, lambda r: f"{r.total} template(s)/stack(s); showing {r.returned}.")
    async def list_templates(
        kind: Annotated[
            TemplateKind | None, Field(description="template or template_stack")
        ] = None,
        name: Annotated[str | None, Field(description="Exact template or stack name")] = None,
        limit: Limit = DEFAULT_LIMIT,
        offset: Offset = 0,
    ) -> ToolResult[list[Template]]:
        """Templates and template stacks (with their ordered member templates and firewalls).
        Read-only."""
        items = await svc.templates(kind, name)
        return _page_result(items, limit, offset, "Filter by kind or name, or page.")

    def jobs_summary(r: ToolResult[list[Job]]) -> str:
        failed = [str(j.id) for j in r.items if j.result is JobResult.FAIL]
        text = f"{r.total} job(s); showing {r.returned}, newest first."
        if failed:
            text += f" Failed: {', '.join(failed)}."
        return text

    @readonly_tool(server, app, jobs_summary)
    async def list_jobs(
        status: Annotated[
            JobStatus | None, Field(description="pending, active or finished")
        ] = None,
        job_type: Annotated[
            str | None, Field(description="Job type, e.g. Commit, CommitAll, Content")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500, description="Maximum jobs to return")] = 20,
        offset: Offset = 0,
    ) -> ToolResult[list[Job]]:
        """Recent and pending Panorama jobs (commits, pushes, content installs) with status and
        result, newest first. Read-only: this server can view jobs but never starts them."""
        items = await svc.jobs(status, job_type)
        return _page_result(items, limit, offset, "Filter by status or job_type, or page.")

    def job_summary(r: ToolResult[Job]) -> str:
        j = r.items
        failed = [d.device_name or d.serial for d in j.devices if d.result is JobResult.FAIL]
        text = f"Job {j.id} ({j.type}): {j.status.value}, result {j.result.value}."
        if failed:
            text += f" Failed on: {', '.join(failed)}."
        return text

    @readonly_tool(server, app, job_summary)
    async def get_job(
        job_id: Annotated[int, Field(gt=0, description="Job id from list_jobs")],
        max_devices: Annotated[
            int, Field(ge=1, le=1000, description="Maximum per-firewall results to include")
        ] = 200,
    ) -> ToolResult[Job]:
        """One Panorama job with its per-firewall results (failures first). Read-only."""
        job = await svc.job(job_id)
        total = len(job.devices)
        truncated = total > max_devices
        job.devices = job.devices[:max_devices]
        return ToolResult[Job](
            items=job,
            total=total,
            returned=len(job.devices),
            truncated=truncated,
            narrowing_hint="Raise max_devices, or check a specific firewall with "
            "list_managed_devices."
            if truncated
            else None,
        )
