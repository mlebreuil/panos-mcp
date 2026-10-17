"""Inventory service: Panorama info, managed firewalls, device groups, templates, jobs (US1)."""

from __future__ import annotations

import asyncio
import difflib
from dataclasses import dataclass

from panos_mcp.client import commands
from panos_mcp.client.xmlapi import PanoramaClient
from panos_mcp.models.common import SHARED, ConfigSource, ErrorCode, ToolError
from panos_mcp.models.inventory import (
    ConfigSync,
    DeviceGroup,
    HAState,
    Job,
    JobResult,
    JobStatus,
    ManagedFirewall,
    PanoramaInfo,
    Template,
    TemplateKind,
)
from panos_mcp.parsers import inventory as p
from panos_mcp.services.hierarchy import DeviceGroupTree, load_tree


@dataclass
class DeviceFilters:
    device_group: str | None = None
    template_stack: str | None = None
    connected: bool | None = None
    config_sync: ConfigSync | None = None
    model: str | None = None
    sw_version: str | None = None


class InventoryService:
    def __init__(self, client: PanoramaClient) -> None:
        self.client = client

    async def panorama_info(self) -> tuple[PanoramaInfo, list[str]]:
        system, ha = await asyncio.gather(
            self.client.op(commands.show_system_info()),
            self.client.op(commands.show_ha_state()),
        )
        warnings: list[str] = []
        try:
            licenses = p.parse_licenses(await self.client.op(commands.request_license_info()))
        except ToolError as exc:
            if exc.code is not ErrorCode.PERMISSION_DENIED:
                raise
            licenses = []
            warnings.append(
                "The admin role cannot read license information; licenses are not shown."
            )
        ha_state, peer_state = p.parse_ha(ha)
        if ha_state is HAState.PASSIVE:
            warnings.append(
                "Connected to the passive Panorama HA peer; configuration may lag the active peer."
            )
        info = PanoramaInfo.model_validate(
            {
                **p.parse_system_info(system),
                "ha_state": ha_state,
                "ha_peer_state": peer_state,
                "licenses": licenses,
                "tls_verification": self.client.settings.verify_tls,
            }
        )
        return info, warnings

    async def _stacks(self) -> list[Template]:
        _, result = await self.client.config(commands.template_stack_xpath(), ConfigSource.RUNNING)
        return p.parse_template_stacks(result)

    async def devices(self) -> list[ManagedFirewall]:
        """All managed firewalls with device-group and template-stack membership."""
        dev_result, dg_result, stacks = await asyncio.gather(
            self.client.op(commands.show_devices_all()),
            self.client.op(commands.show_devicegroups()),
            self._stacks(),
        )
        firewalls = p.parse_devices(dev_result)
        dg_of = {
            serial: dg
            for dg, serials in p.parse_devicegroup_members(dg_result).items()
            for serial in serials
        }
        stack_of = {serial: s.name for s in stacks for serial in s.members}
        for fw in firewalls:
            fw.device_group = dg_of.get(fw.serial)
            fw.template_stack = stack_of.get(fw.serial)
        return firewalls

    async def list_devices(self, f: DeviceFilters) -> list[ManagedFirewall]:
        if f.device_group is not None:
            tree = await load_tree(self.client)
            tree.resolve_scope(f.device_group)
        if f.template_stack is not None:
            names = [s.name for s in await self._stacks()]
            if f.template_stack not in names:
                raise ToolError(
                    ErrorCode.NOT_FOUND,
                    f"Template stack {f.template_stack!r} does not exist.",
                    "Use list_templates with kind=template_stack to see the available stacks.",
                    difflib.get_close_matches(f.template_stack, names, n=3, cutoff=0.5),
                )
        out = []
        for fw in await self.devices():
            if f.device_group is not None and fw.device_group != f.device_group:
                continue
            if f.template_stack is not None and fw.template_stack != f.template_stack:
                continue
            if f.connected is not None and fw.connected != f.connected:
                continue
            if f.config_sync is not None and fw.config_sync != f.config_sync:
                continue
            if f.model is not None and fw.model.lower() != f.model.lower():
                continue
            if f.sw_version is not None and not fw.sw_version.startswith(f.sw_version):
                continue
            out.append(fw)
        return out

    async def require_device(self, serial: str) -> ManagedFirewall:
        """The managed firewall with this serial (not_found with suggestions otherwise)."""
        commands.validate_serial(serial)
        firewalls = p.parse_devices(await self.client.op(commands.show_devices_all()))
        for fw in firewalls:
            if fw.serial == serial:
                return fw
        known = [fw.serial for fw in firewalls]
        raise ToolError(
            ErrorCode.NOT_FOUND,
            f"No managed firewall has serial {serial}.",
            "Use list_managed_devices to find the firewall's serial number.",
            difflib.get_close_matches(serial, known, n=3, cutoff=0.6),
        )

    async def device_groups(self, root: str | None, include_members: bool) -> list[DeviceGroup]:
        tree_result, dg_result = await asyncio.gather(
            self.client.op(commands.show_dg_hierarchy()),
            self.client.op(commands.show_devicegroups()),
        )
        tree = DeviceGroupTree.from_xml(tree_result)
        start = tree.resolve_scope(root) if root else SHARED
        membership = p.parse_devicegroup_members(dg_result) if include_members else {}
        return [
            DeviceGroup(
                name=name,
                parent=tree.parents[name],
                children=tree.children.get(name, []),
                members=membership.get(name, []),
            )
            for name in tree.depth_first(start)
        ]

    async def templates(self, kind: TemplateKind | None, name: str | None) -> list[Template]:
        templates_result, stacks = await asyncio.gather(
            self.client.op(commands.show_templates()), self._stacks()
        )
        items = [*p.parse_templates(templates_result), *stacks]
        if kind is not None:
            items = [t for t in items if t.kind is kind]
        if name is not None:
            matches = [t for t in items if t.name == name]
            if not matches:
                raise ToolError(
                    ErrorCode.NOT_FOUND,
                    f"No template or template stack named {name!r}.",
                    "Call list_templates without a name to see all templates and stacks.",
                    difflib.get_close_matches(name, [t.name for t in items], n=3, cutoff=0.5),
                )
            items = matches
        return items

    async def jobs(self, status: JobStatus | None, job_type: str | None) -> list[Job]:
        jobs = p.parse_jobs(await self.client.op(commands.show_jobs_all()))
        if status is not None:
            jobs = [j for j in jobs if j.status is status]
        if job_type is not None:
            jobs = [j for j in jobs if j.type.lower() == job_type.lower()]
        return sorted(jobs, key=lambda j: j.id, reverse=True)

    async def job(self, job_id: int) -> Job:
        try:
            result = await self.client.op(commands.show_job(job_id))
        except ToolError as exc:
            if exc.code is ErrorCode.PANORAMA_ERROR and "not found" in exc.info.message.lower():
                raise ToolError(
                    ErrorCode.NOT_FOUND,
                    f"Panorama has no job with id {job_id}.",
                    "Use list_jobs to see recent job ids.",
                ) from None
            raise
        jobs = p.parse_jobs(result)
        if not jobs:
            raise ToolError(
                ErrorCode.NOT_FOUND,
                f"Panorama has no job with id {job_id}.",
                "Use list_jobs to see recent job ids.",
            )
        job = jobs[0]
        job.devices.sort(key=lambda d: (d.result is not JobResult.FAIL, d.serial))
        return job
