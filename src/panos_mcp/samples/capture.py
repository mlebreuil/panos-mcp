"""Opt-in live capture of samples from a lab Panorama (research.md R9).

Safety:
- refuses to run unless PANOS_MCP_LIVE=1;
- uses PanoramaClient, so every request passes the read-only allow-list;
- snapshots pending changes + latest commit job before and after, writes nothing if they
  differ (exit 3);
- sanitizes every response in full mode and runs the leak check for all of them before
  writing anything (exit 1 on any leak).
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree.ElementTree import Element, tostring

from panos_mcp.client import commands as c
from panos_mcp.client.xmlapi import PanoramaClient
from panos_mcp.config import Settings
from panos_mcp.models.common import SHARED, ToolError
from panos_mcp.parsers.inventory import parse_jobs
from panos_mcp.samples.layout import SampleId
from panos_mcp.samples.library import SampleError, add_sample, sanitize_xml
from panos_mcp.samples.metadata import SampleRequest, read_meta
from panos_mcp.samples.sanitize.forge import MappingStore
from panos_mcp.services.hierarchy import DeviceGroupTree

EXIT_OK, EXIT_FAIL, EXIT_USAGE, EXIT_LIVE = 0, 1, 2, 3
LOG_TYPES = ("traffic", "threat", "url", "system", "config")
OP_COMMANDS = {
    "show-system-info": c.show_system_info(),
    "show-high-availability-state": c.show_ha_state(),
    "request-license-info": c.request_license_info(),
    "show-devices-all": c.show_devices_all(),
    "show-devicegroups": c.show_devicegroups(),
    "show-dg-hierarchy": c.show_dg_hierarchy(),
    "show-templates": c.show_templates(),
    "show-jobs-all": c.show_jobs_all(),
    "check-pending-changes": c.check_pending_changes(),
}


def build_plan() -> dict[str, object]:
    """Capture plan covering the requests of all tools (placeholders resolved live)."""
    return {
        "version": 1,
        "description": "Read-only requests used by the 13 MCP tools. {scope} expands to "
        "shared and every device group; {job_id} is the latest job; {serial} the first "
        "connected firewall; {dag} the first shared dynamic address group.",
        "op": [{"slug": slug, "cmd": cmd} for slug, cmd in OP_COMMANDS.items()]
        + [
            {"slug": "show-jobs-id", "cmd": "<show><jobs><id>{job_id}</id></jobs></show>"},
            {
                "slug": "show-object-dynamic-address-group-name",
                "cmd": "<show><object><dynamic-address-group><name>{dag}</name>"
                "</dynamic-address-group></object></show>",
                "target": "{serial}",
            },
        ],
        "config": [{"xpath": c.template_stack_xpath(), "slug": "template-stack"}]
        + [
            {
                "xpath": "{scope_xpath}/" + f"{pos}-rulebase/{rt}/rules",
                "slug": f"{rt}-rules-{{scope}}-{pos}",
                "for_each": "scope",
            }
            for rt in ("security", "nat")
            for pos in ("pre", "post")
        ]
        + [
            {"xpath": "{scope_xpath}/" + node, "slug": f"{node}-{{scope}}", "for_each": "scope"}
            for node in c.OBJECT_XPATH_NODE.values()
        ],
        "log": [{"log_type": t, "nlogs": 20} for t in LOG_TYPES],
    }


@dataclass
class Captured:
    request: SampleRequest
    slug: str
    xml: str


@dataclass
class CaptureReport:
    captured: list[Captured] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


async def snapshot(client: PanoramaClient) -> tuple[str, int]:
    """(pending-changes flag, latest commit job id)."""
    pending = await client.op(c.check_pending_changes())
    jobs = parse_jobs(await client.op(c.show_jobs_all()))
    commits = [j.id for j in jobs if j.type.lower() in ("commit", "commitall")]
    return ("".join(pending.itertext()).strip(), max(commits, default=0))


def _xml(root: Element) -> str:
    return tostring(root, encoding="unicode")


async def _placeholders(client: PanoramaClient) -> dict[str, object]:
    tree = DeviceGroupTree.from_xml(await client.op(c.show_dg_hierarchy()))
    jobs = parse_jobs(await client.op(c.show_jobs_all()))
    devices = await client.op(c.show_devices_all())
    serial = next(
        (e.findtext("serial") for e in devices.iter("entry") if e.findtext("connected") == "yes"),
        None,
    )
    _, groups = await client.config(c.object_xpath(SHARED, "address_group"))
    dag = next((e.get("name") for e in groups.iter("entry") if e.find("dynamic") is not None), None)
    return {
        "scopes": [SHARED, *tree.depth_first()],
        "job_id": max((j.id for j in jobs), default=None),
        "serial": serial,
        "dag": dag,
    }


async def collect(client: PanoramaClient, plan: dict[str, object]) -> CaptureReport:
    report = CaptureReport()
    ph = await _placeholders(client)

    async def grab(request: SampleRequest, slug: str, params: dict[str, str]) -> Element | None:
        try:
            root = await client.request(params)
        except ToolError as exc:
            report.skipped.append(f"{slug}: {exc.info.code.value} ({exc.info.message})")
            return None
        report.captured.append(Captured(request, slug, _xml(root)))
        return root

    for item in plan.get("op", []):  # type: ignore[attr-defined]
        cmd = item["cmd"]
        if "{job_id}" in cmd:
            if ph["job_id"] is None:
                continue
            cmd = cmd.replace("{job_id}", str(ph["job_id"]))
        if "{dag}" in cmd:
            if not ph["dag"] or not ph["serial"]:
                report.skipped.append(f"{item['slug']}: no dynamic group or connected firewall")
                continue
            cmd = c.show_dynamic_address_group(str(ph["dag"]))
        params = {"type": "op", "cmd": cmd}
        target = None
        if item.get("target"):
            target = str(ph["serial"])
            params["target"] = target
        await grab(SampleRequest(type="op", cmd=cmd, target=target), item["slug"], params)

    for item in plan.get("config", []):  # type: ignore[attr-defined]
        scopes = ph["scopes"] if item.get("for_each") == "scope" else [None]
        for scope in scopes:  # type: ignore[attr-defined]
            xpath = item["xpath"]
            slug = item["slug"]
            if scope is not None:
                xpath = xpath.replace("{scope_xpath}", c.scope_xpath(scope))
                slug = slug.replace("{scope}", scope.lower())
            for action in ("show", "get"):
                await grab(
                    SampleRequest(type="config", action=action, xpath=xpath),
                    slug,
                    {"type": "config", "action": action, "xpath": xpath},
                )

    for item in plan.get("log", []):  # type: ignore[attr-defined]
        log_type = item["log_type"]
        start = await grab(
            SampleRequest(type="log", log_type=log_type, log_phase="start"),
            f"{log_type}-start",
            {"type": "log", "log-type": log_type, "nlogs": str(item.get("nlogs", 20))},
        )
        job_text = start.findtext("result/job") if start is not None else None
        if not job_text or not job_text.strip().isdigit():
            continue
        job_id = int(job_text)
        client.started_log_jobs.add(job_id)
        for _ in range(int(client.settings.query_timeout)):
            result = await client.request({"type": "log", "action": "get", "job-id": str(job_id)})
            if (result.findtext("result/job/status") or "").upper() == "FIN":
                report.captured.append(
                    Captured(
                        SampleRequest(type="log", log_type=log_type, log_phase="result"),
                        f"{log_type}-result",
                        _xml(result),
                    )
                )
                break
            await asyncio.sleep(1)
        else:
            report.skipped.append(f"{log_type}-result: log query did not finish")
    return report


def write_captured(
    report: CaptureReport, root: Path, version: str, variant: str, store: MappingStore
) -> list[str]:
    """Leak-check everything with a throw-away copy of the mapping, then write."""
    trial = MappingStore(
        directory=store.directory,
        key=store.key,
        mapping=copy.deepcopy(store.mapping),
        persistent=False,
    )
    for item in report.captured:
        sanitize_xml(item.xml, trial, "full", root)  # raises SampleError on any leak
    ids = []
    for item in report.captured:
        suffix = "-candidate" if item.request.action == "get" else ""
        sid = add_sample(
            root,
            panos_version=version,
            request=item.request,
            variant=variant + suffix,
            xml=item.xml,
            source="lab-capture",
            description=f"Captured from a lab Panorama ({item.slug})",
            slug=item.slug,
            store=store,
            force=True,
        )
        ids.append(str(sid))
    store.save()
    return ids


async def run_capture(
    client: PanoramaClient,
    plan: dict[str, object],
    root: Path,
    version: str,
    variant: str,
    store: MappingStore,
) -> tuple[int, list[str], CaptureReport]:
    before = await snapshot(client)
    report = await collect(client, plan)
    after = await snapshot(client)
    if before != after:
        print(
            f"capture: Panorama state changed during capture ({before} -> {after}); "
            "nothing written",
            file=sys.stderr,
        )
        return EXIT_LIVE, [], report
    try:
        ids = write_captured(report, root, version, variant, store)
    except SampleError as exc:
        print(f"capture: {exc}; nothing written", file=sys.stderr)
        return EXIT_FAIL, [], report
    return EXIT_OK, ids, report


def mark_verified(root: Path, ids: list[str]) -> int:
    for sid in ids:
        path = SampleId.parse(sid).meta_path(root)
        meta = read_meta(path)
        meta.status = "verified"
        path.write_text(meta.to_json(), "utf-8")
        print(f"verified {sid}")
    return EXIT_OK


def run_capture_cli(args: argparse.Namespace) -> int:
    if args.write_plan:
        args.write_plan.parent.mkdir(parents=True, exist_ok=True)
        args.write_plan.write_text(json.dumps(build_plan(), indent=2) + "\n", "utf-8")
        print(f"wrote {args.write_plan}")
        return EXIT_OK
    if args.mark_verified:
        return mark_verified(args.samples_dir, args.mark_verified)
    if os.environ.get("PANOS_MCP_LIVE") != "1":
        print(
            "capture: refusing to contact Panorama; set PANOS_MCP_LIVE=1 to opt in", file=sys.stderr
        )
        return EXIT_LIVE
    if not (args.plan and args.version and args.variant):
        print("capture: --plan, --version and --variant are required", file=sys.stderr)
        return EXIT_USAGE
    plan = json.loads(Path(args.plan).read_text("utf-8"))
    settings = Settings()

    async def main() -> int:
        client = PanoramaClient(settings)
        try:
            await client.keygen()
            code, ids, report = await run_capture(
                client,
                plan,
                args.samples_dir,
                args.version,
                args.variant,
                MappingStore.open(args.mapping_dir),
            )
        finally:
            await client.aclose()
        for line in report.skipped:
            print(f"skipped {line}")
        print(f"wrote {len(ids)} sample(s)")
        return code

    return asyncio.run(main())
