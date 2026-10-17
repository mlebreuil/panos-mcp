"""Sample library operations: add, validate, index (contracts/samples-cli.md)."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from xml.etree.ElementTree import Element, indent, tostring

from defusedxml import ElementTree as SafeET

from panos_mcp.client.allowlist import command_path, parse_cmd
from panos_mcp.client.commands import TOOL_REQUESTS
from panos_mcp.samples.layout import SampleId, iter_sample_files, normalize_cmd
from panos_mcp.samples.metadata import (
    Provenance,
    SampleMeta,
    SampleRequest,
    SanitizationRecord,
    read_meta,
    schema_errors,
)
from panos_mcp.samples.sanitize.forge import Forger, MappingStore, Mode, sanitize_tree
from panos_mcp.samples.sanitize.keeplist import load_keeplist
from panos_mcp.samples.sanitize.leakcheck import check_originals, lint
from panos_mcp.samples.scenarios import ResolvedScenario, ScenarioError, list_scenarios

SUPPORTED_VERSIONS = ("11.1", "11.2")


def tool_version() -> str:
    try:
        return f"panos-mcp {version('panos-mcp')}"
    except PackageNotFoundError:  # pragma: no cover
        return "panos-mcp dev"


class SampleError(Exception):
    pass


def slug_for(request: SampleRequest) -> str:
    if request.type == "op" and request.cmd:
        return command_path(parse_cmd(request.cmd)).replace("/", "-")
    raise SampleError("a --slug is required for config and log samples")


@dataclass
class SanitizeOutcome:
    xml: str
    originals: set[str]


def sanitize_xml(
    xml: str, store: MappingStore, mode: Mode, samples_root: Path | None
) -> SanitizeOutcome:
    """Sanitize, then run both leak-check layers; raises SampleError on any leak."""
    root: Element = SafeET.fromstring(xml)
    forger = Forger(store, load_keeplist(samples_root), mode)
    sanitize_tree(root, forger)
    indent(root, space="  ")
    out = tostring(root, encoding="unicode")
    leaks = check_originals(out, forger.originals)
    if leaks:
        raise SampleError(f"leak check failed, original values still present: {leaks}")
    findings = lint(out)
    if findings:
        raise SampleError("sanitization lint failed:\n  " + "\n  ".join(map(str, findings)))
    return SanitizeOutcome(out, forger.originals)


def add_sample(
    root: Path,
    *,
    panos_version: str,
    request: SampleRequest,
    variant: str,
    xml: str,
    source: str,
    description: str,
    slug: str | None = None,
    url: str | None = None,
    notes: str | None = None,
    generator: str | None = None,
    tags: list[str] | None = None,
    store: MappingStore,
    force: bool = False,
) -> SampleId:
    if request.type == "op" and request.cmd:
        request = request.model_copy(update={"cmd": normalize_cmd(request.cmd)})
    sample_id = SampleId(panos_version, request.type, slug or slug_for(request), variant)
    xml_path, meta_path = sample_id.xml_path(root), sample_id.meta_path(root)
    if xml_path.exists() and not force:
        raise SampleError(f"{sample_id} already exists (use --force to overwrite)")
    mode: Mode = "synthetic" if source == "synthetic" else "full"
    outcome = sanitize_xml(xml, store, mode, root)
    now = datetime.now(UTC).replace(microsecond=0)
    meta = SampleMeta(
        id=str(sample_id),
        request=request,
        panos_version=panos_version,
        description=description,
        provenance=Provenance(
            source=source,  # type: ignore[arg-type]
            url=url,
            notes=notes,
            generator=generator,
            captured_at=now if source == "lab-capture" else None,
        ),
        sanitization=SanitizationRecord(
            tool_version=tool_version(), sanitized_at=now, leak_check="passed"
        ),
        status="unverified",
        tags=tags or [],
    )
    errors = schema_errors(json.loads(meta.to_json()))
    if errors:
        raise SampleError("metadata does not match the schema:\n  " + "\n  ".join(errors))
    xml_path.parent.mkdir(parents=True, exist_ok=True)
    xml_path.write_text(outcome.xml + "\n", "utf-8")
    meta_path.write_text(meta.to_json(), "utf-8")
    return sample_id


# --------------------------------------------------------------------------- validate


def validate_library(root: Path) -> list[str]:
    problems: list[str] = []
    known: set[str] = set()
    for xml_path in iter_sample_files(root):
        rel = xml_path.relative_to(root).as_posix()
        try:
            sample_id = SampleId.from_path(root, xml_path)
        except ValueError as exc:
            problems.append(f"{rel}: {exc}")
            continue
        known.add(str(sample_id))
        text = xml_path.read_text("utf-8")
        try:
            findings = lint(text)
        except SafeET.ParseError as exc:
            problems.append(f"{rel}: not well-formed XML: {exc}")
            continue
        problems.extend(f"{rel}: {f}" for f in findings)
        meta_path = sample_id.meta_path(root)
        if not meta_path.exists():
            problems.append(f"{rel}: missing {meta_path.name}")
            continue
        data = json.loads(meta_path.read_text("utf-8"))
        problems.extend(f"{meta_path.relative_to(root)}: {e}" for e in schema_errors(data))
        if data.get("id") != str(sample_id):
            problems.append(f"{meta_path.relative_to(root)}: id {data.get('id')!r} != path")
        if data.get("request", {}).get("type") != sample_id.api_type:
            problems.append(f"{meta_path.relative_to(root)}: request.type does not match path")
    for meta_path in sorted(root.rglob("*.meta.json")):
        xml_path = meta_path.with_name(meta_path.name.removesuffix(".meta.json") + ".xml")
        if not xml_path.exists():
            problems.append(f"{meta_path.relative_to(root)}: no matching .xml")
    for name in list_scenarios(root):
        problems.extend(_validate_scenario(root, name, known))
    return problems


def _validate_scenario(root: Path, name: str, known: set[str]) -> list[str]:
    try:
        scenario = ResolvedScenario(root, name)
    except (ScenarioError, ValueError) as exc:
        return [f"scenarios/{name}.json: {exc}"]
    problems = [
        f"scenarios/{name}.json: references unknown sample {sid}"
        for sid in sorted(scenario.sample_ids() - known)
    ]
    serials = _scenario_serials(root, scenario)
    for s in scenario.chain:
        for response in s.responses:
            target = response.request.target
            if target and serials and target not in serials:
                problems.append(
                    f"scenarios/{s.name}.json: target {target} is not a managed firewall "
                    "in this scenario"
                )
    return problems


def _scenario_serials(root: Path, scenario: ResolvedScenario) -> set[str]:
    serials: set[str] = set()
    for key, sample in scenario.table.items():
        if "<show><devices><all>" in key:
            xml_root = SafeET.fromstring(SampleId.parse(sample).xml_path(root).read_bytes())
            serials.update(t.strip() for t in xml_root.itertext() if t.strip().startswith("9"))
            serials.update(e.get("name", "") for e in xml_root.iter("entry"))
    return serials


# --------------------------------------------------------------------------- index


def _params(request: SampleRequest) -> dict[str, str]:
    if request.type == "op":
        return {"type": "op", "cmd": request.cmd or ""}
    if request.type == "config":
        return {"type": "config", "action": request.action or "", "xpath": request.xpath or ""}
    if request.log_phase == "result":
        return {"type": "log", "action": "get", "job-id": "0"}
    return {"type": "log", "log-type": request.log_type or ""}


def build_index(root: Path) -> str:
    metas: list[SampleMeta] = []
    for xml_path in iter_sample_files(root):
        sample_id = SampleId.from_path(root, xml_path)
        meta_path = sample_id.meta_path(root)
        if meta_path.exists():
            meta = read_meta(meta_path)
            if "generated" not in meta.tags:  # git-ignored scale data stays out of the index
                metas.append(meta)

    lines = [
        "# Sample Library Index",
        "",
        "Generated by `panos-mcp-samples index`. Do not edit by hand.",
        "",
        "## Coverage of tool requests",
        "",
        "| Tool | Request | " + " | ".join(SUPPORTED_VERSIONS) + " |",
        "|---|---|" + "---|" * len(SUPPORTED_VERSIONS),
    ]
    uncovered = 0
    for tool, templates in TOOL_REQUESTS.items():
        for template in templates:
            cells = []
            for ver in SUPPORTED_VERSIONS:
                hits = [
                    m
                    for m in metas
                    if m.panos_version in (ver, "any") and template.matches(_params(m.request))
                ]
                if hits:
                    cells.append(f"✅ {len(hits)}")
                else:
                    cells.append("❌ missing")
                    uncovered += 1
            lines.append(f"| `{tool}` | {template.description} | " + " | ".join(cells) + " |")
    lines += ["", f"Uncovered request/version combinations: **{uncovered}**", ""]

    by_source: dict[str, int] = defaultdict(int)
    for m in metas:
        by_source[m.provenance.source] += 1
    lines += [
        "## Samples",
        "",
        f"Total: {len(metas)} ("
        + ", ".join(f"{k}: {v}" for k, v in sorted(by_source.items()))
        + ")",
        "",
        "| Sample | Provenance | Status | Description |",
        "|---|---|---|---|",
    ]
    for m in sorted(metas, key=lambda m: m.id):
        lines.append(f"| `{m.id}` | {m.provenance.source} | {m.status} | {m.description} |")
    scenarios = [s for s in list_scenarios(root) if s != "large-estate"]
    lines += ["", "## Scenarios", ""] + [f"- `{name}`" for name in scenarios] + [""]
    return "\n".join(lines)


def uncovered_requests(root: Path) -> int:
    text = build_index(root)
    for line in text.splitlines():
        if line.startswith("Uncovered request/version combinations"):
            return int(line.split("**")[1])
    return 0
