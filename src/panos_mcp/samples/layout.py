"""Sample library layout: ids, paths and canonical request keys (data-model.md §C)."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from xml.etree.ElementTree import Element, tostring

from defusedxml import ElementTree as SafeET

ID_RE = re.compile(r"^(any|[0-9]+\.[0-9]+)/(op|config|log)/([a-z0-9-]+)/([a-z0-9-]+)$")


def default_samples_dir() -> Path:
    env = os.environ.get("PANOS_MCP_SAMPLES_DIR")
    if env:
        return Path(env)
    repo_samples = Path(__file__).resolve().parents[3] / "samples"
    if repo_samples.is_dir():
        return repo_samples
    return Path.cwd() / "samples"


@dataclass(frozen=True)
class SampleId:
    version: str
    api_type: str
    slug: str
    variant: str

    @classmethod
    def parse(cls, value: str) -> SampleId:
        match = ID_RE.match(value)
        if not match:
            raise ValueError(
                f"invalid sample id {value!r}; expected <version>/<op|config|log>/<slug>/<variant>"
            )
        return cls(*match.groups())

    @classmethod
    def from_path(cls, root: Path, xml_path: Path) -> SampleId:
        rel = xml_path.relative_to(root).with_suffix("")
        return cls.parse(rel.as_posix())

    def __str__(self) -> str:
        return f"{self.version}/{self.api_type}/{self.slug}/{self.variant}"

    def xml_path(self, root: Path) -> Path:
        return root / f"{self}.xml"

    def meta_path(self, root: Path) -> Path:
        return root / f"{self}.meta.json"


def normalize_cmd(cmd: str) -> str:
    """Canonical op command XML: whitespace-only text removed, explicit end tags."""
    root: Element = SafeET.fromstring(cmd)
    for node in root.iter():
        if node.text is not None and not node.text.strip():
            node.text = None
        elif node.text is not None:
            node.text = node.text.strip()
        node.tail = None
    return tostring(root, encoding="unicode", short_empty_elements=False)


def key_for_request(request: Mapping[str, object]) -> str:
    """Canonical key for a sample's `request` metadata block."""
    req_type = request["type"]
    target = str(request.get("target") or "")
    if req_type == "op":
        return f"op|{normalize_cmd(str(request['cmd']))}|{target}"
    if req_type == "config":
        return f"config|{request['action']}|{request['xpath']}"
    if req_type == "log":
        return f"log|{request['log_type']}|{request['log_phase']}"
    raise ValueError(f"unknown request type {req_type!r}")


def key_for_params(params: Mapping[str, str], log_type_for_job: str | None = None) -> str:
    """Canonical key for an outgoing XML API request (form params).

    Log result requests carry only a job id; the caller supplies the log type of the
    query that created that job. Log query text is deliberately not part of the key.
    """
    req_type = params.get("type")
    if req_type == "op":
        return f"op|{normalize_cmd(params['cmd'])}|{params.get('target', '')}"
    if req_type == "config":
        return f"config|{params['action']}|{params['xpath']}"
    if req_type == "log":
        if params.get("action") == "get":
            return f"log|{log_type_for_job}|result"
        return f"log|{params['log-type']}|start"
    raise ValueError(f"unknown request type {req_type!r}")


def iter_sample_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.xml") if "scenarios" not in p.relative_to(root).parts)
