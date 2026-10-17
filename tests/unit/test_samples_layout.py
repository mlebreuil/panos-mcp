from __future__ import annotations

import json
from pathlib import Path

import pytest

from panos_mcp.samples.layout import SampleId, key_for_params, key_for_request, normalize_cmd
from panos_mcp.samples.metadata import schema_errors


def test_id_path_round_trip(tmp_path: Path) -> None:
    sid = SampleId.parse("11.1/op/show-devices-all/baseline")
    assert SampleId.from_path(tmp_path, sid.xml_path(tmp_path)) == sid
    assert sid.meta_path(tmp_path).name == "baseline.meta.json"
    with pytest.raises(ValueError):
        SampleId.parse("11.1/write/x/y")


def test_canonical_keys_match_between_request_and_params() -> None:
    cmd = "<show>\n  <devices><all/></devices>\n</show>"
    assert normalize_cmd(cmd) == "<show><devices><all></all></devices></show>"
    assert key_for_request({"type": "op", "cmd": cmd}) == key_for_params(
        {"type": "op", "cmd": "<show><devices><all></all></devices></show>"}
    )
    assert key_for_request(
        {"type": "config", "action": "show", "xpath": "/config/shared/address"}
    ) == key_for_params({"type": "config", "action": "show", "xpath": "/config/shared/address"})
    assert key_for_request({"type": "log", "log_type": "traffic", "log_phase": "start"}) == (
        key_for_params({"type": "log", "log-type": "traffic", "query": "(x)", "nlogs": "5"})
    )
    assert key_for_params({"type": "log", "action": "get", "job-id": "9"}, "traffic") == (
        "log|traffic|result"
    )


def meta(**over: object) -> dict[str, object]:
    data: dict[str, object] = {
        "id": "11.1/op/show-devices-all/baseline",
        "request": {"type": "op", "cmd": "<show><devices><all></all></devices></show>"},
        "panos_version": "11.1",
        "description": "Four firewalls in three device groups",
        "provenance": {"source": "synthetic", "notes": "authored"},
        "sanitization": {
            "tool_version": "panos-mcp 0.1.0",
            "sanitized_at": "2026-10-16T09:00:00Z",
            "leak_check": "passed",
        },
        "status": "unverified",
    }
    data.update(over)
    return data


def test_schema_valid_and_rules() -> None:
    assert schema_errors(meta()) == []
    assert schema_errors(meta(provenance={"source": "documentation"}))  # url required
    assert schema_errors(meta(provenance={"source": "lab-capture"}))  # captured_at required
    bad = meta()
    bad["sanitization"] = {**bad["sanitization"], "leak_check": "failed"}  # type: ignore[dict-item]
    assert schema_errors(bad)
    assert schema_errors(json.loads(json.dumps(meta(id="bad id"))))
