from __future__ import annotations

from datetime import datetime
from pathlib import Path
from xml.etree.ElementTree import Element

import pytest
from defusedxml import ElementTree as SafeET

from panos_mcp.models.logs import LogType
from panos_mcp.parsers.logs import parse_job_status, parse_log_entries, parse_policy_match


def result(root: Path, rel: str) -> Element:
    node = SafeET.fromstring((root / f"{rel}.xml").read_bytes()).find("result")
    assert node is not None
    return node


@pytest.mark.parametrize("version", ["11.1", "11.2"])
def test_traffic(samples_root: Path, version: str) -> None:
    r = result(samples_root, f"{version}/log/traffic-result/baseline")
    assert parse_job_status(r) == "FIN"
    entries = parse_log_entries(r, LogType.TRAFFIC)
    assert len(entries) == 6
    times = [e.receive_time or datetime.min for e in entries]
    assert times == sorted(times, reverse=True)
    first = entries[0]
    assert (first.src, first.dst, first.dport, first.action, first.rule) == (
        "10.10.1.5",
        "192.0.2.10",
        443,
        "deny",
        "Block-Known-Bad",
    )
    assert first.device_serial == "900000000001" and first.from_zone == "trust"
    assert {e.action for e in entries} == {"allow", "deny"}
    assert "packets" in first.extra and "seqno" not in first.extra


@pytest.mark.parametrize("version", ["11.1", "11.2"])
def test_other_types(samples_root: Path, version: str) -> None:
    threat = parse_log_entries(
        result(samples_root, f"{version}/log/threat-result/baseline"), LogType.THREAT
    )
    assert threat[0].threat_name == "Eicar Test File" and threat[0].threat_id == "39040"
    assert {t.severity for t in threat} == {"medium", "high", "informational"}
    url = parse_log_entries(result(samples_root, f"{version}/log/url-result/baseline"), LogType.URL)
    assert "news.example.com/today" in {u.url for u in url} and url[0].category
    system = parse_log_entries(
        result(samples_root, f"{version}/log/system-result/baseline"), LogType.SYSTEM
    )
    assert system[0].event_id and system[0].description
    config = parse_log_entries(
        result(samples_root, f"{version}/log/config-result/baseline"), LogType.CONFIG
    )
    assert {c.admin for c in config} == {"admin", "netops"} and config[0].command and config[0].path


def test_pending_and_policy_match(samples_root: Path) -> None:
    assert parse_job_status(result(samples_root, "11.1/log/traffic-result/pending")) == "ACT"
    allow = parse_policy_match(
        result(samples_root, "11.1/op/test-security-policy-match/match-allow")
    )
    assert allow == ("Allow-Admin-Web", "allow")
    assert (
        parse_policy_match(result(samples_root, "11.1/op/test-security-policy-match/no-match"))
        is None
    )
