from __future__ import annotations

from pathlib import Path
from xml.etree.ElementTree import Element

import pytest
from defusedxml import ElementTree as SafeET

from panos_mcp.models.inventory import ConfigSync, HAState, JobResult, JobStatus, TemplateKind
from panos_mcp.parsers import inventory as p

VERSIONS = ["11.1", "11.2"]


def result(root: Path, version: str, rel: str) -> Element:
    node = SafeET.fromstring((root / version / f"{rel}.xml").read_bytes()).find("result")
    assert node is not None
    return node


@pytest.mark.parametrize("version", VERSIONS)
def test_devices(samples_root: Path, version: str) -> None:
    fws = {
        f.serial: f
        for f in p.parse_devices(result(samples_root, version, "op/show-devices-all/baseline"))
    }
    assert len(fws) == 4
    hq = fws["900000000001"]
    assert (hq.hostname, hq.model, hq.mgmt_ip) == ("fw-hq-01", "PA-3420", "10.10.0.11")
    assert hq.sw_version.startswith(version)
    assert hq.connected and hq.config_sync is ConfigSync.IN_SYNC
    assert (
        hq.ha is not None and hq.ha.local_state == "active" and hq.ha.peer_serial == "900000000002"
    )
    assert fws["900000000004"].vsys == ["vsys1", "vsys2"]
    assert fws["900000000003"].sw_version.startswith("10.2")
    assert "app_threat" in hq.content_versions


@pytest.mark.parametrize("version", VERSIONS)
def test_device_variants(samples_root: Path, version: str) -> None:
    disc = p.parse_devices(result(samples_root, version, "op/show-devices-all/one-disconnected"))
    assert [f.serial for f in disc if not f.connected] == ["900000000003"]
    sync = p.parse_devices(result(samples_root, version, "op/show-devices-all/out-of-sync"))
    assert {f.serial for f in sync if f.config_sync is ConfigSync.OUT_OF_SYNC} == {
        "900000000002",
        "900000000004",
    }
    assert p.parse_devices(result(samples_root, version, "op/show-devices-all/empty")) == []


@pytest.mark.parametrize("version", VERSIONS)
def test_groups_templates_stacks(samples_root: Path, version: str) -> None:
    members = p.parse_devicegroup_members(
        result(samples_root, version, "op/show-devicegroups/baseline")
    )
    assert members["Region-A-DG"] == ["900000000001", "900000000002"]
    assert members["Global-DG"] == []
    templates = p.parse_templates(result(samples_root, version, "op/show-templates/baseline"))
    assert [t.name for t in templates] == ["T-Base", "T-Region-A", "T-Branch", "T-Region-B"]
    stacks = p.parse_template_stacks(
        result(samples_root, version, "config/template-stack/baseline-running")
    )
    a = next(s for s in stacks if s.name == "Stack-A")
    assert a.kind is TemplateKind.TEMPLATE_STACK
    assert a.templates == ["T-Region-A", "T-Base"] and a.members == ["900000000001", "900000000002"]
    cand = p.parse_template_stacks(
        result(samples_root, version, "config/template-stack/baseline-candidate")
    )
    assert "T-Region-A" in next(s for s in cand if s.name == "Stack-B").templates


@pytest.mark.parametrize("version", VERSIONS)
def test_system_ha_licenses(samples_root: Path, version: str) -> None:
    info = p.parse_system_info(result(samples_root, version, "op/show-system-info/baseline"))
    assert info["hostname"] == "panorama-lab-01" and info["model"] == "Panorama"
    assert str(info["sw_version"]).startswith(version)
    states = {
        v: p.parse_ha(result(samples_root, version, f"op/show-high-availability-state/{v}"))[0]
        for v in ("standalone", "active", "passive")
    }
    assert states == {
        "standalone": HAState.STANDALONE,
        "active": HAState.ACTIVE,
        "passive": HAState.PASSIVE,
    }
    licenses = p.parse_licenses(result(samples_root, version, "op/request-license-info/baseline"))
    assert [lic.feature for lic in licenses if lic.expired] == ["Premium Support"]


@pytest.mark.parametrize("version", VERSIONS)
def test_jobs(samples_root: Path, version: str) -> None:
    jobs = p.parse_jobs(result(samples_root, version, "op/show-jobs-all/baseline"))
    by_id = {j.id: j for j in jobs}
    assert set(by_id) == {101, 102, 103, 104, 105, 106}
    assert by_id[104].status is JobStatus.ACTIVE and by_id[104].progress == 45
    assert by_id[105].status is JobStatus.PENDING
    assert by_id[102].result is JobResult.FAIL
    assert by_id[101].queued_at is not None and by_id[101].finished_at is not None
    job = p.parse_jobs(result(samples_root, version, "op/show-jobs-id/push-partial-fail"))[0]
    assert len(job.devices) == 3
    failed = [d for d in job.devices if d.result is JobResult.FAIL]
    assert failed[0].serial == "900000000003" and "unknown address" in failed[0].messages[0]
