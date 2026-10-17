from __future__ import annotations

from pathlib import Path
from xml.etree.ElementTree import Element

import pytest
from defusedxml import ElementTree as SafeET

from panos_mcp.models.objects import (
    Address,
    AddressGroup,
    AddressType,
    ObjectKind,
    SecurityProfileGroup,
    Service,
    ServiceGroup,
    Tag,
)
from panos_mcp.models.policy import NatType, Position, RuleAction, SourceTranslationKind
from panos_mcp.parsers.objects import parse_dag_members, parse_objects
from panos_mcp.parsers.policy import parse_nat_rules, parse_security_rules


def result(root: Path, rel: str) -> Element:
    node = SafeET.fromstring((root / f"{rel}.xml").read_bytes()).find("result")
    assert node is not None
    return node


@pytest.mark.parametrize("version", ["11.1", "11.2"])
def test_security_rules(samples_root: Path, version: str) -> None:
    rules = parse_security_rules(
        result(samples_root, f"{version}/config/security-rules-shared-pre/baseline"),
        "shared",
        Position.PRE,
    )
    assert [r.name for r in rules] == ["Block-Known-Bad", "Allow-DNS", "Allow-Web-In"]
    web = rules[2]
    assert web.action is RuleAction.ALLOW and web.profile_group == "strict-profiles"
    assert web.applications == ["web-browsing", "ssl"] and web.services == ["application-default"]
    assert web.from_zones == ["untrust"] and web.to_zones == ["dmz"] and web.tags == ["web"]
    assert web.uuid and web.scope == "shared" and web.position is Position.PRE
    region = parse_security_rules(
        result(samples_root, f"{version}/config/security-rules-region-a-dg-pre/baseline"),
        "Region-A-DG",
        Position.PRE,
    )
    by = {r.name: r for r in region}
    assert (
        by["Deny-Not-Corp"].negate_source and by["Deny-Not-Corp"].action is RuleAction.RESET_CLIENT
    )
    assert by["Allow-Partners"].profiles == {"virus": "default", "spyware": "strict"}
    glob = parse_security_rules(
        result(samples_root, f"{version}/config/security-rules-global-dg-pre/baseline"),
        "Global-DG",
        Position.PRE,
    )
    assert next(r for r in glob if r.name == "Legacy-FTP").disabled
    branch = parse_security_rules(
        result(samples_root, f"{version}/config/security-rules-branch-dg-pre/baseline"),
        "Branch-DG",
        Position.PRE,
    )
    printer = next(r for r in branch if r.name == "Allow-Printer")
    assert printer.target is not None and printer.target.devices == ["900000000003"]


@pytest.mark.parametrize("version", ["11.1", "11.2"])
def test_nat_rules(samples_root: Path, version: str) -> None:
    shared = parse_nat_rules(
        result(samples_root, f"{version}/config/nat-rules-shared-pre/baseline"),
        "shared",
        Position.PRE,
    )
    snat, static = shared
    assert snat.source_translation is not None
    assert snat.source_translation.kind is SourceTranslationKind.DYNAMIC_IP_AND_PORT
    assert snat.source_translation.interface == "ethernet1/1" and snat.nat_type is NatType.IPV4
    assert static.source_translation is not None and static.source_translation.bidirectional
    assert static.source_translation.addresses == ["203.0.113.10"]
    branch = parse_nat_rules(
        result(samples_root, f"{version}/config/nat-rules-branch-dg-pre/baseline"),
        "Branch-DG",
        Position.PRE,
    )
    dnat = branch[0]
    assert dnat.destination_translation is not None
    assert (dnat.destination_translation.address, dnat.destination_translation.port) == (
        "web-srv-01",
        443,
    )
    assert dnat.service == "svc-tcp-8443"
    pool = branch[1].source_translation
    assert pool is not None and pool.kind is SourceTranslationKind.DYNAMIC_IP


@pytest.mark.parametrize("version", ["11.1", "11.2"])
def test_objects(samples_root: Path, version: str) -> None:
    def objs(slug: str, kind: ObjectKind) -> dict[str, object]:
        parsed = parse_objects(
            result(samples_root, f"{version}/config/{slug}/baseline"), kind, "shared"
        )
        return {o.name: o for o in parsed}

    addresses = objs("address-shared", ObjectKind.ADDRESS)
    types = {a.type for a in addresses.values() if isinstance(a, Address)}
    assert types == set(AddressType)
    web = addresses["web-srv-01"]
    assert isinstance(web, Address) and web.value == "10.20.1.10/32" and web.tags == ["web", "prod"]
    groups = objs("address-group-shared", ObjectKind.ADDRESS_GROUP)
    assert isinstance(groups["all-servers"], AddressGroup)
    assert groups["all-servers"].static_members == ["web-servers", "db-srv-01"]
    dyn = groups["dyn-web"]
    assert isinstance(dyn, AddressGroup) and dyn.dynamic_filter == "'web' and 'prod'"
    services = objs("service-shared", ObjectKind.SERVICE)
    syslog = services["svc-udp-514"]
    assert isinstance(syslog, Service) and syslog.protocol == "udp" and syslog.source_port
    sg = objs("service-group-shared", ObjectKind.SERVICE_GROUP)["web-svcs"]
    assert isinstance(sg, ServiceGroup) and "svc-tcp-8443" in sg.members
    tag = objs("tag-shared", ObjectKind.TAG)["prod"]
    assert isinstance(tag, Tag) and tag.color == "color5"
    pg = objs("profile-group-shared", ObjectKind.SECURITY_PROFILE_GROUP)["strict-profiles"]
    assert isinstance(pg, SecurityProfileGroup) and pg.profiles["spyware"] == "strict"


def test_dag_members(samples_root: Path) -> None:
    members = parse_dag_members(
        result(samples_root, "11.1/op/show-object-dynamic-address-group-name/baseline")
    )
    assert members == ["10.20.1.10", "10.20.1.11", "10.20.1.12"]
