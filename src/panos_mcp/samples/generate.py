"""Deterministic synthetic datasets for scale tests (research.md R13).

`large-estate`: N managed firewalls and M security rules spread over the baseline device
groups, with matching address objects and groups. Output is git-ignored (regenerate with
`panos-mcp-samples generate large-estate`), written as 11.1 samples plus the
`large-estate` scenario, which extends `baseline`.
"""

from __future__ import annotations

import json
import random
from pathlib import Path
from xml.etree.ElementTree import tostring

from defusedxml import ElementTree as SafeET

from panos_mcp.client import commands as c
from panos_mcp.samples.library import add_sample
from panos_mcp.samples.metadata import SampleRequest
from panos_mcp.samples.sanitize.forge import MappingStore

VERSION = "11.1"
VARIANT = "large-estate"
DEVICE_GROUPS = ("Region-A-DG", "Branch-DG", "Region-B-DG")
# share of rules per (scope, position)
RULE_SPLIT = (
    (("shared", "pre"), 0.10),
    (("Global-DG", "pre"), 0.20),
    (("Region-A-DG", "pre"), 0.30),
    (("Branch-DG", "pre"), 0.30),
    (("shared", "post"), 0.05),
    (("Branch-DG", "post"), 0.05),
)
APPS = ("ssl", "web-browsing", "dns", "ssh", "ntp", "ldap", "smtp", "any")
ZONES = ("trust", "untrust", "dmz")
N_ADDRESSES = 2000
GROUP_SIZE = 10


def _ok(inner: str) -> str:
    return f'<response status="success"><result>{inner}</result></response>'


def _m(*values: str) -> str:
    return "".join(f"<member>{v}</member>" for v in values)


def address_name(i: int) -> str:
    return f"gen-host-{i:04d}"


def address_ip(i: int) -> str:
    return f"10.100.{i // 250}.{i % 250 + 1}"


def _baseline_devices(root: Path) -> tuple[list[str], dict[str, list[str]]]:
    """Keep the baseline firewalls so inherited baseline samples (targets) stay valid."""
    base = root / VERSION / "op"
    devices = SafeET.fromstring((base / "show-devices-all" / "baseline.xml").read_bytes())
    groups = SafeET.fromstring((base / "show-devicegroups" / "baseline.xml").read_bytes())
    entries = [tostring(e, encoding="unicode") for e in devices.iterfind("result/devices/entry")]
    members = {
        g.get("name", ""): [d.get("name", "") for d in g.iterfind("devices/entry")]
        for g in groups.iterfind("result/devicegroups/entry")
    }
    return entries, members


def _devices(n: int, root: Path) -> tuple[str, dict[str, list[str]]]:
    entries, members = _baseline_devices(root)
    for dg in DEVICE_GROUPS:
        members.setdefault(dg, [])
    for i in range(n):
        serial = f"9100{i:08d}"
        dg = DEVICE_GROUPS[i % len(DEVICE_GROUPS)]
        members[dg].append(serial)
        entries.append(
            f'<entry name="{serial}"><serial>{serial}</serial>'
            f"<connected>{'no' if i % 50 == 7 else 'yes'}</connected>"
            f"<hostname>fw-gen-{i:04d}</hostname><ip-address>10.250.{i // 250}.{i % 250 + 1}"
            f"</ip-address><model>PA-440</model><sw-version>11.1.4-h2</sw-version>"
            f'<vsys><entry name="vsys1"><shared-policy-status>In Sync</shared-policy-status>'
            f"</entry></vsys></entry>"
        )
    return _ok(f"<devices>{''.join(entries)}</devices>"), members


def _devicegroups(members: dict[str, list[str]]) -> str:
    groups = "".join(
        f'<entry name="{dg}"><devices>'
        + "".join(f'<entry name="{s}"><serial>{s}</serial></entry>' for s in serials)
        + "</devices></entry>"
        for dg, serials in members.items()
    )
    return _ok(f"<devicegroups>{groups}</devicegroups>")


def _addresses() -> str:
    entries = "".join(
        f'<entry name="{address_name(i)}"><ip-netmask>{address_ip(i)}/32</ip-netmask></entry>'
        for i in range(N_ADDRESSES)
    )
    return _ok(f"<address>{entries}</address>")


def _groups() -> str:
    entries = "".join(
        f'<entry name="gen-grp-{g:03d}"><static>'
        + _m(*(address_name(g * GROUP_SIZE + k) for k in range(GROUP_SIZE)))
        + "</static></entry>"
        for g in range(N_ADDRESSES // GROUP_SIZE)
    )
    return _ok(f"<address-group>{entries}</address-group>")


def _rules(rng: random.Random, scope: str, pos: str, count: int) -> str:
    out = []
    for i in range(count):

        def endpoint() -> str:
            roll = rng.random()
            if roll < 0.2:
                return "any"
            if roll < 0.4:
                return f"gen-grp-{rng.randrange(N_ADDRESSES // GROUP_SIZE):03d}"
            return address_name(rng.randrange(N_ADDRESSES))

        action = "allow" if rng.random() < 0.85 else "deny"
        out.append(
            f'<entry name="R-{scope}-{pos}-{i:05d}"><from>{_m(rng.choice(ZONES))}</from>'
            f"<to>{_m(rng.choice(ZONES))}</to><source>{_m(endpoint())}</source>"
            f"<destination>{_m(endpoint(), endpoint())}</destination>"
            f"<source-user>{_m('any')}</source-user><category>{_m('any')}</category>"
            f"<application>{_m(rng.choice(APPS))}</application>"
            f"<service>{_m('application-default')}</service><action>{action}</action>"
            "</entry>"
        )
    return _ok(f"<rules>{''.join(out)}</rules>")


def generate_large_estate(
    root: Path,
    *,
    devices: int = 500,
    rules: int = 10000,
    seed: int = 42,
    store: MappingStore | None = None,
) -> list[str]:
    """Write the large-estate samples and scenario under `root`; return sample ids."""
    rng = random.Random(seed)  # noqa: S311 - deterministic test data, not security
    store = store or MappingStore.ephemeral(b"large-estate-generator-key-00000")
    generator = f"generate.py seed={seed} devices={devices} rules={rules}"
    responses: list[dict[str, object]] = []
    ids: list[str] = []

    def add(
        request: dict[str, str],
        xml: str,
        description: str,
        slug: str | None = None,
        also_get: bool = False,
    ) -> None:
        sid = str(
            add_sample(
                root,
                panos_version=VERSION,
                request=SampleRequest.model_validate(request),
                variant=VARIANT,
                xml=xml,
                source="synthetic",
                description=description,
                slug=slug,
                generator=generator,
                tags=["large", "generated"],
                store=store,
                force=True,
            )
        )
        ids.append(sid)
        responses.append({"request": request, "sample": sid})
        if also_get:
            responses.append({"request": {**request, "action": "get"}, "sample": sid})

    devices_xml, members = _devices(devices, root)
    add(
        {"type": "op", "cmd": c.show_devices_all()},
        devices_xml,
        f"{devices} generated managed firewalls",
    )
    add(
        {"type": "op", "cmd": c.show_devicegroups()},
        _devicegroups(members),
        "Device groups with the generated firewalls",
    )
    add(
        {"type": "config", "action": "show", "xpath": c.object_xpath("shared", "address")},
        _addresses(),
        f"{N_ADDRESSES} generated shared addresses",
        slug="address-shared",
        also_get=True,
    )
    add(
        {"type": "config", "action": "show", "xpath": c.object_xpath("shared", "address_group")},
        _groups(),
        "Generated static address groups",
        slug="address-group-shared",
        also_get=True,
    )
    for (scope, pos), share in RULE_SPLIT:
        count = round(rules * share)
        add(
            {"type": "config", "action": "show", "xpath": c.rulebase_xpath(scope, "security", pos)},  # type: ignore[arg-type]
            _rules(rng, scope, pos, count),
            f"{count} generated security {pos}-rules in {scope}",
            slug=f"security-rules-{scope.lower()}-{pos}",
            also_get=True,
        )

    scenario = {
        "name": "large-estate",
        "description": f"Baseline extended with {devices} firewalls and {rules} security rules "
        "(generated; git-ignored).",
        "panos_version": VERSION,
        "extends": "baseline",
        "responses": responses,
    }
    path = root / "scenarios" / "large-estate.json"
    path.write_text(json.dumps(scenario, indent=2) + "\n", "utf-8")
    return ids
