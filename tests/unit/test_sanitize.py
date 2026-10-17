from __future__ import annotations

import ipaddress
import re
from xml.etree.ElementTree import tostring

import pytest
from defusedxml import ElementTree as SafeET

from panos_mcp.samples.sanitize.forge import (
    DOC_V4,
    Forger,
    MappingStore,
    sanitize_tree,
)
from panos_mcp.samples.sanitize.keeplist import BUILTIN

KEY = b"k" * 32


def forger(mode: str = "full", key: bytes = KEY) -> Forger:
    return Forger(MappingStore.ephemeral(key), BUILTIN, mode)  # type: ignore[arg-type]


def in_doc(addr: str) -> bool:
    return any(ipaddress.ip_address(addr) in net for net in DOC_V4)


def test_public_ipv4_to_documentation_range_preserving_prefix() -> None:
    f = forger()
    host = f.ip_token("8.8.8.8")
    assert in_doc(host) and host.endswith(".8")
    net = f.ip_token("8.8.8.0/24")
    assert net.endswith("/24") and in_doc(net.split("/")[0])
    assert ipaddress.ip_address(host) in ipaddress.ip_network(net)
    rng = f.ip_token("8.8.8.10-8.8.8.20")
    lo, hi = rng.split("-")
    assert int(ipaddress.ip_address(hi)) - int(ipaddress.ip_address(lo)) == 10


def test_rfc1918_stays_in_block_with_subnet_membership() -> None:
    f = forger()
    for real, block in (
        ("10.20.5.6", "10.0.0.0/8"),
        ("172.20.1.1", "172.16.0.0/12"),
        ("192.168.50.10", "192.168.0.0/16"),
    ):
        forged = f.ip_token(real)
        assert ipaddress.ip_address(forged) in ipaddress.ip_network(block)
        assert forged != real
    net = f.ip_token("10.20.0.0/16")
    assert ipaddress.ip_address(f.ip_token("10.20.5.6")) in ipaddress.ip_network(net)


def test_special_ranges() -> None:
    f = forger()
    assert ipaddress.ip_address(f.ip_token("100.70.1.1")) in ipaddress.ip_network("100.64.0.0/10")
    assert f.ip_token("127.0.0.1") == "127.0.0.1"
    assert f.ip_token("169.254.1.1") == "169.254.1.1"
    assert f.ip_token("224.0.0.5") == "224.0.0.5"


def test_ipv6() -> None:
    f = forger()
    assert ipaddress.ip_address(f.ip_token("2a00:1450:4001::1")) in ipaddress.ip_network(
        "2001:db8::/32"
    )
    assert ipaddress.ip_address(f.ip_token("fd12:3456::1")) in ipaddress.ip_network("fd00::/8")


def test_fqdn_label_count_preserved() -> None:
    f = forger()
    out = f.fqdn("www.corp.acme.com")
    assert out.endswith((".example.com", ".example.net"))
    assert out.count(".") == 3


def test_name_shape_preserved() -> None:
    f = forger()
    out = f.name("PAR-DC1-web-srv-01")
    assert out != "PAR-DC1-web-srv-01"
    assert re.fullmatch(r"[A-Z]{3}-[A-Z]{2}\d-[a-z]{3}-[a-z]{3}-\d{2}", out)


def test_hostname_serial_mac_user_email_text_url() -> None:
    f = forger()
    assert re.fullmatch(r"fw-[a-z]{3}-\d{2}", f.hostname("paris-edge-fw1"))
    assert re.fullmatch(r"panorama-\d{2}", f.hostname("corp-panorama-01"))
    serial = f.serial("007051000123456")
    assert serial.startswith("9") and len(serial) == 15 and serial.isdigit()
    assert f.mac("b4:0c:25:e0:12:34").startswith("00:00:5e:00:53:")
    assert re.fullmatch(r"user-\d{3}", f.user("jdoe"))
    assert f.user("CORP\\jdoe").startswith("EXAMPLE\\user-")
    assert re.fullmatch(r"user-\d{3}@example\.com", f.email("jane.doe@corp.com"))
    text = f.text("Contact Jane for access to the payroll servers")
    assert "Jane" not in text and abs(len(text) - 46) < 5
    assert f.url("https://intranet.corp.com/hr/payroll?id=1").startswith("https://site-")


def test_secrets_redacted() -> None:
    xml = (
        "<response><result><entry name='admin'><phash>$1$abcdef</phash></entry>"
        "<key>LUFRPT1abcdef==</key><pre-shared-key>s3cret</pre-shared-key></result></response>"
    )
    f = forger()
    root = sanitize_tree(SafeET.fromstring(xml), f)
    out = tostring(root, encoding="unicode")
    assert "abcdef" not in out and "s3cret" not in out
    assert out.count("REDACTED") == 3


def test_keeplist_values_unchanged() -> None:
    f = forger()
    for value in (
        "any",
        "application-default",
        "ssl",
        "web-browsing",
        "service-http",
        "default",
        "strict",
        "allow",
        "deny",
    ):
        assert f.name(value) == value


def test_deterministic_and_key_dependent() -> None:
    a, b, c = forger(), forger(), forger(key=b"z" * 32)
    assert a.name("web-srv-01") == b.name("web-srv-01")
    assert a.ip_token("8.8.4.4") == b.ip_token("8.8.4.4")
    assert a.name("web-srv-01") != c.name("web-srv-01") or a.ip_token("8.8.4.4") != c.ip_token(
        "8.8.4.4"
    )


def test_consistent_across_files() -> None:
    f = forger()
    x1 = "<r><entry name='web-srv-01'><ip-netmask>203.0.114.5</ip-netmask></entry></r>"
    x2 = "<r><member>web-srv-01</member><src>203.0.114.5</src></r>"
    t1 = tostring(sanitize_tree(SafeET.fromstring(x1), f), encoding="unicode")
    t2 = tostring(sanitize_tree(SafeET.fromstring(x2), f), encoding="unicode")
    forged_name = f.store.mapping["name"]["web-srv-01"]
    assert forged_name in t1 and forged_name in t2
    forged_ip = f.ip_token("203.0.114.5")
    assert forged_ip in t1 and forged_ip in t2


def test_entry_name_equal_to_serial_forged_as_serial() -> None:
    f = forger()
    xml = "<r><devices><entry name='007051000123456'><serial>007051000123456</serial></entry></devices></r>"
    out = tostring(sanitize_tree(SafeET.fromstring(xml), f), encoding="unicode")
    forged = f.serial("007051000123456")
    assert out.count(forged) == 2


@pytest.mark.parametrize("value", ["10.20.0.0/16", "Branch-DG", "Fictional comment"])
def test_synthetic_mode_keeps_fictional_values(value: str) -> None:
    f = forger("synthetic")
    xml = f"<r><member>{value}</member><description>{value}</description></r>"
    out = tostring(sanitize_tree(SafeET.fromstring(xml), f), encoding="unicode")
    assert out.count(value) == 2


def test_synthetic_mode_still_fixes_lint_failures() -> None:
    f = forger("synthetic")
    xml = (
        "<r><ip-netmask>8.8.8.8</ip-netmask><serial>007051000123456</serial>"
        "<mac>b4:0c:25:e0:12:34</mac><description>mail jane@corp.com</description>"
        "<phash>x</phash></r>"
    )
    out = tostring(sanitize_tree(SafeET.fromstring(xml), f), encoding="unicode")
    for real in ("8.8.8.8", "007051000123456", "b4:0c:25", "corp.com"):
        assert real not in out
    assert "REDACTED" in out


def test_mapping_dir_refused_inside_repo() -> None:
    from pathlib import Path

    from panos_mcp.samples.sanitize.forge import MappingDirError

    repo_dir = Path(__file__).resolve().parents[2] / "samples" / "not-ignored-mapping"
    with pytest.raises(MappingDirError):
        MappingStore.open(repo_dir)
    assert not repo_dir.exists()


def test_whole_block_prefix_is_not_a_leak() -> None:
    f = forger()
    assert f.ip_token("10.0.0.0/8") == "10.0.0.0/8"
    assert "10.0.0.0" not in f.originals
    assert f.ip_token("192.168.0.0/16") == "192.168.0.0/16"


def test_dynamic_group_filter_tags_forged_consistently() -> None:
    f = forger()
    xml = (
        "<r><entry name='web'><color>color3</color></entry>"
        "<entry name='dyn'><dynamic><filter>'web' and 'prod'</filter></dynamic></entry></r>"
    )
    out = tostring(sanitize_tree(SafeET.fromstring(xml), f), encoding="unicode")
    forged_web = f.store.mapping["name"]["web"]
    assert f"'{forged_web}' and '" in out and "'web'" not in out and "'prod'" not in out
