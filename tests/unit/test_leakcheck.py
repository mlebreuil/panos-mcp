from __future__ import annotations

from panos_mcp.samples.sanitize.leakcheck import check_originals, lint


def test_originals_detected_with_token_boundaries() -> None:
    text = "<r><a>10.1.1.10</a><b>web-srv-01</b></r>"
    assert check_originals(text, {"10.1.1.1"}) == []
    assert check_originals(text, {"10.1.1.10", "web-srv-01", "ab"}) == ["10.1.1.10", "web-srv-01"]


def rules(text: str) -> set[str]:
    return {f.rule for f in lint(text)}


def test_lint_flags_each_rule() -> None:
    assert rules("<r><ip-netmask>8.8.8.8</ip-netmask></r>") == {"public-ipv4-not-documentation"}
    assert rules("<r><fqdn>www.corp.com</fqdn></r>") == {"domain-not-example"}
    assert rules("<r><mac>b4:0c:25:e0:12:34</mac></r>") == {"mac-not-documentation"}
    assert rules("<r><serial>007051000123456</serial></r>") == {"serial-not-forged"}
    assert rules("<r><phash>$1$abc</phash></r>") == {"secret-not-redacted"}
    assert rules("<r><description>mail jane@corp.com</description></r>") == {"email-not-example"}
    assert rules("<r><a>2a00:1450:4001::1</a></r>") == {"public-ipv6-not-documentation"}


def test_lint_accepts_forged_values() -> None:
    clean = (
        "<r><ip-netmask>192.0.2.10</ip-netmask><a>198.18.4.1</a><b>10.1.2.3</b>"
        "<netmask>255.255.255.0</netmask><w>10.0.0.0/0.0.255.255</w>"
        "<fqdn>app.example.com</fqdn><mac>00:00:5e:00:53:01</mac><serial>900000000001</serial>"
        "<phash>REDACTED</phash><description>user-001@example.com</description>"
        "<sw-version>11.1.4-h2</sw-version><v>2001:db8::1</v><t>2026/10/16 09:00:01</t></r>"
    )
    assert lint(clean) == []


def test_element_names_are_not_leaks() -> None:
    assert check_originals("<r><admin>user-001</admin></r>", {"admin"}) == []
    assert check_originals("<r><admin>admin</admin></r>", {"admin"}) == ["admin"]
