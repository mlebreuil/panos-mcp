"""Values the sanitizer never replaces: PAN-OS built-ins, enums and predefined objects.

Extend with `samples/keeplist.txt` (one value per line, `#` comments).
"""

from __future__ import annotations

from pathlib import Path

BUILTIN: frozenset[str] = frozenset(
    {
        # generic / enums
        "any",
        "none",
        "yes",
        "no",
        "default",
        "strict",
        "enable",
        "disable",
        "disabled",
        "allow",
        "deny",
        "drop",
        "reset-client",
        "reset-server",
        "reset-both",
        "alert",
        "block",
        "continue",
        "override",
        "pre",
        "post",
        "shared",
        "predefined",
        "panorama",
        "connected",
        "disconnected",
        "in sync",
        "out of sync",
        "synchronized",
        "unknown",
        "active",
        "passive",
        "standalone",
        "suspended",
        "initial",
        "non-functional",
        "ipv4",
        "ipv6",
        "nat64",
        "nptv6",
        "tcp",
        "udp",
        "sctp",
        "icmp",
        "ip-netmask",
        "ip-range",
        "ip-wildcard",
        "fqdn",
        "static",
        "dynamic",
        "dynamic-ip-and-port",
        "dynamic-ip",
        "static-ip",
        "bi-directional",
        "application-default",
        "localhost.localdomain",
        "vsys1",
        "vsys2",
        "vsys3",
        "trust",
        "untrust",
        "dmz",
        "intrazone-default",
        "interzone-default",
        "FIN",
        "ACT",
        "PEND",
        "OK",
        "FAIL",
        "success",
        "error",
        # predefined services
        "service-http",
        "service-https",
        # common predefined applications
        "ssl",
        "web-browsing",
        "dns",
        "ntp",
        "ping",
        "traceroute",
        "ssh",
        "telnet",
        "ftp",
        "smtp",
        "pop3",
        "imap",
        "ldap",
        "kerberos",
        "ms-rdp",
        "msrpc",
        "ms-ds-smb",
        "snmp",
        "syslog",
        "dhcp",
        "netbios-ns",
        "netbios-ss",
        "incomplete",
        "insufficient-data",
        "not-applicable",
        "unknown-tcp",
        "unknown-udp",
        "google-base",
        "office365-base",
        "paloalto-updates",
        "paloalto-wildfire-cloud",
        "ocsp",
        "http-video",
        "github-base",
        # url categories / threat values
        "malware",
        "phishing",
        "command-and-control",
        "grayware",
        "business-and-economy",
        "computer-and-internet-info",
        "news",
        "social-networking",
        "low",
        "medium",
        "high",
        "critical",
        "informational",
        "client-to-server",
        "server-to-client",
        # security profile names
        "default-profile",
    }
)


def load_keeplist(samples_root: Path | None) -> frozenset[str]:
    values = set(BUILTIN)
    if samples_root is not None:
        extra = samples_root / "keeplist.txt"
        if extra.is_file():
            for line in extra.read_text("utf-8").splitlines():
                value = line.split("#", 1)[0].strip()
                if value:
                    values.add(value)
    return frozenset(values)
