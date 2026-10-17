"""Type-preserving, keyed, consistent replacement of sensitive values (research.md R8).

The same real value always maps to the same forged value (HMAC key + persistent
mapping), so references between rules, groups and objects stay consistent.

Modes:
- ``full`` (documentation / lab-capture samples): every sensitive value is forged.
- ``synthetic`` (hand-authored samples that are fictional by construction): names,
  free text and private addresses are kept; secrets are redacted and anything that
  would fail the CI lint (public IPs, MACs, serials, emails, domains) is forged.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal
from xml.etree.ElementTree import Element

from panos_mcp.samples.sanitize.classify import (
    EMAIL_RE,
    IPV4_TOKEN_RE,
    MAC_RE,
    URL_RE,
    Kind,
    classify_element,
    parse_ip_like,
)

Mode = Literal["full", "synthetic"]
REDACTED = "REDACTED"
DEFAULT_MAPPING_DIR = Path.home() / ".config" / "panos-mcp" / "sanitize"

DOC_V4 = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
)
DOC_V6 = ipaddress.ip_network("2001:db8::/32")
CGNAT = ipaddress.ip_network("100.64.0.0/10")
DOC_MAC_PREFIX = "00:00:5e:00:53:"
EXAMPLE_DOMAINS = ("example.com", "example.net", "example.org")

WORDS = (
    "alpha",
    "bravo",
    "cedar",
    "delta",
    "ember",
    "fjord",
    "gamma",
    "harbor",
    "indigo",
    "juniper",
    "kepler",
    "lumen",
    "maple",
    "nimbus",
    "onyx",
    "pixel",
    "quartz",
    "raven",
    "sierra",
    "tundra",
    "umber",
    "vertex",
    "willow",
    "xenon",
    "yonder",
    "zephyr",
)
SENTENCES = (
    "Forged description for sample data.",
    "Neutral placeholder comment text.",
    "Sample entry used for testing only.",
    "Generic note replaced by the sanitizer.",
)


class MappingDirError(Exception):
    pass


def _git_tracks(path: Path) -> bool:
    """True if `path` is inside a git work tree and NOT git-ignored."""
    for parent in [path, *path.parents]:
        if (parent / ".git").exists():
            result = subprocess.run(  # noqa: S603 - fixed argv
                ["git", "-C", str(parent), "check-ignore", "-q", str(path)],  # noqa: S607
                capture_output=True,
                check=False,
            )
            return result.returncode != 0
    return False


@dataclass
class MappingStore:
    """HMAC key + real->forged mapping, stored outside the repository."""

    directory: Path
    key: bytes = b""
    mapping: dict[str, dict[str, str]] = field(default_factory=dict)
    persistent: bool = True

    @classmethod
    def open(cls, directory: Path | None = None) -> MappingStore:
        directory = (directory or DEFAULT_MAPPING_DIR).expanduser().resolve()
        if _git_tracks(directory):
            raise MappingDirError(
                f"{directory} is inside a git repository and not ignored; "
                "the sanitization key and mapping must never be committed"
            )
        directory.mkdir(parents=True, exist_ok=True)
        key_file = directory / "sanitize.key"
        if not key_file.exists():
            key_file.write_text(secrets.token_hex(32), "utf-8")
            key_file.chmod(0o600)
        store = cls(directory=directory, key=bytes.fromhex(key_file.read_text("utf-8").strip()))
        map_file = directory / "mapping.json"
        if map_file.exists():
            store.mapping = json.loads(map_file.read_text("utf-8"))
        return store

    @classmethod
    def ephemeral(cls, key: bytes) -> MappingStore:
        """In-memory store (tests)."""
        return cls(directory=Path("/nonexistent"), key=key, persistent=False)

    def save(self) -> None:
        if not self.persistent:
            return
        path = self.directory / "mapping.json"
        path.write_text(json.dumps(self.mapping, indent=1, sort_keys=True), "utf-8")
        path.chmod(0o600)

    def digest(self, *parts: str) -> int:
        mac = hmac.new(self.key, "\x1f".join(parts).encode(), hashlib.sha256).digest()
        return int.from_bytes(mac[:8], "big")


class Forger:
    def __init__(self, store: MappingStore, keep: frozenset[str], mode: Mode = "full") -> None:
        self.store = store
        self.keep = keep
        self.mode = mode
        self.originals: set[str] = set()

    # ------------------------------------------------------------------ mapping core

    def _mapped(self, kind: str, real: str, make: Callable[[int], str]) -> str:
        table = self.store.mapping.setdefault(kind, {})
        if real in table:
            forged = table[real]
        else:
            used = set(table.values())
            attempt = 0
            forged = make(attempt)
            while forged in used and attempt < 50:
                attempt += 1
                forged = make(attempt)
            table[real] = forged
        if forged != real:
            self.originals.add(real)
        return forged

    def _num(self, *parts: str) -> int:
        return self.store.digest(*parts)

    # ------------------------------------------------------------------ IP addresses

    def ip_token(self, value: str) -> str:
        """Forge an address, prefix, `a-b` range or `addr/mask` wildcard."""
        stripped = value.strip()
        if "-" in stripped and stripped.count("-") == 1 and parse_ip_like(stripped):
            left, right = stripped.split("-")
            a, b = self._addr(left), self._addr(right)
            if int(ipaddress.ip_address(a)) > int(ipaddress.ip_address(b)):
                a, b = b, a
            return f"{a}-{b}"
        if "/" in stripped:
            addr, suffix = stripped.split("/", 1)
            forged = self._addr(addr)
            if suffix.isdigit():
                original = ipaddress.ip_network(stripped, strict=False)
                if str(original.network_address) == ipaddress.ip_address(addr).compressed:
                    # a network prefix stays a valid network
                    result = str(ipaddress.ip_network(f"{forged}/{suffix}", strict=False))
                    if result == str(original):
                        # prefix covers the whole forging block (e.g. 10.0.0.0/8): nothing
                        # identifying to hide, and the network address is not a leak
                        self.originals.discard(addr)
                    return result
            return f"{forged}/{suffix}"  # interface address or wildcard mask
        return self._addr(stripped)

    def _addr(self, value: str) -> str:
        addr = ipaddress.ip_address(value.strip())
        if isinstance(addr, ipaddress.IPv4Address):
            return str(self._v4(addr))
        return str(self._v6(addr))

    def _octet(self, ns: str, parent: str, value: int, modulo: int, base: int = 0) -> int:
        forged = self._mapped(
            f"octet:{ns}:{parent}",
            str(value),
            lambda attempt: str(base + (self._num(ns, parent, str(value), str(attempt)) % modulo)),
        )
        return int(forged)

    def _v4(self, addr: ipaddress.IPv4Address) -> ipaddress.IPv4Address:
        if any(addr in net for net in DOC_V4) or not _v4_sensitive(addr):
            return addr
        a, b, c, d = (int(x) for x in str(addr).split("."))
        is_private = addr.is_private and addr not in CGNAT
        if self.mode == "synthetic" and is_private:
            return addr
        if addr in ipaddress.ip_network("10.0.0.0/8"):
            nb = self._octet("10", "", b, 256)
            out = (10, nb, self._octet("10", str(nb), c, 256), d)
        elif addr in ipaddress.ip_network("172.16.0.0/12"):
            nb = self._octet("172", "", b, 16, 16)
            out = (172, nb, self._octet("172", str(nb), c, 256), d)
        elif addr in ipaddress.ip_network("192.168.0.0/16"):
            out = (192, 168, self._octet("192.168", "", c, 256), d)
        elif addr in CGNAT:
            nb = self._octet("cgnat", "", b, 64, 64)
            out = (100, nb, self._octet("cgnat", str(nb), c, 256), d)
        else:
            nb = self._octet("pub", "", a * 256 + b, 2, 18)
            out = (198, nb, self._octet("pub", f"{a}.{b}", c, 256), d)
        forged = ipaddress.IPv4Address(".".join(str(x) for x in out))
        if forged != addr:
            self.originals.add(str(addr))
        return forged

    def _v6(self, addr: ipaddress.IPv6Address) -> ipaddress.IPv6Address:
        if addr in DOC_V6 or addr.is_link_local or addr.is_loopback or addr.is_multicast:
            return addr
        if addr.is_unspecified:
            return addr
        ula = addr in ipaddress.ip_network("fc00::/7")
        if self.mode == "synthetic" and ula:
            return addr
        value = int(addr)
        upper48, upper64, lower64 = value >> 80, value >> 64, value & ((1 << 64) - 1)
        h48 = self._num("v6-48", str(upper48)) & 0xFFFF
        h64 = self._num("v6-64", str(upper64)) & 0xFFFF
        low = self._num("v6-low", str(lower64)) & ((1 << 64) - 1)
        prefix = 0xFD00_0000 if ula else 0x2001_0DB8
        forged = ipaddress.IPv6Address((prefix << 96) | (h48 << 80) | (h64 << 64) | low)
        self.originals.add(str(addr))
        return forged

    # ------------------------------------------------------------------ other kinds

    def name(self, real: str) -> str:
        if self.mode == "synthetic" or self._keep(real):
            return real
        return self._mapped("name", real, lambda attempt: _shape_name(real, self, attempt))

    def hostname(self, real: str) -> str:
        if self.mode == "synthetic" or self._keep(real):
            return real

        def make(attempt: int) -> str:
            n = self._num("host", real, str(attempt))
            if "panorama" in real.lower():
                return f"panorama-{n % 100:02d}"
            site = WORDS[n % len(WORDS)][:3]
            return f"fw-{site}-{(n // 7) % 100:02d}"

        return self._mapped("hostname", real, make)

    def serial(self, real: str) -> str:
        if real.startswith("9") or not real.strip():
            return real
        length = max(len(real), 8)

        def make(attempt: int) -> str:
            digits = str(self._num("serial", real, str(attempt))).rjust(length, "0")
            return "9" + digits[-(length - 1) :]

        return self._mapped("serial", real, make)

    def mac(self, real: str) -> str:
        if real.lower().startswith(DOC_MAC_PREFIX):
            return real
        return self._mapped(
            "mac",
            real.lower(),
            lambda attempt: (
                DOC_MAC_PREFIX + f"{self._num('mac', real.lower(), str(attempt)) % 256:02x}"
            ),
        )

    def user(self, real: str) -> str:
        if self.mode == "synthetic" or self._keep(real) or not real.strip():
            return real
        domain = ""
        if "\\" in real:
            domain = "EXAMPLE\\"
        table = self.store.mapping.setdefault("user", {})
        return self._mapped(
            "user", real, lambda attempt: f"{domain}user-{len(table) + 1 + attempt:03d}"
        )

    def email(self, real: str) -> str:
        domain = real.rsplit("@", 1)[-1].lower()
        if domain in EXAMPLE_DOMAINS or domain.endswith(".test"):
            return real
        table = self.store.mapping.setdefault("email", {})
        return self._mapped(
            "email", real, lambda attempt: f"user-{len(table) + 1 + attempt:03d}@example.com"
        )

    def fqdn(self, real: str) -> str:
        lower = real.lower().rstrip(".")
        if lower.endswith(EXAMPLE_DOMAINS) or lower.endswith(".test") or self._keep(real):
            return real

        def make(attempt: int) -> str:
            labels = lower.split(".")
            n = self._num("fqdn", lower, str(attempt))
            if len(labels) == 1:
                return WORDS[n % len(WORDS)]
            if len(labels) == 2:
                return f"{WORDS[n % len(WORDS)]}.test"
            head = [
                "*" if label == "*" else WORDS[(n >> (5 * i)) % len(WORDS)]
                for i, label in enumerate(labels[:-2])
            ]
            return ".".join([*head, EXAMPLE_DOMAINS[n % 2]])

        return self._mapped("fqdn", lower, make)

    def text(self, real: str) -> str:
        if self.mode == "synthetic" or not real.strip():
            return self.scan(real)

        def make(attempt: int) -> str:
            sentence = SENTENCES[self._num("text", real, str(attempt)) % len(SENTENCES)]
            if len(real) > len(sentence):
                sentence = (sentence + " ") * (len(real) // (len(sentence) + 1) + 1)
            return sentence[: max(len(real), 12)].rstrip()

        return self._mapped("text", real, make)

    def url(self, real: str) -> str:
        if self.mode == "synthetic":
            return self.scan(real)

        def make(attempt: int) -> str:
            scheme, rest = ("", real)
            if "://" in real:
                scheme, rest = real.split("://", 1)
                scheme += "://"
            path = rest.split("?", 1)[0].split("/")[1:]
            n = self._num("url", real, str(attempt))
            segments = "/".join(f"p{i + 1}" for i, _ in enumerate(path) if _)
            host = f"site-{n % 100:02d}.example.com"
            return f"{scheme}{host}" + (f"/{segments}" if segments else "")

        return self._mapped("url", real, make)

    def scan(self, text: str) -> str:
        """Replace embedded IPs, emails, MACs and URLs in otherwise unclassified text."""

        def ipv4(match: re.Match[str]) -> str:
            token = match.group(0)
            base = token.split("/")[0]
            if _looks_like_mask(base):
                return token
            try:
                return self.ip_token(token)
            except ValueError:
                return token

        out = EMAIL_RE.sub(lambda m: self.email(m.group(0)), text)
        if self.mode == "full":
            out = URL_RE.sub(lambda m: self.url(m.group(0)), out)
        out = MAC_RE.sub(lambda m: self.mac(m.group(0)), out)
        return IPV4_TOKEN_RE.sub(ipv4, out)

    def _keep(self, value: str) -> bool:
        return value in self.keep or value.isdigit()

    # ------------------------------------------------------------------ dispatch

    def value(self, kind: Kind, text: str) -> str:
        match kind:
            case Kind.SECRET:
                if text.strip() and text != REDACTED:
                    self.originals.add(text)
                    return REDACTED
                return text
            case Kind.IP:
                return self.ip_token(text)
            case Kind.FQDN:
                return self.fqdn(text)
            case Kind.NAME:
                return self.name(text)
            case Kind.HOSTNAME:
                return self.hostname(text)
            case Kind.SERIAL:
                return self.serial(text)
            case Kind.MAC:
                return self.mac(text)
            case Kind.USER:
                return self.user(text)
            case Kind.EMAIL:
                return self.email(text)
            case Kind.TEXT:
                return self.text(text)
            case Kind.URL:
                return self.url(text)
            case Kind.KEEP:
                return text
            case Kind.SCAN:
                return self.scan(text)
            case Kind.FILTER:
                return _QUOTED_RE.sub(lambda m: f"'{self.name(m.group(1))}'", text)


def _v4_sensitive(addr: ipaddress.IPv4Address) -> bool:
    return not (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
        or str(addr) == "255.255.255.255"
    )


def _looks_like_mask(value: str) -> bool:
    try:
        bits = int(ipaddress.IPv4Address(value))
    except ValueError:
        return False
    inverted = bits ^ 0xFFFFFFFF
    return (
        bits == 0
        or ((bits | (bits - 1)) & 0xFFFFFFFF) == 0xFFFFFFFF
        or (inverted & (inverted + 1)) == 0
    )


_TOKEN_RE = re.compile(r"[A-Za-z]+|\d+|[^A-Za-z\d]+")
_QUOTED_RE = re.compile(r"'([^']+)'")


def _shape_name(real: str, forger: Forger, attempt: int) -> str:
    out: list[str] = []
    for i, token in enumerate(_TOKEN_RE.findall(real)):
        n = forger._num("name", real, str(i), str(attempt))
        if token.isdigit():
            out.append(str(n % (10 ** len(token))).zfill(len(token)))
        elif token.isalpha():
            word = WORDS[n % len(WORDS)]
            while len(word) < len(token):
                word += WORDS[(n // 31 + len(word)) % len(WORDS)]
            word = word[: len(token)]
            if token.isupper():
                word = word.upper()
            elif token[0].isupper():
                word = word.capitalize()
            out.append(word)
        else:
            out.append(token)
    return "".join(out)


# --------------------------------------------------------------------------- tree


def sanitize_tree(root: Element, forger: Forger) -> Element:
    """Sanitize an XML response in place; forger.originals collects replaced values."""
    text_kinds: dict[str, Kind] = {}
    for node in root.iter():
        if node.text and node.text.strip():
            kind = classify_element(node.tag, node.text)
            if kind in (Kind.SERIAL, Kind.HOSTNAME, Kind.NAME):
                text_kinds.setdefault(node.text.strip(), kind)

    for node in root.iter():
        for attr, value in list(node.attrib.items()):
            node.set(attr, _attr_value(attr, value, forger, text_kinds))
        if node.text and node.text.strip():
            kind = classify_element(node.tag, node.text)
            stripped = node.text.strip()
            forged = forger.value(kind, stripped)
            node.text = node.text.replace(stripped, forged) if forged != stripped else node.text
    return root


def _attr_value(attr: str, value: str, forger: Forger, text_kinds: dict[str, Kind]) -> str:
    if attr == "name":
        kind = text_kinds.get(value, Kind.NAME)
        if kind is Kind.NAME and parse_ip_like(value):
            kind = Kind.IP
        return forger.value(kind, value)
    if attr == "loc":
        return forger.value(Kind.NAME, value)
    if attr == "admin":
        return forger.value(Kind.USER, value)
    if attr in ("serial", "target"):
        return forger.value(Kind.SERIAL, value)
    return forger.value(Kind.SCAN, value)
