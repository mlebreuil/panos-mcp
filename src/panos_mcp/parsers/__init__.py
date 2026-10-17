"""XML response -> model parsers. Tolerant of missing optional elements."""

from __future__ import annotations

from typing import overload
from xml.etree.ElementTree import Element


@overload
def text(node: Element | None, path: str) -> str | None: ...
@overload
def text(node: Element | None, path: str, default: str) -> str: ...
@overload
def text(node: Element | None, path: str, default: None) -> str | None: ...


def text(node: Element | None, path: str, default: str | None = None) -> str | None:
    if node is None:
        return default
    value = node.findtext(path)
    if value is None:
        return default
    value = value.strip()
    return value if value else default


def members(node: Element | None, path: str) -> list[str]:
    """Texts of `<member>` children under `path` (e.g. `source` -> source/member)."""
    if node is None:
        return []
    container = node.find(path)
    if container is None:
        return []
    return [(m.text or "").strip() for m in container.findall("member") if (m.text or "").strip()]


def yes(value: str | None) -> bool:
    return (value or "").strip().lower() in ("yes", "true", "1")


def lines(node: Element | None) -> list[str]:
    if node is None:
        return []
    return [(n.text or "").strip() for n in node.iter("line") if (n.text or "").strip()]


def name_of(node: Element) -> str:
    return node.get("name") or ""
