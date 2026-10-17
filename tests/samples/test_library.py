"""The committed sample library must be valid and sanitized (runs in CI)."""

from __future__ import annotations

from pathlib import Path

from panos_mcp.samples.cli import main
from panos_mcp.samples.library import validate_library


def test_library_is_valid(samples_root: Path) -> None:
    assert validate_library(samples_root) == []


def test_validate_cli_exit_code(samples_root: Path) -> None:
    assert main(["--samples-dir", str(samples_root), "validate"]) == 0
