"""FR-006: the server opens no network listener (stdio only)."""

from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest

psutil = pytest.importorskip("psutil")


def test_no_listening_sockets() -> None:
    env = {**os.environ, "PANOS_MCP_SAMPLES_SCENARIO": "baseline"}
    proc = subprocess.Popen(
        [sys.executable, "-m", "panos_mcp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    try:
        time.sleep(1.5)
        assert proc.poll() is None, proc.stderr.read() if proc.stderr else ""
        try:
            connections = psutil.Process(proc.pid).net_connections(kind="inet")
        except psutil.AccessDenied:
            pytest.skip("not permitted to inspect process sockets on this platform")
        listening = [c for c in connections if c.status == psutil.CONN_LISTEN]
        assert listening == []
    finally:
        proc.terminate()
        proc.wait(timeout=5)
