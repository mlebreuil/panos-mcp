from __future__ import annotations

import logging

import pytest

from panos_mcp.logging import configure_logging, get_logger


def test_secrets_masked(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("DEBUG", ["TESTKEY-DO-NOT-LEAK", "PW-DO-NOT-LEAK"])
    log = get_logger("t")
    log.info("key=%s", "TESTKEY-DO-NOT-LEAK")
    log.info("header X-PAN-KEY: abc123secret sent")
    log.info("url /api/?type=keygen&password=hunter2&user=admin")
    log.info("pw %s", "PW-DO-NOT-LEAK")
    try:
        raise RuntimeError("boom TESTKEY-DO-NOT-LEAK")
    except RuntimeError:
        log.exception("failed")
    captured = capsys.readouterr()
    assert captured.out == ""
    err = captured.err
    for secret in ("TESTKEY-DO-NOT-LEAK", "abc123secret", "hunter2", "PW-DO-NOT-LEAK"):
        assert secret not in err
    assert "***" in err
    assert "Traceback" in err


def test_stderr_only() -> None:
    logger = configure_logging("INFO")
    import sys

    assert all(
        isinstance(h, logging.StreamHandler) and h.stream is sys.stderr for h in logger.handlers
    )
