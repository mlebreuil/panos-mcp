"""stderr-only logging with secret redaction (stdout is the MCP stdio channel)."""

from __future__ import annotations

import logging
import re
import sys
from collections.abc import Iterable

MASK = "***"
_HEADER_RE = re.compile(r"(X-PAN-KEY\s*[:=]\s*)(\S+)", re.IGNORECASE)
_PARAM_RE = re.compile(r"((?:^|[?&\s])(?:key|password)=)([^&\s]+)", re.IGNORECASE)

LOGGER_NAME = "panos_mcp"


class RedactionFilter(logging.Filter):
    """Masks configured secrets and API key headers/params in every record."""

    def __init__(self, secrets: Iterable[str] = ()) -> None:
        super().__init__()
        self._secrets = [s for s in secrets if s]

    def redact(self, text: str) -> str:
        for secret in self._secrets:
            text = text.replace(secret, MASK)
        text = _HEADER_RE.sub(lambda m: m.group(1) + MASK, text)
        return _PARAM_RE.sub(lambda m: m.group(1) + MASK, text)

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        record.msg = self.redact(message)
        record.args = None
        if record.exc_info:
            formatted = logging.Formatter().formatException(record.exc_info)
            record.exc_text = self.redact(formatted)
            record.exc_info = None
        return True


def configure_logging(level: str, secrets: Iterable[str] = ()) -> logging.Logger:
    """Attach one stderr handler with redaction to the package logger."""
    logger = logging.getLogger(LOGGER_NAME)
    logger.handlers.clear()
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    handler.addFilter(RedactionFilter(secrets))
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    # httpx logs every request at INFO on the root logger; keep stderr quiet unless debugging.
    logging.getLogger("httpx").setLevel(logging.DEBUG if level == "DEBUG" else logging.WARNING)
    return logger


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"{LOGGER_NAME}.{name}")
