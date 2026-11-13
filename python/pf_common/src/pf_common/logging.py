"""Structured JSON logging.

One JSON object per line with the same core fields the Go services emit
(``ts``, ``level``, ``msg``, ``service``, ``version``). Request-scoped
fields such as ``request_id`` are bound with :func:`bind_context` and added
to every record logged while handling that request.
"""

from __future__ import annotations

import json
import logging
import sys
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any, TextIO

_context: ContextVar[dict[str, Any] | None] = ContextVar("pf_log_context", default=None)

_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warn": logging.WARNING,
    "warning": logging.WARNING,
    "error": logging.ERROR,
}

# Attributes of logging.LogRecord that are not user-supplied "extra" fields.
_RESERVED = frozenset(logging.makeLogRecord({}).__dict__) | {"message", "asctime", "taskName"}


def bind_context(**fields: Any) -> None:
    """Attach ``fields`` to every record logged in the current context."""
    current = _context.get() or {}
    _context.set({**current, **fields})


def clear_context() -> None:
    """Remove every bound field from the current context."""
    _context.set(None)


class JSONFormatter(logging.Formatter):
    """Formats records as single-line JSON objects."""

    def __init__(self, service: str, version: str) -> None:
        super().__init__()
        self._static = {"service": service, "version": version}

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(timespec="milliseconds"),
            "level": "WARN" if record.levelno == logging.WARNING else record.levelname,
            "msg": record.getMessage(),
            **self._static,
            "logger": record.name,
        }
        entry.update(_context.get() or {})
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                entry[key] = value
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str, ensure_ascii=False)


def configure_logging(
    service: str, version: str, level: str = "info", stream: TextIO | None = None
) -> None:
    """Route all logging, including uvicorn's, through the JSON formatter."""
    handler = logging.StreamHandler(stream if stream is not None else sys.stdout)
    handler.setFormatter(JSONFormatter(service, version))

    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(_LEVELS.get(level.lower(), logging.INFO))

    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uvicorn_logger = logging.getLogger(name)
        uvicorn_logger.handlers.clear()
        uvicorn_logger.propagate = True
    # Requests are logged once, with a request id, by the access-log middleware.
    logging.getLogger("uvicorn.access").disabled = True
