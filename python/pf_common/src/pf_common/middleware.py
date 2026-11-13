"""ASGI middleware shared by ParallelF Python services.

Written against the plain ASGI interface so it has no framework
dependency and wraps every response, including error responses.
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from pf_common.logging import bind_context, clear_context

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

REQUEST_ID_HEADER = "X-Request-ID"
_REQUEST_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{8,64}")
_PROBE_PATHS = frozenset({"/healthz", "/readyz"})

_SECURITY_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
    (b"cache-control", b"no-store"),
)

access_logger = logging.getLogger("pf.access")


def resolve_request_id(inbound: str | None) -> str:
    """Return a well-formed inbound request id, or a newly generated one."""
    if inbound and _REQUEST_ID_PATTERN.fullmatch(inbound):
        return inbound
    return str(uuid.uuid4())


class RequestContextMiddleware:
    """Assigns a request id, sets security headers and writes the access log.

    The request id is taken from a valid inbound ``X-Request-ID`` (the
    gateway forwards one) so a request can be followed across services. It
    is stored in ``scope["state"]["request_id"]`` and bound to the logging
    context for the duration of the request.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        inbound: str | None = None
        for key, value in scope.get("headers", []):
            if key == b"x-request-id":
                inbound = value.decode("latin-1")
                break
        request_id = resolve_request_id(inbound)

        state = scope.setdefault("state", {})
        state["request_id"] = request_id
        bind_context(request_id=request_id)

        status = 500
        managed = {b"x-request-id"} | {name for name, _ in _SECURITY_HEADERS}

        async def send_with_headers(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message["status"])
                headers = [
                    (k, v) for k, v in message.get("headers", []) if k.lower() not in managed
                ]
                headers.append((b"x-request-id", request_id.encode("latin-1")))
                headers.extend(_SECURITY_HEADERS)
                message = {**message, "headers": headers}
            await send(message)

        started = time.perf_counter()
        try:
            await self.app(scope, receive, send_with_headers)
        finally:
            path = str(scope.get("path", ""))
            if status >= 500:
                level = logging.ERROR
            elif path in _PROBE_PATHS:
                level = logging.DEBUG
            else:
                level = logging.INFO
            extra: dict[str, Any] = {
                "method": scope.get("method"),
                "path": path,
                "status": status,
                "duration_ms": round((time.perf_counter() - started) * 1000, 3),
            }
            subject = state.get("subject")
            if subject:
                extra["subject"] = subject
            access_logger.log(level, "http request", extra=extra)
            clear_context()
