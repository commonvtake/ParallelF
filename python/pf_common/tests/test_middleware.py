import asyncio
import io
import json
from typing import Any

import pytest

from pf_common.logging import configure_logging
from pf_common.middleware import (
    Message,
    Receive,
    RequestContextMiddleware,
    Scope,
    Send,
    resolve_request_id,
)


def _call(
    app: Any, *, path: str = "/x", headers: list[tuple[bytes, bytes]] | None = None
) -> tuple[list[Message], Scope]:
    scope: Scope = {"type": "http", "method": "GET", "path": path, "headers": headers or []}
    sent: list[Message] = []

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        sent.append(message)

    asyncio.run(RequestContextMiddleware(app)(scope, receive, send))
    return sent, scope


def _headers(message: Message) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for key, value in message["headers"]:
        out.setdefault(key.decode().lower(), []).append(value.decode())
    return out


async def _ok_app(scope: Scope, receive: Receive, send: Send) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": 201,
            "headers": [(b"content-type", b"application/json"), (b"x-request-id", b"from-app")],
        }
    )
    await send({"type": "http.response.body", "body": b"{}"})


def test_generates_request_id_and_sets_security_headers() -> None:
    sent, scope = _call(_ok_app)

    headers = _headers(sent[0])
    request_id = scope["state"]["request_id"]
    assert headers["x-request-id"] == [request_id], "exactly one id, the middleware's"
    assert len(request_id) == 36
    assert headers["x-content-type-options"] == ["nosniff"]
    assert headers["content-security-policy"] == ["default-src 'none'; frame-ancestors 'none'"]
    assert headers["content-type"] == ["application/json"]


def test_valid_inbound_request_id_is_kept() -> None:
    sent, scope = _call(_ok_app, headers=[(b"x-request-id", b"gateway-request-0001")])

    assert scope["state"]["request_id"] == "gateway-request-0001"
    assert _headers(sent[0])["x-request-id"] == ["gateway-request-0001"]


@pytest.mark.parametrize("bad", ["short", "has space in it", "x" * 65, "inject\r\nX-Evil: 1", ""])
def test_invalid_inbound_request_id_is_replaced(bad: str) -> None:
    assert resolve_request_id(bad) != bad
    assert resolve_request_id(None)


def test_access_log_records_status_and_request_id() -> None:
    stream = io.StringIO()
    configure_logging("svc", "v", "debug", stream)

    _, scope = _call(_ok_app, path="/api/v1/ai/info")

    records = [json.loads(line) for line in stream.getvalue().splitlines()]
    access = [r for r in records if r["msg"] == "http request"]
    assert len(access) == 1
    assert access[0]["status"] == 201
    assert access[0]["path"] == "/api/v1/ai/info"
    assert access[0]["request_id"] == scope["state"]["request_id"]
    assert access[0]["level"] == "INFO"


def test_failing_app_is_logged_as_error_and_exception_propagates() -> None:
    stream = io.StringIO()
    configure_logging("svc", "v", "info", stream)

    async def broken(scope: Scope, receive: Receive, send: Send) -> None:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        _call(broken)

    access = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert access[-1]["status"] == 500
    assert access[-1]["level"] == "ERROR"


def test_non_http_scopes_pass_through() -> None:
    seen: list[str] = []

    async def lifespan_app(scope: Scope, receive: Receive, send: Send) -> None:
        seen.append(scope["type"])

    async def receive() -> Message:
        return {}

    async def send(message: Message) -> None:
        return None

    asyncio.run(RequestContextMiddleware(lifespan_app)({"type": "lifespan"}, receive, send))
    assert seen == ["lifespan"]
