"""The Python service behind the gateway."""

from __future__ import annotations

from collections.abc import Callable

import httpx

ContractCheck = Callable[[str, object], None]


def test_ai_info_reports_capabilities_as_not_implemented(
    gateway: httpx.Client, viewer_headers: dict[str, str], contract: ContractCheck
) -> None:
    response = gateway.get("/api/v1/ai/info", headers=viewer_headers)

    assert response.status_code == 200
    info = response.json()
    contract("AIInfo", info)
    assert info["service"] == "pf-aid"
    assert info["capabilities"], "the service lists its planned capabilities"
    assert {capability["status"] for capability in info["capabilities"]} == {"not_implemented"}


def test_request_id_reaches_the_python_service(
    gateway: httpx.Client, viewer_headers: dict[str, str]
) -> None:
    # A route that does not exist on pf-aid: the 404 body is written by the
    # Python service and must carry the id the gateway forwarded.
    response = gateway.get(
        "/api/v1/ai/no-such-route",
        headers={**viewer_headers, "X-Request-ID": "integration-test-ai-01"},
    )

    assert response.status_code == 404
    assert response.headers["x-request-id"] == "integration-test-ai-01"
    assert response.json()["request_id"] == "integration-test-ai-01"
