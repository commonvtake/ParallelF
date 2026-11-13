"""Tests for the FastAPI application factory."""

from typing import Annotated

from fastapi import Depends
from fastapi.testclient import TestClient
from pydantic import BaseModel, Field

from pf_common.auth import InvalidTokenError, Principal
from pf_common.problems import PROBLEM_MEDIA_TYPE, ProblemError
from pf_common.web import create_app, require_principal


class FakeVerifier:
    def verify(self, token: str) -> Principal:
        if token != "good":
            raise InvalidTokenError("signature mismatch for kid=secret-kid")
        return Principal(subject="user-1", username="owner", roles=("owner",))


class Widget(BaseModel):
    name: str = Field(min_length=1)


async def _database_ok() -> None:
    return None


async def _database_down() -> None:
    raise ConnectionError("dial tcp 10.0.0.5:5432: refused")


def make_client(*, database_up: bool = True) -> TestClient:
    app = create_app(
        service="pf-test",
        version="1.0.0",
        title="Test service",
        verifier=FakeVerifier(),
        checks={"postgres": _database_ok if database_up else _database_down},
    )

    @app.get("/secure")
    def secure(principal: Annotated[Principal, Depends(require_principal)]) -> dict[str, str]:
        return {"subject": principal.subject}

    @app.post("/widgets")
    def create_widget(widget: Widget) -> Widget:
        return widget

    @app.get("/teapot")
    def teapot() -> None:
        raise ProblemError(418, "teapot", "I am a teapot", "Short and stout.")

    @app.get("/crash")
    def crash() -> None:
        raise RuntimeError("database password is hunter2")

    return TestClient(app, raise_server_exceptions=False)


def test_healthz_is_public_and_carries_request_id() -> None:
    response = make_client().get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "pf-test", "version": "1.0.0"}
    assert len(response.headers["x-request-id"]) == 36
    assert response.headers["x-content-type-options"] == "nosniff"


def test_readyz_reflects_dependency_state_without_leaking_detail() -> None:
    ready = make_client().get("/readyz")
    assert ready.status_code == 200
    assert ready.json()["checks"] == {"postgres": "ok"}

    not_ready = make_client(database_up=False).get("/readyz")
    assert not_ready.status_code == 503
    assert not_ready.json() == {
        "status": "unavailable",
        "service": "pf-test",
        "version": "1.0.0",
        "checks": {"postgres": "unavailable"},
    }
    assert "10.0.0.5" not in not_ready.text


def test_authenticated_route_accepts_valid_token() -> None:
    response = make_client().get("/secure", headers={"Authorization": "Bearer good"})

    assert response.status_code == 200
    assert response.json() == {"subject": "user-1"}


def test_missing_or_invalid_token_is_a_401_problem() -> None:
    client = make_client()

    for headers in ({}, {"Authorization": "Bearer bad"}, {"Authorization": "Basic Zm9v"}):
        response = client.get("/secure", headers=headers)

        assert response.status_code == 401
        assert response.headers["content-type"].startswith(PROBLEM_MEDIA_TYPE)
        assert response.headers["www-authenticate"].startswith("Bearer")
        body = response.json()
        assert body["type"] == "https://parallelf.dev/problems/unauthorized"
        assert body["status"] == 401
        assert body["instance"] == "/secure"
        assert body["request_id"] == response.headers["x-request-id"]
        assert "secret-kid" not in response.text


def test_inbound_request_id_is_propagated() -> None:
    response = make_client().get("/healthz", headers={"X-Request-ID": "gateway-request-0001"})

    assert response.headers["x-request-id"] == "gateway-request-0001"


def test_unknown_route_and_wrong_method_are_problems() -> None:
    client = make_client()

    missing = client.get("/nope")
    assert missing.status_code == 404
    assert missing.json()["type"] == "https://parallelf.dev/problems/not-found"

    wrong_method = client.delete("/healthz")
    assert wrong_method.status_code == 405
    assert wrong_method.json()["type"] == "https://parallelf.dev/problems/method-not-allowed"
    assert wrong_method.headers["content-type"].startswith(PROBLEM_MEDIA_TYPE)


def test_validation_errors_list_fields() -> None:
    response = make_client().post("/widgets", json={"name": ""})

    assert response.status_code == 422
    body = response.json()
    assert body["type"] == "https://parallelf.dev/problems/validation"
    assert body["errors"][0]["field"] == "name"


def test_problem_error_is_rendered() -> None:
    response = make_client().get("/teapot")

    assert response.status_code == 418
    assert response.json()["title"] == "I am a teapot"
    assert response.json()["detail"] == "Short and stout."


def test_unhandled_exception_is_a_generic_500_problem() -> None:
    response = make_client().get("/crash")

    assert response.status_code == 500
    body = response.json()
    assert body["type"] == "https://parallelf.dev/problems/internal"
    assert body["request_id"] == response.headers["x-request-id"]
    assert "hunter2" not in response.text


def test_framework_docs_are_disabled() -> None:
    client = make_client()
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404
