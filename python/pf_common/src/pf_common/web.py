"""FastAPI application factory for ParallelF services.

``create_app`` returns an application with the platform conventions already
applied: request ids, structured access logs, problem+json errors, health
endpoints and bearer-token authentication via :func:`require_principal`.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from pf_common.auth import InvalidTokenError, Principal, TokenVerifier, bearer_token
from pf_common.health import HealthCheck, HealthResponse, run_checks
from pf_common.middleware import REQUEST_ID_HEADER, RequestContextMiddleware
from pf_common.problems import (
    PROBLEM_MEDIA_TYPE,
    FieldError,
    ProblemError,
    internal,
    not_found,
    unauthorized,
)

logger = logging.getLogger(__name__)

_HTTP_SLUGS = {
    400: ("bad-request", "Bad request"),
    403: ("forbidden", "Permission denied"),
    405: ("method-not-allowed", "Method not allowed"),
    413: ("payload-too-large", "Payload too large"),
    415: ("unsupported-media-type", "Unsupported media type"),
}


def _request_id(request: Request) -> str | None:
    value = getattr(request.state, "request_id", None)
    return value if isinstance(value, str) else None


def _problem_response(request: Request, error: ProblemError) -> JSONResponse:
    request_id = _request_id(request)
    problem = error.to_problem(instance=request.url.path, request_id=request_id)
    headers = dict(error.headers)
    if request_id:
        # Also set here: the 500 handler runs outside the request middleware.
        headers[REQUEST_ID_HEADER] = request_id
    return JSONResponse(
        problem.model_dump(exclude_none=True),
        status_code=error.status,
        media_type=PROBLEM_MEDIA_TYPE,
        headers=headers,
    )


async def _handle_problem(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, ProblemError)  # noqa: S101 - registered for this type only
    return _problem_response(request, exc)


async def _handle_http_exception(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, StarletteHTTPException)  # noqa: S101
    if exc.status_code == 404:
        return _problem_response(request, not_found())
    slug, title = _HTTP_SLUGS.get(exc.status_code, ("http-error", "Request failed"))
    return _problem_response(request, ProblemError(exc.status_code, slug, title))


async def _handle_validation_error(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)  # noqa: S101
    errors = [
        FieldError(
            field=".".join(str(part) for part in error.get("loc", ())[1:]) or "body",
            code=str(error.get("type", "invalid")),
            message=str(error.get("msg", "")) or None,
        )
        for error in exc.errors()
    ]
    return _problem_response(
        request,
        ProblemError(
            422, "validation", "Validation failed", "The request is not valid.", errors=errors
        ),
    )


async def _handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
    logger.error("unhandled exception", exc_info=exc)
    return _problem_response(request, internal())


def require_principal(request: Request) -> Principal:
    """FastAPI dependency: authenticate the request or answer 401.

    Declared as a plain function so FastAPI runs it in a worker thread; key
    downloads on a cache miss never block the event loop.
    """
    verifier: TokenVerifier = request.app.state.verifier
    token = bearer_token(request.headers.get("authorization"))
    if token is None:
        raise unauthorized("A bearer access token is required.")
    try:
        principal = verifier.verify(token)
    except InvalidTokenError as exc:
        logger.info("access token rejected", extra={"error": str(exc)})
        raise unauthorized("The access token is invalid or expired.", invalid_token=True) from None
    request.state.subject = principal.subject
    return principal


def create_app(
    *,
    service: str,
    version: str,
    title: str,
    verifier: TokenVerifier,
    checks: Mapping[str, HealthCheck] | None = None,
) -> FastAPI:
    """Create a FastAPI application with the ParallelF service conventions."""
    # The published contract is api/openapi/parallelf.v1.yaml; the framework's
    # generated schema and docs UI stay off so there is one source of truth.
    app = FastAPI(title=title, version=version, openapi_url=None, docs_url=None, redoc_url=None)
    app.state.verifier = verifier
    readiness_checks = dict(checks or {})

    app.add_middleware(RequestContextMiddleware)
    app.add_exception_handler(ProblemError, _handle_problem)
    app.add_exception_handler(StarletteHTTPException, _handle_http_exception)
    app.add_exception_handler(RequestValidationError, _handle_validation_error)
    app.add_exception_handler(Exception, _handle_unexpected)

    @app.get("/healthz", response_model=HealthResponse, response_model_exclude_none=True)
    async def healthz() -> HealthResponse:
        """Liveness: the process is running. Never checks dependencies."""
        return HealthResponse(status="ok", service=service, version=version)

    @app.get("/readyz", response_model=HealthResponse, response_model_exclude_none=True)
    async def readyz() -> Any:
        """Readiness: every registered dependency check passes."""
        results = await run_checks(readiness_checks)
        healthy = all(state == "ok" for state in results.values())
        body = HealthResponse(
            status="ok" if healthy else "unavailable",
            service=service,
            version=version,
            checks=results or None,
        )
        if healthy:
            return body
        return JSONResponse(body.model_dump(exclude_none=True), status_code=503)

    return app
