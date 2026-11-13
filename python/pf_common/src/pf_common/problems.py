"""RFC 9457 problem details, matching the Go services' error format."""

from __future__ import annotations

from pydantic import BaseModel

PROBLEM_TYPE_BASE = "https://parallelf.dev/problems/"
PROBLEM_MEDIA_TYPE = "application/problem+json"


class FieldError(BaseModel):
    field: str
    code: str
    message: str | None = None


class Problem(BaseModel):
    type: str
    title: str
    status: int
    detail: str | None = None
    instance: str | None = None
    request_id: str | None = None
    errors: list[FieldError] | None = None


class ProblemError(Exception):
    """Raise from a handler or dependency to return a problem response."""

    def __init__(
        self,
        status: int,
        slug: str,
        title: str,
        detail: str | None = None,
        *,
        errors: list[FieldError] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(f"{status} {slug}: {detail or title}")
        self.status = status
        self.slug = slug
        self.title = title
        self.detail = detail
        self.errors = errors
        self.headers = headers or {}

    def to_problem(self, *, instance: str | None, request_id: str | None) -> Problem:
        return Problem(
            type=PROBLEM_TYPE_BASE + self.slug,
            title=self.title,
            status=self.status,
            detail=self.detail,
            instance=instance,
            request_id=request_id,
            errors=self.errors,
        )


def unauthorized(detail: str, *, invalid_token: bool = False) -> ProblemError:
    challenge = 'Bearer realm="parallelf"'
    if invalid_token:
        challenge += ', error="invalid_token"'
    return ProblemError(
        401,
        "unauthorized",
        "Authentication required",
        detail,
        headers={"WWW-Authenticate": challenge},
    )


def not_found(detail: str = "No such route.") -> ProblemError:
    return ProblemError(404, "not-found", "Resource not found", detail)


def internal() -> ProblemError:
    return ProblemError(
        500,
        "internal",
        "Internal server error",
        "The request could not be completed. Quote the request_id when reporting this.",
    )
