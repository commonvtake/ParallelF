"""Typed service configuration loaded from environment variables.

A settings class is a pydantic model. Field ``oidc_issuer`` is read from
``PF_OIDC_ISSUER``; when that is unset, the content of the file named by
``PF_OIDC_ISSUER_FILE`` is used (the Docker and Kubernetes secrets
convention). Every problem is reported at once, by variable name.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlparse

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, ValidationError

ENV_PREFIX = "PF_"


class SettingsError(ValueError):
    """Raised when the environment does not contain a valid configuration."""


def _http_url(value: str) -> str:
    value = value.strip().rstrip("/")
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("must be an absolute http(s) URL")
    return value


HttpUrlStr = Annotated[str, AfterValidator(_http_url)]
"""An absolute http(s) URL kept as a plain string without a trailing slash."""


class ServiceSettings(BaseModel):
    """Settings every ParallelF HTTP service needs."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    http_host: str = "0.0.0.0"
    http_port: int = Field(default=8000, ge=1, le=65535)
    log_level: Literal["debug", "info", "warn", "error"] = "info"
    version: str = "dev"
    """Build version, set in the container image as ``PF_VERSION``."""

    oidc_issuer: HttpUrlStr
    """Exact ``iss`` claim expected in access tokens."""
    oidc_jwks_url: HttpUrlStr
    """Where this service downloads the identity provider's signing keys."""
    oidc_audience: str = Field(default="parallelf-api", min_length=1)


def env_name(field: str) -> str:
    """Return the environment variable that configures ``field``."""
    return ENV_PREFIX + field.upper()


def load_settings[T: BaseModel](model: type[T], env: Mapping[str, str] | None = None) -> T:
    """Build ``model`` from ``env`` (default: the process environment)."""
    source = os.environ if env is None else env
    values: dict[str, str] = {}
    problems: list[str] = []

    for field in model.model_fields:
        name = env_name(field)
        raw = source.get(name, "").strip()
        if raw:
            values[field] = raw
            continue
        file_path = source.get(name + "_FILE", "").strip()
        if not file_path:
            continue
        try:
            content = Path(file_path).read_text(encoding="utf-8").strip()
        except OSError as exc:
            problems.append(f"{name}_FILE: cannot read secret file ({exc.strerror})")
            continue
        if content:
            values[field] = content
        else:
            problems.append(f"{name}_FILE: secret file is empty")

    try:
        settings = model.model_validate(values)
    except ValidationError as exc:
        for error in exc.errors():
            location = error["loc"][0] if error["loc"] else "?"
            message = "is required" if error["type"] == "missing" else error["msg"]
            problems.append(f"{env_name(str(location))}: {message}")
        raise SettingsError("invalid configuration: " + "; ".join(sorted(problems))) from None

    if problems:
        raise SettingsError("invalid configuration: " + "; ".join(sorted(problems)))
    return settings
