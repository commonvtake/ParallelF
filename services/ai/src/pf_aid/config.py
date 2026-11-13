"""pf-aid configuration."""

from __future__ import annotations

from pydantic import Field

from pf_common.settings import ServiceSettings


class Settings(ServiceSettings):
    """Settings read from ``PF_*`` environment variables."""

    http_port: int = Field(default=9006, ge=1, le=65535)
