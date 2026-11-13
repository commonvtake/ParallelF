"""Liveness and readiness, in the same JSON shape as the Go services."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Mapping
from typing import Literal

from pydantic import BaseModel

logger = logging.getLogger(__name__)

HealthCheck = Callable[[], Awaitable[None]]
"""A readiness check. It raises when the dependency is unusable."""


class HealthResponse(BaseModel):
    status: Literal["ok", "unavailable"]
    service: str
    version: str
    checks: dict[str, Literal["ok", "unavailable"]] | None = None


async def run_checks(
    checks: Mapping[str, HealthCheck], timeout_seconds: float = 2.0
) -> dict[str, Literal["ok", "unavailable"]]:
    """Run every check concurrently. Failure causes are logged, not returned."""

    async def run_one(name: str, check: HealthCheck) -> tuple[str, Literal["ok", "unavailable"]]:
        try:
            await asyncio.wait_for(check(), timeout=timeout_seconds)
        except Exception as exc:
            logger.warning(
                "readiness check failed", extra={"check": name, "error": str(exc) or repr(exc)}
            )
            return name, "unavailable"
        return name, "ok"

    results = await asyncio.gather(*(run_one(name, check) for name, check in checks.items()))
    return dict(sorted(results))
