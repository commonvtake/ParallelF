"""HTTP application of pf-aid."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, FastAPI, Request
from pydantic import BaseModel

from pf_aid import SERVICE_NAME
from pf_aid.config import Settings
from pf_common.auth import OIDCTokenVerifier, Principal, TokenVerifier
from pf_common.web import create_app, require_principal


class Capability(BaseModel):
    name: str
    status: Literal["available", "not_implemented"]
    description: str


class AIInfo(BaseModel):
    service: str
    version: str
    capabilities: list[Capability]


# Planned capabilities (docs/architecture/subsystems/ai.md). None exist yet;
# the API says so explicitly instead of returning placeholder data.
PLANNED_CAPABILITIES: tuple[Capability, ...] = (
    Capability(
        name="investigations",
        status="not_implemented",
        description="Read-only, evidence-cited investigation of an incident.",
    ),
    Capability(
        name="evidence-tools",
        status="not_implemented",
        description="Bounded, parameterised queries over verified telemetry.",
    ),
    Capability(
        name="citation-validation",
        status="not_implemented",
        description="Deterministic check that every claim cites retrieved evidence.",
    ),
)

router = APIRouter(prefix="/api/v1/ai", tags=["ai"])


@router.get("/info", response_model=AIInfo)
def get_info(
    request: Request, _principal: Annotated[Principal, Depends(require_principal)]
) -> AIInfo:
    """Describe the service and which capabilities exist."""
    return AIInfo(
        service=SERVICE_NAME,
        version=request.app.version,
        capabilities=list(PLANNED_CAPABILITIES),
    )


def build_app(settings: Settings, verifier: TokenVerifier | None = None) -> FastAPI:
    """Create the application. ``verifier`` is injectable for tests."""
    app = create_app(
        service=SERVICE_NAME,
        version=settings.version,
        title="ParallelF AI Investigator",
        verifier=verifier
        or OIDCTokenVerifier(
            issuer=settings.oidc_issuer,
            jwks_url=settings.oidc_jwks_url,
            audience=settings.oidc_audience,
        ),
    )
    app.include_router(router)
    return app
