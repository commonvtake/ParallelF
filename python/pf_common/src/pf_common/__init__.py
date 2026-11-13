"""Shared building blocks for ParallelF Python services.

Modules:
    settings  typed configuration from environment variables
    logging   structured JSON logging with request-scoped context
    auth      OIDC access-token verification
    problems  RFC 9457 problem details
    health    liveness and readiness models
    web       FastAPI application factory wiring all of the above
"""
