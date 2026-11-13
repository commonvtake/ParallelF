"""Entry point: ``pf-aid`` (see ``[project.scripts]``)."""

from __future__ import annotations

import logging
import sys

import uvicorn

from pf_aid import SERVICE_NAME
from pf_aid.app import build_app
from pf_aid.config import Settings
from pf_common.logging import configure_logging
from pf_common.settings import SettingsError, load_settings


def main() -> None:
    try:
        settings = load_settings(Settings)
    except SettingsError as exc:
        sys.stderr.write(f"{SERVICE_NAME}: {exc}\n")
        raise SystemExit(1) from None

    configure_logging(SERVICE_NAME, settings.version, settings.log_level)
    logging.getLogger(SERVICE_NAME).info(
        "starting",
        extra={
            "addr": f"{settings.http_host}:{settings.http_port}",
            "oidc_issuer": settings.oidc_issuer,
            "oidc_audience": settings.oidc_audience,
        },
    )
    uvicorn.run(
        build_app(settings),
        host=settings.http_host,
        port=settings.http_port,
        log_config=None,  # keep the JSON logging configured above
        access_log=False,  # the request middleware writes the access log
        server_header=False,
        timeout_graceful_shutdown=10,
    )


if __name__ == "__main__":
    main()
