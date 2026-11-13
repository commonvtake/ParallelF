# syntax=docker/dockerfile:1
#
# Builds pf-aid. The build context is the repository root (the service
# depends on the shared python/pf_common package and the workspace lockfile):
#
#   docker build -f services/ai/Dockerfile .

ARG PYTHON_VERSION=3.12

FROM python:${PYTHON_VERSION}-slim AS build
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never
RUN pip install --no-cache-dir uv==0.11.32
WORKDIR /app

COPY pyproject.toml uv.lock ./
COPY python/pf_common ./python/pf_common
COPY services/ai ./services/ai
# Installs exactly the locked versions; nothing is editable, so the virtual
# environment is self-contained and can be copied to the runtime stage.
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable --package pf-aid

FROM python:${PYTHON_VERSION}-slim
RUN groupadd --system --gid 10001 pf && \
    useradd --system --uid 10001 --gid pf --no-create-home --shell /usr/sbin/nologin pf
COPY --from=build /app/.venv /app/.venv

ARG VERSION=dev
ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PF_VERSION=${VERSION}
USER pf
EXPOSE 9006
ENTRYPOINT ["pf-aid"]
