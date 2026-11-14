# syntax=docker/dockerfile:1
#
# Builds one Go service. The build context is the repository root:
#
#   docker build -f deploy/docker/go-service.Dockerfile --build-arg SERVICE=core .
#
# SERVICE is "core", "gateway" or "cloud" and selects services/<SERVICE>/cmd/<BINARY>;
# BINARY defaults to pf-<SERVICE> (pf-cloudd for the cloud service).

ARG GO_VERSION=1.27

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY pkg ./pkg
COPY gen ./gen
COPY services/core ./services/core
COPY services/gateway ./services/gateway
COPY services/cloud ./services/cloud

ARG SERVICE
ARG BINARY=
ARG VERSION=dev
ARG COMMIT=unknown
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    test -n "${SERVICE}" && \
    CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w \
        -X github.com/commonvtake/parallelf/pkg/version.Version=${VERSION} \
        -X github.com/commonvtake/parallelf/pkg/version.Commit=${COMMIT}" \
      -o /out/service "./services/${SERVICE}/cmd/${BINARY:-pf-${SERVICE}}"

# Distroless: no shell and no package manager. Health checks use the
# binary's own -healthcheck flag.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/service /service
USER nonroot:nonroot
ENTRYPOINT ["/service"]
