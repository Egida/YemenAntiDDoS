# syntax=docker/dockerfile:1
# YemenAntiDDoS Controller — multi-stage image
#   stage 1: Vue 3 console build (Node 22)
#   stage 2: Go build (embeds console/dist via go:embed)
#   stage 3: minimal runtime (non-root, mTLS-ready)
#
# Build:  docker build -t yemenantiddos/controller .
# Use BuildKit for cache mounts: DOCKER_BUILDKIT=1 (default in modern Docker).

FROM node:22-bookworm-slim AS console
WORKDIR /src/controller/console
COPY controller/console/package.json controller/console/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci
COPY controller/console/ ./
ARG XSIGHT_VERSION=docker
ENV XSIGHT_VERSION=$XSIGHT_VERSION
RUN npm run build \
 && test -f dist/index.html

FROM golang:1.25-bookworm AS build
WORKDIR /src
# Cache module downloads separately from source changes.
COPY shared/go.mod shared/go.mod
COPY controller/go.mod controller/go.sum controller/
WORKDIR /src/controller
RUN --mount=type=cache,target=/go/pkg/mod go mod download
WORKDIR /src
COPY shared/ shared/
COPY controller/ controller/
COPY proto/ proto/
COPY --from=console /src/controller/console/dist/ controller/console/dist/
WORKDIR /src/controller
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -buildvcs=false -trimpath -o /out/xsight-controller . \
 && CGO_ENABLED=0 go build -buildvcs=false -trimpath -o /out/xsight-cert ./cmd/xsight-cert

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /etc/xsight --shell /usr/sbin/nologin xsight \
 && mkdir -p /etc/xsight/pki \
 && chown -R xsight:xsight /etc/xsight
COPY --from=build /out/xsight-controller /usr/local/bin/xsight-controller
COPY --from=build /out/xsight-cert /usr/local/bin/xsight-cert

EXPOSE 8080 50051
VOLUME ["/etc/xsight"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -sf http://127.0.0.1:8080/metrics >/dev/null || exit 1

USER xsight
WORKDIR /etc/xsight
ENTRYPOINT ["/usr/local/bin/xsight-controller"]
CMD ["-config", "/etc/xsight/config.yaml"]
