# SPDX-FileCopyrightText: 2026 Kebag-Logic
# SPDX-License-Identifier: MIT
#
# Multi-stage build (BE-3). Persistent data (pcaps, sessions, users) lives
# in /data — mount a volume there (BE-8).
#
#   docker build -t avb-introspection .
#   docker run -p 8342:8342 -v avb-data:/data avb-introspection
#
# Stamp the build (shown by `--version`, the startup banner and the OCI
# label) with --build-arg VERSION="$(git describe --tags --always --dirty)".
#
# Podman takes the same flags, with one exception: build with
#   podman build --format docker -t avb-introspection .
# or the HEALTHCHECK below is silently dropped (the OCI image format has no
# healthcheck field). Resource limits, hardening flags, and how to run several
# instances to scale out: docs/CONTAINER.md.
#
# v2 note: live capture will additionally need --network host and
# --cap-add NET_RAW --cap-add NET_ADMIN.

ARG VERSION=dev

FROM debian:bookworm-slim AS build
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
        g++ make zlib1g-dev libsodium-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Makefile ./
COPY backend ./backend
ARG VERSION
# Only the binary is shipped; strip the debug info the default CXXFLAGS add
# (≈25 MB → ≈3 MB). Build with `make` on the host if you want symbols.
RUN make -j"$(nproc)" VERSION="$VERSION" build/avb-introspectd \
    && strip --strip-unneeded build/avb-introspectd

FROM debian:bookworm-slim
ARG VERSION
LABEL org.opencontainers.image.title="AVB Introspection" \
      org.opencontainers.image.description="Milan/AVB protocol introspection backend and web UI" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.source="https://github.com/Mister-M-alt/avb-introspection" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.documentation="https://github.com/Mister-M-alt/avb-introspection/blob/main/docs/CONTAINER.md"
# Fixed uid/gid (999 is what `useradd --system` picked for the first images,
# so existing /data volumes keep working): a stable id is what lets you chown
# a bind mount, write a Kubernetes securityContext, or map it under rootless
# Podman without inspecting the image first.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
        zlib1g libsodium23 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 999 avb \
    && useradd --system --uid 999 --gid 999 --home /app --shell /usr/sbin/nologin avb
WORKDIR /app
COPY --from=build /src/build/avb-introspectd ./avb-introspectd
COPY frontend ./frontend
COPY docs/API.md ./docs/API.md
RUN mkdir -p /data && chown avb:avb /data
# Numeric on purpose: Kubernetes' runAsNonRoot refuses to start an image whose
# USER is a name it cannot verify ("non-numeric user"); 999 is `avb` above.
USER 999:999
VOLUME /data
EXPOSE 8342

# GET /api/bootstrap is the only cheap unauthenticated endpoint, and it is
# exempt from the login throttle. bash's /dev/tcp keeps curl (and its attack
# surface) out of the runtime image — note /bin/sh is dash here, which has no
# /dev/tcp, so the exec form with bash is required. Override the port below if
# you change --port; if you set --bind, keep 127.0.0.1 reachable (0.0.0.0 or
# ::) or the probe cannot connect. Startup re-analyzes every stored session,
# hence the generous start period (docs/CONTAINER.md §9).
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/8342 && printf 'GET /api/bootstrap HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n' >&3 && head -1 <&3 | grep -q ' 200 '"]

# SIGTERM starts a graceful stop: the listener closes, WebSocket streams get
# a 1001 close frame, in-flight requests finish, then the process exits 0. A
# second SIGTERM exits immediately. Give `stop` a timeout longer than your
# largest upload takes to validate (docs/CONTAINER.md §9).
STOPSIGNAL SIGTERM

ENTRYPOINT ["/app/avb-introspectd"]
CMD ["--port", "8342", "--data", "/data", "--frontend", "/app/frontend"]
