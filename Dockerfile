# SPDX-FileCopyrightText: 2026 Kebag-Logic
# SPDX-License-Identifier: MIT
#
# Multi-stage build (BE-3). Persistent data (pcaps, sessions, users) lives
# in /data — mount a volume there (BE-8).
#
#   docker build -t avb-introspection .
#   docker run -p 8342:8342 -v avb-data:/data avb-introspection
#
# v2 note: live capture will additionally need --network host and
# --cap-add NET_RAW --cap-add NET_ADMIN.

FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        g++ make zlib1g-dev libsodium-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Makefile ./
COPY backend ./backend
RUN make -j"$(nproc)" build/avb-introspectd

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        zlib1g libsodium23 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --home /app avb
WORKDIR /app
COPY --from=build /src/build/avb-introspectd ./avb-introspectd
COPY frontend ./frontend
COPY docs/API.md ./docs/API.md
RUN mkdir -p /data && chown avb /data
USER avb
VOLUME /data
EXPOSE 8342
ENTRYPOINT ["/app/avb-introspectd"]
CMD ["--port", "8342", "--data", "/data", "--frontend", "/app/frontend"]
