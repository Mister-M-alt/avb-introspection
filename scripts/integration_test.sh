#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Kebag-Logic
# SPDX-License-Identifier: MIT
#
# End-to-end integration test (TV-3): builds, starts the backend against a
# scratch data dir, drives the full API including WebSocket streaming, then
# restarts the backend and verifies persistence (BE-8).
set -euo pipefail
cd "$(dirname "$0")/.."

PORT=$((20000 + RANDOM % 20000))
DATA=$(mktemp -d "${TMPDIR:-/tmp}/avb-it.XXXXXX")
BIN=build/avb-introspectd
PID=""

cleanup() {
    [ -n "$PID" ] && kill "$PID" 2>/dev/null || true
    wait 2>/dev/null || true
    rm -rf "$DATA"
}
trap cleanup EXIT

wait_port() {
    for _ in $(seq 1 100); do
        if python3 - "$PORT" <<'EOF'
import socket, sys
s = socket.socket()
s.settimeout(0.2)
try:
    s.connect(("127.0.0.1", int(sys.argv[1])))
except OSError:
    sys.exit(1)
sys.exit(0)
EOF
        then return 0; fi
        sleep 0.1
    done
    echo "server did not come up on :$PORT" >&2
    return 1
}

make -s -j"$(nproc)" "$BIN"
python3 tools/gen_pcaps.py >/dev/null

echo "== start backend on :$PORT (data: $DATA)"
"$BIN" --port "$PORT" --data "$DATA" --frontend frontend &
PID=$!
wait_port

python3 scripts/it_client.py "$PORT" main

echo "== restart backend (BE-8 persistence)"
kill "$PID"
wait "$PID" 2>/dev/null || true
"$BIN" --port "$PORT" --data "$DATA" --frontend frontend &
PID=$!
wait_port

python3 scripts/it_client.py "$PORT" after_restart

echo "INTEGRATION TEST OK"
