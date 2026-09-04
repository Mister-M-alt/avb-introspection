#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Kebag-Logic
# SPDX-License-Identifier: MIT
#
# Install or upgrade AVB Introspection as a systemd service from a release
# bundle (or a source checkout that has been built with `make`).
#
#   sudo ./install.sh                       # from the unpacked bundle
#   sudo AVB_ADMIN_USER=alex AVB_ADMIN_PASSWORD='s3cret' ./install.sh
#
# What it does, idempotently:
#   - creates the `avb` service account
#   - installs the binary + frontend under /opt/avb-introspection
#   - installs deploy/avb-introspectd.service (data dir is managed by the
#     unit's StateDirectory=, so nothing to create or chown by hand)
#   - writes /etc/avb-introspection/env (mode 0600) from AVB_ADMIN_USER /
#     AVB_ADMIN_PASSWORD / AVB_DISABLE_REGISTRATION / AVB_TRUSTED_PROXIES when
#     given; an existing file is kept and only those keys are replaced
#   - on an upgrade, stops the service before swapping files and starts it
#     again (a restart is required anyway: the running binary is the old one)
#
# Front it with nginx afterwards: deploy/nginx.production.conf (TLS) —
# docs/DEPLOYMENT.md, Level 3 (one host) and Level 4 (segmented network).
set -euo pipefail

PREFIX=${PREFIX:-/opt/avb-introspection}
ENV_DIR=/etc/avb-introspection
ENV_FILE=$ENV_DIR/env
UNIT=avb-introspectd
HERE="$(cd "$(dirname "$0")" && pwd)"

die() { echo "error: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo ./install.sh)"

# Layout: a release bundle has the binary next to this script; a source
# checkout has it under build/ and this script under deploy/.
BIN=""
for cand in "$HERE/avb-introspectd" "$HERE/build/avb-introspectd" "$HERE/../build/avb-introspectd"; do
  [ -f "$cand" ] && { BIN=$cand; break; }
done
[ -n "$BIN" ] || die "avb-introspectd not found (run make first, or unpack the release bundle)"
FRONTEND=""
for cand in "$HERE/frontend" "$HERE/../frontend"; do
  [ -d "$cand" ] && { FRONTEND=$cand; break; }
done
[ -n "$FRONTEND" ] || die "frontend/ directory not found next to the binary"
UNIT_SRC=""
for cand in "$HERE/deploy/$UNIT.service" "$HERE/$UNIT.service"; do
  [ -f "$cand" ] && { UNIT_SRC=$cand; break; }
done
[ -n "$UNIT_SRC" ] || die "$UNIT.service not found"

command -v systemctl >/dev/null || die "systemd is required"
"$BIN" --version >/dev/null 2>&1 || die "$BIN does not run on this host (missing zlib/libsodium?)"

echo "== service account"
id -u avb >/dev/null 2>&1 || useradd --system --home /var/lib/avb-introspection --shell /usr/sbin/nologin avb

was_active=0
if systemctl is-active --quiet "$UNIT"; then
  was_active=1
  echo "== stopping the running service for the upgrade"
  systemctl stop "$UNIT"
fi

echo "== install binary + frontend -> $PREFIX  ($("$BIN" --version))"
install -d -m 0755 "$PREFIX"
install -m 0755 "$BIN" "$PREFIX/avb-introspectd"
# Swap the frontend atomically-ish: stage, then rename.
rm -rf "$PREFIX/frontend.new"
cp -r "$FRONTEND" "$PREFIX/frontend.new"
rm -rf "$PREFIX/frontend.old"
[ -d "$PREFIX/frontend" ] && mv "$PREFIX/frontend" "$PREFIX/frontend.old"
mv "$PREFIX/frontend.new" "$PREFIX/frontend"
rm -rf "$PREFIX/frontend.old"

echo "== systemd unit"
install -m 0644 "$UNIT_SRC" "/etc/systemd/system/$UNIT.service"

# Environment file: create if missing; replace only the keys we were given.
install -d -m 0750 "$ENV_DIR"
if [ ! -f "$ENV_FILE" ]; then
  cat > "$ENV_FILE" <<'EOT'
# AVB Introspection runtime environment (read by the systemd unit).
# KEY=VALUE lines; no shell quoting needed. Keep this file mode 0600.
#
# AVB_ADMIN_USER=admin
# AVB_ADMIN_PASSWORD=change-me
# AVB_DISABLE_REGISTRATION=1
# AVB_TRUSTED_PROXIES=10.20.0.5     # only when nginx runs on another host
EOT
fi
chmod 0600 "$ENV_FILE"
set_key() { # set_key KEY VALUE — replace or append
  local key=$1 val=$2 tmp
  tmp=$(mktemp "$ENV_DIR/.env.XXXXXX")
  grep -v -E "^#? ?${key}=" "$ENV_FILE" > "$tmp" || true
  printf '%s=%s\n' "$key" "$val" >> "$tmp"
  chmod 0600 "$tmp" && mv "$tmp" "$ENV_FILE"
}
if [ -n "${AVB_ADMIN_USER:-}" ]; then
  [ -n "${AVB_ADMIN_PASSWORD:-}" ] || die "AVB_ADMIN_USER given without AVB_ADMIN_PASSWORD"
  set_key AVB_ADMIN_USER "$AVB_ADMIN_USER"
  set_key AVB_ADMIN_PASSWORD "$AVB_ADMIN_PASSWORD"
  echo "   provisioned admin '$AVB_ADMIN_USER' in $ENV_FILE (mode 0600)"
fi
[ -n "${AVB_DISABLE_REGISTRATION:-}" ] && set_key AVB_DISABLE_REGISTRATION "$AVB_DISABLE_REGISTRATION"
[ -n "${AVB_TRUSTED_PROXIES:-}" ] && set_key AVB_TRUSTED_PROXIES "$AVB_TRUSTED_PROXIES"
if ! grep -q -E '^AVB_ADMIN_USER=' "$ENV_FILE"; then
  echo "   note: no AVB_ADMIN_USER in $ENV_FILE — until an admin exists, the first"
  echo "   account registered through the UI becomes the administrator."
fi

systemctl daemon-reload
if [ "$was_active" -eq 1 ]; then
  systemctl start "$UNIT"
else
  systemctl enable --now "$UNIT"
fi

# Readiness: the banner is printed only once the port is bound.
for _ in $(seq 1 50); do
  systemctl is-active --quiet "$UNIT" || break
  if journalctl -u "$UNIT" -b --no-pager -o cat 2>/dev/null | tail -20 | grep -q 'listening on'; then break; fi
  sleep 0.2
done
systemctl --no-pager --lines=3 status "$UNIT" || true

echo
echo "Done. Backend listening on 127.0.0.1:8342 (loopback only). Put an nginx TLS"
echo "proxy in front for remote access: deploy/nginx.production.conf, docs/DEPLOYMENT.md."
