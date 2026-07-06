#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Kebag-Logic
# SPDX-License-Identifier: MIT
#
# Install AVB Introspection as a systemd service from this release bundle.
# Run from the unpacked bundle directory:  sudo ./install.sh
#
# It installs the binary + frontend under /opt/avb-introspection, creates the
# `avb` service account and /var/lib/avb-introspection data dir, and enables
# the systemd unit. Set AVB_ADMIN_USER / AVB_ADMIN_PASSWORD to provision the
# first administrator (otherwise the first account created in the UI becomes
# admin). See docs/DEPLOYMENT.md for Docker and nginx.
set -euo pipefail

PREFIX=/opt/avb-introspection
DATA=/var/lib/avb-introspection
HERE="$(cd "$(dirname "$0")" && pwd)"

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo ./install.sh)"; exit 1; }
[ -f "$HERE/avb-introspectd" ] || { echo "avb-introspectd not found next to install.sh"; exit 1; }

echo "== service account + directories"
id -u avb >/dev/null 2>&1 || useradd --system --home "$DATA" avb
mkdir -p "$PREFIX" "$DATA"

echo "== install binary + frontend -> $PREFIX"
install -m 0755 "$HERE/avb-introspectd" "$PREFIX/avb-introspectd"
rm -rf "$PREFIX/frontend"
cp -r "$HERE/frontend" "$PREFIX/frontend"
chown -R avb:avb "$DATA"

echo "== systemd unit"
install -m 0644 "$HERE/deploy/avb-introspectd.service" /etc/systemd/system/avb-introspectd.service

if [ -n "${AVB_ADMIN_USER:-}" ]; then
  install -d -m 0755 /etc/systemd/system/avb-introspectd.service.d
  cat > /etc/systemd/system/avb-introspectd.service.d/admin.conf <<EOF
[Service]
Environment=AVB_ADMIN_USER=${AVB_ADMIN_USER}
Environment=AVB_ADMIN_PASSWORD=${AVB_ADMIN_PASSWORD:-}
EOF
  chmod 0600 /etc/systemd/system/avb-introspectd.service.d/admin.conf
  echo "   provisioned admin '${AVB_ADMIN_USER}' (drop-in, mode 0600)"
fi

systemctl daemon-reload
systemctl enable --now avb-introspectd
sleep 1
systemctl --no-pager --lines=0 status avb-introspectd || true

echo
echo "Done. Backend listening on :8342 (put an nginx TLS proxy in front for"
echo "remote access — see deploy/nginx.conf and docs/DEPLOYMENT.md)."
