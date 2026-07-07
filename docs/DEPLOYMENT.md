<!-- SPDX-FileCopyrightText: 2026 Kebag-Logic -->
<!-- SPDX-License-Identifier: MIT -->

# Deployment guide

Three ways to run AVB Introspection, from quickest to production. Pick one.

- [1. Local (build & run)](#1-local-build--run) — try it on your machine
- [2. Docker](#2-docker) — one container, persistent volume
- [3. systemd + nginx](#3-systemd--nginx-bare-metal--vm) — a real deployment
- [First login & the admin account](#first-login--the-admin-account)
- [Where data lives](#where-data-lives)
- [Updating a deployment](#updating-a-deployment)
- [Optional system tools](#optional-system-tools-compressed-captures)
- [Troubleshooting](#troubleshooting)

The backend is a single self-contained binary that serves both the JSON/WebSocket
API and the static web UI from one port (default `8342`). There is no database
and no external service to run.

---

## 1. Local (build & run)

**Dependencies:** `g++` (C++20), `make`, `zlib`, `libsodium`. Python 3 is only
needed for the test-data generator and the browser tests.

```bash
# Debian/Ubuntu:  sudo apt install g++ make zlib1g-dev libsodium-dev
# Arch:           sudo pacman -S gcc make zlib libsodium
# Fedora:         sudo dnf install gcc-c++ make zlib-devel libsodium-devel

make -j                                    # -> build/avb-introspectd
AVB_ADMIN_USER=admin AVB_ADMIN_PASSWORD=change-me \
  ./build/avb-introspectd                  # listens on :8342, data in ./data
```

Open <http://localhost:8342>, log in as the admin you just provisioned, and
upload a capture. No traffic handy? Generate some:

```bash
python3 tools/gen_pcaps.py                 # writes scenarios to testdata/
# then upload testdata/milan_scenario.pcap in the UI
```

---

## 2. Docker

```bash
docker build -t avb-introspection .
docker run -d --name avb -p 8342:8342 \
  -e AVB_ADMIN_USER=admin -e AVB_ADMIN_PASSWORD=change-me \
  -v avb-data:/data \
  avb-introspection
```

The UI is on <http://localhost:8342>. Uploaded pcaps, sessions and accounts
persist in the `avb-data` volume and survive restarts.

To put it behind nginx with TLS in one shot, use the compose file in `deploy/`
(UI on port 80, or 443 once you enable the TLS block in `deploy/nginx.conf`):

```bash
docker compose -f deploy/docker-compose.yml up --build -d
```

---

## 3. systemd + nginx (bare-metal / VM)

The reference production layout: the daemon runs as an unprivileged `avb`
service and an nginx reverse proxy terminates TLS and forwards to it.

### 3a. Install the daemon as a service

```bash
# build it (see dependencies under "Local" above)
make -j

# dedicated service account + install locations
sudo useradd --system --home /var/lib/avb-introspection avb
sudo mkdir -p /opt/avb-introspection /var/lib/avb-introspection
sudo cp build/avb-introspectd /opt/avb-introspection/
sudo cp -r frontend           /opt/avb-introspection/
sudo chown -R avb:avb /var/lib/avb-introspection

# the unit (serves on :8342, data in /var/lib/avb-introspection)
sudo cp deploy/avb-introspectd.service /etc/systemd/system/
```

Provision the admin credentials in a private drop-in (keeps the password out of
the packaged unit):

```bash
sudo systemctl edit avb-introspectd
# in the editor, add:
#   [Service]
#   Environment=AVB_ADMIN_USER=alex
#   Environment=AVB_ADMIN_PASSWORD=change-me

sudo systemctl enable --now avb-introspectd
systemctl status avb-introspectd            # should be "active (running)"
```

The unit is hardened (`ProtectSystem=strict`, `NoNewPrivileges`, a private
`/tmp`) and only allowed to write `/var/lib/avb-introspection`. If an admin later
points the pcap library at another path (Admin → Storage), add that path to
`ReadWritePaths=` in the unit or the change is rejected.

### 3b. Front it with nginx

`deploy/nginx.conf` has the correct WebSocket upgrade for `/api/ws`, large
streamed uploads, and a ready-to-enable TLS server block. Point its upstream at
`127.0.0.1:8342` and install it:

```bash
sudo cp deploy/nginx.conf /etc/nginx/conf.d/avb-introspection.conf
sudo nginx -t && sudo systemctl reload nginx
```

---

## First login & the admin account

There are two ways to get the first administrator:

- **Provisioned (recommended for servers).** Set `AVB_ADMIN_USER` /
  `AVB_ADMIN_PASSWORD` in the environment (as above). The account is created as
  admin on first start, or promoted if it already exists. The password is only
  used when the account is first created.
- **First-run setup (no env provided).** If no admin exists yet, the login
  screen shows a **first-time setup** banner and the very first account you
  create becomes the administrator. Every account created afterwards is a
  regular user.

Admins get an **Admin** panel: create/delete users and roles (you cannot delete
your own account or the last remaining admin), live presence, and a **Storage**
section to change where the pcap library is kept on disk.

---

## Where data lives

Everything is under the `--data` directory (`./data` locally,
`/var/lib/avb-introspection` for the service), and survives restarts:

```
<data>/users.json                 accounts (Argon2id password hashes)
<data>/meta.json                  pcap + session index, folders, storage root
<data>/devices.json               user-assigned device names
<data>/pcaps/<id>.pcap            uploaded capture library (root configurable)
<data>/sessions/<id>/capture.pcap each session's own self-contained copy
<data>/sessions/<id>/notes.md     investigation notes
```

A session keeps its **own** copy of the capture, so deleting a library pcap (or
its original server path) never breaks an existing investigation.

---

## Updating a deployment

**Docker:** rebuild the image and recreate the container; the `avb-data` volume
carries the data across.

**systemd:** the running binary is held open, so stop before copying:

```bash
make -j
sudo systemctl stop avb-introspectd
sudo cp build/avb-introspectd /opt/avb-introspection/
sudo cp -r frontend           /opt/avb-introspection/
sudo systemctl start avb-introspectd
```

Frontend-only changes don't need a restart — the daemon serves the files from
disk, so `sudo cp -r frontend /opt/avb-introspection/` is enough (users should
hard-refresh, Ctrl+Shift+R, to bypass the browser cache).

---

## Optional system tools (compressed captures)

Uploads and server-path opens may be compressed; the backend detects the format
by magic bytes and inflates it with the matching **system** tool, so install
whichever formats you need:

| Format        | Tool needed |
|---------------|-------------|
| `.gz`, `.Z`   | `gzip`      |
| `.xz`         | `xz`        |
| `.zst`        | `zstd`      |
| `.bz2`        | `bzip2`     |
| `.lz4`        | `lz4`       |
| `.lz`         | `lzip`      |
| `.zip`        | `unzip`     |

Plain `.pcap` / `.pcapng` never need any of these. A missing tool produces a
clear upload error naming the tool, rather than a silent failure.

---

## Server options

```
--port N            listen port                    (default 8342)
--data DIR          persistent data directory      (default ./data)
--frontend DIR      static frontend directory      (default ./frontend)
--max-threads N     serving thread cap             (default 64)
--max-upload-mb N   pcap upload limit in MiB        (default 1024)
```

Security-relevant environment variables (see **[SECURITY.md](SECURITY.md)**):

```
AVB_ADMIN_USER / AVB_ADMIN_PASSWORD   provision/promote the first global admin
AVB_DISABLE_REGISTRATION=1            close open self-registration (recommended
                                      when exposed — admins/owners create users)
AVB_RATE_RPS / AVB_RATE_BURST         per-non-admin API rate limit (default 30 / 90)
AVB_LOGIN_RPS / AVB_LOGIN_BURST       per-IP login/register limit (default 0.5 / 6)
```

TLS is **not** terminated by the backend — always run a reverse proxy (nginx)
in front for anything beyond a trusted lab network. For a hardened,
internet-facing or multi-tenant deployment (VLAN segmentation, systemd
sandbox, one-container-per-domain, and a bypass-verification checklist),
follow **[SECURITY.md](SECURITY.md)**.

---

## Troubleshooting

- **`admin provisioning failed: username must be 3-32 chars…`** — `AVB_ADMIN_USER`
  must be 3–32 chars of `[a-zA-Z0-9_.-]` and the password ≥ 8 chars.
- **Upload says a tool "is not installed on the backend host"** — install the
  matching decompressor (see the table above) or upload an uncompressed capture.
- **Changing the pcap storage root is rejected as "not writable"** — the service
  user can't write that path. For systemd, add it to `ReadWritePaths=` in the
  unit (`ProtectSystem=strict` makes everything else read-only), then
  `sudo systemctl daemon-reload && sudo systemctl restart avb-introspectd`.
- **WebSocket / live event stream doesn't connect behind a proxy** — ensure the
  proxy forwards the `Upgrade`/`Connection` headers for `/api/ws` (the provided
  `deploy/nginx.conf` already does).
- **The UI looks stale after an update** — hard-refresh (Ctrl+Shift+R); the
  browser cached the previous `app.js`/`style.css`.
