<!-- SPDX-FileCopyrightText: 2026 Kebag-Logic -->
<!-- SPDX-License-Identifier: MIT -->

# Containers & scale-out

Running AVB Introspection under Podman or Docker, and how to grow it past one
box. The backend is a single self-contained binary with no database, so the
image is trivial — and that same design fixes *how* it scales: you add
**instances**, never replicas of one instance.

- [1. Read this first — replicas are not safe](#1-read-this-first--replicas-are-not-safe) — the one hard constraint
- [2. Quick start](#2-quick-start) — Podman and Docker, one container
- [3. The image](#3-the-image) — what is in it, how to extend it
- [4. Configuration](#4-configuration) — flags, environment, networking
- [5. Storage &amp; volumes](#5-storage--volumes) — what must persist
- [6. Runtime hardening](#6-runtime-hardening) — the systemd sandbox, as container flags
- [7. Scaling out — one instance per shard](#7-scaling-out--one-instance-per-shard) — the supported model
- [8. Scaling up — sizing one instance](#8-scaling-up--sizing-one-instance) — threads, memory, uploads
- [9. Health, readiness &amp; shutdown](#9-health-readiness--shutdown) — probes and stop timeouts
- [10. What true replication would require](#10-what-true-replication-would-require) — for the roadmap
- [11. Troubleshooting](#11-troubleshooting)

**Where this fits:** the reference behind deployment **Levels 1, 2 and 5**
of [DEPLOYMENT.md](DEPLOYMENT.md) (one container · compose stack behind nginx
· multi-tenant shards). Start there for a recipe; come here for the why and
the knobs.

Everything here is Podman/Docker-interchangeable unless a heading says
otherwise. Commands are written with `podman`; substitute `docker` verbatim.

| Template | Role |
| --- | --- |
| [`Dockerfile`](../Dockerfile) | the image — multi-stage, non-root, minimal runtime (§3) |
| [`deploy/docker-compose.yml`](../deploy/docker-compose.yml) | one instance behind nginx (§2c) |
| [`deploy/docker-compose.scale.yml`](../deploy/docker-compose.scale.yml) | sharded multi-instance stack (§7b) |
| [`deploy/nginx.scale.conf`](../deploy/nginx.scale.conf) | routes each shard to its own instance (§7c) |

Non-container deployment paths: **[DEPLOYMENT.md](DEPLOYMENT.md)**. Threat
model and hardening rationale: **[SECURITY.md](SECURITY.md)**. Network
placement: **[NETWORK.md](NETWORK.md)**.

---

## 1. Read this first — replicas are not safe

**Do not run several containers against one `/data` volume, and do not put
two instances behind a load-balancing pool.** This is not a tuning caveat —
it destroys data. `docker compose up --scale app=3`, a Kubernetes
`Deployment` with `replicas: 2`, and a second `server` line in an nginx
`upstream` are all unsafe.

The reason is architectural rather than a bug: **memory is authoritative and
disk is a write-behind snapshot of it.** `<data>` is read exactly once, at
startup; after that every mutation edits in-memory structures and rewrites
the whole file. Nothing re-reads it, and no file is ever locked — the mutexes
guarding that state are `std::mutex`, which is process-local and gives two
containers no mutual exclusion whatsoever.

What that means concretely, per piece of state:

| State | Lives in | With a second instance on the same volume |
| --- | --- | --- |
| Pcap/session **id counters** | process memory | both hand out `p3`/`s4` — the two writes **overwrite each other's capture**, and deleting one session removes the other's directory |
| `meta.json`, `users.json`, `devices.json` | in-memory image, whole-file rewrite | last writer wins: a pcap uploaded on A silently vanishes when B next saves anything |
| Those files' **staging** paths | fixed `meta.json.tmp`, `users.json.tmp` | no `O_EXCL`, no pid suffix — concurrent writes interleave into one mangled file, which is then renamed into place |
| Bearer tokens | process memory, never persisted | a token minted by A is a **401 on B**; any restart logs everyone out |
| Analysis engine + sessions | process memory, rebuilt at boot | `GET /api/sessions` is served from memory, so a session created on A is a 404 on B, and the WebSocket answers close code `4004` |
| WebSocket event streams | per-session, in-process | live events only reach clients that landed on the instance holding that session |
| Presence | in-memory, keyed by token | each instance shows a different partial "who is online" |
| Rate limits + FlowGuard windows | in-memory token buckets | thresholds **divide by N**: 3 instances mean 3× the real request rate before a limit trips, and the "≥8 failed logins in 60 s" brute-force alert needs ~24 |
| Upload staging (`.upload-<seq>.tmp`) | per-process counter from 0 | both use `.upload-0.tmp`; one instance's cleanup deletes the other's in-flight upload |
| `/api/metrics`, `/api/admin/monitor` | this process only | CPU, memory, threads and req/min describe whichever instance answered |

The worst outcome is not a lost upload. A `meta.json` mangled by two
interleaved writers **fails to parse at the next start**, `Store::init`
returns false and the daemon exits 1 — so *every* instance then refuses to
boot, from a volume whose captures are still on disk but whose index is gone.
Snapshot `<data>` before experimenting (§5).

Three further consequences, worth knowing even if you never try replicas:

- **Index writes are atomic and durable.** `meta.json`, `users.json`,
  `devices.json` and each session's `notes.md` are written temp-file →
  `fsync` → `rename` (→ directory `fsync`), so a reader never observes a
  half-written file and a completed save survives a power loss. Captures
  themselves are still plain sequential writes (below).
- **Two *fresh* instances can each mint a first admin.** The bootstrap path
  reads process-local user state, and `AVB_DISABLE_REGISTRATION` does **not**
  suppress it — while no admin exists, the first registration still becomes
  one. Provision `AVB_ADMIN_USER`/`AVB_ADMIN_PASSWORD` explicitly (§4).
- **Uploaded pcaps and session captures are written straight to their final
  path**, with no staging rename, so a collision corrupts the capture itself
  rather than just the index.

The supported way to use more than one container is **§7: one instance per
shard, each with its own volume.** That is horizontal *partitioning* — it
scales throughput and isolates tenants, and it is the model the app's
multi-tenant design already assumes.

---

## 2. Quick start

### 2a. Podman (rootless)

```bash
# --format docker is needed for the image's HEALTHCHECK to survive the build;
# Podman defaults to the OCI format, which has no healthcheck field and drops
# it with only a warning. Harmless to omit if you probe externally (§9).
podman build --format docker -t avb-introspection .

podman volume create avb-data
podman run -d --name avb \
  -p 8342:8342 \
  -v avb-data:/data \
  -e AVB_ADMIN_USER=admin -e AVB_ADMIN_PASSWORD=change-me-please \
  avb-introspection
```

The UI is on <http://localhost:8342>. Pcaps, sessions, notes and accounts
persist in `avb-data`.

Rootless Podman runs the container's `avb` user as a **subordinate uid** on
the host, which is why bind mounts fail where named volumes work. Use a named
volume (above) and the problem never arises. If you must bind-mount a host
directory, hand it to the container's user explicitly:

```bash
# ":U" chowns the source to the uid the container actually runs as.
podman run -d --name avb -p 8342:8342 -v ./data:/data:U,Z avb-introspection

# ...or map your own uid into the container instead of remapping the files:
podman run -d --name avb -p 8342:8342 --userns=keep-id -v ./data:/data:Z avb-introspection
```

Drop `,Z` on systems without SELinux — it relabels the source for container
access, which is harmless elsewhere but only meaningful with SELinux
enforcing.

Rootless containers cannot bind host ports below 1024. Publish `8342` (or any
port ≥ 1024) and let a reverse proxy own 80/443 — the recommended layout
anyway, since the backend does not terminate TLS.

### 2b. Docker

Identical, minus the uid remapping:

```bash
docker build -t avb-introspection .
docker run -d --name avb -p 8342:8342 \
  -e AVB_ADMIN_USER=admin -e AVB_ADMIN_PASSWORD=change-me-please \
  -v avb-data:/data \
  avb-introspection
```

### 2c. Behind nginx, in one shot

[`deploy/docker-compose.yml`](../deploy/docker-compose.yml) brings up the
backend plus an nginx that terminates the public port, forwards the WebSocket
upgrade for `/api/ws`, and streams large uploads:

```bash
podman-compose -f deploy/docker-compose.yml up -d     # or: docker compose ...
```

It needs `deploy/env/app.env` (copy `app.env.example`, mode 0600, fill in
the admin credentials) — required on purpose, so the stack never comes up with
the first-registration-becomes-admin bootstrap open. The backend runs
read-only with no capabilities on an internal network, resource-capped, and
with `AVB_TRUSTED_PROXIES` set so it attributes requests to real client
addresses rather than to nginx (§4).

The UI is then on port 80 — or 443 once you fill in the TLS block. For an
internet-facing deployment use
[`deploy/nginx.production.conf`](../deploy/nginx.production.conf) instead and
read **[SECURITY.md](SECURITY.md)** first.

> **Podman note:** `podman-compose` handles this file, but on a server
> Quadlet units (§7d) integrate far better with systemd — you get journald
> logs, ordering and `systemctl status` per instance. Compose is the quickest
> path; Quadlet is the durable one.

---

## 3. The image

Multi-stage, built from `debian:bookworm-slim`:

- **build stage** — `g++`, `make`, `zlib1g-dev`, `libsodium-dev`; compiles
  `build/avb-introspectd` from `Makefile` + `backend/` only, so editing the
  frontend or the docs does not invalidate the compile layer.
- **runtime stage** — `zlib1g` and `libsodium23` only, a system user `avb`
  with a **fixed uid/gid of 999** (so a bind mount can be `chown`ed, a
  Kubernetes `securityContext` written, or a rootless mapping chosen without
  inspecting the image), the stripped binary (≈3 MB), `frontend/`, and
  `docs/API.md`. Runs as `USER 999:999` (numeric, so a Kubernetes
  `runAsNonRoot` check can verify it), declares `VOLUME /data`, `EXPOSE 8342`
  and `STOPSIGNAL SIGTERM`. Pass `--build-arg VERSION=…` to stamp the build;
  it shows in `--version`, the startup banner and the
  `org.opencontainers.image.version` label.

`ENTRYPOINT` is the binary and `CMD` holds the default flags, so you can
override flags without repeating the binary path:

```bash
podman run ... avb-introspection --port 8342 --data /data \
                                 --frontend /app/frontend --max-threads 256
```

**Optional decompressors.** Compressed uploads are inflated by *system*
tools, and the runtime image deliberately ships none of them — so `.gz`,
`.xz`, `.zst`, `.bz2`, `.lz4`, `.lz` and `.zip` uploads fail with an error
naming the missing tool. Plain `.pcap`/`.pcapng` always work. Add only what
you need, in a derived image:

```dockerfile
FROM avb-introspection
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
        gzip xz-utils zstd \
    && rm -rf /var/lib/apt/lists/*
USER avb
```

Keeping them out is a defensible default: each is another parser reached with
attacker-controlled bytes (see [SECURITY.md](SECURITY.md) §3). If you add
them, note that the daemon `fork`/`exec`s them — so a custom seccomp profile
must keep those syscalls available.

**CI** exercises the deployment on every push (`.github/workflows/ci.yml`,
job `deploy`): the image is built, run with the §6 hardening flags until its
`HEALTHCHECK` reports healthy, queried, and stopped — the stop must exit 0
inside ten seconds; both compose stacks are parsed and the single-instance
one is brought up and queried through nginx; every shipped nginx config
passes `nginx -t`; and the systemd unit, nftables template and install script
are syntax-checked.

---

## 4. Configuration

Command-line flags, all with container-appropriate defaults already set in
`CMD`:

```
--bind ADDR         listen address                 (default 0.0.0.0; :: = IPv6 dual-stack)
--port N            listen port, 1-65535           (default 8342)
--data DIR          persistent data directory      (default ./data)
--frontend DIR      static frontend directory      (default ./frontend)
--max-threads N     serving thread cap             (default 64)
--max-upload-mb N   pcap upload limit in MiB       (default 1024)
--version           print the build version and exit
```

Bad values are rejected at startup (exit 2, message on stderr). There is no
`--config`, no log-level flag, and no TLS option.

Environment variables — the only ones the binary reads:

| Variable | Effect |
| --- | --- |
| `AVB_ADMIN_USER` / `AVB_ADMIN_PASSWORD` | create the first global admin, or promote an existing account. The password is used **only** when the account does not exist yet |
| `AVB_DISABLE_REGISTRATION=1` | close open self-registration — set this on anything reachable beyond a lab. It does not block the very first admin bootstrap |
| `AVB_RATE_RPS` / `AVB_RATE_BURST` | per-non-admin API token bucket (default `30` / `90`) |
| `AVB_LOGIN_RPS` / `AVB_LOGIN_BURST` | per-IP login/register throttle (default `0.5` / `6`) |
| `AVB_TRUSTED_PROXIES` | comma-separated IPs/CIDRs (v4 or v6) of reverse proxies whose `X-Real-IP` / `X-Forwarded-For` is believed. Loopback is always trusted. A malformed entry is fatal at startup rather than silently ignored |

All are read once at startup; there is no reload, and `SIGHUP` is not handled
(it kills the process). Pass secrets by file rather than on the command line,
so they stay out of `podman inspect` and shell history:

```bash
podman run -d --name avb --env-file ./avb.env -v avb-data:/data avb-introspection
# avb.env, mode 0600:
#   AVB_ADMIN_USER=alex
#   AVB_ADMIN_PASSWORD=...
#   AVB_DISABLE_REGISTRATION=1
```

**Networking.** The listener defaults to `0.0.0.0` (IPv4). `--bind` takes
any IPv4 or IPv6 literal: `127.0.0.1` for a same-host proxy (what the systemd
unit uses), `::` for a dual-stack socket that also serves IPv4 clients. In a
container the default is right: the daemon binds all interfaces *inside its
own network namespace*, and you control exposure with the port publish —
`-p 127.0.0.1:8342:8342` for host-loopback only, or publishing nothing at all
and keeping the instance on an internal network, as the compose files do. If
you do set `--bind` in a container, keep `127.0.0.1` reachable or the
`HEALTHCHECK` cannot connect.

**Trusted proxy headers.** The app attributes a request to the socket peer
unless that peer is **loopback or listed in `AVB_TRUSTED_PROXIES`**, in which
case it believes the proxy's `X-Real-IP` (falling back to the last hop of
`X-Forwarded-For`). This matters more than it sounds: the login brute-force
throttle, the FlowGuard alerts and the per-IP buckets all key on that
address. In a container the proxy lives in a *different* namespace, so its
connections are not `127.0.0.1` — without the variable every client shares
one bucket under nginx's address, and one abusive client can 429 everyone's
logins. Both compose stacks set it to the private ranges, which is exact
there (the backend network is internal and unpublished, so its only possible
peers are the stack's own containers); pin a subnet under `networks:` and
narrow it if you prefer. Keep the edge `limit_req_zone` in nginx as well — it
is the first line against floods. A **Podman pod** (§7d) is the other way to
get this right: proxy and backend share a network namespace, so the proxy
genuinely is loopback and nothing needs configuring.

**Uploads through the proxy.** The server rejects `Transfer-Encoding` of any
kind with `501`, so the proxy must forward a `Content-Length` and never
chunk. `proxy_request_buffering off` in the shipped nginx config is fine,
because the browser sends a Content-Length.

---

## 5. Storage & volumes

One volume, mounted at `/data`. Everything that must survive a restart is
under it:

```
<data>/users.json                 accounts (Argon2id password hashes)
<data>/meta.json                  pcap + session index, id counters, domains
<data>/devices.json               user-assigned device names
<data>/security.log               append-only security alerts (JSONL)
<data>/pcaps/<id>.pcap            upload library, "default" domain
<data>/pcaps/domains/<dom>/…      upload library, other domains
<data>/sessions/<id>/capture.pcap the session's own self-contained copy
<data>/sessions/<id>/notes.md     investigation notes
```

Sizing is dominated by captures. Each session keeps its **own** copy of its
capture, so a pcap analyzed in three sessions occupies roughly four copies
overall (library + three sessions). That is deliberate — deleting a library
pcap never breaks a running investigation — but budget for it.

**Nothing analytic is persisted.** Events, the packet index and the protocol
state machines are rebuilt by re-analyzing `capture.pcap` at every start
(§9), so the volume stays small relative to memory, and a restart costs CPU
rather than disk.

Back up with the container stopped, so you capture a consistent `meta.json`:

```bash
podman stop avb
podman run --rm -v avb-data:/data:ro -v "$PWD":/backup:Z docker.io/library/busybox \
  tar czf /backup/avb-data-backup.tar.gz -C /data .
podman start avb
```

The pcap library root is relocatable at runtime (Admin → Storage). If an
admin points it outside `/data`, mount **that** path as a second writable
volume too, or the library disappears on the next recreate. Layout
options, the migration, sizing and the mount-missing pitfall:
[DEPLOYMENT.md, "Where to store captures"](DEPLOYMENT.md#where-to-store-captures).

---

## 6. Runtime hardening

The daemon needs **no Linux capabilities** and makes no outbound connections;
it opens only ordinary TCP sockets and has no live-capture path. The shipped
systemd unit exploits that heavily — the container equivalents:

| systemd directive | Container flag |
| --- | --- |
| `CapabilityBoundingSet=` (empty) | `--cap-drop=ALL` |
| `NoNewPrivileges=true` | `--security-opt no-new-privileges` |
| `ProtectSystem=strict` + `ReadWritePaths=` | `--read-only` plus the `/data` volume |
| `PrivateTmp=true` | `--tmpfs /tmp:rw,noexec,nosuid,size=64m` |
| `MemoryMax=2G`, `CPUQuota=200%` | `--memory=2g --cpus=2` |
| `TasksMax=256` | `--pids-limit=256` |
| `LimitNOFILE=8192` | `--ulimit nofile=8192:8192` |
| dedicated `avb` user | already `USER avb` in the image |

Put together:

```bash
podman run -d --name avb \
  -p 127.0.0.1:8342:8342 \
  -v avb-data:/data \
  --env-file ./avb.env \
  --cap-drop=ALL \
  --security-opt no-new-privileges \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --memory=4g --memory-reservation=2g --cpus=2 \
  --pids-limit=256 --ulimit nofile=8192:8192 \
  --restart=unless-stopped --stop-timeout=60 \
  avb-introspection
```

`--read-only` works because the daemon stages upload temp files inside
`<data>` rather than `/tmp`; one writable volume is genuinely sufficient. The
tmpfs is belt-and-braces for the decompression helpers if you added any (§3).
See §8 before settling on `--memory` — the default upload limit interacts
badly with a small cap.

Two things containers do **not** give you that the systemd unit does, and
which therefore move to the network layer: the cgroup egress firewall
(`IPAddressDeny=any`) and the seccomp allow-list beyond the runtime default.
For the egress equivalent, put the instance on an **internal** network with
no gateway — the compose stacks in §7b do exactly that, so the backend can
reach nothing but its proxy. See [SECURITY.md](SECURITY.md) §2c and
[NETWORK.md](NETWORK.md) for the host- and VLAN-level rules.

---

## 7. Scaling out — one instance per shard

The model: **partition the users, give each partition its own container and
its own volume, and route to it deterministically.** No shared state, so none
of §1 applies. Each shard is an ordinary single instance, and a shard that
dies takes only its own tenants with it.

```
                      ┌─ avb-acme    :8342  ── volume avb-acme-data
 clients ── nginx ────┼─ avb-globex  :8342  ── volume avb-globex-data
            (routes)  └─ avb-initech :8342  ── volume avb-initech-data
```

This is routing, not load balancing: a given tenant always reaches the same
instance, so tokens, sessions and WebSocket streams stay put. There is no
sticky-session cookie to configure — the path prefix or hostname *is* the
affinity.

### 7a. Choosing a shard key

| Shard key | Use when | Notes |
| --- | --- | --- |
| **Tenant / customer** | tenants are mutually untrusting | strongest: isolation is kernel-enforced rather than application logic. Composes with in-process domains for that tenant's own teams |
| **Team / department** | one organisation, load is the problem | simplest to reason about; matches how people already group captures |
| **Workload class** | a few users run very large captures | give heavy analysts a shard with a bigger `--memory`/`--cpus` and leave everyone else on a small one |

Do **not** shard by anything a single user crosses — a user cannot see data
on another shard, by design. Cross-shard search and a global user list do not
exist; if you need them, you need §10, not §7.

### 7b. The compose stack

[`deploy/docker-compose.scale.yml`](../deploy/docker-compose.scale.yml) is a
ready three-shard stack: one nginx, three backends, three volumes, each
backend resource-capped and on an internal network with no route out.

```bash
podman-compose -f deploy/docker-compose.scale.yml up -d
# or: docker compose -f deploy/docker-compose.scale.yml up -d
```

Each shard gets its own admin credentials and its own `AVB_*` limits. Add a
fourth by copying one service block, its volume, and one `location` in the
nginx config — there is no registry to update and no state to migrate.

**Do not** collapse those three services into `--scale app=3` of one service.
They are separate services precisely because they must not share a volume
(§1).

### 7c. nginx routing

[`deploy/nginx.scale.conf`](../deploy/nginx.scale.conf) routes by path
prefix, which needs neither DNS nor a certificate per tenant:

```
https://avb.example.com/acme/     ─▶ avb-acme
https://avb.example.com/globex/   ─▶ avb-globex
```

The SPA detects its base path at runtime, so a prefix costs no rebuild —
rename them freely. Routing by `server_name` (one subdomain per shard) works
equally well and is cleaner if you already hold wildcard DNS and a wildcard
certificate; the file shows both.

Each shard keeps its own `upstream` block with exactly **one** `server`. If
you ever find yourself adding a second `server` line to an upstream, stop —
that is the load-balancing pool §1 rules out.

### 7d. Podman pods and Quadlet

On a server, prefer systemd-managed units to a long-lived compose process.
Quadlet (Podman 4.4+) generates the units from declarative files under
`/etc/containers/systemd/`:

```ini
# /etc/containers/systemd/avb-acme.container
[Unit]
Description=AVB Introspection — acme shard
After=network-online.target

[Container]
Image=localhost/avb-introspection:latest
ContainerName=avb-acme
Volume=avb-acme-data:/data
PublishPort=127.0.0.1:8342:8342
EnvironmentFile=/etc/avb/acme.env
DropCapability=ALL
NoNewPrivileges=true
ReadOnly=true
Tmpfs=/tmp:rw,noexec,nosuid,size=64m
PodmanArgs=--memory=4g --cpus=2 --pids-limit=256

[Service]
Restart=on-failure
TimeoutStopSec=60

[Install]
WantedBy=multi-user.target
```

`systemctl daemon-reload && systemctl start avb-acme` — one unit per shard,
each with the §6 hardening and its own quotas. With nginx on the host
proxying to `127.0.0.1:8342`, the proxy is loopback from the container's
point of view (the port publish rewrites the source), so no
`AVB_TRUSTED_PROXIES` is needed in `acme.env`; check the admin Security
panel shows real client addresses and add it if not.

A **pod** is the other useful Podman primitive here: putting nginx and one
backend in the same pod makes them share a network namespace, so the proxy
reaches the backend over `127.0.0.1` — which restores accurate per-client IPs
in the app's own rate limiter (§4).

### 7e. Capacity — knowing when to split

Shard when a single instance runs out of headroom, and let the numbers say
which resource:

- **`GET /api/metrics`** (any authenticated user) — thread-pool size, live
  connections, sessions and their event counts.
- **`GET /api/admin/monitor`** (global admin) — process CPU and resident
  memory, plus **per-domain requests/min**. That last one is exactly the
  signal you want: the domain at the top of the list is the one to split off.

Both report **only the instance that answered**, which is correct here — each
shard is independent, so scrape each one.

One container-specific caveat: the monitor's *host* memory figures come from
`/proc/meminfo`, which inside a container still reports the **host's** total
and available memory, not the cgroup limit. Process RSS is accurate; "memory
available" is not. Use `podman stats` for the cgroup view.

---

## 8. Scaling up — sizing one instance

Before adding shards, make sure the instance is not artificially limited.

**Uploads are buffered entirely in memory — size `--memory` accordingly.**
This is the trap most likely to bite a containerized deployment. A request
body is held in RAM, then written to a staging file and copied again, so a
single upload transiently costs roughly **3× its size**. With the default
`--max-upload-mb 1024`, one upload can need several GiB — and a container
capped at `--memory=2g` (the value the systemd unit uses) will be OOM-killed
mid-upload. Either raise the memory limit or lower the upload limit so they
agree:

```bash
# a 2 GiB container: cap uploads well below a third of it
podman run ... --memory=2g avb-introspection \
  --port 8342 --data /data --frontend /app/frontend --max-upload-mb 256
```

Keep nginx's `client_max_body_size` ≥ `--max-upload-mb`, or the proxy rejects
the request before the app ever sees it.

**Threads.** `--max-threads` (default 64) caps a pool that grows on demand,
with one trap: **an open WebSocket occupies a pool thread for its entire
lifetime**, and every browser viewing a session holds one. At the default,
roughly 64 concurrent viewers will starve ordinary HTTP serving — uploads and
page loads then queue behind idle event streams. The work queue is unbounded,
so this shows up as latency, never as a `503`.

Size it as *peak concurrent session viewers + headroom for HTTP*, and raise
the pids limit to match (peak threads ≈ 1 + `--max-threads` + one decode fan-
out per running analysis):

```bash
podman run ... --pids-limit=512 avb-introspection \
  --port 8342 --data /data --frontend /app/frontend --max-threads 256
```

**CPU.** Analysis fans decoding out across cores and then re-orders packets by
timestamp on a single thread. More cores shorten a capture's analysis but do
not raise the ceiling on that serialized stage. `--cpus` below the host core
count directly slows analysis.

**Memory held by sessions.** A session keeps its entire event log, packet
index, device inventory and protocol state machines in RAM for as long as it
exists — and **every session is restored at startup**, so steady-state memory
scales with the *total retained* across all sessions, not with what anyone is
viewing. Deleting finished sessions is the lever. Measure your own captures
via `/api/metrics` rather than assuming a ratio.

**Login bursts.** Account state is guarded by a single mutex that also covers
the Argon2id verification, so a flood of logins briefly stalls token
validation for *all* requests. The per-IP login throttle
(`AVB_LOGIN_RPS`/`AVB_LOGIN_BURST`) and nginx's `limit_req` on `/api/login`
are what keep that in check — leave them on.

---

## 9. Health, readiness & shutdown

**Startup is not instant.** Every persisted session is re-analyzed from its
capture at boot, on one detached thread each. A volume with many large
sessions takes a while to become fully useful and spikes CPU meanwhile. The
port accepts connections almost immediately, so give probes a start period
and do not read a slow first minute as a failure.

The log banner — `avb-introspectd <version> listening on 0.0.0.0:8342` — is
printed only *after* the socket is bound, so it is a valid readiness line for
log-watching tooling; a bind failure prints `fatal:` and exits 1 without it.

**Health probe.** `GET /api/bootstrap` is unauthenticated, cheap, touches no
disk, and is exempt from the login throttle — the right target. It exercises
the full HTTP, routing and auth-store path, and leaks only whether an admin
account exists.

```yaml
healthcheck:
  test:
    - CMD
    - bash
    - -c
    - >-
      exec 3<>/dev/tcp/127.0.0.1/8342 &&
      printf 'GET /api/bootstrap HTTP/1.0\r\nHost: localhost\r\n\r\n' >&3 &&
      head -1 <&3 | grep -q ' 200 '
  interval: 30s
  timeout: 5s
  start_period: 30s
  retries: 3
```

Two details that are easy to get wrong. It uses bash's `/dev/tcp` rather than
`curl`, so the runtime image stays free of an HTTP client — but that means
`bash` must be named explicitly, because `/bin/sh` is dash here and has no
`/dev/tcp`. And the command is a **folded block scalar** (`>-`) rather than a
quoted string: inside a double-quoted YAML scalar the `\r\n` would be
converted to real control characters before `printf` ever saw them.

`podman healthcheck run avb` runs it on demand.

> **Podman drops the image's `HEALTHCHECK` by default.** The OCI image format
> has no healthcheck field, so `podman build` discards the instruction with
> only a warning — `HEALTHCHECK is not supported for OCI image format and will
> be ignored`. Build with `--format docker` to keep it, or define the probe at
> run time instead (`--health-cmd`, or the compose `healthcheck:` block above,
> both of which work regardless of image format). Docker is unaffected.

**Shutdown is graceful and quick.** On `SIGTERM`/`SIGINT` the daemon stops
accepting, tells every WebSocket stream to close (clients receive a `1001
Going Away` frame within about 100 ms and reconnect to the restarted
instance on their own), wakes idle keep-alive connections out of their
socket wait, lets requests that are mid-handler finish, and exits 0. With
nothing heavy in flight that takes well under a second; the CI smoke test
requires it inside ten. A **second** `SIGTERM`/`SIGINT` exits immediately
(status `128+signal`) for an operator who cannot wait.

What can still hold a stop is a request that is genuinely busy — a large
upload being validated, or a response being sent to a client that has
stopped reading (bounded by the 30 s socket timeout). Give `stop` a timeout
longer than your largest upload takes: `--stop-timeout=60`, the compose
files' `stop_grace_period: 60s`, or `TimeoutStopSec=60` in a Quadlet unit.
SIGKILL after that is not *corrupting* — index writes are atomic and durable,
and analysis is rebuilt on the next start — but the interrupted request is
lost.

**Restart policy.** `--restart=unless-stopped` (or `Restart=on-failure`) is
right. There is no clustering, so a restarting instance is briefly
unavailable to its shard, and it logs its users out — tokens live in memory
(§1). It cannot corrupt anything by restarting.

**Updating.** Rebuild, then recreate — the volume carries the data across:

```bash
podman build -t avb-introspection .
podman stop avb && podman rm avb
podman run -d --name avb ...   # same flags, same volume
```

Take the §5 snapshot first on anything you care about. There is no schema
migration, and no rollback. `podman run --rm avb-introspection --version`
(or the `org.opencontainers.image.version` label) tells you what a given
image is, if you stamped the build with `--build-arg VERSION`.

---

## 10. What true replication would require

Included so the constraint in §1 reads as a known boundary rather than an
oversight. To put N interchangeable replicas behind one pool, all of the
following would have to change:

1. **Tokens** — currently opaque random values in a per-process map. They
   would need to be signed and stateless (HMAC/JWT with an expiry and a shared
   secret), or moved to a shared store.
2. **Identifiers** — replace the in-memory `mNextPcap`/`mNextSession`
   counters with UUIDs or a shared allocator.
3. **Metadata** — replace whole-file JSON rewrites with per-record writes
   under compare-and-swap. Pointing today's code at a shared filesystem does
   *not* fix this: the races are in the read-modify-write, not the storage
   medium.
4. **Analysis results** — persist the event log, packet index and state
   snapshots so any replica can serve a session it did not analyze. Today the
   session list is served from the in-memory engine.
5. **Presence and the WebSocket stream** — need a shared bus; both are
   strictly process-local today.
6. **Rate limiting and FlowGuard** — shared counters, or accept the N×
   dilution and compensate at the proxy.

Until then §7 is the answer, and for the multi-tenant workloads this tool is
built for it is a good one: stronger isolation than replicas would give, and
no distributed state to go wrong.

---

## 11. Troubleshooting

- **`fatal:` about `meta.json`, and the container exits 1** — the metadata
  file is unparseable, almost always because two instances shared a volume
  (§1). Restore `<data>` from a snapshot; the captures under `pcaps/` and
  `sessions/` are intact, only the index is lost.
- **Random 401s, sessions appearing and disappearing** — more than one
  instance is serving one origin. Look for a `--scale`d service or a second
  `server` line in an nginx `upstream`.
- **Permission denied on `/data` under rootless Podman** — a bind mount owned
  by your host uid. Use a named volume, or add `:U`, or `--userns=keep-id`
  (§2a).
- **WebSocket closes with code `4004`** — that instance does not know the
  session id: either it was created on another shard, or the container was
  recreated and the id came from a stale browser tab.
- **The live event stream never connects** — the proxy is not forwarding
  `Upgrade`/`Connection` for `/api/ws`. The shipped nginx configs do.
- **Upload fails with `501`** — something in the chain is chunking the body;
  the server requires a `Content-Length`.
- **Upload fails at a size the app should accept** — nginx
  `client_max_body_size` is below `--max-upload-mb`.
- **Container OOM-killed during an upload** — uploads are buffered in memory
  at roughly 3× their size; raise `--memory` or lower `--max-upload-mb` (§8).
- **OOM-killed shortly after start instead** — that is the restore loop
  re-analyzing every session at once (§9). More memory, or fewer retained
  sessions.
- **`"<tool> is not installed on the backend host"`** — a compressed upload;
  the runtime image ships no decompressors by default (§3).
- **The UI stalls under load with idle browsers connected** — thread-pool
  exhaustion from long-lived WebSockets; raise `--max-threads` (§8).
- **`podman stop` takes a long time and ends in SIGKILL** — a busy request
  (large upload validating, or a client not reading its response) is being
  allowed to finish; raise `--stop-timeout` (§9). Idle connections and event
  streams no longer hold a stop.
- **Everyone gets `429` on login the moment one client misbehaves**, or the
  admin Security panel attributes all traffic to one address — the app is
  seeing the proxy's address. Set `AVB_TRUSTED_PROXIES` (§4); the shipped
  compose stacks do.
- **`fatal: AVB_TRUSTED_PROXIES: bad address or CIDR range`** — a typo in the
  list; the daemon refuses to start rather than silently trust nobody.
