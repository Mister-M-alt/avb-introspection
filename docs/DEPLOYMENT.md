<!-- SPDX-FileCopyrightText: 2026 Kebag-Logic -->
<!-- SPDX-License-Identifier: MIT -->

# Deployment guide — five levels

AVB Introspection is one self-contained binary (JSON/WebSocket API plus the
web UI on a single port, default `8342`, no database) — so deploying it is
mostly a question of *how exposed and how hardened* you need to be. This
guide is a ladder. Pick the **lowest level that fits**, follow it top to
bottom, and climb only when a later section's "what you gain" matters to you.
Every level is complete on its own: prerequisites, steps, a **check** block
with expected output, and the day-two operations (update, back up).

```
Level 1  Quick start        one container, your machine          podman/docker run          5 min
Level 2  Team               compose stack behind nginx, a LAN    deploy/docker-compose.yml  15 min
Level 3  Production host    systemd sandbox + nginx TLS          deploy/install.sh          1 h
Level 4  Hardened network   two hosts, VLANs, default-deny       NETWORK.md + firewall.nft  ½ day
Level 5  Expert             multi-tenant shards, Quadlet, sizing docker-compose.scale.yml   as needed
```

- [Choose a level](#choose-a-level)
- [Level 1 — Quick start: one container](#level-1--quick-start-one-container)
- [Level 2 — Team: compose stack behind nginx](#level-2--team-compose-stack-behind-nginx)
- [Level 3 — Production: systemd + nginx with TLS on one host](#level-3--production-systemd--nginx-with-tls-on-one-host)
- [Level 4 — Hardened: segmented network, two hosts](#level-4--hardened-segmented-network-two-hosts)
- [Level 5 — Expert: multi-tenant and scale-out](#level-5--expert-multi-tenant-and-scale-out)
- Reference, all levels: [First login & the admin account](#first-login--the-admin-account) ·
  [Where data lives](#where-data-lives) · [Where to store captures](#where-to-store-captures) ·
  [Backup & restore](#backup--restore) ·
  [Updating](#updating) · [Server options & environment](#server-options--environment) ·
  [Optional decompressors](#optional-system-tools-compressed-captures) ·
  [Developer build](#developer-build-no-container) · [Troubleshooting](#troubleshooting)

The deep references behind the levels: **[CONTAINER.md](CONTAINER.md)**
(image, volumes, hardening flags, scale-out, sizing — Levels 1, 2, 5),
**[SECURITY.md](SECURITY.md)** (threat model, sandbox, proxy hardening,
verification matrix — Levels 3, 4) and **[NETWORK.md](NETWORK.md)** (VLAN
plan, inter-VLAN ACLs — Level 4).

---

## Choose a level

| | Level 1 | Level 2 | Level 3 | Level 4 | Level 5 |
| --- | --- | --- | --- | --- | --- |
| **For** | trying it, a lab bench | a team on a trusted LAN | one internet-facing server | regulated / hostile networks | several tenants, or one box is not enough |
| **Runs as** | one container | container + nginx container | systemd service + host nginx | Level 3 on an isolated VLAN | one container **per tenant** (+ Quadlet) |
| **Reachable from** | your machine | the LAN, port 80/443 | the internet, 443 only | the internet, via a DMZ | any of the above |
| **TLS** | no | optional (own certs) | yes (certbot or PKI) | yes | yes |
| **Client IPs seen by the app** | direct | yes (`AVB_TRUSTED_PROXIES` set) | yes (loopback proxy) | yes (trusted DMZ proxy) | yes |
| **Sandbox** | container defaults | read-only, no caps, internal net | systemd: read-only FS, seccomp, no egress | + host firewall + VLAN ACLs | kernel isolation per tenant |
| **Tenants** | one | in-process domains | in-process domains | in-process domains | a container each |
| **You need** | podman or docker | compose | a VM, DNS name, certificate | a network team, a bastion | Level 2 or 3 fluency |

Two rules hold at every level, because of how the backend keeps state
(memory is authoritative, disk is a write-behind snapshot):

- **One running instance per data directory / volume, always.** Never
  `--scale`, never two `server` lines in an nginx `upstream`. To grow, add
  *instances* with their own data (Level 5). [CONTAINER.md §1](CONTAINER.md#1-read-this-first--replicas-are-not-safe)
  lists exactly what breaks otherwise.
- **Provision the first admin from the environment** (`AVB_ADMIN_USER` /
  `AVB_ADMIN_PASSWORD`) on anything reachable by others. Until an admin
  exists, whoever registers first becomes one — and `AVB_DISABLE_REGISTRATION`
  does not close that window. The daemon prints a warning at startup while it
  is open.

---

## Level 1 — Quick start: one container

**For:** trying the tool, a capture bench, a single analyst.
**You get:** the full UI and API on your machine, data that survives restarts,
a health check, graceful stop. **Not yet:** TLS, hardening, exposure beyond
your machine — do not publish this port to a network you do not trust.

**Prerequisites:** Podman or Docker, and this repository (or a release
bundle).

```bash
# Build the image. Podman needs --format docker or the HEALTHCHECK is dropped.
podman build --format docker -t avb-introspection .      # docker: docker build -t avb-introspection .

# Run it: data in a named volume, the first admin from the environment.
podman volume create avb-data
podman run -d --name avb -p 8342:8342 \
  -e AVB_ADMIN_USER=admin -e AVB_ADMIN_PASSWORD='change-me-please' \
  -v avb-data:/data \
  avb-introspection
```

Open <http://localhost:8342> and log in as that admin. No traffic handy?
`python3 tools/gen_pcaps.py` writes Milan scenarios to `testdata/`; upload
`testdata/milan_scenario.pcap`.

**Check:**

```bash
curl -s http://localhost:8342/api/bootstrap      # {"needs_admin":false}
podman healthcheck run avb && echo healthy       # docker: docker inspect -f '{{.State.Health.Status}}' avb
podman logs avb | grep 'listening on'            # printed only once the port is bound
```

**Operate:**

```bash
podman stop avb                                  # graceful: streams closed, requests finished, ~1 s
podman start avb
podman run --rm avb-introspection --version      # what is this image?

# Update: rebuild, recreate with the same volume (data is in the volume, not the container).
podman build --format docker -t avb-introspection . && podman rm -f avb && podman run -d --name avb ... # same flags

# Back up (stopped = consistent), restore = untar into an empty volume the same way.
podman stop avb
podman run --rm -v avb-data:/data:ro -v "$PWD":/backup docker.io/library/busybox tar czf /backup/avb-data.tgz -C /data .
podman start avb
```

**Good to know:** rootless Podman cannot publish ports below 1024 (keep 8342
or anything ≥ 1024) and wants a *named* volume rather than a bind mount; both
are explained in [CONTAINER.md §2a](CONTAINER.md#2a-podman-rootless). If the
machine is shared, publish on loopback only: `-p 127.0.0.1:8342:8342`.
Compressed uploads need the matching decompressor in the image — see
[Optional decompressors](#optional-system-tools-compressed-captures). Where
the captures end up on disk, and how to give them a bigger disk:
[Where to store captures](#where-to-store-captures).

**Level 2 adds:** an nginx front door, a hardened container on an internal
network, an env file instead of secrets on the command line, optional TLS.

---

## Level 2 — Team: compose stack behind nginx

**For:** a team on a trusted LAN, or a host that already sits behind your
own TLS terminator. **You get:** nginx on port 80 (443 once you add
certificates) in front of a backend that runs read-only with no capabilities
on an internal network with no route out, resource caps, security headers,
edge rate limiting, and correct client addresses inside the app. **Not yet:**
the OS-level sandbox and egress firewall of a systemd host, automated
certificates.

**Prerequisites:** Level 1 tooling plus `docker compose` (v2) or
`podman-compose`.

**Steps:**

```bash
# 1. Admin credentials. The stack refuses to start without this file — on purpose.
cp deploy/env/app.env.example deploy/env/app.env && chmod 600 deploy/env/app.env
$EDITOR deploy/env/app.env          # AVB_ADMIN_USER, AVB_ADMIN_PASSWORD; AVB_DISABLE_REGISTRATION=1 is preset

# 2. Up.
docker compose -f deploy/docker-compose.yml up --build -d
# podman-compose -f deploy/docker-compose.yml up -d
```

Rootless Podman cannot bind port 80: change `"80:80"` to `"8080:80"` under
the nginx service (redirects stay on that port — the config uses relative
`Location` headers), or raise `net.ipv4.ip_unprivileged_port_start`.

**Check:**

```bash
docker compose -f deploy/docker-compose.yml ps             # app "healthy", nginx "running"
curl -s http://localhost/api/bootstrap                      # {"needs_admin":false}   (through nginx)
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8342/api/bootstrap   # 000: the backend is not published
curl -s -o /dev/null -D - -H 'Accept-Encoding: gzip' http://localhost/app.js | grep -i content-encoding   # gzip (static assets only)
```

Log in, then open **Admin → Security**: unauthenticated traffic must be
attributed to *your* address, not to the nginx container's. That is
`AVB_TRUSTED_PROXIES` at work (the compose file sets it); without it every
per-IP limit would key on nginx and one bad client could lock everyone out
of login ([CONTAINER.md §4](CONTAINER.md#4-configuration)).

**Add TLS (own certificates):**

1. Put `fullchain.pem` and `privkey.pem` in `deploy/certs/`.
2. In `deploy/docker-compose.yml` uncomment the `443:443` port and the
   `./certs` volume on the nginx service.
3. In `deploy/nginx.conf` uncomment the TLS `server {}` block, set its
   `server_name`, and turn the plain `:80` server into a redirect
   (`return 301 https://$host$request_uri;`) if you do not want plain HTTP
   on the LAN.
4. `docker compose -f deploy/docker-compose.yml up -d` (recreates nginx).

The app can also be mounted under a path prefix (`/avb_investigation/` is
pre-wired in `nginx.conf`; the SPA detects its base path at runtime), which
is handy when nginx already serves other things on `/`.

**Operate:**

```bash
docker compose -f deploy/docker-compose.yml logs -f app                    # startup banner, warnings
docker compose -f deploy/docker-compose.yml exec app tail -n 20 /data/security.log   # audit trail (JSONL)

# Update: pull/checkout, rebuild, recreate. The volume carries the data.
docker compose -f deploy/docker-compose.yml up --build -d

# Back up: stop the app (nginx can stay), tar the volume, start. `docker volume ls` shows the
# exact volume name (compose prefixes it with the project name, here "deploy").
docker compose -f deploy/docker-compose.yml stop app
docker run --rm -v deploy_avb-data:/data:ro -v "$PWD":/backup busybox tar czf /backup/avb-data.tgz -C /data .
docker compose -f deploy/docker-compose.yml start app
```

**Sizing:** uploads are buffered in RAM at roughly three times their size,
so `mem_limit` (4g) and `--max-upload-mb` (default 1024, mirrored by
`client_max_body_size` in `nginx.conf`) are chosen together. Lower both for a
small box; raise `--max-threads` if many browsers watch sessions at once —
[CONTAINER.md §8](CONTAINER.md#8-scaling-up--sizing-one-instance) has the
arithmetic.

**Level 3 adds:** a systemd-native install with journald logs, an OS sandbox
that also denies egress, Let's Encrypt automation, and a host that is
designed to face the internet.

---

## Level 3 — Production: systemd + nginx with TLS on one host

**For:** one server that people reach from anywhere. **You get:** the daemon
as a sandboxed system service (read-only filesystem, no capabilities,
seccomp allow-list, a cgroup egress firewall so a compromise cannot phone
home, CPU/memory ceilings), bound to loopback behind an nginx that
terminates TLS with HSTS, security headers and edge rate limits — plus
backups, updates and a verification you can rerun after every change.
**Not yet:** network segmentation and a default-deny host firewall (Level 4).

**Prerequisites:** a Linux VM or host with systemd, a DNS name pointing at
it, ports 80/443 reachable, and either Let's Encrypt (certbot) or
certificate files from your PKI. Build tools: `g++` (C++20), `make`, `zlib`,
`libsodium` development packages — or a release bundle that already contains
the binary.

### 3a. The service

```bash
# Debian/Ubuntu: sudo apt install g++ make zlib1g-dev libsodium-dev
# Fedora:        sudo dnf install gcc-c++ make zlib-devel libsodium-devel
make -j                                                        # -> build/avb-introspectd

sudo AVB_ADMIN_USER=admin AVB_ADMIN_PASSWORD='change-me' AVB_DISABLE_REGISTRATION=1 \
     ./deploy/install.sh
```

`install.sh` creates the `avb` account, installs the binary and frontend
under `/opt/avb-introspection`, installs the unit, writes
`/etc/avb-introspection/env` (mode 0600) and starts the service. The data
directory `/var/lib/avb-introspection` is created and owned by the unit
itself (`StateDirectory=`). Re-running the script later is the upgrade path.
The manual equivalent of every step is in the unit file's header.

**Check:**

```bash
systemctl status avb-introspectd                        # active (running)
ss -ltnp | grep 8342                                    # 127.0.0.1:8342 — loopback only, never 0.0.0.0
curl -s http://127.0.0.1:8342/api/bootstrap             # {"needs_admin":false}
systemd-analyze security avb-introspectd                # exposure score: aim for "OK" / low
journalctl -u avb-introspectd -b | grep 'listening on'  # readiness line, printed after the bind
```

### 3b. nginx with TLS

```bash
sudo apt install nginx certbot                           # or your distro's equivalents

# 1. Install the hardened template. Its 443 block needs certificate files before nginx will
#    start, so begin with a throwaway self-signed pair (your own PKI: point at those files
#    instead and skip steps 2-3).
sudo openssl req -x509 -newkey rsa:2048 -nodes -days 7 -subj /CN=avb.example.com \
     -keyout /etc/ssl/private/avb-bootstrap.key -out /etc/ssl/certs/avb-bootstrap.crt
sudo cp deploy/nginx.production.conf /etc/nginx/conf.d/avb.conf
sudo sed -i 's/__SERVER_NAME__/avb.example.com/g; s#__APP_UPSTREAM__#127.0.0.1:8342#; s#__CERT__#/etc/ssl/certs/avb-bootstrap.crt#; s#__KEY__#/etc/ssl/private/avb-bootstrap.key#; s/__MAX_UPLOAD__/1024m/' \
    /etc/nginx/conf.d/avb.conf
sudo nginx -t && sudo systemctl reload nginx

# 2. Real certificate via the webroot the template already serves on :80. certbot records the
#    webroot method and the deploy hook, so renewals (its timer) need nothing further.
sudo mkdir -p /var/www/certbot
sudo certbot certonly --webroot -w /var/www/certbot -d avb.example.com \
     --deploy-hook 'systemctl reload nginx'

# 3. Switch nginx to it and drop the bootstrap pair.
sudo sed -i 's#/etc/ssl/certs/avb-bootstrap.crt#/etc/letsencrypt/live/avb.example.com/fullchain.pem#; s#/etc/ssl/private/avb-bootstrap.key#/etc/letsencrypt/live/avb.example.com/privkey.pem#' \
    /etc/nginx/conf.d/avb.conf
sudo nginx -t && sudo systemctl reload nginx
sudo rm /etc/ssl/certs/avb-bootstrap.crt /etc/ssl/private/avb-bootstrap.key
sudo certbot renew --dry-run                             # proves the renewal path end to end
```

The template redirects `:80` to HTTPS, sets HSTS, CSP and the other headers,
rate-limits per IP at the edge (login and register tighter), streams uploads
through without buffering, and forwards the WebSocket upgrade for `/api/ws`.
On some distributions a default site also listens on `:80`; remove it if you
do not want it. Newer nginx logs a deprecation note for the template's
`listen ... http2` form — that form is deliberate, the alternative directive
does not exist on the nginx that Debian 12, Ubuntu 24.04 and RHEL 9 ship.

Because nginx and the daemon share the host, the proxy is a **loopback
peer** and its `X-Real-IP` is believed automatically: no `AVB_TRUSTED_PROXIES`
needed. Confirm in **Admin → Security** that actors carry real client
addresses.

### 3c. Host firewall

A single host needs only an inbound allow-list; use whatever you standardise
on:

```bash
sudo ufw default deny incoming && sudo ufw allow 22/tcp && sudo ufw allow 80,443/tcp && sudo ufw enable
```

Do **not** apply `deploy/firewall.nft` here yet: its default-deny *egress*
chain would block certbot renewals and package updates unless you add those
destinations. That template belongs to Level 4, where the app host originates
nothing.

### 3d. Check from outside, then keep checking

```bash
base=https://avb.example.com
nmap -Pn -p 22,80,443,8342 avb.example.com                                # 443 open · 8342 closed/filtered
curl -s -o /dev/null -w '%{http_code}\n' $base/api/sessions               # 401 without a token
for i in $(seq 9); do curl -s -o /dev/null -w '%{http_code} ' \
  -XPOST $base/api/login -d '{"username":"admin","password":"x"}'; done; echo   # 401 ×6, then 429
curl -sI $base/ | grep -i -E 'strict-transport|content-security'          # HSTS + CSP present
```

[SECURITY.md §8](SECURITY.md#8-verification--prove-it-cant-be-bypassed) is
the full matrix (sandbox, ports, auth, tenant isolation, flow monitor);
rerun it after every change.

**Operate:**

- **Logs:** `journalctl -u avb-introspectd -f`; the security audit trail is
  `/var/lib/avb-introspection/security.log` (append-only JSONL) — ship it to
  your log store together with nginx's access log.
- **Update:** build the new version, then `sudo ./deploy/install.sh` (stops,
  swaps, restarts; `avb-introspectd --version` shows what runs). Sessions are
  re-analyzed from their stored captures at start.
- **Back up:** see [Backup & restore](#backup--restore) — stop, tar the data
  directory, start.
- **Sizing:** the unit caps memory at 2G; with the default 1 GiB upload
  limit one large upload can hit that. Either raise `MemoryMax=` or add
  `--max-upload-mb 512` to `ExecStart=` (and lower `client_max_body_size` to
  match). Changing `--max-threads` needs a matching `TasksMax=`.
- **Captures on another disk:** either mount the disk at
  `/var/lib/avb-introspection` before the service starts, or move just the
  library there from Admin → Storage after adding the path to
  `ReadWritePaths=` — both spelled out in
  [Where to store captures](#where-to-store-captures).

**Level 4 adds:** the app on its own VLAN with a DMZ proxy, a default-deny
host firewall, and proof that a fully compromised app still cannot reach the
rest of your network.

---

## Level 4 — Hardened: segmented network, two hosts

**For:** environments where the analyzer must be assumed compromisable —
external users, compliance, mixed-trust networks. **You get:** nginx alone in
a DMZ, the daemon on an app VLAN with **no route anywhere** (default-deny
egress at the host *and* at the VLAN boundary, plus the unit's cgroup egress
firewall — three independent layers), management only from a bastion, and a
verification matrix that proves it. **Not yet:** per-tenant kernel isolation
(Level 5).

**Prerequisites:** Level 3 fluency; two hosts (or VMs); the ability to
provision VLANs and inter-VLAN ACLs. Read
[NETWORK.md](NETWORK.md) once end to end — this section is the checklist for
it.

### 4a. Decide the addresses

| Placeholder | Meaning | Example |
| --- | --- | --- |
| nginx host (DMZ, VLAN 20) | the only thing users reach; the only thing that reaches the app | `10.20.0.5` |
| app host (VLAN 30) | where the daemon binds | `10.30.0.10` |
| bastion (VLAN 40) | the only source allowed to SSH to the app host | `10.40.0.5` |
| DNS / NTP | only if the app host needs them at all | `10.40.0.53` / `10.40.0.123` |

The full VLAN plan and the inter-VLAN ACL intent (four permitted flows,
everything else denied and logged) are in
[NETWORK.md §2–3](NETWORK.md#2-fill-in-values).

### 4b. App host

Install as in Level 3a, then point the daemon at its VLAN address and tell it
which proxy to believe:

```bash
# Listen on the app-VLAN address instead of loopback, and admit the DMZ nginx through the
# unit's cgroup firewall (drop-ins add to IPAddressAllow=; ExecStart= must be cleared first).
sudo systemctl edit avb-introspectd
#   [Service]
#   ExecStart=
#   ExecStart=/opt/avb-introspection/avb-introspectd --bind 10.30.0.10 --port 8342 --data /var/lib/avb-introspection --frontend /opt/avb-introspection/frontend
#   IPAddressAllow=10.20.0.5

# The DMZ proxy is not loopback any more: without this, every per-IP limit keys on nginx.
echo 'AVB_TRUSTED_PROXIES=10.20.0.5' | sudo tee -a /etc/avb-introspection/env
sudo systemctl restart avb-introspectd
ss -ltnp | grep 8342                                     # 10.30.0.10:8342
```

Then the host firewall — default-deny both ways, with a safety net so a
mistake cannot lock you out:

```bash
sudo sed 's/__NGINX_IP__/10.20.0.5/; s/__BASTION_IP__/10.40.0.5/; s/__DNS_IP__/10.40.0.53/; s/__NTP_IP__/10.40.0.123/' \
    deploy/firewall.nft | sudo tee /etc/nftables.conf >/dev/null
sudo nft -c -f /etc/nftables.conf                        # syntax check
sudo systemd-run --unit=nft-safety --on-active=120 nft flush ruleset   # auto-undo in 2 minutes
sudo nft -f /etc/nftables.conf
# still able to SSH from the bastion? then keep it:
sudo systemctl stop nft-safety.timer
sudo systemctl enable --now nftables
```

Delete the DNS/NTP lines if the host needs neither; add anything else the
host legitimately originates (package mirror, log shipping) explicitly. A hit
on the `nft-egress-drop` log line is an alarm, not noise — wire it to your
SIEM.

### 4c. DMZ host

Level 3b with one difference: `__APP_UPSTREAM__` is `10.30.0.10:8342`. The
DMZ host's own firewall allows inbound 443 (and 80 for the redirect / ACME)
and outbound 8342 to the app host only.

### 4d. Prove it

From the users' VLAN, the app host, and the bastion — each line's expected
result is what makes the layout worth having:

```bash
nmap -Pn -p 22,80,443,8342 avb.example.com     # users' VLAN: 443 open, everything else filtered
nmap -Pn -p 8342 10.30.0.10                    # users' VLAN: filtered (only the DMZ may reach it)
sudo -u avb curl -m3 https://1.1.1.1           # app host: MUST fail — egress is dead
systemd-analyze security avb-introspectd       # app host: sandbox intact
grep -E 'CapEff|NoNewPrivs' /proc/$(systemctl show -p MainPID --value avb-introspectd)/status
```

then the application-level rows of
[SECURITY.md §8c–8e](SECURITY.md#8c-auth-limits-and-brute-force-protection-are-live)
(auth, throttles, cross-tenant 404s, FlowGuard alerts landing in
`security.log`). Keep the outputs; they are your evidence.

**Operate:** as Level 3, with two additions — `security.log` *and* the
firewall's `nft-egress-drop` / VLAN `deny log` hits go to the SIEM, and
updates are staged through the bastion (`scp` the bundle, `sudo
./install.sh`); the app host cannot fetch anything itself.

**Level 5 adds:** one container per tenant for kernel-enforced isolation,
horizontal growth by sharding, and the sizing knobs for big captures and
many concurrent viewers.

---

## Level 5 — Expert: multi-tenant and scale-out

**For:** several organisations on one service, or a single instance that has
run out of headroom. **You get:** kernel-level isolation between tenants,
deterministic routing to per-tenant instances, systemd-managed containers
(Quadlet), capacity signals that tell you *when* to split, and the knobs for
a large instance. **The constraint that shapes all of it:** an instance is
never replicated — it is *partitioned*.
[CONTAINER.md §1](CONTAINER.md#1-read-this-first--replicas-are-not-safe)
and [§10](CONTAINER.md#10-what-true-replication-would-require) explain why and
what true replication would require.

### 5a. Which isolation?

| | In-process **domains** | One **container per tenant** |
| --- | --- | --- |
| Set up | Admin → Domains, no infrastructure | one service + volume + `location` per tenant |
| Isolation | enforced by every handler (cross-domain = 404), covered by tests | enforced by the kernel: separate volume, memory, quotas |
| Shared | process, memory, rate-limit budget, a single global admin | nothing — each tenant has its own admin and limits |
| Use when | teams of one organisation that trust the operator | external customers, compliance, or a noisy tenant |

They compose: a container per *customer*, domains for that customer's
*teams* ([SECURITY.md §4](SECURITY.md#4-tenant-isolation--domains)).

### 5b. The sharded stack (compose)

```bash
for t in acme globex initech; do
  cp deploy/env/$t.env.example deploy/env/$t.env && chmod 600 deploy/env/$t.env
done
$EDITOR deploy/env/acme.env deploy/env/globex.env deploy/env/initech.env   # one admin per shard, never shared
docker compose -f deploy/docker-compose.scale.yml up --build -d          # or podman-compose … up -d
```

**Check:**

```bash
docker compose -f deploy/docker-compose.scale.yml ps        # three shards "healthy"
curl -s http://localhost/acme/api/bootstrap                  # {"needs_admin":false}
curl -s -o /dev/null -w '%{http_code}\n' http://localhost/   # 404: a bare "/" is deliberately unrouted
```

Each shard is a complete Level 2 instance: its own volume, env, resource
caps, `AVB_TRUSTED_PROXIES`, health check; all on one internal network
behind one nginx that routes by path prefix
(`deploy/nginx.scale.conf`). **Adding a tenant** is copying one service
block plus its volume in the compose file, one env file, and one `location`
group in the nginx config — no registry, nothing to migrate. **Removing** one
is the reverse plus `docker volume rm` when you are sure. Route by
**subdomain** instead if you hold wildcard DNS and a wildcard certificate
(the alternative block in `nginx.scale.conf`); each tenant then has its own
origin, which is also stronger browser-side isolation.

**Rolling update, one shard at a time** (a shard's users are logged out by
its restart, so schedule it):

```bash
docker compose -f deploy/docker-compose.scale.yml build
docker compose -f deploy/docker-compose.scale.yml up -d --no-deps acme
curl -s http://localhost/acme/api/bootstrap && docker compose -f deploy/docker-compose.scale.yml up -d --no-deps globex
```

Stamp builds (`AVB_VERSION=$(git describe --tags --always) docker compose … build`)
so `podman run --rm avb-introspection --version` and the image label tell you
what each shard runs.

### 5c. Server-grade: Quadlet

On a server, long-lived compose processes are the wrong tool. Podman's
Quadlet generates a systemd unit per container from a declarative file, so
each shard gets journald logs, `systemctl status`, ordering and restart
policy — the recipe with the hardening flags is
[CONTAINER.md §7d](CONTAINER.md#7d-podman-pods-and-quadlet). Pair it with a
Level 3 nginx on the host: each shard publishes on a distinct loopback port
(`127.0.0.1:8342`, `:8343`, …) and the production nginx template's
multi-tenant variant routes to them. With the port publish, the proxy is
loopback from the container's point of view, so client addresses arrive
correctly without `AVB_TRUSTED_PROXIES` — verify in each shard's
Admin → Security panel.

### 5d. Sizing one instance

| Knob | Bounds | Size it by |
| --- | --- | --- |
| `--max-upload-mb` + memory cap | one upload costs ~3× its size in RAM | `mem_limit` / `MemoryMax` ≥ 3 × upload limit + working set; nginx `client_max_body_size` ≥ upload limit |
| `--max-threads` (+ `pids_limit` / `TasksMax`) | every open WebSocket holds a serving thread | peak concurrent session viewers + headroom for HTTP |
| CPUs | parallel decode, then a serialized state pass | more cores shorten analysis; the state pass is the ceiling |
| retained sessions | every session's events, index and state live in RAM, and all are restored at start | delete finished sessions; measure via `/api/metrics` |

Details and the failure modes of getting each wrong:
[CONTAINER.md §8](CONTAINER.md#8-scaling-up--sizing-one-instance).

### 5e. Knowing when to split

`GET /api/metrics` (any user) shows pool size, connections and per-session
throughput; `GET /api/admin/monitor` (global admin) shows process CPU and
memory plus **requests per minute per domain** — the domain at the top of
that list is the one to move to its own shard. Both describe the instance
that answered; scrape every shard. In containers the *host* memory figures
come from `/proc/meminfo` and ignore the cgroup limit — use `podman stats`
for the cgroup view ([CONTAINER.md §7e](CONTAINER.md#7e-capacity--knowing-when-to-split)).

### 5f. Kubernetes (guidance, not a shipped artifact)

No manifests are shipped, but the image works under Kubernetes if you honour
the single-instance model: a `Deployment` with `replicas: 1` and
`strategy: Recreate` (never `RollingUpdate`, which would briefly run two pods
on one volume) over a `ReadWriteOnce` PVC at `/data`; `runAsUser: 999`,
`runAsNonRoot: true`, `readOnlyRootFilesystem: true`, `capabilities.drop:
[ALL]`; readiness and liveness probes on `GET /api/bootstrap` with a start
delay proportional to retained sessions; `terminationGracePeriodSeconds: 60`;
resources from 5d; env from a `Secret`; and `AVB_TRUSTED_PROXIES` set to the
ingress controller's pod CIDR (it is not loopback). One such Deployment per
tenant is the Level 5 model on a cluster.

---

## First login & the admin account

There are two ways to get the first administrator:

- **Provisioned (all levels beyond your own machine).** Set
  `AVB_ADMIN_USER` / `AVB_ADMIN_PASSWORD` in the environment (Level 1: `-e`;
  Level 2/5: the env files; Level 3/4: `/etc/avb-introspection/env`). The
  account is created as admin on first start, or promoted if it already
  exists. The password is only used when the account is first created.
- **First-run setup (no env provided).** If no admin exists yet, the login
  screen shows a **first-time setup** banner and the very first account you
  create becomes the administrator. Every account created afterwards is a
  regular user. `AVB_DISABLE_REGISTRATION=1` does *not* suppress this
  bootstrap, and the daemon warns on stderr while it is open — provision
  explicitly on anything exposed.

Admins get an **Admin** panel: create/delete users and roles (you cannot
delete your own account or the last remaining admin), live presence,
**Monitoring**, **Security** (flow alerts and sampled flows), **Domains**
(isolated tenants with owners), and a **Storage** section to change where the
pcap library is kept on disk.

---

## Where data lives

Everything is under the `--data` directory (`./data` locally, `/data` in a
container, `/var/lib/avb-introspection` for the service), and survives
restarts:

```
<data>/users.json                 accounts (Argon2id password hashes; mode 0600)
<data>/meta.json                  pcap + session index, folders, storage root, domains
<data>/devices.json               user-assigned device names
<data>/security.log               append-only security alerts (JSONL)
<data>/pcaps/<id>.pcap            uploaded capture library (root configurable)
<data>/pcaps/domains/<dom>/…      the library of every non-default domain
<data>/sessions/<id>/capture.pcap each session's own self-contained copy
<data>/sessions/<id>/notes.md     investigation notes
```

A session keeps its **own** copy of the capture, so deleting a library pcap
(or its original server path) never breaks an existing investigation —
budget disk for it (next section). The index files are written crash-safely
(temp file, `fsync`, rename), so a reader never sees a torn file and a
completed write survives a power loss.

Analysis results are **not** stored — events, the packet index and the
protocol state machines are rebuilt by re-analyzing each session's capture at
every start. That keeps the directory small, but startup costs CPU (and
steady-state memory) proportional to how many sessions you retain.

## Where to store captures

Captures are the only thing that takes real space, so decide this once, per
deployment. A capture can live in three places:

| Place | Path | Who writes it | Relocatable? |
| --- | --- | --- | --- |
| **The library** — every upload | `<pcap root>/<id>.pcap`; non-default domains under `<pcap root>/domains/<dom>/` | the daemon, on upload | yes — the *pcap root* defaults to `<data>/pcaps` and can be moved (below) |
| **Session copies** — one per analysis session | `<data>/sessions/<id>/capture.pcap` | the daemon, when a session is created (a combined session holds the merged capture) | no — always under the data directory, so a session stays self-contained |
| **A drop folder** — captures produced elsewhere | anywhere the daemon can *read*, e.g. `/srv/captures` fed by your capture appliance | you (or your tooling) | n/a — opened by an **admin** via "server path"; the file is copied into the session and never modified |

### Pick a layout

| You want | Do this | Keep in mind |
| --- | --- | --- |
| **The default** — small library, few sessions | nothing: everything sits under the data directory (`./data`, `/data` in a container, `/var/lib/avb-introspection` under systemd) | size that disk for library **plus** one copy per session |
| **One big disk for everything** (recommended) | mount it *at the data directory*: a filesystem on `/var/lib/avb-introspection` (systemd — see the mount note below) or as the `/data` volume (containers: create the named volume on that disk, or bind-mount it with `:U` under rootless Podman) | one place to size, snapshot and back up; library, sessions, notes and accounts move together |
| **Only the library elsewhere** — sessions small, library huge | `Admin → Storage`, enter the absolute path, **Apply** (API: `PUT /api/admin/storage {"pcap_root": "/mnt/captures"}`) | session copies stay in the data directory; the path must be writable by the service (prerequisites below); an empty value resets to the default |
| **A drop folder** for captures taken by other machines | export it read-only to the app host and have an admin open files by server path (Level 3/4: any path readable by user `avb`; containers: `-v /srv/captures:/captures:ro`) | admin-only by design (it is a host-filesystem read); compressed files are inflated into `<data>` first, so the data disk needs room for the inflated size |

### Moving the library: prerequisites and the migration

Under **systemd** the sandbox makes everything but the data directory
read-only, and the disk must be there before the daemon starts. Prepare the
path first, then change the root in the UI:

```bash
sudo install -d -o avb -g avb -m 0700 /mnt/captures       # on the mounted disk
sudo systemctl edit avb-introspectd
#   [Unit]
#   RequiresMountsFor=/mnt/captures            # never start with the mount missing
#   [Service]
#   ReadWritePaths=/mnt/captures               # adds to the unit's list
sudo systemctl daemon-reload && sudo systemctl restart avb-introspectd
# then Admin → Storage → /mnt/captures → Apply
```

In a **container** the path must be a volume (the root filesystem is
read-only) that every future `run`/`up` attaches: add
`avb-captures:/captures` next to `avb-data:/data` (and `avb-captures:` under
`volumes:` in the compose file), recreate, then set the root to
`/captures`. Recreating the container *without* that mount makes the library
vanish until you add it back.

The migration is copy-first: every file is copied to the new root, the
setting is switched, and only then are the originals deleted — so it needs
free space for **both** copies while it runs and takes time proportional to
the library. A failure at any point leaves the old location intact and the
setting unchanged. Each tenant domain keeps its `domains/<dom>/` subtree
under the new root.

**Mount-missing pitfall.** If the configured root cannot be created at
startup (its parent is not mounted), the daemon falls back to the default
root *for that run* so the service still comes up: the library looks empty,
new uploads land under `<data>/pcaps`, and the first metadata save drops the
setting. If the mount point exists but nothing is mounted, the setting
survives but every capture is "missing" and Analyze fails. Both are cured
by ensuring the mount before the service — `RequiresMountsFor=` on systemd,
the volume line in the compose file — which is why it is a prerequisite
above. If it did happen: stop the daemon, mount the disk, move any uploads
that landed under `<data>/pcaps` into the root, and set the root again from
Admin → Storage.

### Sizing the disk

```
steady state   = library + Σ session copies (one full capture per session; a combined
                 session = the sum of its sources)
while uploading  + 2 × the upload (staging file + library copy), + the inflated size
                 for a compressed upload
while migrating  + the whole library (copy-first)
```

A capture analysed in three sessions therefore occupies four copies. That
is deliberate — deleting a library pcap never breaks an investigation — but
it makes **deleting finished sessions** the lever for reclaiming space.
`Admin → Domains` (or `GET /api/admin/domains`) shows library bytes per
tenant; `du -sh <data>/sessions` shows the session side. Memory is a
separate budget: uploads are buffered in RAM at about three times their size
([Level 5d](#5d-sizing-one-instance)).

### Ownership, permissions, filesystems

- Files are created by the service user: `avb` — uid 999 in the container
  image. Under systemd the unit's `UMask=0077` makes them owner-only
  (`0600`), so other host users cannot read captures; relax it in a drop-in
  only if you must. Containers use the default umask.
- A drop folder needs read access for that user (`chgrp avb`, `chmod 750`
  is enough) and must not live under `/home`, `/root` or `/run/user`, which
  `ProtectHome=true` hides from the service.
- Local disk is the recommendation. A network filesystem works for a
  **single** instance (slower: every session's capture is re-read at each
  start) — but a root or data directory must **never** be shared between two
  running instances, on any filesystem; that corrupts the index
  ([CONTAINER.md §1](CONTAINER.md#1-read-this-first--replicas-are-not-safe)).
  At Level 5 every shard has its own volume(s).
- Back up the library root *and* the data directory when they differ
  ([Backup & restore](#backup--restore)); a snapshot of one disk that holds
  both is the simplest consistent copy.

---

## Backup & restore

A copy taken while the instance is **stopped** is always consistent:

```bash
# Level 3/4
sudo systemctl stop avb-introspectd
sudo tar -C /var/lib/avb-introspection -czf avb-data-$(date +%F).tar.gz .
sudo systemctl start avb-introspectd
# Level 1: podman stop avb; tar the volume (Level 1 "Operate"); podman start avb
# Level 2/5: docker compose … stop <service>; tar its volume; start (Level 2 "Operate"); one volume per shard
```

If the pcap library was moved out of the data directory
([Where to store captures](#where-to-store-captures)), archive that root in
the same stopped window — `meta.json` refers to it by absolute path.

Restore is the reverse: stop, unpack over an empty data directory (or
volume) owned by the service user (`avb`, uid 999 in the image), start.
Sessions are re-analyzed from their stored captures at startup, so a restored
instance is fully usable once that finishes. A copy taken while running is
*usually* fine — every index file is replaced atomically — but can pair a
newer `meta.json` with an older capture; prefer the stopped copy or a
filesystem/volume snapshot.

---

## Updating

| Level | How |
| --- | --- |
| 1 | rebuild the image, `podman rm -f avb`, run again with the same volume |
| 2 / 5 | `docker compose -f … up --build -d` (Level 5: `--no-deps <shard>`, one at a time) |
| 3 / 4 | build (or unpack the bundle), `sudo ./deploy/install.sh` — it stops, swaps and restarts |

Stops are graceful: SIGTERM closes event streams with a `1001` frame, lets
in-flight requests finish and exits 0 — give container stops a timeout longer
than your largest upload takes to validate (the shipped files use 60 s).
Users are logged out by a restart (tokens live in memory) and sessions are
re-analyzed from their captures. `avb-introspectd --version` — also in the
startup banner and, for images, the `org.opencontainers.image.version` label —
tells you what is running. Frontend-only changes need no restart on Level 3/4
(files are served from disk; users hard-refresh, Ctrl+Shift+R).

---

## Server options & environment

```
--bind ADDR         listen address                 (default 0.0.0.0; 127.0.0.1 behind
                                                    a same-host proxy, :: for IPv6)
--port N            listen port, 1-65535           (default 8342)
--data DIR          persistent data directory      (default ./data)
--frontend DIR      static frontend directory      (default ./frontend)
--max-threads N     serving thread cap             (default 64)
--max-upload-mb N   pcap upload limit in MiB        (default 1024)
--version           print the build version and exit
```

Bad values are rejected at startup (exit 2), and the `listening on` banner is
printed only after the socket is bound, so it is a reliable readiness line in
the journal or container log.

Security-relevant environment variables (see **[SECURITY.md](SECURITY.md)**):

```
AVB_ADMIN_USER / AVB_ADMIN_PASSWORD   provision/promote the first global admin
AVB_DISABLE_REGISTRATION=1            close open self-registration (recommended
                                      when exposed — admins/owners create users)
AVB_RATE_RPS / AVB_RATE_BURST         per-non-admin API rate limit (default 30 / 90)
AVB_LOGIN_RPS / AVB_LOGIN_BURST       per-IP login/register limit (default 0.5 / 6)
AVB_TRUSTED_PROXIES                   comma-separated IPs/CIDRs of reverse proxies
                                      whose X-Real-IP / X-Forwarded-For is believed
                                      (loopback always is); needed when nginx runs
                                      in another container or on another host
```

TLS is **not** terminated by the backend — always run a reverse proxy (nginx)
in front for anything beyond a trusted lab network (Levels 2–5).

---

## Optional system tools (compressed captures)

Uploads and server-path opens may be compressed; the backend detects the
format by magic bytes and inflates it with the matching **system** tool, so
install whichever formats you need:

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
clear upload error naming the tool, rather than a silent failure. The
container image ships **none** of them by default — each is another parser
fed attacker-controlled bytes — see
[CONTAINER.md §3](CONTAINER.md#3-the-image) for the derived-image recipe. On
a systemd host they run inside the unit's sandbox.

---

## Developer build (no container)

**Dependencies:** `g++` (C++20), `make`, `zlib`, `libsodium`. Python 3 is only
needed for the test-data generator and the browser tests.

```bash
# Debian/Ubuntu:  sudo apt install g++ make zlib1g-dev libsodium-dev
# Arch:           sudo pacman -S gcc make zlib libsodium
# Fedora:         sudo dnf install gcc-c++ make zlib-devel libsodium-devel

make -j                                    # -> build/avb-introspectd
AVB_ADMIN_USER=admin AVB_ADMIN_PASSWORD=change-me \
  ./build/avb-introspectd                  # listens on :8342, data in ./data
python3 tools/gen_pcaps.py                 # scenarios to upload, in testdata/
```

`make -j test`, `./scripts/integration_test.sh` and
`python3 scripts/e2e_playwright.py` are the test suites (README, "Testing").

---

## Troubleshooting

Tagged with the levels where each usually shows up.

- **`WARNING: no admin account exists …` at startup** (any) — the
  first-registration bootstrap is open. Set `AVB_ADMIN_USER` /
  `AVB_ADMIN_PASSWORD` and restart; on Level 2 that means the env file the
  stack requires.
- **`admin provisioning failed: username must be 3-32 chars…`** (any) —
  `AVB_ADMIN_USER` must be 3–32 chars of `[a-zA-Z0-9_.-]` and the password
  ≥ 8 chars.
- **`fatal: bind() failed on 127.0.0.1:8342`** (L3/L4) — port in use, or
  `--bind` names an address this host does not have. Nothing was served; the
  banner is printed only after a successful bind.
- **`fatal: AVB_TRUSTED_PROXIES: bad address or CIDR range`** (L2–L5) — a
  typo in the list; the daemon refuses to start rather than silently trust
  nobody.
- **Everyone gets `429` on login as soon as one client misbehaves**, or the
  admin Security panel attributes all traffic to one address (L2, L4, L5) —
  the app is seeing the proxy's address. Set `AVB_TRUSTED_PROXIES` to the
  proxy's address/subnet (the compose stacks do; Level 4 sets it by hand).
- **`podman-compose up` fails on port 80** (L2/L5 rootless) — unprivileged
  ports; publish `8080:80` instead, or raise
  `net.ipv4.ip_unprivileged_port_start`.
- **Permission denied on `/data` under rootless Podman** (L1) — a bind mount
  owned by your host uid. Use a named volume, or `:U`, or `--userns=keep-id`
  ([CONTAINER.md §2a](CONTAINER.md#2a-podman-rootless)).
- **Container OOM-killed during an upload** (L1/L2/L5) — uploads are
  buffered at ~3× their size; raise the memory cap or lower `--max-upload-mb`
  (and nginx `client_max_body_size`).
- **OOM-killed or very slow shortly after start** (any) — the restore loop
  re-analyzing every retained session at once; more memory or fewer retained
  sessions.
- **`nginx -t`: `unknown directive "http2"`** (L3/L4) — you replaced the
  template's `listen … http2` with the newer `http2 on;`, which the distro
  nginx does not know. Keep the template's form.
- **Certbot webroot challenge fails** (L3) — the `:80` server must answer
  for the name *before* issuance (step 1 of 3b, with the bootstrap
  certificate); check `curl http://avb.example.com/.well-known/acme-challenge/x`
  returns a 404 from *this* nginx, not a redirect from another site or a
  timeout from the firewall.
- **Changing the pcap storage root is rejected as "not writable"** (L3/L4) —
  the service user can't write that path. Add it to `ReadWritePaths=` via
  `systemctl edit avb-introspectd` (`ProtectSystem=strict` makes everything
  else read-only), then `daemon-reload` and restart. In a container, mount
  that path as a second writable volume.
- **Locked out after applying the firewall** (L4) — the `nft-safety` timer
  from 4b flushes the ruleset after two minutes; wait, reconnect, fix the
  rule that dropped you (usually the bastion or SSH line), retry.
- **`sudo -u avb curl https://…` succeeds on the app host** (L4) — egress is
  not dead. Check the nft OUTPUT policy is `drop`, the unit still has
  `IPAddressDeny=any`, and the VLAN ACL denies VLAN 30 outbound.
- **Upload says a tool "is not installed on the backend host"** (any) —
  install the matching decompressor (table above) or upload an uncompressed
  capture; in the image, use the derived-image recipe.
- **Upload fails with `501`** (L2–L5) — something in the chain chunks the
  body; the server requires a `Content-Length`. The shipped nginx configs do
  not chunk.
- **WebSocket / live event stream doesn't connect behind a proxy** (L2–L5) —
  ensure the proxy forwards the `Upgrade`/`Connection` headers for `/api/ws`
  (the shipped configs do). Close code `4004` means that instance does not
  know the session id — a different shard, or a recreated instance and a
  stale tab.
- **`podman stop` takes a long time and ends in SIGKILL** (L1/L2/L5) — a
  busy request (large upload validating, or a client not reading its
  response) is being allowed to finish; raise the stop timeout. Idle
  connections and event streams no longer hold a stop.
- **Random 401s, sessions appearing and disappearing** (L5) — more than one
  instance is serving one origin. Look for a `--scale`d service or a second
  `server` line in an nginx `upstream`
  ([CONTAINER.md §1](CONTAINER.md#1-read-this-first--replicas-are-not-safe)).
- **`fatal:` about `meta.json` and the process exits 1** (any) — the index is
  unparseable, almost always because two instances shared a data directory.
  Restore from a backup; captures under `pcaps/` and `sessions/` are intact.
- **The UI looks stale after an update** (any) — hard-refresh
  (Ctrl+Shift+R); the browser cached the previous `app.js`/`style.css`.
