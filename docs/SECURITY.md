<!-- SPDX-FileCopyrightText: 2026 Kebag-Logic -->
<!-- SPDX-License-Identifier: MIT -->

# Security & remote-exposure hardening

This document is the deployment security guide for exposing AVB Introspection
to a network beyond a trusted lab: the threat model, how to place the server
so that **even a full compromise of the app cannot be used to reach the rest
of your systems**, the built-in protections (multi-tenant domains, rate
limiting, flow monitoring), and a concrete **verification checklist** you run
to prove the box cannot be repurposed or bypassed.

The guiding principle is *defence in depth*: the application enforces
authentication, tenant isolation, rate limits and anomaly detection; but you
do **not** trust the application alone. The network, the reverse proxy and the
OS sandbox each independently contain it, so that a bug in one layer is caught
by the next.

**Ready-to-fill templates** implement everything below — see
**[docs/NETWORK.md](NETWORK.md)** for the VLAN plan and inter-VLAN ACLs that
tie them together:

| Template | Role |
| --- | --- |
| [`deploy/nginx.production.conf`](../deploy/nginx.production.conf) | TLS reverse proxy — the only public listener (§5) |
| [`deploy/firewall.nft`](../deploy/firewall.nft) | host firewall — default-deny egress (§2c) |
| [`deploy/avb-introspectd.service`](../deploy/avb-introspectd.service) | systemd sandbox (§3) |

---

## 1. What you are exposing, and the threat model

`avb-introspectd` is a single C++ binary that:

- serves the SPA and a REST/WebSocket API on **one TCP port** (8342 by
  default), plain HTTP — **it does not terminate TLS**;
- reads and decodes user-uploaded pcap files (attacker-controlled bytes);
- shells out to decompression tools (`gzip`, `xz`, `unzip`, …) for compressed
  uploads;
- writes into one data directory (uploads, sessions, notes, users, logs).

Assets to protect, in priority order:

1. **The host.** The nightmare outcome is not "someone reads a pcap" — it is
   the server being turned into a foothold: a crypto-miner, a pivot into your
   VLANs, a spam relay. Everything below is built to make that impossible even
   if the app is fully compromised.
2. **Tenant data isolation.** One team's captures/sessions/notes must never be
   reachable by another team (see §4, domains).
3. **Availability.** One user (or one abusive client) must not be able to
   starve the service for everyone (see §5–§6).

Realistic attack surface once it is reachable from a wider network:

| Vector | Mitigated by |
| --- | --- |
| Malicious pcap → parser memory-safety bug → RCE | §3 OS sandbox (no new privs, read-only FS, syscall filter, private net) contains the blast radius |
| Compromised process tries to phone home / pivot | §2 network isolation + §3 `IPAddressDeny`, `RestrictAddressFamilies`, egress firewall |
| Credential stuffing / brute force | §6 per-IP login limiter + §7 flow monitor `auth-bruteforce` |
| Endpoint / object scanning across tenants | §4 domain 404-scoping + §7 `probe` detection |
| Upload flood / request flood (DoS) | §5 nginx limits + §6 token-bucket limiter + §7 `upload-flood`/`rate-anomaly` |
| Path traversal in API or static serving | static handler rejects `..`; §7 raises `path-traversal` on any `..` in a request path |
| Stealing TLS/credentials off the wire | §2 TLS terminated at nginx; backend bound to loopback |

---

## 2. Network placement — put it where a compromise is useless

**Do not bind the backend to a public interface.** Terminate TLS at nginx and
keep `avb-introspectd` on loopback (or a private, firewalled segment).

### 2a. Single host (simplest safe layout)

```
Internet / corp LAN ──▶ nginx :443 (TLS) ──▶ 127.0.0.1:8342 avb-introspectd
```

- Run the backend with the port bound to localhost only. The systemd unit
  restricts it to loopback with `IPAddressAllow=localhost` +
  `IPAddressDeny=any` (§3), so even if a firewall rule is missing the socket
  is unreachable from off-box.
- nginx is the *only* process with a public listener.

### 2b. VLAN segmentation (recommended for anything beyond a small team)

Treat the analyzer as an untrusted appliance and give it its own VLAN with **no
route to your production or management networks**. A capture appliance only
ever needs (a) to receive HTTPS from users and (b) nothing else outbound.

```
                    │ firewall / L3 switch with inter-VLAN ACLs
   VLAN 10 users ───┼──▶ 443 ─▶ VLAN 20 (DMZ): nginx ──▶ 8342 ─▶ VLAN 30: avb-introspectd
                    │                                               (no default route)
   VLAN 40 mgmt  ───┘  ✗ no path to VLAN 30 except SSH from a bastion
```

Concrete ACL intent (adapt to your switch/firewall syntax):

- **VLAN 30 (app) egress: default deny.** The app never needs to originate
  connections. Deny all outbound, then—if you use them—allow only DNS to your
  resolver and NTP. No route to VLAN 40 (mgmt), no route to the Internet.
- **VLAN 20 → VLAN 30:** allow only `tcp/8342` from the nginx host.
- **VLAN 10 → VLAN 20:** allow only `tcp/443`.
- **VLAN 30 → anywhere:** drop and **log** (a hit here is your early-warning
  that the app is trying to pivot — wire it to your SIEM).
- Management (SSH) reaches VLAN 30 only from a bastion in VLAN 40, never the
  other direction.

If you capture live AVB/TSN traffic onto this box, keep the capture NIC on a
**separate, isolated interface** (SPAN/mirror port, no IP or a link-local only)
so the capture network and the management/service network never bridge.

### 2c. Host firewall (belt-and-braces, on the app host itself)

Even inside its VLAN, lock the host down with `nftables` so a compromise cannot
open outbound sockets. A ready-to-fill template is at
**[`deploy/firewall.nft`](../deploy/firewall.nft)** — the essentials:

```nft
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif lo accept
    ip saddr <NGINX_IP> tcp dport 8342 accept   # only nginx may reach the app
    tcp dport 22 ip saddr <BASTION_IP> accept    # mgmt from bastion only
  }
  chain output {
    type filter hook output priority 0; policy drop;
    ct state established,related accept
    oif lo accept
    # allow ONLY what the host genuinely needs (DNS/NTP to your servers):
    ip daddr <DNS_IP> udp dport 53 accept
    ip daddr <NTP_IP> udp dport 123 accept
    # everything else outbound is dropped + logged:
    log prefix "egress-drop " drop
  }
}
```

The default-drop **output** chain is the important half: it is what stops a
compromised process from becoming a miner or a pivot. `systemd`'s
`IPAddressDeny` (§3) enforces the same intent at the cgroup level, so the two
back each other up.

---

## 3. OS sandbox — the app cannot repurpose the host

The shipped systemd unit (`deploy/avb-introspectd.service`) is aggressively
sandboxed so that arbitrary code execution inside the daemon still cannot touch
anything but its own data directory and cannot open outbound network
connections. Key directives and *why each one matters here*:

| Directive | Effect |
| --- | --- |
| `DynamicUser=` / dedicated `avb` user | never runs as root; owns nothing but its data dir |
| `NoNewPrivileges=true` | a setuid binary can't escalate — kills most privilege-escalation chains |
| `ProtectSystem=strict` + `ReadWritePaths=` | the **entire filesystem is read-only** except the one data dir; no writing binaries, cron, systemd units |
| `ProtectHome=true` | `/home`, `/root` invisible |
| `PrivateTmp=true` | isolated `/tmp` — no tmp-based IPC or symlink attacks |
| `PrivateDevices=true` | no raw device access |
| `ProtectKernelTunables/Modules/Logs`, `ProtectControlGroups` | cannot retune the kernel, load modules, or escape its cgroup |
| `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` | only ordinary sockets; no `AF_PACKET` raw-packet spoofing, no `AF_NETLINK` |
| `IPAddressAllow=localhost` + `IPAddressDeny=any` | **cgroup-level egress firewall**: the process literally cannot connect anywhere but loopback — a compromise cannot phone home even if the host firewall is misconfigured |
| `RestrictNamespaces=true`, `LockPersonality=true`, `MemoryDenyWriteExecute=true` | blocks container-escape primitives and W^X-violating JIT-spray shellcode |
| `SystemCallFilter=@system-service` + `SystemCallArchitectures=native` | seccomp allow-list; `@reboot`, `@swap`, `@module`, `@raw-io` etc. are denied |
| `CapabilityBoundingSet=` (empty) | drops **all** Linux capabilities |
| `RestrictSUIDSGID=true` | cannot create setuid files to persist |

> **Compression tools:** compressed uploads are handled by `fork`+`exec` of
> `gzip`/`xz`/`unzip`/… These inherit the sandbox. If you do **not** need
> compressed-upload support, set `SystemCallFilter=~@process` off is *not*
> possible (exec is needed), but you can remove the tools from the image to
> disable the feature entirely, or keep them — they run under the same
> read-only-FS, no-egress sandbox.

Resource quotas in the same unit prevent a single tenant or a decode storm from
taking the host down:

```
CPUQuota=200%          # at most two cores
MemoryMax=2G           # OOM-killed before it eats the host
MemoryHigh=1536M
TasksMax=256           # thread/fork bomb ceiling
LimitNOFILE=8192
```

Tune these to your hardware; the point is that there is always a hard ceiling.

---

## 4. Tenant isolation — domains

Multiple teams share one deployment without seeing each other's data. The model
(implemented, see `docs/API.md` and the code):

- **Every user belongs to exactly one domain.** `users.json` records it; the
  built-in `default` domain holds all pre-existing accounts (seamless
  migration).
- **Every object is domain-owned** — pcaps, folders, sessions (captures +
  notes), device names. On disk, non-default domains get their own subtree
  (`pcaps/domains/<id>/…`) so two tenants can never collide.
- **Roles:** a **global admin** (the `AVB_ADMIN_USER`) manages domains and
  every user; a **domain owner** manages just the users of their own domain,
  from the *My domain* view.
- **Authorization is deny-by-default and existence-hiding.** Every data
  handler resolves the caller's domain and refuses cross-domain access by
  answering **404, identical to a genuinely missing object** — so a user
  cannot even probe whether another tenant's session id exists. The WebSocket
  event stream enforces the same rule.
- **Opening captures by server path** (a host-filesystem read) is **admin
  only** — regular users and domain owners must upload.
- **Presence and metrics are domain-scoped**; only the global admin sees across
  domains.

### One-container-per-domain (stronger isolation)

In-process domain scoping is enforced on every handler and covered by tests,
but if your tenants are mutually untrusting (e.g. external customers), run
**one container per domain** for kernel-level isolation instead of relying on
application logic:

```
nginx ─┬─ /acme/  ─▶ container avb-acme   (own volume, own AVB_ADMIN_USER)
       ├─ /globex/─▶ container avb-globex (own volume)
       └─ /initech/▶ container avb-initech(own volume)
```

- Each container has its **own data volume** — isolation is enforced by the
  kernel/namespaces, not the app. A logic bug in one cannot reach another's
  disk.
- Each is a separate systemd/`docker` unit with the §3 sandbox and its own
  `CPUQuota`/`MemoryMax`, so one tenant's heavy analysis can't starve another.
- nginx routes by path prefix (the SPA auto-detects its base path — see
  `deploy/nginx.conf`), or by `server_name` (one subdomain per tenant).

**Which to choose:** in-process domains for internal teams who trust the
operator; one-container-per-domain when tenants are external or compliance
requires hard isolation. They compose — run a container per *customer*, with
in-process domains for that customer's internal *teams*.

---

## 5. Reverse proxy hardening (nginx)

Use **[`deploy/nginx.production.conf`](../deploy/nginx.production.conf)** — the
production TLS template: fill in a handful of placeholders (FQDN, upstream,
cert paths) and drop it into `/etc/nginx/conf.d/`. (`deploy/nginx.conf` is the
simpler port-80 config the docker-compose stack uses.) Both ship with the
hardening below:

- **TLS only** in production: HSTS, TLS 1.2/1.3, modern ciphers; redirect
  80→443.
- **Security headers:** `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, a restrictive `Content-Security-Policy` (the SPA is
  self-contained — no external origins), `Referrer-Policy: no-referrer`.
- **Request limits** as a first line against floods, in front of the app's own
  limiter: `limit_req_zone` (per-IP request rate) and `limit_conn_zone`
  (per-IP concurrent connections), plus `client_max_body_size` matching the
  backend's `--max-upload-mb`.
- **Only expose what's needed:** proxy `/` and `/api/`; nothing else. The
  backend has no other listeners.
- **Do not leak the backend:** `proxy_hide_header` the server token; the app is
  reached only via the proxy.

The app trusts `X-Real-IP`/`X-Forwarded-For` **only from a loopback peer**, so
a remote client cannot forge its source IP to escape the per-IP limiter; set
`proxy_set_header X-Real-IP $remote_addr;` at the proxy.

---

## 6. Rate limiting (built in)

Enforced in the API dispatch, before any handler work (`util/ratelimit.h`,
token-bucket):

- **Per-user general limit** for every non-admin: default **30 req/s, burst
  90** (`AVB_RATE_RPS` / `AVB_RATE_BURST`). Admins are exempt.
- **A stricter bucket for expensive operations** — upload and session/analysis
  creation — so a user cannot launch a decode storm: ~0.2/s, burst 8.
- **Per-IP bucket on the unauthenticated `login`/`register` endpoints**
  (0.5/s, burst 6) — this is the brute-force throttle, applied *before*
  password verification so guessing is rate-limited regardless of validity.
- Over-limit requests get **HTTP 429 with `Retry-After`**.
- The flow monitor (§7) **raises the penalty** (÷4 refill rate) for any actor
  it flags, so a suspected attacker is throttled harder automatically.

Set `AVB_DISABLE_REGISTRATION=1` on an exposed deployment so accounts are
created only by an admin or a domain owner — open self-registration is off.

---

## 7. Flow monitoring & anomaly detection (built in)

A lightweight FlowGuard (`sec/flowguard.h`) samples **every** API request and
decides whether the flow looks like normal usage. Per actor (a logged-in user,
or a client IP for unauthenticated traffic) it keeps a rolling 60 s window plus
a slow EWMA baseline of that actor's own rate, and raises alerts:

| Alert | Trigger |
| --- | --- |
| `auth-bruteforce` | ≥ 8 auth failures (401) in 60 s |
| `probe` | ≥ 15 denied/unknown (403/404) in 60 s — endpoint or cross-tenant object scanning |
| `path-traversal` | any `..` component in a request path (first strike) |
| `rate-anomaly` | request rate ≫ 8× the actor's learned baseline (and above an absolute floor) |
| `limit-hammering` | keeps sending through 429s (≥ 20 in 60 s) |
| `upload-flood` | a non-admin uploads > 512 MiB in 60 s |

On an alert the actor's rate-limit **penalty is raised for 5 minutes**, the
event is appended to `<data>/security.log` (append-only JSONL for your SIEM),
and it surfaces in the admin **Security** panel. FlowGuard also retains a
**sample of flows** — every suspect one plus 1-in-16 of normal traffic — with a
legit/suspect verdict, so an operator can see what "normal" looked like when
judging an alert. The admin **Monitoring** panel shows live process CPU/memory
and **per-domain** load (users online, running analyses, storage, req/min, WS
clients) so one tenant spiking is immediately visible.

`security.log` is your audit trail — ship it to a central logstore; a burst of
`egress-drop` firewall hits (§2c) alongside FlowGuard alerts is a high-signal
compromise indicator.

---

## 8. Verification — prove it can't be bypassed

Run these after every deployment. They are the difference between "we
configured hardening" and "we verified the box cannot be repurposed."

### 8a. The OS sandbox actually holds

```bash
# One number that summarises the sandbox. Aim for "OK" / a low exposure score.
systemd-analyze security avb-introspectd

# The process must have NO capabilities and NoNewPrivs set:
pid=$(systemctl show -p MainPID --value avb-introspectd)
grep -E 'CapEff|NoNewPrivs' /proc/$pid/status
#   CapEff: 0000000000000000   ← empty
#   NoNewPrivs: 1

# The filesystem is read-only except the data dir — this MUST fail:
sudo -u avb touch /usr/bin/x 2>&1 | grep -q 'Read-only' && echo "FS locked ✓"

# Egress is blocked at the cgroup — this MUST fail/timeout:
systemd-run --uid=avb -p IPAddressDeny=any --wait \
  curl -m3 https://example.com 2>&1 | grep -qi 'refused\|timed out' \
  && echo "egress blocked ✓"
```

### 8b. Only the intended ports are open

```bash
# From the app host: the backend must be loopback-only, nginx public.
ss -ltnp | grep -E ':8342|:443|:80'
#   8342 bound to 127.0.0.1 (NOT 0.0.0.0)

# From another host on the users' VLAN: only 443 answers.
nmap -Pn -p 22,80,443,8342 <server_ip>
#   443 open · 8342 filtered/closed · 22 filtered (bastion only)

# From the app's VLAN outbound: default-deny egress works.
sudo -u avb curl -m3 https://1.1.1.1     # MUST fail
```

### 8c. Auth, limits and brute-force protection are live

```bash
base=https://avb.example.com

# No token → 401 on everything but login/register/bootstrap:
curl -s -o /dev/null -w '%{http_code}\n' $base/api/sessions          # 401

# Brute force is throttled (per-IP bucket) — expect 401s then 429s:
for i in $(seq 20); do
  curl -s -o /dev/null -w '%{http_code} ' \
    -XPOST $base/api/login -d '{"username":"admin","password":"x"}'
done; echo
#   401 401 401 401 401 401 429 429 429 …

# A non-admin flooding a data endpoint hits 429 past the burst:
tok=$(curl -s -XPOST $base/api/login -d '{"username":"u","password":"…"}' | jq -r .token)
seq 300 | xargs -P50 -I{} curl -s -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $tok" $base/api/sessions | sort | uniq -c
#   ~90 × 200 then 210 × 429
```

### 8d. Tenant isolation cannot be crossed (404, not 403)

```bash
# As a user in domain B, every reference to a domain-A object is a 404,
# indistinguishable from "does not exist" — no existence leak:
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $B_tok" \
  $base/api/sessions/$A_session_id            # 404
curl -s -H "Authorization: Bearer $B_tok" $base/api/pcaps   # only B's pcaps
# Server-path open is admin-only:
curl -s -XPOST -H "Authorization: Bearer $B_tok" \
  $base/api/sessions -d '{"path":"/etc/passwd"}'            # 403
```

### 8e. The flow monitor fires and is audited

```bash
# Trigger a traversal probe, then confirm the alert + the JSONL audit line:
curl -s --path-as-is -H "Authorization: Bearer $tok" $base/api/x/../../../y >/dev/null
curl -s -H "Authorization: Bearer $admin_tok" $base/api/admin/security | jq '.alerts[0]'
sudo tail -1 /var/lib/avb-introspection/security.log     # matching JSON line
```

If every check above behaves as annotated, the deployment is sound: the app is
authenticated and tenant-isolated, floods and guessing are throttled and
alerted, and — most importantly — a total compromise of the process is boxed
into a read-only, no-egress, capability-less sandbox with no route to the rest
of your network.

---

## 9. Quick checklist

- [ ] TLS terminated at nginx; backend bound to `127.0.0.1:8342`, never public.
- [ ] App host in its **own VLAN** with **default-deny egress**; only nginx may
      reach `:8342`; SSH only from a bastion.
- [ ] Host `nftables` output chain default-drop (+ log); systemd
      `IPAddressDeny=any` backs it up.
- [ ] systemd unit sandbox intact — verify with `systemd-analyze security`.
- [ ] `CPUQuota`/`MemoryMax`/`TasksMax` set to hard ceilings.
- [ ] `AVB_DISABLE_REGISTRATION=1`; first admin provisioned via
      `AVB_ADMIN_USER`.
- [ ] A domain per team (or a container per tenant for external customers).
- [ ] `security.log` shipped to your central logstore; egress-drop firewall
      logs wired to alerting.
- [ ] Ran the §8 verification matrix and every check behaved as annotated.
