<!-- SPDX-FileCopyrightText: 2026 Kebag-Logic -->
<!-- SPDX-License-Identifier: MIT -->

# Network deployment template — nginx proxy + VLAN segmentation

A copy-and-fill template for placing AVB Introspection on a network so that
**even a full compromise of the app is useless to an attacker**: it can reach
nothing but the reverse proxy, and it cannot originate a connection to the rest
of your systems. This is the network layer of `docs/SECURITY.md`; read that for
the threat model and the OS-sandbox and app-level controls.

Three files implement this template — fill in their placeholders and deploy:

| File | Role |
| --- | --- |
| [`deploy/nginx.production.conf`](../deploy/nginx.production.conf) | TLS reverse proxy — the only public listener |
| [`deploy/firewall.nft`](../deploy/firewall.nft) | host firewall — default-deny egress on the app host |
| [`deploy/avb-introspectd.service`](../deploy/avb-introspectd.service) | systemd sandbox — read-only FS, no caps, cgroup egress deny |

---

## 1. Reference topology

Give the analyzer its own VLAN with **no route to production or management**.
A capture appliance only ever needs to *receive* HTTPS from users; it should
never originate traffic anywhere.

```
   ┌────────────── VLAN 10: Users ──────────────┐
   │  analyst laptops                            │
   └───────────────────┬─────────────────────────┘
                       │  allow tcp/443 only
                       ▼
   ┌────────────── VLAN 20: DMZ ─────────────────┐
   │  nginx (TLS)  ── deploy/nginx.production.conf│
   └───────────────────┬─────────────────────────┘
                       │  allow tcp/8342 only, from the nginx IP
                       ▼
   ┌────────────── VLAN 30: App ─────────────────┐
   │  avb-introspectd  ── loopback/8342           │
   │  • DEFAULT-DENY egress (no route out)        │
   │  • host firewall: deploy/firewall.nft        │
   │  • systemd sandbox: the .service unit        │
   └──────────────────────────────────────────────┘

   ┌────────────── VLAN 40: Mgmt ────────────────┐
   │  bastion/jump host ── SSH to VLAN 30 only    │
   └──────────────────────────────────────────────┘   (never the reverse)

   Capture NIC (if sniffing live AVB/TSN): a SEPARATE, isolated interface
   (SPAN/mirror port, no IP or link-local only) — never bridged to the above.
```

**Simplest safe collapse:** if you cannot provision VLANs, run **nginx on the
same host** as the backend, bind the backend to `127.0.0.1:8342`, and rely on
`deploy/firewall.nft` + the systemd sandbox. The app is then only reachable via
nginx, and still cannot phone home. VLANs add defence in depth on top.

---

## 2. Fill-in values

Decide these once and substitute them into the three files:

| Placeholder | Meaning | Example |
| --- | --- | --- |
| `__SERVER_NAME__` | public FQDN users browse to | `avb.example.com` |
| `__APP_UPSTREAM__` | where nginx proxies to | `127.0.0.1:8342` (same host) or `10.30.0.10:8342` |
| `__CERT__` / `__KEY__` | TLS cert + key | `/etc/letsencrypt/live/avb.example.com/{fullchain,privkey}.pem` |
| `__MAX_UPLOAD__` | matches backend `--max-upload-mb` | `1024m` |
| `__NGINX_IP__` | only source allowed to reach `:8342` | `127.0.0.1` or the nginx VLAN-20 IP |
| `__BASTION_IP__` | only source allowed to SSH the app host | `10.40.0.5` |
| `__DNS_IP__` / `__NTP_IP__` | internal resolver / time server (omit if unused) | `10.40.0.53` / `10.40.0.123` |

VLAN/subnet plan (adapt to your addressing):

| VLAN | Purpose | Example subnet | Inbound allowed | Outbound allowed |
| --- | --- | --- | --- | --- |
| 10 | Users | `10.10.0.0/16` | — | `443`→VLAN 20 |
| 20 | DMZ (nginx) | `10.20.0.0/24` | `443` from VLAN 10 | `8342`→VLAN 30 |
| 30 | App | `10.30.0.0/24` | `8342` from nginx; `22` from bastion | **default deny** (only DNS/NTP if needed) |
| 40 | Mgmt | `10.40.0.0/24` | — | `22`→VLAN 30 |

---

## 3. Inter-VLAN ACLs (enforced on your L3 switch / router / firewall)

The intent is the same everywhere; the syntax differs by platform. The rule
that matters most is **VLAN 30 egress = default deny, and log the drops** — that
is what turns a compromised app into a dead end and gives you an alarm the
moment it tries to pivot.

### Intent (vendor-neutral)

```
permit tcp  VLAN10  ->  VLAN20:443           # users reach nginx
deny        VLAN10  ->  VLAN30               # users cannot reach the app directly
permit tcp  VLAN20(nginx) -> VLAN30:8342     # nginx reaches the app
permit tcp  VLAN40(bastion) -> VLAN30:22     # mgmt SSH in
deny   log  VLAN30  ->  any                  # app originates NOTHING (alarm on hit)
deny   log  VLAN30  ->  VLAN40               # app can never reach management
```

### Example A — Linux router with nftables (inter-VLAN forwarding)

If a Linux box routes between the VLAN interfaces (`vlan10`, `vlan20`,
`vlan30`, `vlan40`), enforce it in the `forward` hook:

```nft
table inet vlanacl {
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept

        # users -> nginx (443)
        iif "vlan10" oif "vlan20" ip daddr <NGINX_IP> tcp dport 443 accept
        # nginx -> app (8342)
        iif "vlan20" oif "vlan30" ip saddr <NGINX_IP> tcp dport 8342 accept
        # bastion -> app (22)
        iif "vlan40" oif "vlan30" ip saddr <BASTION_IP> tcp dport 22 accept

        # app VLAN may originate nothing — log then drop (default policy also drops)
        iif "vlan30" limit rate 10/minute log prefix "vlan30-egress-drop " drop
    }
}
```

### Example B — Cisco IOS style (illustrative)

```
ip access-list extended VLAN30_IN     ! applied inbound on the VLAN30 SVI
 permit tcp 10.30.0.0 0.0.0.255 eq 8342 10.20.0.0 0.0.0.255 established
 permit tcp 10.30.0.0 0.0.0.255 eq 22   10.40.0.0 0.0.0.255 established
 deny   ip  10.30.0.0 0.0.0.255 any log        ! app originates nothing
!
ip access-list extended VLAN20_IN     ! nginx DMZ
 permit tcp 10.20.0.0 0.0.0.255 10.30.0.10 0.0.0.0 eq 8342
 permit tcp any 10.20.0.0 0.0.0.255 eq 443
 deny   ip  10.20.0.0 0.0.0.255 10.40.0.0 0.0.0.255 log   ! DMZ can't reach mgmt
interface Vlan30
 ip access-group VLAN30_IN in
interface Vlan20
 ip access-group VLAN20_IN in
```

Whatever the platform: **default-deny both directions and add only the four
flows in the intent block.** Send the `deny ... log` hits to your SIEM.

---

## 4. Bring-up order & verification

1. Provision VLANs + inter-VLAN ACLs (§3). Verify from a user host that only
   `443` reaches the DMZ and nothing reaches VLAN 30 directly.
2. On the app host: fill in and apply `deploy/firewall.nft`, then install the
   sandboxed `deploy/avb-introspectd.service`. Verify the sandbox and the
   loopback binding.
3. On the DMZ host: fill in and install `deploy/nginx.production.conf`, provide
   certs, `nginx -t && reload`.
4. Run the **verification matrix in `docs/SECURITY.md` §8** — it proves, with
   `systemd-analyze security`, `ss`, `nmap` and a `curl` bypass matrix, that
   the sandbox holds, only the intended ports answer, egress is blocked, auth
   and rate limits are live, and tenant isolation cannot be crossed.

Quick smoke checks:

```bash
# From a user-VLAN host: only 443 answers; the app port is filtered.
nmap -Pn -p 22,80,443,8342 __SERVER_NAME__      # 443 open · 8342 filtered

# On the app host: egress is dead (MUST fail/timeout).
sudo -u avb curl -m3 https://1.1.1.1            # blocked by firewall + sandbox
ss -ltnp | grep 8342                            # bound to 127.0.0.1, not 0.0.0.0
```

If all of those behave as annotated, a total compromise of the process is boxed
into a read-only, no-egress sandbox on an isolated VLAN with no route to the
rest of your network — which is the whole point.
