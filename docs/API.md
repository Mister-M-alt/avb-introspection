<!-- SPDX-FileCopyrightText: 2026 Kebag-Logic -->
<!-- SPDX-License-Identifier: MIT -->

# AVB Introspection — Backend API contract (v1, frozen)

Base URL: the backend serves everything from one port (default `8342`).
Static frontend at `/`, API under `/api/`. All request/response bodies are
JSON (`application/json`) unless stated otherwise.

## Authentication

- `GET /api/bootstrap`, `POST /api/register` and `POST /api/login` are the
  only unauthenticated API endpoints. Static files are served without auth.
- Every other `/api/*` call requires `Authorization: Bearer <token>`.
- The WebSocket endpoint takes the token as a query parameter (browsers
  cannot set headers on WS): `/api/ws?token=<token>&session=<id>`.
- Errors use HTTP status codes with body `{"error": "<message>"}`.
  401 = missing/bad token, 403 = forbidden, 404 = unknown object,
  409 = conflict, 400 = bad request, **429 = rate limited**.

**Multi-tenancy (domains).** Every user belongs to exactly one *domain*
(default `default`). Data endpoints are domain-scoped: pcaps, folders,
sessions, notes and device names are only ever visible within the caller's
domain, and a reference to another domain's object answers **404**, identical
to a missing object, so existence never leaks across tenants. See
`docs/SECURITY.md` §4.

**Rate limiting (429).** Non-admin callers are limited by a per-user token
bucket (default 30 r/s, burst 90; `AVB_RATE_RPS`/`AVB_RATE_BURST`), with a
stricter bucket for uploads and session creation. The unauthenticated
`login`/`register` endpoints are limited per client IP (default 0.5 r/s,
burst 6; `AVB_LOGIN_RPS`/`AVB_LOGIN_BURST`). Over-limit responses are `429`
with a `Retry-After` header. Admins are exempt. Set
`AVB_DISABLE_REGISTRATION=1` to close open self-registration.

### GET /api/bootstrap

`{"needs_admin": true}` on a fresh deployment with no admin account yet
(no `AVB_ADMIN_USER` provisioned) — the login screen uses this to offer
first-time admin creation. `false` once any admin exists.

### POST /api/register

Request: `{"username": "alex", "password": "secret1234"}` (username 3–32
chars `[a-zA-Z0-9_.-]`, password ≥ 8 chars).
Response 201: `{"ok": true, "role": "user" | "admin"}`. 409 if the username
exists. **Bootstrap:** while no admin exists, the first account created is
made `admin`; afterwards new accounts are regular `user`s.

### POST /api/login

Request: `{"username": "alex", "password": "secret1234"}`
Response 200: `{"token": "<64 hex chars>", "username": "alex"}`. 401 on bad
credentials. `429` (with `Retry-After`) when the per-IP login rate is
exceeded — the brute-force throttle applies before password verification.

### POST /api/logout

Response: `{"ok": true}` (token invalidated).

### GET /api/me

Response: `{"username": "alex", "role": "user", "domain": "default",
"domain_owner": false}` (role: `"admin" | "user"`; `domain_owner` true when
the caller owns their domain and may manage its users via `/api/domain`).

## Presence

Lets every user see who is connected and what they are looking at.

### PUT /api/presence

Heartbeat, sent by the frontend every ~10 s and on view changes.
Request: `{"view": "session/s1"}` (free-form label ≤ 128 chars; conventions:
`home`, `session/<id>`, `session/<id>:notes`, `admin`).
Response: `{"ok": true}`. Entries expire after 60 s without a heartbeat.

### GET /api/presence

Response: `{"users": [{"username": "alex", "view": "session/s1",
"idle_s": 3.2}]}` — one entry per active login session.

## Admin

All `/api/admin/*` endpoints require the `admin` role (403 otherwise).
The deployment provisions the first admin from the environment:
`AVB_ADMIN_USER` (created as admin, or promoted if the account exists) and
`AVB_ADMIN_PASSWORD` (used only when the account is being created).

### GET /api/admin/users

`{"users": [{"username": "alex", "role": "user", "domain": "default",
"online": true, "view": "session/s1"}]}`

### POST /api/admin/users

Request: `{"username": "bob", "password": "…", "role": "user" | "admin",
"domain": "acme"}` (`domain` optional, defaults to `default`; must exist).
Response 201: `{"ok": true}`. 409 when the name exists.

### DELETE /api/admin/users/{username}

Response: `{"ok": true}` (revokes the user's tokens). 400 when targeting
your own account or the last admin.

### GET /api/admin/domains

`{"domains": [{"id": "default", "name": "Default", "owner": "", "users": 3,
"sessions": 2, "pcaps": 5, "pcap_bytes": 12345678}, …]}` — every domain with
its inventory.

### POST /api/admin/domains

Request: `{"id": "acme", "name": "ACME Labs", "owner": "bob",
"owner_password": "…"}`. `id` must match `[a-z][a-z0-9-]{0,31}` and not be
reserved. `owner` becomes the domain owner: if the account is new,
`owner_password` creates it inside the domain; an existing account is moved
into the domain. Response 201: `{"ok": true, "id": "acme", "owner": "bob"}`.
409 when the domain exists.

### DELETE /api/admin/domains/{id}[?force=1]

Deletes a domain. Without `force` it must hold no pcaps or sessions (400
otherwise). With `force=1` its captures and sessions are removed too. Its
user accounts are moved back to the `default` domain (not deleted). The
built-in `default` domain cannot be removed. Response: `{"ok": true}`.

### GET /api/admin/monitor

Live host + per-domain load for the admin dashboard:
`{"cpu": {"process_pct", "system_pct", "cores"}, "mem": {"rss_kb",
"total_kb", "available_kb"}, "uptime_s", "domains": [{"id", "name", "owner",
"users", "online", "sessions", "running", "pcaps", "pcap_bytes",
"req_per_min", "ws_clients"}]}`.

### GET /api/admin/security

Flow-monitor snapshot (see `docs/SECURITY.md` §7):
`{"recorded", "suspect", "alerts": [{"ts", "actor", "domain", "kind",
"detail", "path"}], "samples": [{"ts", "actor", "method", "path", "status",
"verdict"}], "actors": [{"actor", "domain", "role", "req_per_min",
"baseline_rpm", "penalty"}]}`. Alert `kind` ∈ `auth-bruteforce`, `probe`,
`path-traversal`, `rate-anomaly`, `limit-hammering`, `upload-flood`.

## Domain self-service

For domain **owners** (and admins). A domain owner manages only the users of
their own domain.

### GET /api/domain

`{"id": "acme", "name": "ACME Labs", "owner": "bob", "is_owner": true,
"users": [{"username": "bob", "role": "user", "owner": true}, …]}`. The
`users` array is present only when the caller owns the domain.

### POST /api/domain/users

Owner-only. Request: `{"username": "carol", "password": "…"}` — creates a
regular user inside the owner's domain. Response 201: `{"ok": true}`.

### DELETE /api/domain/users/{username}

Owner-only. Removes a user from the owner's domain. 403 for admins, the
domain owner, or a user in another domain; 404 when not in your domain.

### GET /api/admin/storage

`{"pcap_root": "/var/lib/avb-introspection/pcaps",
"default_root": "/var/lib/avb-introspection/pcaps", "pcap_count": 3}`

### PUT /api/admin/storage

Request: `{"pcap_root": "/mnt/captures"}` — absolute path where the pcap
library is stored; `""` resets to the default (`<data>/pcaps`). Existing
files are migrated (copy first, delete after). The path must be writable
by the service (systemd deployments: add it to `ReadWritePaths`).
Response: `{"ok": true, "pcap_root": "/mnt/captures"}`; 400 with a
diagnostic when the path is not usable.

## Pcap management

### GET /api/pcaps

Response: `{"pcaps": [{"id": "p1", "name": "trace.pcap", "size": 12345,
"uploaded_at": "2026-07-02T16:00:00Z", "folder": ""}], "folders": ["certs"]}`
`folder` is the library folder the capture is filed in ("" = root; flat).
`folders` lists every folder (explicitly created or in use).

### POST /api/pcaps?name=trace.pcap[&folder=certs]

Body: raw pcap/pcapng bytes (`application/octet-stream`), optionally
compressed (gzip, xz, zstd, bzip2, lz4, lzip, compress, or a `.zip`
archive — detected by magic bytes and inflated server-side through the
matching system tool; for a zip the pcap/pcapng entry is extracted). The
stored capture and reported `size` are the decompressed bytes, and a known
compression suffix is stripped from `name`. `POST /api/sessions` with
`path` accepts compressed files the same way. The optional `folder` query
param files the upload straight into that library folder (created if
needed; omit or leave empty for the root).
Response 201: `{"id": "p1", "name": "trace.pcap", "size": 12345, "folder": "certs"}`.
400 if the file is not a valid pcap/pcapng (after decompression) or the
folder name is invalid.

### PUT /api/pcaps/{id}

Request: `{"folder": "certs"}` — move the capture into a library folder
(`""` moves it back to the root; the folder is created if needed).
Response: `{"ok": true}`.

### DELETE /api/pcaps/{id}

Admin or the caller's **domain owner**. Removes the stored file and its
metadata. Sessions keep their own capture copy, so existing investigations
are unaffected. Response: `{"ok": true}`; 403 for other non-admins, 404 for
unknown ids **or ids in another domain**.

### POST /api/pcaps/folders

Request: `{"name": "certs"}` (1-64 chars, no `/`). Idempotent.
Response 201: `{"ok": true}`.

### DELETE /api/pcaps/folders/{name}

Deletes an **empty** folder (400 while captures are still filed in it).
Response: `{"ok": true}`.

## Analysis sessions

### POST /api/sessions

Request: `{"pcap_id": "p1"}` **or** `{"path": "/data/traces/x.pcap"}`
(a path visible to the backend, e.g. a mounted volume). Opening by `path`
reads an arbitrary host file and is therefore **admin only** (403 otherwise —
regular users and domain owners upload to the library instead). The new
session belongs to the caller's domain.
Response 201: `{"id": "s1", "status": "running"}`. Analysis runs
asynchronously; poll `GET /api/sessions/{id}` or attach via WebSocket.

### GET /api/sessions

Response:
```json
{"sessions": [{
  "id": "s1", "name": "trace.pcap", "pcap_id": "p1",
  "status": "running" | "done" | "error",
  "error": "",                       // set when status == "error"
  "packets": 1234, "events": 2345, "decode_errors": 2,
  "duration": 12.5,                  // capture length, seconds
  "start_ts_ns": "1719912345123456789", // first packet, epoch ns, AS A STRING
                                        // (JS needs BigInt for ns precision;
                                        // used for time-of-day display)
  "created_at": "2026-07-02T16:00:00Z"
}]}
```

### GET /api/sessions/{id}

Same object as above plus per-protocol counts:
`"protocols": {"MSRP": 10, "MVRP": 4, "MAAP": 6, "ADP": 8, "AECP": 12, "ACMP": 10, "GPTP": 4719}`

### DELETE /api/sessions/{id}

Response: `{"ok": true}`

## Events

Protocols are exactly:
`"MSRP" | "MVRP" | "MAAP" | "ADP" | "AECP" | "ACMP" | "GPTP"`.
Event kinds are exactly: `"packet" | "transition" | "error"`.
GPTP packet-event types: `SYNC, FOLLOW_UP, PDELAY_REQ, PDELAY_RESP,
PDELAY_RESP_FOLLOW_UP, ANNOUNCE, SIGNALING`.

An **event object**:
```json
{
  "i": 17,                       // event index, 0-based, dense, stable
  "n": 42,                       // 1-based packet number; 0 for derived events (e.g. timeouts)
  "ts": 3.141593,                // seconds since first packet of the capture
  "kind": "packet",
  "proto": "ACMP",
  "type": "CONNECT_RX_COMMAND",  // short label: message type, or "STATE" for transitions
  "src": "aa:bb:cc:00:00:01",    // empty string when not applicable
  "dst": "91:e0:f0:01:00:00",
  "summary": "Controller 0x0000000000000099 connects talker 0x…:0 -> listener 0x…:0",
  "entity": "0x001b92fffe000001", // associated entity id or ""
  "stream": "91:e0:f0:00:0e:80:0001", // associated stream/attribute key or ""
  "fields": {"status": "SUCCESS", "sequence_id": 7}
}
```
For `kind == "transition"`, `fields` is always:
`{"object": "<state object key>", "from": "<state>", "to": "<state>", "why": "<cause>"}`
and `type` is `"STATE"`.
For `kind == "error"`, `type` is `"DECODE_ERROR"` and `summary` explains the
problem; `proto` is the outermost protocol identified (or `"MSRP"`-style best
guess; may also be `"ETH"`).

### GET /api/sessions/{id}/events?offset=0&limit=1000&proto=MSRP,ACMP&kind=packet,transition

All query params optional. `limit` ≤ 10000, default 1000. Filters combine
with AND; `proto`/`kind` are comma-separated allowlists.
Response: `{"total": 2345, "matched": 200, "offset": 0, "events": [ ... ]}`
(`total` = all events in session, `matched` = after filtering; `events` is
the `[offset, offset+limit)` slice **of the filtered list**).

### GET /api/sessions/{id}/events?compact=1

Returns every event in a compact parallel-array form for the timeline
(no paging): `{"protos": ["MSRP","MVRP","MAAP","ADP","AECP","ACMP"],
"kinds": ["packet","transition","error"],
"events": [[i, n, ts, protoIdx, kindIdx, "type"], ...]}`

## Investigation notes

Every session is a folder on the backend holding its own copy of the
capture plus a user-edited markdown file (`notes.md`, seeded with an
investigation template at session creation).

### GET /api/sessions/{id}/notes

Response: `{"markdown": "# Investigation: trace.pcap\n\n...",
"rev": "a1b2c3d4e5f60708"}` — `rev` identifies the content revision
(16 hex chars).

### PUT /api/sessions/{id}/notes

Request: `{"markdown": "<full replacement content>", "rev": "<the rev the
edit was based on>"}` (≤ 1 MiB). With a matching `rev` the save succeeds:
`{"ok": true, "rev": "<new rev>"}`. With a stale `rev` (someone else saved
in between): **409** `{"error": "...", "rev": "<current>",
"markdown": "<current content>"}` so the client can merge. Omitting `rev`
skips the check (last write wins). 400 when `markdown` is missing.

## Session info & devices

### GET /api/sessions/{id}/info

File metadata of the session's capture copy, the capture time window, and
the device inventory (every observed frame source):

```json
{
  "file": {"path": "...", "size": 679272, "modified": "2026-07-02T18:53:01Z",
           "accessed": "2026-07-02T19:00:00Z",
           "created": "2026-07-02T18:53:01Z"},   // "" if the fs has no btime
  "capture": {"start_ts_ns": "1719912345123456789",
              "end_ts_ns": "1719912589180791789",
              "start_iso": "2026-06-26T17:41:58Z",
              "end_iso": "2026-06-26T17:46:02Z",
              "duration": 244.06, "packets": 5393},
  "session": {"id": "s1", "name": "trace.pcap",
              "created_at": "2026-07-02T18:56:43Z"},
  "devices": [{
    "mac": "00:1b:92:00:00:01",
    "packets": 1234,
    "protocols": ["GPTP", "MSRP", "ADP"],
    "entity_id": "0x001b92fffe000001",  // "" when no ATDECC association
    "entity_name": "Stage Box FOH",     // auto, learned via AEM (PA-6)
    "name": "FOH Rack"                  // user-assigned, "" if unset
  }]
}
```

### PUT /api/devices

Assign a display name to a device. Names are **global** (a device keeps its
name across sessions) and persist in `data/devices.json`.
Request: `{"mac": "aa:bb:cc:dd:ee:ff", "name": "FOH Rack"}` (name ≤ 64
chars; empty string removes the entry; MAC is case-normalized).
Response: `{"ok": true}`. 400 on malformed MAC/name.

The frontend should display `name` (user) → `entity_name` (auto) → `mac` as
the device label wherever a MAC appears (events table src/dst, inspector
fields, state view).

## Packet inspector

### GET /api/sessions/{id}/packets/{n}   (n = 1-based packet number)

```json
{
  "n": 42, "ts": 3.141593, "len": 68, "caplen": 68,
  "layers": [
    {"service": "ethernet_mac_frame",
     "fields": [{"name": "dst_mac", "value": "91:e0:f0:01:00:00"},
                {"name": "ethertype", "value": "0x22f0"}]},
    {"service": "1722_avtp_control",
     "fields": [{"name": "subtype", "value": "0xfa (ADP)"}]},
    {"service": "atdecc_adp",
     "fields": [{"name": "message_type", "value": "ENTITY_AVAILABLE"},
                {"name": "entity_id", "value": "0x001b92fffe000001"}]}
  ],
  "hex": "91e0f001000000225e00000122f0..."   // full frame, lowercase hex, no separators
}
```
Field `value`s are always strings, pre-formatted for display. Layer
`service` names follow TSN-GEN conventions: `ethernet_mac_frame`,
`mrp_msrp`, `mrp_mvrp`, `1722_avtp_control`, `1722_maap`, `atdecc_adp`,
`atdecc_aecp`, `atdecc_acmp`, `8021as_gptp`.

## State

### GET /api/sessions/{id}/state

Every state object has a `history` array of
`{"ts": 1.5, "n": 12, "from": "…", "to": "…", "why": "…"}`.

```json
{
  "entities": [{
    "entity_id": "0x001b92fffe000001", "name": "Stage Box FOH",
    "model_id": "0x001b92fffe112233", "state": "AVAILABLE",
    "last_seen": 10.2, "available_index": 3,
    "talker_sources": 2, "listener_sinks": 2,
    "gptp_gm": "0x001b92fffe00aaaa", "gptp_domain": 0,
    "gm_in_sync": "MATCH",   // announced GM vs the GM observed via gPTP:
                             // MATCH | MISMATCH | UNKNOWN (live, PA-6)
    "history": [...]
  }],
  "reservations": [{
    "stream_id": "0x001b92fffe000001:0001", "talker_mac": "00:1b:92:00:00:01",
    "dest_mac": "91:e0:f0:00:0e:80", "vlan": 2,
    "max_frame_size": 224, "max_interval_frames": 1,
    "priority": 3, "rank": 1, "accumulated_latency": 125000,
    "state": "ESTABLISHED",
    "declaration": "ADVERTISE",             // or "FAILED"
    "failure_bridge": "", "failure_code": 0, // set when declaration == FAILED
    "gptp_sync": "HEALTHY",   // live annotation from observed gPTP truth
                              // (HEALTHY | LOST | UNKNOWN); NOT part of the
                              // reservation state machine or its history
    "listeners": [{"mac": "00:1b:92:00:00:02", "state": "READY"}],
    "history": [...]
  }],
  "vlans": [{
    "vid": 2, "state": "REGISTERED",
    "members": ["00:1b:92:00:00:01", "00:1b:92:00:00:02"], "history": [...]
  }],
  "domains": [{"class_id": 6, "priority": 3, "vid": 2, "declarer": "00:1b:92:00:00:01"}],
  "mrp": [{                          // MRP Registrar layer (802.1Q 10.7.8),
                                     // shared by MSRP + MVRP
    "proto": "MVRP", "kind": "VID", "attribute": "VLAN 2",
    "source": "00:1b:92:00:00:01",
    "registrar": "IN",               // IN | LV | MT (registrar state machine)
    "last_event": "JoinIn",          // last observed MRP AttributeEvent
    "events": 3,
    "log": [                         // observed event stream (step-through UI)
      {"ts": 0.0, "n": 5, "event": "JoinIn", "state": "IN"},
      {"ts": 2.1, "n": 40, "event": "Lv", "state": "LV"}
    ],
    "history": [{"ts": 0.0, "n": 5, "from": "MT", "to": "IN",
                 "why": "rJoin (JoinIn) — registered"}]
  }],
  "maap": [{
    "claimant": "00:1b:92:00:00:01", "range_start": "91:e0:f0:00:0e:80",
    "count": 8, "state": "ACQUIRED", "conflicts": 0, "history": [...]
  }],
  "connections": [{
    "talker_entity": "0x001b92fffe000001", "talker_unique_id": 0,
    "listener_entity": "0x001b92fffe000002", "listener_unique_id": 0,
    "controller_entity": "0x0000000000000099",
    "stream_id": "0x001b92fffe000001:0001", "dest_mac": "91:e0:f0:00:0e:80",
    "vlan": 2, "connection_count": 1, "state": "CONNECTED", "history": [...]
  }],
  "aecp": [{
    "controller": "0x0000000000000099", "target": "0x001b92fffe000001",
    "commands": 5, "responses": 5, "timeouts": 0, "unsolicited": 1,
    "last": [{"sequence_id": 4, "command": "GET_NAME", "status": "SUCCESS", "rtt_ms": 1.2}]
  }],
  "milan_sinks": [{
    "listener_entity": "0x001b92fffe000002", "listener_unique_id": 0,
    "state": "SETTLED_RSV_OK",   // Milan v1.2 §5.5.3: UNBOUND | PRB_W_AVAIL |
                                 // PRB_W_DELAY | PRB_W_RESP | PRB_W_RESP2 |
                                 // PRB_W_RETRY | SETTLED_NO_RSV | SETTLED_RSV_OK
    "probing_status": "PROBING_COMPLETED", // Milan Table 5.5 mapping
    "bound_talker": "0x001b92fffe000001", "bound_talker_unique_id": 0,
    "controller": "0x0000000000000099",
    "stream_id": "0x…", "dest_mac": "…", "vlan": 2,
    "probes_sent": 3,
    "talker_discovered": "TK_DISCOVERED", // Milan §5.6.4 listener discovery
                                          // machine for the bound talker:
                                          // TK_DISCOVERED | TK_NOT_DISCOVERED |
                                          // N/A (when UNBOUND)
    "history": [...]
  }],
  "milan_talkers": [{               // Milan talkers are stateless (§5.5.2.7):
    "talker_entity": "0x001b92fffe000001", "talker_unique_id": 0,
    "probes_received": 2, "probe_responses": 2, "last_status": "SUCCESS",
    "stream_id": "0x…",
    "srp_declaration": "ADVERTISE", // live from MSRP: ADVERTISE|FAILED|NONE
    "disconnect_tx_seen": 0,
    "get_tx_connection_seen": 0,    // >0 raises a warning (not implemented
    "history": [...]                //  by Milan talkers, §5.5.4.4)
  }],
  "gptp": {
    "domains": [{
      "domain": 0,
      "state": "GM_PRESENT",              // NO_GM | GM_PRESENT | GM_TIMED_OUT
      "sync": "HEALTHY",                  // UNKNOWN | HEALTHY | LOST
      "grandmaster": {
        "clock_identity": "0x001b21fffeef2ad0",
        "name": "Stage Box FOH",          // via AEM names when known
        "priority1": 200, "priority2": 248,
        "clock_class": 248, "clock_accuracy": "0x21",
        "offset_scaled_log_variance": 17258,
        "steps_removed": 0, "time_source": "INTERNAL_OSCILLATOR",
        "current_utc_offset": 0
      },
      "sync_interval_ms": 125.0,          // declared logSyncInterval
      "announce_interval_ms": 1000.0,
      "last_sync": 243.31, "last_announce": 243.4, "last_sync_gap_ms": 126.3,
      "sync_count": 1631, "follow_up_count": 1631, "unmatched_follow_ups": 0,
      "announce_count": 209,
      "cumulative_rate_offset_ppm": -3.2, // Follow_Up 802.1AS TLV
      "gm_time_base_indicator": 8,
      "path_trace": "0x001b21fffeef2ad0",
      // Observer-side BMCA (802.1AS 10.3): the priority-vector comparison
      // run over every announcer, checked against the clock driving Sync.
      "expected_gm": "0x001b21fffeef2ad0", "expected_gm_name": "",
      "sync_gm": "0x001b21fffeef2ad0",
      // Observer readout only — no timeline events (a single tap point can't
      // tell a real fault from a topology artifact, so the tool reports the
      // observation; GM changes are narrated by the entity events instead):
      //   CONVERGED           best-announced clock is driving Sync
      //   PRIORITY_INVERSION  a better-priority1 clock is announced but not
      //                       driving Sync — investigate
      //   TIEBREAK            equal priority1; clockIdentity decides (common
      //                       and benign with a single tap point)
      //   UNKNOWN             not enough observed
      "bmca": "CONVERGED",
      "announcers": 1,
      "history": [...]
    }],
    "ports": [{
      "port": "0x001b21fffeef2ad0:1",
      "clock_identity": "0x001b21fffeef2ad0", "port_number": 1,
      "src_mac": "00:1b:21:ef:2a:d0", "name": "", "domain": 0,
      "role": "MASTER",          // UNKNOWN | MASTER | SLAVE — inferred from a
                                 // single tap point (Sync/Announce senders are
                                 // MASTER, pdelay-only ports SLAVE)
      "as_capable": "AS_CAPABLE",// UNKNOWN | AS_CAPABLE | NOT_AS_CAPABLE
      "sync_sent": 1615, "announce_sent": 205, "signaling_sent": 0,
      "pdelay": {
        "initiated": 206, "complete": 204, "lost": 2, "consecutive_lost": 0,
        "req_interval_ms": 1000.0,
        "last_turnaround_us": 812.4,      // responder wire timestamps (exact)
        "last_observed_gap_ms": 1.9       // capture-clock gap (approximate)
      },
      "md": {   // 802.1AS-2020 Clause 11 media-dependent machines
                // (full-duplex point-to-point: 802.3 copper & fiber)
        "clause": "11 (full-duplex point-to-point, 802.3 copper/fiber)",
        "pdelay_req_state": "WAITING_FOR_PDELAY_INTERVAL_TIMER",
                // NOT_ENABLED | WAITING_FOR_PDELAY_RESP |
                // WAITING_FOR_PDELAY_RESP_FOLLOW_UP |
                // WAITING_FOR_PDELAY_INTERVAL_TIMER | RESET
        "pdelay_resp_state": "WAITING_FOR_PDELAY_REQ",
                // NOT_ENABLED | WAITING_FOR_PDELAY_REQ |
                // SENT_PDELAY_RESP_WAITING_FOR_TIMESTAMP
        "sync_send_state": "IDLE", // NOT_ENABLED | FOLLOW_UP_PENDING | IDLE
        "resets": 2       // MDPdelayReq RESET entries (lost responses)
      },
      "announce_state": "RECEIVED", // NONE | RECEIVED | AGED (10.2.12 aging)
      "gptp_capable": "UNKNOWN",    // UNKNOWN | GPTP_CAPABLE |
                                    // CAPABLE_TIMED_OUT (Signaling TLV,
                                    // 10.2.15, timeout 10.7.3.3)
      "requested_intervals": {      // last message-interval-request TLV
        "link_delay": "0 (1 s)",    // sent BY this port (10.6.4.3);
        "time_sync": "-3 (125 ms)", // absent if never seen
        "announce": "0 (1 s)"
      },
      "history": [...]
    }]
  }
}
```

State value enums:
- entity: `AVAILABLE | DEPARTING | TIMED_OUT` (+ `gm_in_sync`: `MATCH | MISMATCH | UNKNOWN`)
- reservation: `PENDING | ESTABLISHED | LISTENER_FAILED | TALKER_FAILED | WITHDRAWN` (+ `gptp_sync` annotation)
- vlan: `REGISTERED | LEAVING | WITHDRAWN`
- maap: `PROBING | ACQUIRED | DEFENDING | LOST`
- connection: `DISCONNECTED | CONNECTING | CONNECTED | DISCONNECTING | FAILED`
- gptp domain: `NO_GM | GM_PRESENT | GM_TIMED_OUT`, sync `UNKNOWN | HEALTHY | LOST`
- gptp port: role `UNKNOWN | MASTER | SLAVE` (inferred), as_capable `UNKNOWN | AS_CAPABLE | NOT_AS_CAPABLE`
- milan sink: `UNBOUND | PRB_W_AVAIL | PRB_W_DELAY | PRB_W_RESP | PRB_W_RESP2 | PRB_W_RETRY | SETTLED_NO_RSV | SETTLED_RSV_OK`
- mrp registrar: `IN | LV | MT` (802.1Q Registrar state machine, LeaveTime 1.0 s)

Note on ACMP naming: event `type` labels use the IEEE 1722.1 message names;
Milan renames the same wire values (CONNECT_RX→BIND_RX, DISCONNECT_RX→
UNBIND_RX, CONNECT_TX→PROBE_TX) and the Milan vocabulary is used in the
`milan_sinks` transition reasons. ACMP command timeouts follow Milan
Table 5.26 (200 ms).

## Metrics (NF-2)

### GET /api/metrics

```json
{
  "process": {"cpu_user_s": 1.2, "cpu_sys_s": 0.3, "rss_kb": 34567, "uptime_s": 120.5, "threads": 9},
  "pool": {"threads": 4, "max_threads": 64, "queued": 0, "active": 1},
  "sessions": [{"id": "s1", "packets": 1234, "events": 2345,
                "decode_errors": 2, "analysis_ms": 87, "pps": 14183.9}],
  "clients": [{"addr": "127.0.0.1:52344", "user": "alex", "kind": "ws",
               "messages": 12, "bytes_sent": 45678, "connected_s": 33.1}]
}
```

## WebSocket event stream

`GET /api/ws?token=<token>&session=<id>` with standard RFC 6455 upgrade.

- Server → client messages are **binary frames**; each frame is a complete
  zlib stream (RFC 1950 — decompress in the browser with
  `new DecompressionStream("deflate")`) containing one UTF-8 JSON message:
  - `{"type": "batch", "events": [<event>, ...]}` — events in capture order,
    batched (≤ 500 per batch).
  - `{"type": "progress", "packets": 500, "events": 812}` — periodic.
  - `{"type": "complete", "total": 2345}` — analysis finished, all events sent.
  - `{"type": "error", "error": "..."}`
- A client attaching to a finished session receives the full event stream as
  batches, then `complete`. Multiple clients may attach to the same session
  (BE-7); each gets an independent full stream.
- Client → server messages are text JSON: `{"type": "ping"}` →
  `{"type": "pong"}` (sent as a compressed binary frame like everything else).
- Close codes: 4001 bad/missing token, 4004 unknown session.

## CORS / same-origin

The frontend is served by the same process; no CORS headers are emitted.
The frontend must use relative URLs (`/api/...`).
