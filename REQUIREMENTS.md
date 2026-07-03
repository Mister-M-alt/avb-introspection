# AVB Introspection — Requirements

**Status:** Draft v0.3 (open questions resolved, see §8) — **Date:** 2026-07-02

## 1. Purpose

Build a Milan-oriented introspection tool that observes and reconstructs the
state machines of the AVB/TSN control protocols from network traffic, and
presents protocol events, per-packet details, and state transitions in a web
frontend.

The tool is an *observer*: it decodes and correlates traffic. It does not
generate traffic — that is TSN-GEN's job.

## 2. Scope

### In scope (v1)

- Protocols, as profiled by Milan v1.2: **MSRP**, **MVRP**, **MAAP**,
  **ATDECC** (**ADP**, **AECP**, **ACMP**), and **gPTP** (802.1AS, as a
  passive observer — see OQ-9).
- Analysis of pcap files (uploaded through the API or read from a mounted
  volume).
- Multiple concurrent users observing the same trace.
- Simple user accounts (registration, hashed passwords).
- Persistence of uploaded pcaps and analysis sessions across restarts.

### Deferred to v2

- Live capture on a network interface (BE-6, FE-7).

### Out of scope

- Traffic generation and fault injection (covered by TSN-GEN).
- Milan conformance verdicts — the tool reports observed behaviour, it does
  not certify it.

## 3. References

| Ref | Document |
|---|---|
| [MILAN] | AVnu Alliance, Milan Specification v1.2 |
| [802.1Q] | IEEE 802.1Q — MRP, MVRP, MSRP |
| [1722] | IEEE 1722 — AVTP, MAAP |
| [1722.1] | IEEE 1722.1 — ATDECC (ADP, AECP, ACMP) |
| [TSN-GEN] | TSN-GEN traffic generator |

## 4. System overview

Two strictly separated components:

```
+-----------+      network API        +------------------+
| Frontend  | <=====================> |  Backend (C++)   |
| (browser) |  REST + WS event flow   |  in Docker       |
+-----------+                         +----+--------+----+
                                           |        |
                                      pcap files  live NIC
                                                   (v2)
```

- **Backend** — lightweight, multithreaded C++ service, packaged as a Docker
  image, controlled exclusively over the network.
- **Frontend** — web application (Firefox first) connecting to a local or
  remote backend.

## 5. Functional requirements

### 5.1 Protocol analysis (PA)

- **PA-1** — The backend shall decode MSRP, MVRP, MAAP, ADP, AECP and ACMP
  frames as profiled by Milan v1.2.
- **PA-2** — For each protocol, the tool shall reconstruct the protocol state
  machines from observed traffic — e.g. MRP applicant/registrar state per
  attribute (MSRP/MVRP), probe/defend state per address range (MAAP), entity
  availability with timeout tracking (ADP), in-flight command/response
  correlation (AECP), connection state per stream (ACMP).
- **PA-3** — Every decoded packet shall be exposed as an *event* carrying:
  capture timestamp, protocol, message type, source/destination, and the
  decoded fields.
- **PA-4** — State-machine transitions shall be exposed as events linked to
  the packet(s) that caused them.
- **PA-5** — Malformed or truncated frames shall be reported as decode-error
  events; they shall never crash or stall the backend.
- **PA-6** — Entities shall be correlated across protocols by entity ID, and
  enriched with the names and model information learned from ADP/AECP, so
  that ACMP connections and stream reservations can be attributed to named
  entities.

### 5.2 Backend (BE)

- **BE-1** — Implemented in lightweight C++ (proposed: C++20): minimal runtime
  dependencies and small footprint, suitable for lab machines and embedded
  Linux targets.
- **BE-2** — TSN-GEN is designed so that its protocol "logic" layer can be
  overridden. The backend shall implement its decoders and state machines as
  TSN-GEN logic overrides that model the real protocol behaviour, rather than
  re-implementing the protocol stack from scratch.
- **BE-3** — Packaged as a Docker image. Persistent data (pcaps, sessions,
  user accounts) lives on a mounted volume. *(v2: live capture will
  additionally require `NET_RAW`/`NET_ADMIN` and interface access — host
  networking or macvlan — to be documented in the run instructions.)*
- **BE-4** — Controlled exclusively over a network API; no local interaction
  is required after start-up. The API consists of REST-style HTTP endpoints
  for control (sessions, uploads, accounts) and a WebSocket event stream
  using binary framing with lightweight compression (algorithm chosen at
  design time, e.g. LZ4 or permessage-deflate — see §9).
- **BE-5** — Accept pcap input two ways: (a) uploaded through the API,
  (b) opened from a path already visible to the backend (mounted volume).
  Both pcap and pcapng formats shall be accepted.
- **BE-6** *(v2)* — Support live capture on a named interface, feeding the
  same event pipeline as pcap analysis.
- **BE-7** — Handle multiple concurrent client connections; several clients
  may attach to the same analysis session and receive the same event stream.
- **BE-8** — Uploaded pcaps and analysis sessions shall be persisted locally
  (on the mounted volume) and shall survive a backend restart.
- **BE-9** — Each session shall be a self-contained folder holding its own
  copy of the capture and a user-editable markdown investigation notes file
  (`notes.md`, seeded from a template), exposed through the API.

### 5.3 Backend concurrency model (CO)

- **CO-1** — Client connections shall be served by a pool of I/O threads that
  grows with the number of concurrent requests, up to a configurable maximum.
- **CO-2** — Packet filtering and decoding shall be parallelised: the capture
  is partitioned across worker threads (e.g. one per CPU core), each worker
  filters/decodes its share, and a single recombination stage merges the
  results back into one event stream.
- **CO-3** — The recombination stage shall strictly restore capture-timestamp
  order *before* state-machine evaluation — state reconstruction is
  order-sensitive, so parallel workers must never let reordered packets reach
  the state machines.
- **CO-4** — Thread usage shall adapt to the current load (active sessions
  and requests) rather than being statically fixed.

### 5.4 Frontend (FE)

- **FE-1** — Runs in the browser without plugins; Firefox (current release)
  is the v1 reference target.
- **FE-2** — Connects to a local or remote backend; host and port shall be
  user-configurable.
- **FE-3** — Displays all events grouped and filterable per protocol (MSRP,
  MVRP, MAAP, ADP, AECP, ACMP), using Milan v1.2 terminology and field names.
- **FE-4** — Packet inspector: selecting a packet shows the full decoded
  Milan/AVB detail — all fields plus the raw bytes.
- **FE-5** — Timeline view: events of all protocols on a common time axis
  with one lane per protocol; zoomable and filterable by protocol, entity and
  stream.
- **FE-6** — State view: current and past states of each reconstructed state
  machine, with transitions navigable to the packets that caused them.
- **FE-7** *(v2)* — For live sessions, all views shall update in near real
  time.
- **FE-8** — Wherever an entity ID appears (timeline, state view, packet
  lists), the entity name learned via ADP/AECP shall be shown alongside it
  when available (PA-6).
- **FE-9** — The session view shall include an investigation-notes editor
  (markdown, with preview) backed by the session's `notes.md` (BE-9).

### 5.5 Security (SE)

- **SE-1** — Users shall register an account and log in before accessing any
  session or trace data.
- **SE-2** — Passwords shall be stored only as salted hashes using a modern
  password-hashing function (Argon2id or bcrypt).
- **SE-3** — All API endpoints and the WebSocket event stream shall require
  an authenticated session.
- **SE-4** — For deployments reachable beyond the local machine, TLS is
  recommended (e.g. terminated by a reverse proxy); to be confirmed (§9).

## 6. Non-functional requirements (NF)

- **NF-1** — Backend targets Linux; x86-64 first, arm64 desirable.
- **NF-2** — Observability: no fixed performance targets are set for v1;
  instead the backend shall expose runtime metrics sufficient to diagnose
  problems after the fact — at minimum packet-processing rate, per-client CPU
  usage, memory usage, event-queue depths, drop counters and decode-error
  counts, available through the API and the logs.
- **NF-3** — Under overload the backend shall apply backpressure to clients
  and degrade gracefully; it shall never silently drop state.
- **NF-4** — Licensing: the tool shall be released under the MIT licence (or
  another OSI-approved open-source licence); all dependencies must have
  compatible permissive licences (e.g. libpcap/BSD).

## 7. Testing and validation (TV)

- **TV-1** — TSN-GEN shall be used to generate reference traffic scenarios
  for each protocol; the decoded events and state transitions shall match the
  generated scenario (golden-trace tests).
- **TV-2** — A set of reference pcaps — including malformed frames — shall be
  replayed against the decoders in CI.
- **TV-3** — Frontend/backend integration shall be validated against at least
  one TSN-GEN-generated scenario (as a pcap in v1; live in v2).
- **TV-4** — The web UI shall be exercised end-to-end in a real browser
  (Playwright, headless Firefox) in CI: authentication, upload, analysis
  views, state, and investigation notes.

## 8. Decision log

Resolutions of the open questions from draft v0.2:

| OQ | Decision | Folded into |
|---|---|---|
| OQ-1 | Backend protocol logic is implemented as overrides of TSN-GEN's logic layer, modelling the real protocols. | BE-2 |
| OQ-2 | REST for control + WebSocket event stream; binary framing with lightweight compression. | BE-4 |
| OQ-3 | ADP and AECP are in scope for v1. | PA-1, PA-6, FE-3, FE-8 |
| OQ-4 | v1 is pcap-only; live capture moves to v2. | Scope, BE-6, FE-7 |
| OQ-5 | Simple accounts: registration required, hashed passwords. | SE-1..SE-3 |
| OQ-6 | No fixed performance numbers; deep runtime monitoring instead (packet rate, per-client CPU, …). | NF-2 |
| OQ-7 | Pcaps and sessions persist locally and survive restarts. | BE-8, BE-3 |
| OQ-8 | MIT (or other open-source) licence; compatible dependencies. | NF-4 |

## 9. Remaining open questions

- **OQ-9** — *gPTP:* **resolved during implementation** — gPTP (802.1AS) is
  decoded and reconstructed in v1 as a passive observer (grandmaster per
  domain via Announce/BMCA, sync health with syncReceiptTimeout, per-port
  role/asCapable/pdelay tracking), with cross-protocol correlation: ADP
  entities get a live `gm_in_sync` check of their announced grandmaster, and
  MSRP reservations carry a `gptp_sync` annotation. Folded into PA-1, PA-2
  and PA-6. Real-capture validation showed 87% of Milan lab traffic is gPTP.
- **OQ-10** — *Compression algorithm:* **resolved during implementation** —
  zlib deflate (RFC 1950) at `Z_BEST_SPEED`: lightweight on the backend and
  decompressed natively in the browser via `DecompressionStream("deflate")`,
  no client-side library needed.
- **OQ-11** — *Toolchain:* **resolved during implementation** — C++20, plain
  Make (CMake unnecessary; keeps the toolchain minimal), Docker base image
  `debian:bookworm-slim`. Dependencies: zlib, libsodium.
- **OQ-12** — *TLS:* confirm whether TLS (via reverse proxy or native) is
  required for v1 remote deployments, or acceptable to defer.

## 10. Multi-user domains — v2 outlook (design, not yet implemented)

v1 already supports multiple concurrent users with roles (`admin`/`user`,
SE-1..3), presence, and conflict-safe notes editing — but all users share
one flat data space. The long-term goal is one deployment serving **users
from different domains (teams/organizations) that must stay isolated from
one another**. The agreed design to prepare for:

- **Tenancy model** — every user belongs to exactly one *domain*. Roles
  become domain-scoped: a *domain admin* manages users and data of their
  domain; a *global admin* (the deployment operator) manages domains and
  global settings. The v1 `AVB_ADMIN_USER` becomes the first global admin.
- **Data isolation** — every object is domain-owned: pcap uploads, session
  folders (captures + notes), and device names move under
  `data/domains/<domain>/{pcaps,sessions,devices.json}`; `users.json` gains
  a `domain` field. Device names become per-domain (the same MAC may carry
  different names in different domains).
- **Authorization** — every API handler resolves the caller's domain and
  refuses cross-domain object access, answering **404** (not 403) so object
  existence does not leak across domains. The admin API splits into
  `/api/admin/…` (domain scope) and `/api/global/…` (global admin).
- **Presence and metrics scoping** — presence lists only the caller's
  domain; per-session metrics likewise. The global admin sees everything.
- **Resource isolation (NF-3)** — per-domain quotas: upload bytes, stored
  sessions, concurrent analyses, and WebSocket clients, so one domain cannot
  starve another on a shared deployment.
- **Audit** — admin actions (user create/delete, quota changes) recorded in
  an append-only per-domain audit log.
- **Migration** — existing single-tenant data moves to a built-in domain
  named `default`; v1 accounts join it unchanged, preserving BE-8.
