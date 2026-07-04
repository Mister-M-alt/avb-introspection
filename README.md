# AVB Introspection

A Milan-oriented introspection tool for AVB/TSN control protocols: it decodes
**MSRP, MVRP, MAAP, ATDECC (ADP, AECP, ACMP)** and **gPTP (802.1AS)** traffic
from pcap files, reconstructs the protocol state machines (reservations, VLAN
registrations, address claims, entity lifecycles, command correlation, stream
connections, grandmaster election and sync health), correlates them across
protocols (e.g. each entity's announced grandmaster is checked against the
grandmaster actually observed on the wire), and presents events, per-packet
detail, timelines and live state in a web UI.

The **Network Status** view is the single home for the observed topology and
every reconstructed protocol **state machine as a live spec diagram** (Milan
ACMP listener sink, ADP, 802.1AS media-dependent, and the 802.1Q MRP
Applicant/Registrar). It maps the observed devices; click an endstation or port
to see all of its state machines, **grouped per protocol** and each in a
foldable, resizable card. Above the graph it always shows the **network-wide**
machines that belong to no single device — the gPTP domain grandmaster/BMCA
lifecycle, the MSRP SR reservation domain, and MAAP multicast-address claims.
Every diagram overlays the state **as of where the timeline cursor sits**:
select a packet (in the event table or on the timeline) and each machine's
highlighted *current* state — and the sync/stream links and gPTP port roles —
re-time to that moment; with nothing selected they show the final observed
state. Click any **transition** to list the event(s) that drove it, each
linking straight to its triggering packet.

The tool is an *observer* — it decodes and correlates traffic; generating
traffic is [TSN-GEN]'s job. See [REQUIREMENTS.md](REQUIREMENTS.md) for the
full requirements and [docs/API.md](docs/API.md) for the API contract.

## Quick start

Dependencies: `g++` (C++20), `make`, `zlib`, `libsodium` (and Python 3 for
the test-data generator).

```bash
make -j                       # -> build/avb-introspectd
./build/avb-introspectd       # listens on :8342, data in ./data
```

Open http://localhost:8342 in Firefox, register an account, upload a pcap
(or open one by server path), and explore. To try it without real traffic:

```bash
python3 tools/gen_pcaps.py    # writes Milan scenarios to testdata/
# then upload testdata/milan_scenario.pcap in the UI
```

### Docker (BE-3)

```bash
docker build -t avb-introspection .
docker run -p 8342:8342 -v avb-data:/data avb-introspection
```

Uploaded pcaps, sessions and user accounts persist in the `/data` volume and
survive restarts (BE-8).

## Architecture

```
frontend/            single-page web UI (vanilla JS, Firefox-first)
backend/src/
  pcapio/            pcap + pcapng readers (Ethernet captures)
  decode/            wire-format decoders for the six protocols
  tsn_gen/           vendored TSN-GEN logic-override contract (see below)
  logic/             protocol state machines as TSN-GEN logic modules
  engine/            parallel decode -> ordered single-threaded state pass
  net/               HTTP/1.1 + RFC 6455 WebSocket server (POSIX sockets)
  auth/              accounts, Argon2id password hashes (libsodium)
  store/             on-disk persistence of pcaps + session metadata
  api/               REST endpoints, WS streaming, metrics, static serving
```

Concurrency model (CO-1..4): client connections are served by a thread pool
that grows on demand up to `--max-threads`; captures are partitioned across
CPU cores and decoded in parallel; the decoded packets are then re-ordered
by capture timestamp and fed to the state machines by a single thread —
state reconstruction is order-sensitive, so reordered packets never reach
the logic modules.

The WebSocket event stream uses binary frames, each a zlib (RFC 1950)
stream the browser inflates with `DecompressionStream("deflate")` (OQ-10:
zlib at `Z_BEST_SPEED` — lightweight, native on both ends).

## TSN-GEN integration (BE-2)

TSN-GEN's protocol *logic* layer is an override mechanism: modules subclass
`ILogicModule` (`onEncode` / `onDecode` / `nextLayer`), register with
`REGISTER_LOGIC("<service>", Class)`, and read named vars through a
`LayerContext`. This backend implements every protocol state machine as
exactly such a module (`backend/src/logic/`):

| Service | Module | State reconstructed |
|---|---|---|
| `mrp_msrp` | MsrpLogic | reservation per StreamID, SR domains |
| `mrp_mvrp` | MvrpLogic | VLAN registration per VID |
| `1722_maap` | MaapLogic | address range per claimant (probe/defend) |
| `atdecc_adp` | AdpLogic | entity lifecycle incl. valid_time expiry |
| `atdecc_aecp` | AecpLogic | in-flight commands, timeouts, entity names |
| `atdecc_acmp` | AcmpLogic | stream connection per talker/listener pair |

The three contract headers in `backend/src/tsn_gen/` are vendored unmodified
from TSN-GEN (MIT). TSN-GEN v1 ships `LayerContext::getValue/setValue` as
stubs pending its Stack serializer; `VarLayerContext` here is the working
implementation backed by the decoders' field storage, so the modules run for
real today and can be linked into TSN-GEN unchanged once its serializer
lands. `VarLayerContext::getBytes/setBytes` anticipates TSN-GEN's planned
typed accessors for fields wider than `uint64_t` (e.g. the 64-byte AEM
`entity_name`).

## Investigation sessions

Every analysis session is a self-contained folder under
`data/sessions/<id>/` holding its own copy of the capture plus `notes.md`
— markdown investigation notes seeded from a template and editable in the
UI's **Notes** tab (with preview). Deleting a library upload never breaks
an existing investigation, and notes survive restarts with the session.

**Combining captures.** Several library pcaps can be merged into one session
and timeline: tick them in the library and choose *Combine into a session*
(or `POST /api/sessions {"pcap_ids": [...]}`). The backend merges all packets by
absolute capture time into one `capture.pcap`, which everything downstream then
treats as an ordinary single-file session. Captures uploaded in any order land
on a single chronological timeline: **disjoint** windows keep their real gaps
(e.g. ring-buffer splits, or capture part 1 then part 2), and **overlapping**
windows — such as two tap points watching the same period — are interleaved
packet-by-packet by timestamp. Every packet keeps a tag for the **source
capture** it came from (a per-packet sidecar), shown as a coloured badge in the
inspector; each source gets an editable **alias** (defaulting to its filename)
you can rename in the session's Info tab — handy for labelling tap points.

## Testing

```bash
make -j test                   # unit tests incl. golden-trace runs (TV-1/2)
./scripts/integration_test.sh  # black-box REST+WS test with restart (TV-3)
python3 scripts/e2e_playwright.py   # browser E2E, headless Firefox (TV-4)
```

The browser suite needs Playwright once: `pip install playwright &&
playwright install firefox` (add `--with-deps` on Ubuntu;
on other distros the GTK3/ALSA stack must be present).

`tools/gen_pcaps.py` builds byte-exact golden scenarios per protocol
(including malformed frames — decode errors become events, never crashes,
PA-5). It stands in for TSN-GEN generated traffic; regenerate the scenarios
through TSN-GEN once its serializer lands.

## Server options

```
--port N            listen port                    (default 8342)
--data DIR          persistent data directory      (default ./data)
--frontend DIR      static frontend directory      (default ./frontend)
--max-threads N     serving thread cap (CO-1)      (default 64)
--max-upload-mb N   pcap upload limit              (default 1024)
```

Runtime metrics (NF-2: per-session packet rates, per-client bytes, CPU/RSS,
pool utilisation) are at `GET /api/metrics` and shown on the UI home screen.

## Security, users & admin (SE)

Registration + login are required for every API call; passwords are stored
as Argon2id hashes (libsodium `crypto_pwhash_str`); sessions use random
64-hex bearer tokens. TLS is not terminated by the backend — put a reverse
proxy in front for deployments beyond a trusted lab network (OQ-12).

Accounts have roles (`admin`/`user`). Provision the admin from the
deployment environment — created on first start, or promoted if the
account already exists:

```bash
AVB_ADMIN_USER=alex AVB_ADMIN_PASSWORD=change-me ./build/avb-introspectd
```

Admins get an **Admin** panel in the UI: user management (create/delete,
roles) and live presence. Everyone sees the presence indicator in the
header — who is online and which session they are looking at — and
concurrent notes editing is conflict-safe (revision check with a merge
prompt instead of silent overwrites).

**Multi-domain outlook:** the tool is designed to eventually serve users
from different domains (teams/organizations) with full isolation between
them — domain-scoped data, authorization, quotas, and presence. The agreed
design is documented in REQUIREMENTS.md §10 ("Multi-user domains — v2
outlook").

### Remote deployment

`deploy/` contains an nginx reverse-proxy setup for remote access: correct
WebSocket upgrade for `/api/ws`, 1 GiB streamed uploads, and a ready-to-
enable TLS server block.

```bash
docker compose -f deploy/docker-compose.yml up --build   # UI on port 80
```

For bare metal, point the upstream in `deploy/nginx.conf` at
`127.0.0.1:8342` and drop it into `/etc/nginx/conf.d/`.

## Notes / deviations

- **OQ-11**: built with plain Make + C++20 (CMake was proposed; Make keeps
  the toolchain minimal). GCC ≥ 12 or a comparable Clang works.
- v1 is pcap-only; live capture (BE-6) and real-time views (FE-7) are v2.
- pcapng inputs are supported alongside classic pcap (µs and ns variants).

## License

MIT — see [LICENSE](LICENSE). Runtime dependencies: zlib (zlib licence),
libsodium (ISC); vendored TSN-GEN headers (MIT, Kebag-Logic).
