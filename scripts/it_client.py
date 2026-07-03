#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Kebag-Logic
# SPDX-License-Identifier: MIT
"""Integration-test client (TV-3): drives the running backend over its real
REST + WebSocket API using only the stdlib. Phases: main, after_restart."""
import base64
import http.client
import json
import os
import socket
import struct
import sys
import time
import zlib

PORT = int(sys.argv[1])
PHASE = sys.argv[2]
FAILS = 0


def check(cond, what):
    global FAILS
    if cond:
        print(f"  ok: {what}")
    else:
        print(f"  FAIL: {what}")
        FAILS += 1


def req(method, path, body=None, token=None, raw_body=None):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=60)
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = raw_body
    if body is not None:
        data = json.dumps(body)
        headers["Content-Type"] = "application/json"
    c.request(method, path, body=data, headers=headers)
    r = c.getresponse()
    payload = r.read()
    ctype = r.getheader("Content-Type", "")
    c.close()
    if "json" in ctype and payload:
        return r.status, json.loads(payload)
    return r.status, payload


def wait_done(token, sid, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        st, s = req("GET", f"/api/sessions/{sid}", token=token)
        if st == 200 and s["status"] in ("done", "error"):
            return s
        time.sleep(0.2)
    raise TimeoutError(f"session {sid} did not finish")


# --- minimal WebSocket client ----------------------------------------------


class WsConn:
    """Buffered WebSocket client — frames may arrive in the same recv() as
    the 101 response, so all reads go through one buffer."""

    def __init__(self, path):
        self.s = socket.create_connection(("127.0.0.1", PORT), timeout=60)
        self.buf = b""
        key = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall((f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n"
                        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                        f"Sec-WebSocket-Key: {key}\r\n"
                        "Sec-WebSocket-Version: 13\r\n\r\n").encode())
        while b"\r\n\r\n" not in self.buf:
            chunk = self.s.recv(4096)
            if not chunk:
                raise ConnectionError("closed during handshake")
            self.buf += chunk
        head, _, self.buf = self.buf.partition(b"\r\n\r\n")
        if b" 101 " not in head.split(b"\r\n", 1)[0]:
            raise ConnectionError(f"no upgrade: {head[:80]!r}")

    def _rx(self, n):
        while len(self.buf) < n:
            chunk = self.s.recv(65536)
            if not chunk:
                raise ConnectionError("closed")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def read(self):
        h = self._rx(2)
        op = h[0] & 0x0F
        ln = h[1] & 0x7F
        if ln == 126:
            ln = struct.unpack(">H", self._rx(2))[0]
        elif ln == 127:
            ln = struct.unpack(">Q", self._rx(8))[0]
        return op, self._rx(ln) if ln else b""

    def send_text(self, text):
        data = text.encode()
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        hdr = bytes([0x81])
        if len(data) < 126:
            hdr += bytes([0x80 | len(data)])
        else:
            hdr += bytes([0x80 | 126]) + struct.pack(">H", len(data))
        self.s.sendall(hdr + mask + masked)

    def close(self):
        self.s.close()


def ws_messages(path, send_ping=False):
    """Yields (type, message) until the server closes."""
    c = WsConn(path)
    pinged = False
    try:
        while True:
            try:
                op, payload = c.read()
            except ConnectionError:
                yield ("__close__", 1006)
                return
            if op == 0x8:  # close
                yield ("__close__", struct.unpack(">H", payload[:2])[0]
                       if len(payload) >= 2 else 1005)
                return
            if op != 0x2:
                continue
            msg = json.loads(zlib.decompress(payload).decode())
            yield (msg.get("type"), msg)
            if send_ping and not pinged and msg.get("type") == "batch":
                c.send_text(json.dumps({"type": "ping"}))
                pinged = True
    finally:
        c.close()


# --- phases -----------------------------------------------------------------


def phase_main():
    print("phase: main")
    st, _ = req("POST", "/api/register",
                {"username": "alex", "password": "correct-horse-9"})
    check(st == 201, "register -> 201")
    st, _ = req("POST", "/api/register",
                {"username": "alex", "password": "correct-horse-9"})
    check(st == 409, "duplicate register -> 409")
    st, _ = req("POST", "/api/register", {"username": "x", "password": "short"})
    check(st == 400, "invalid register -> 400")

    st, _ = req("POST", "/api/login", {"username": "alex", "password": "wrong-pass-1"})
    check(st == 401, "bad login -> 401")
    st, r = req("POST", "/api/login", {"username": "alex", "password": "correct-horse-9"})
    check(st == 200 and len(r["token"]) == 64, "login -> token")
    token = r["token"]

    st, _ = req("GET", "/api/me")
    check(st == 401, "no token -> 401 (SE-3)")
    st, r = req("GET", "/api/me", token=token)
    check(st == 200 and r["username"] == "alex", "GET /api/me")

    st, page = req("GET", "/")
    check(st == 200 and b"<" in page[:200], "frontend served at /")

    st, _ = req("POST", "/api/pcaps?name=junk.pcap", token=token,
                raw_body=b"not a pcap at all")
    check(st == 400, "garbage upload -> 400")

    with open("testdata/milan_scenario.pcap", "rb") as f:
        blob = f.read()
    st, r = req("POST", "/api/pcaps?name=milan_scenario.pcap", token=token,
                raw_body=blob)
    check(st == 201, "pcap upload -> 201")
    pcap_id = r["id"]

    st, r = req("POST", "/api/sessions", {"pcap_id": pcap_id}, token=token)
    check(st == 201, "session create -> 201")
    sid = r["id"]
    s = wait_done(token, sid)
    check(s["status"] == "done", "analysis done")
    check(s["packets"] == 36, f"36 packets (got {s['packets']})")
    check(s["decode_errors"] == 0, "no decode errors")
    check(all(s["protocols"][p] > 0
              for p in ("MSRP", "MVRP", "MAAP", "ADP", "AECP", "ACMP")),
          "all six protocols seen")

    st, ev = req("GET", f"/api/sessions/{sid}/events", token=token)
    total = ev["total"]
    check(st == 200 and total > 36, f"events fetched (total {total})")
    check(len(ev["events"]) == total, "single page holds all")
    ts = [e["ts"] for e in ev["events"]]
    check(ts == sorted(ts), "events in capture-time order (CO-3)")

    st, ft = req("GET",
                 f"/api/sessions/{sid}/events?proto=ACMP&kind=transition",
                 token=token)
    check(ft["matched"] > 0 and
          all(e["proto"] == "ACMP" and e["kind"] == "transition"
              for e in ft["events"]),
          "proto/kind filters")

    st, cp = req("GET", f"/api/sessions/{sid}/events?compact=1", token=token)
    check(len(cp["events"]) == total and cp["protos"][4] == "ADP",
          "compact timeline feed")

    st, pk = req("GET", f"/api/sessions/{sid}/packets/1", token=token)
    check(st == 200 and pk["layers"][0]["service"] == "ethernet_mac_frame"
          and len(pk["hex"]) >= 120, "packet inspector")
    st, _ = req("GET", f"/api/sessions/{sid}/packets/999", token=token)
    check(st == 404, "unknown packet -> 404")

    st, state = req("GET", f"/api/sessions/{sid}/state", token=token)
    names = {e["entity_id"]: e["name"] for e in state["entities"]}
    check("Stage Box FOH" in names.values() and "Monitor Desk" in names.values(),
          "entities named via AEM (PA-6)")
    check(state["connections"][0]["state"] == "DISCONNECTED",
          "connection torn down at trace end")
    check(state["reservations"][0]["state"] == "WITHDRAWN", "reservation withdrawn")
    check(state["maap"][0]["state"] == "ACQUIRED", "MAAP range acquired")
    check(len(state["vlans"]) == 1 and state["vlans"][0]["vid"] == 2, "VLAN 2")
    check(all("history" in e for e in state["entities"]), "state history present")

    # Investigation notes: seeded template, full-replace edit, validation.
    st, nt = req("GET", f"/api/sessions/{sid}/notes", token=token)
    check(st == 200 and nt["markdown"].startswith("# Investigation:"),
          "notes seeded with template")
    edited = "# My notes\n\n- edited via integration test\n"
    st, _ = req("PUT", f"/api/sessions/{sid}/notes", {"markdown": edited},
                token=token)
    check(st == 200, "notes saved")
    st, nt = req("GET", f"/api/sessions/{sid}/notes", token=token)
    check(nt["markdown"] == edited, "notes round-trip")
    st, _ = req("PUT", f"/api/sessions/{sid}/notes", {"nope": 1}, token=token)
    check(st == 400, "bad notes body -> 400")

    # Session info: file metadata, capture window, device inventory.
    st, info = req("GET", f"/api/sessions/{sid}/info", token=token)
    check(st == 200 and info["capture"]["packets"] == 36, "info: capture block")
    check(info["capture"]["start_ts_ns"].isdigit()
          and int(info["capture"]["end_ts_ns"]) > int(info["capture"]["start_ts_ns"]),
          "info: ns capture window")
    check(info["file"]["size"] > 0 and info["file"]["modified"] != "",
          "info: file stat")
    devs = {d["mac"]: d for d in info["devices"]}
    talker = devs.get("00:1b:92:00:00:01")
    check(talker is not None and talker["entity_name"] == "Stage Box FOH"
          and "MSRP" in talker["protocols"],
          "info: device auto-named via its entity")

    st, _ = req("PUT", "/api/devices",
                {"mac": "00:1B:92:00:00:01", "name": "FOH Rack"}, token=token)
    check(st == 200, "device rename")
    st, info = req("GET", f"/api/sessions/{sid}/info", token=token)
    check({d["mac"]: d for d in info["devices"]}
          ["00:1b:92:00:00:01"]["name"] == "FOH Rack",
          "device name round-trip (case-normalized)")
    st, _ = req("PUT", "/api/devices", {"mac": "junk", "name": "x"}, token=token)
    check(st == 400, "bad device mac -> 400")

    st, s2 = req("GET", f"/api/sessions/{sid}", token=token)
    check(s2["start_ts_ns"].isdigit() and int(s2["start_ts_ns"]) > 0,
          "session start_ts_ns for ToD display")

    st, mx = req("GET", "/api/metrics", token=token)
    check(all(k in mx for k in ("process", "pool", "sessions", "clients")),
          "metrics shape (NF-2)")
    check(mx["process"]["rss_kb"] > 0 and mx["pool"]["threads"] >= 1,
          "metrics content")

    # WebSocket: full stream + ping/pong + close after complete.
    got, completed, ponged = 0, False, False
    for typ, msg in ws_messages(f"/api/ws?token={token}&session={sid}",
                                send_ping=True):
        if typ == "batch":
            got += len(msg["events"])
        elif typ == "pong":
            ponged = True
        elif typ == "complete":
            completed = True
            check(msg["total"] == total, "WS complete total matches")
        elif typ == "__close__":
            break
    check(completed and got == total, f"WS streamed all {total} events deflated")
    check(ponged, "WS ping -> pong")

    for typ, msg in ws_messages(f"/api/ws?token=bogus&session={sid}"):
        check(typ == "__close__" and msg == 4001, "WS bad token -> close 4001")
        break
    for typ, msg in ws_messages(f"/api/ws?token={token}&session=nope"):
        check(typ == "__close__" and msg == 4004, "WS bad session -> close 4004")
        break

    # Second concurrent-ish client on the same finished session (BE-7).
    got2 = sum(len(m["events"]) for t, m in
               ws_messages(f"/api/ws?token={token}&session={sid}")
               if t == "batch")
    check(got2 == total, "second client receives the same stream (BE-7)")

    # Open a capture by server path, then delete the session.
    st, r = req("POST", "/api/sessions",
                {"path": os.path.abspath("testdata/adp.pcap")}, token=token)
    check(st == 201, "session from server path")
    sid2 = r["id"]
    wait_done(token, sid2)
    st, _ = req("DELETE", f"/api/sessions/{sid2}", token=token)
    check(st == 200, "session delete")
    st, _ = req("GET", f"/api/sessions/{sid2}", token=token)
    check(st == 404, "deleted session gone")

    print(f"main phase: {'OK' if FAILS == 0 else f'{FAILS} FAILURES'}")


def phase_after_restart():
    print("phase: after_restart (BE-8)")
    st, r = req("POST", "/api/login", {"username": "alex", "password": "correct-horse-9"})
    check(st == 200, "users survived restart")
    token = r["token"]

    st, r = req("GET", "/api/pcaps", token=token)
    check(any(p["name"] == "milan_scenario.pcap" for p in r["pcaps"]),
          "pcaps survived restart")

    st, r = req("GET", "/api/sessions", token=token)
    milan = [s for s in r["sessions"] if s["name"] == "milan_scenario.pcap"]
    check(len(milan) == 1, "session metadata survived restart")
    s = wait_done(token, milan[0]["id"])
    check(s["status"] == "done" and s["packets"] == 36,
          "session re-analyzed after restart")

    st, state = req("GET", f"/api/sessions/{milan[0]['id']}/state", token=token)
    check(any(e["name"] == "Stage Box FOH" for e in state["entities"]),
          "state reconstructed after restart")

    st, nt = req("GET", f"/api/sessions/{milan[0]['id']}/notes", token=token)
    check(nt["markdown"] == "# My notes\n\n- edited via integration test\n",
          "edited notes survived restart")

    st, info = req("GET", f"/api/sessions/{milan[0]['id']}/info", token=token)
    devs = {d["mac"]: d for d in info["devices"]}
    check(devs.get("00:1b:92:00:00:01", {}).get("name") == "FOH Rack",
          "device names survived restart (global store)")
    print(f"after_restart phase: {'OK' if FAILS == 0 else f'{FAILS} FAILURES'}")


if PHASE == "main":
    phase_main()
elif PHASE == "after_restart":
    phase_after_restart()
else:
    print(f"unknown phase {PHASE}")
    sys.exit(2)

sys.exit(1 if FAILS else 0)
