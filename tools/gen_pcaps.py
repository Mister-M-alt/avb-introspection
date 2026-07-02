#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Kebag-Logic
# SPDX-License-Identifier: MIT
"""Golden-scenario pcap generator (TV-1).

Pure-stdlib stand-in for TSN-GEN traffic on this machine: builds
byte-exact MSRP/MVRP/MAAP/ADP/AECP/ACMP frames per IEEE 802.1Q, 1722,
1722.1 as profiled by Milan v1.2, and writes classic pcap files under
testdata/. Each scenario mirrors a TSN-GEN action graph; when TSN-GEN's
serializer lands these scenarios should be regenerated through it.
"""
import os
import struct
import sys

BASE_TS = 1700000000.0

# --- primitives -----------------------------------------------------------


def mac(s: str) -> bytes:
    return bytes(int(b, 16) for b in s.split(":"))


def eth(dst: str, src: str, etype: int, payload: bytes, vlan=None) -> bytes:
    hdr = mac(dst) + mac(src)
    if vlan is not None:
        hdr += struct.pack(">HH", 0x8100, vlan)
    frame = hdr + struct.pack(">H", etype) + payload
    if len(frame) < 60:
        frame += bytes(60 - len(frame))
    return frame


def avtp_ctrl(subtype: int, msg_type: int, status5: int, cdl: int) -> bytes:
    b1 = (0 << 7) | (0 << 4) | (msg_type & 0xF)
    return struct.pack(">BBH", subtype, b1, ((status5 & 0x1F) << 11) | (cdl & 0x7FF))


ADP_MC = "91:e0:f0:01:00:00"
MAAP_MC = "91:e0:f0:00:ff:00"
ETYPE_AVTP = 0x22F0
ETYPE_MSRP = 0x22EA
ETYPE_MVRP = 0x88F5
MSRP_MC = "01:80:c2:00:00:0e"
MVRP_MC = "01:80:c2:00:00:21"


def adp(msg_type, valid_s, entity, model=0x001B92FFFE112233, avail_idx=0,
        gm=0x001B92FFFE00AAAA, tss=2, lss=2, assoc=0):
    body = struct.pack(">QQIHHHHIIQ", entity, model, 0x00008508, tss, 0x4801,
                       lss, 0x4801, 0x00000001, avail_idx, gm)
    body += struct.pack(">B3xHHQ4x", 0, 0, 0, assoc)
    return avtp_ctrl(0xFA, msg_type, valid_s // 2, 56) + body


def aecp(msg_type, status, target, controller, seq, cmd, payload=b"", unsol=False):
    pdu = struct.pack(">QQH", target, controller, seq)
    pdu += struct.pack(">H", ((0x8000 if unsol else 0) | (cmd & 0x7FFF)))
    pdu += payload
    return avtp_ctrl(0xFB, msg_type, status, len(pdu) - 8) + pdu


def name64(s: str) -> bytes:
    b = s.encode()[:64]
    return b + bytes(64 - len(b))


def entity_descriptor(entity, model, name, avail_idx=1):
    d = struct.pack(">HH", 0x0000, 0)  # descriptor_type ENTITY, index 0
    d += struct.pack(">QQIHHHHIIQ", entity, model, 0x00008508, 2, 0x4801, 2,
                     0x4801, 0x00000001, avail_idx, 0)
    d += name64(name)
    d += struct.pack(">HH", 0, 1)  # vendor/model name string refs
    d += name64("fw-1.2.3") + name64("group") + name64("SN-0001")
    d += struct.pack(">HH", 1, 0)  # configurations_count, current
    return d


def read_desc_cmd(target, controller, seq, desc_type=0, desc_idx=0):
    payload = struct.pack(">HHHH", 0, 0, desc_type, desc_idx)
    return aecp(0, 0, target, controller, seq, 0x0004, payload)


def read_desc_entity_resp(target, controller, seq, name):
    payload = struct.pack(">HH", 0, 0) + entity_descriptor(target, 0x001B92FFFE112233, name)
    return aecp(1, 0, target, controller, seq, 0x0004, payload)


def get_name_cmd(target, controller, seq):
    return aecp(0, 0, target, controller, seq, 0x0011, struct.pack(">HHHH", 0, 0, 0, 0))


def get_name_resp(target, controller, seq, name, status=0):
    return aecp(1, status, target, controller, seq, 0x0011,
                struct.pack(">HHHH", 0, 0, 0, 0) + name64(name))


def set_name_cmd(target, controller, seq, name):
    return aecp(0, 0, target, controller, seq, 0x0010,
                struct.pack(">HHHH", 0, 0, 0, 0) + name64(name))


def set_name_resp(target, controller, seq, name, status=0):
    return aecp(1, status, target, controller, seq, 0x0010,
                struct.pack(">HHHH", 0, 0, 0, 0) + name64(name))


def acmp(msg_type, status, stream_id, controller, talker, listener,
         t_uid=0, l_uid=0, dest="00:00:00:00:00:00", conn_count=0, seq=0,
         flags=0, vlan=0):
    pdu = struct.pack(">QQQQHH", stream_id, controller, talker, listener,
                      t_uid, l_uid)
    pdu += mac(dest) + struct.pack(">HHHHH", conn_count, seq, flags, vlan, 0)
    return avtp_ctrl(0xFC, msg_type, status, 44) + pdu


def maap(msg_type, req_start, req_count, conf_start="00:00:00:00:00:00",
         conf_count=0, version=1):
    pdu = struct.pack(">Q", 0) + mac(req_start) + struct.pack(">H", req_count)
    pdu += mac(conf_start) + struct.pack(">H", conf_count)
    return avtp_ctrl(0xFE, msg_type, version, 16) + pdu


# --- MRP ------------------------------------------------------------------

NEW, JOININ, IN, JOINMT, MT, LV = range(6)
IGNORE, ASKFAIL, READY, READYFAIL = range(4)


def three_packed(events):
    out = b""
    evs = list(events)
    while len(evs) % 3:
        evs.append(0)
    for i in range(0, len(evs), 3):
        out += bytes([evs[i] * 36 + evs[i + 1] * 6 + evs[i + 2]])
    return out[: (len(events) + 2) // 3]


def four_packed(events):
    out = b""
    evs = list(events)
    while len(evs) % 4:
        evs.append(0)
    for i in range(0, len(evs), 4):
        out += bytes([evs[i] * 64 + evs[i + 1] * 16 + evs[i + 2] * 4 + evs[i + 3]])
    return out[: (len(events) + 3) // 4]


def mrp_vector(first_value, events, leave_all=False, listener_events=None):
    hdr = struct.pack(">H", ((0x2000 if leave_all else 0) | len(events)))
    v = hdr + first_value + three_packed(events)
    if listener_events is not None:
        v += four_packed(listener_events)
    return v


def msrp_pdu(messages):
    """messages: list of (attr_type, attr_len, [vectors])"""
    pdu = b"\x00"  # protocol version
    for attr_type, attr_len, vectors in messages:
        vec = b"".join(vectors) + b"\x00\x00"  # vector list + EndMark
        pdu += struct.pack(">BBH", attr_type, attr_len, len(vec)) + vec
    pdu += b"\x00\x00"  # message list EndMark
    return pdu


def mvrp_pdu(vectors):
    pdu = b"\x00" + struct.pack(">BB", 1, 2)  # version, VID attr, len 2
    pdu += b"".join(vectors) + b"\x00\x00"  # vector EndMark
    pdu += b"\x00\x00"  # message EndMark
    return pdu


def talker_fv(stream_id, dest, vlan, mfs=224, mif=1, prio=3, rank=1, lat=125000):
    return (struct.pack(">Q", stream_id) + mac(dest) + struct.pack(">H", vlan)
            + struct.pack(">HHB", mfs, mif, (prio << 5) | (rank << 4))
            + struct.pack(">I", lat))


def talker_failed_fv(stream_id, dest, vlan, bridge, code, **kw):
    return talker_fv(stream_id, dest, vlan, **kw) + struct.pack(">QB", bridge, code)


def listener_fv(stream_id):
    return struct.pack(">Q", stream_id)


def domain_fv(class_id, prio, vid):
    return struct.pack(">BBH", class_id, prio, vid)


# --- pcap writer -----------------------------------------------------------


def write_pcap(path, packets):
    """packets: list of (t_offset_seconds, frame_bytes)"""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for t, frame in packets:
            ts = BASE_TS + t
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            f.write(frame)
    print(f"  {path}: {len(packets)} packets")


# --- actors ----------------------------------------------------------------

TALKER_MAC = "00:1b:92:00:00:01"
LISTENER_MAC = "00:1b:92:00:00:02"
CTRL_MAC = "00:1b:92:00:00:99"
BRIDGE_MAC = "00:1b:92:00:00:10"
E_TALKER = 0x001B92FFFE000001
E_LISTENER = 0x001B92FFFE000002
E_CTRL = 0x0000000000000099
STREAM_ID = (0x001B92000001 << 16) | 0x0001  # talker MAC + unique id 1
STREAM_DEST = "91:e0:f0:00:0e:80"
VLAN = 2


def msrp_talker(events, attr=1, **kw):
    fv = talker_fv(STREAM_ID, STREAM_DEST, VLAN, **kw) if attr == 1 else None
    return eth(MSRP_MC, TALKER_MAC, ETYPE_MSRP,
               msrp_pdu([(1, 25, [mrp_vector(fv, events)])]))


def scenario_msrp_basic():
    pk = []
    pk.append((0.00, eth(MVRP_MC, TALKER_MAC, ETYPE_MVRP,
                         mvrp_pdu([mrp_vector(struct.pack(">H", VLAN), [JOININ])]))))
    pk.append((0.05, eth(MVRP_MC, LISTENER_MAC, ETYPE_MVRP,
                         mvrp_pdu([mrp_vector(struct.pack(">H", VLAN), [JOININ])]))))
    pk.append((0.10, eth(MSRP_MC, BRIDGE_MAC, ETYPE_MSRP,
                         msrp_pdu([(4, 4, [mrp_vector(domain_fv(6, 3, VLAN), [JOININ])])]))))
    pk.append((0.20, msrp_talker([JOININ])))
    pk.append((0.30, eth(MSRP_MC, LISTENER_MAC, ETYPE_MSRP,
                         msrp_pdu([(3, 8, [mrp_vector(listener_fv(STREAM_ID), [JOININ],
                                                      listener_events=[READY])])]))))
    pk.append((1.00, msrp_talker([JOININ])))  # steady re-declaration
    pk.append((2.00, msrp_talker([LV])))      # talker withdraws
    write_pcap("testdata/msrp_basic.pcap", pk)


def scenario_msrp_failure():
    pk = []
    pk.append((0.00, eth(MSRP_MC, BRIDGE_MAC, ETYPE_MSRP,
                         msrp_pdu([(2, 34, [mrp_vector(
                             talker_failed_fv(STREAM_ID, STREAM_DEST, VLAN,
                                              0x001B92FFFE000010, 1),
                             [JOININ])])]))))
    pk.append((0.10, eth(MSRP_MC, LISTENER_MAC, ETYPE_MSRP,
                         msrp_pdu([(3, 8, [mrp_vector(listener_fv(STREAM_ID), [JOININ],
                                                      listener_events=[ASKFAIL])])]))))
    write_pcap("testdata/msrp_failure.pcap", pk)


def scenario_mvrp():
    vid_fv = struct.pack(">H", VLAN)
    pk = []
    pk.append((0.0, eth(MVRP_MC, TALKER_MAC, ETYPE_MVRP,
                        mvrp_pdu([mrp_vector(vid_fv, [NEW])]))))
    pk.append((0.1, eth(MVRP_MC, LISTENER_MAC, ETYPE_MVRP,
                        mvrp_pdu([mrp_vector(vid_fv, [JOININ])]))))
    # LeaveAll (no values) from the bridge
    pk.append((1.0, eth(MVRP_MC, BRIDGE_MAC, ETYPE_MVRP,
                        mvrp_pdu([mrp_vector(vid_fv, [], leave_all=True)]))))
    pk.append((1.1, eth(MVRP_MC, TALKER_MAC, ETYPE_MVRP,
                        mvrp_pdu([mrp_vector(vid_fv, [JOININ])]))))
    pk.append((2.0, eth(MVRP_MC, TALKER_MAC, ETYPE_MVRP,
                        mvrp_pdu([mrp_vector(vid_fv, [LV])]))))
    pk.append((2.1, eth(MVRP_MC, LISTENER_MAC, ETYPE_MVRP,
                        mvrp_pdu([mrp_vector(vid_fv, [LV])]))))
    write_pcap("testdata/mvrp.pcap", pk)


def scenario_maap():
    a, b = TALKER_MAC, LISTENER_MAC
    range_a = "91:e0:f0:00:38:00"
    range_b = "91:e0:f0:00:77:00"
    pk = []
    for i in range(3):  # A probes its range
        pk.append((0.1 * i, eth(MAAP_MC, a, ETYPE_AVTP, maap(1, range_a, 8))))
    pk.append((0.4, eth(MAAP_MC, a, ETYPE_AVTP, maap(3, range_a, 8))))  # A announce
    # B claims A's range: B announces, A defends, B backs off to a new range
    pk.append((1.0, eth(MAAP_MC, b, ETYPE_AVTP, maap(3, range_a, 4))))
    pk.append((1.1, eth(MAAP_MC, a, ETYPE_AVTP,
                        maap(2, range_a, 8, conf_start=range_a, conf_count=4))))
    pk.append((1.3, eth(MAAP_MC, b, ETYPE_AVTP, maap(1, range_b, 4))))
    pk.append((1.6, eth(MAAP_MC, b, ETYPE_AVTP, maap(3, range_b, 4))))
    write_pcap("testdata/maap.pcap", pk)


def scenario_adp():
    pk = []
    pk.append((0.0, eth(ADP_MC, CTRL_MAC, ETYPE_AVTP, adp(2, 0, 0))))  # discover
    pk.append((0.1, eth(ADP_MC, TALKER_MAC, ETYPE_AVTP, adp(0, 4, E_TALKER, avail_idx=5))))
    pk.append((0.2, eth(ADP_MC, LISTENER_MAC, ETYPE_AVTP, adp(0, 62, E_LISTENER, avail_idx=9))))
    pk.append((1.0, eth(ADP_MC, TALKER_MAC, ETYPE_AVTP, adp(0, 4, E_TALKER, avail_idx=6))))
    pk.append((2.0, eth(ADP_MC, LISTENER_MAC, ETYPE_AVTP, adp(1, 62, E_LISTENER, avail_idx=10))))  # departing
    # available_index goes backwards -> reboot heuristic
    pk.append((3.0, eth(ADP_MC, TALKER_MAC, ETYPE_AVTP, adp(0, 4, E_TALKER, avail_idx=1))))
    # silence > valid_time (4 s), then unrelated traffic advances time
    pk.append((9.0, eth(ADP_MC, CTRL_MAC, ETYPE_AVTP, adp(2, 0, 0))))
    write_pcap("testdata/adp.pcap", pk)


def scenario_aecp():
    t, c = E_TALKER, E_CTRL
    tm, cm = TALKER_MAC, CTRL_MAC
    pk = []
    pk.append((0.00, eth(tm, cm, ETYPE_AVTP, read_desc_cmd(t, c, 1))))
    pk.append((0.01, eth(cm, tm, ETYPE_AVTP, read_desc_entity_resp(t, c, 1, "Stage Box FOH"))))
    pk.append((0.10, eth(tm, cm, ETYPE_AVTP, get_name_cmd(t, c, 2))))
    pk.append((0.11, eth(cm, tm, ETYPE_AVTP, get_name_resp(t, c, 2, "Stage Box FOH"))))
    pk.append((0.20, eth(tm, cm, ETYPE_AVTP, set_name_cmd(t, c, 3, "Stage Box Monitor"))))
    pk.append((0.21, eth(cm, tm, ETYPE_AVTP, set_name_resp(t, c, 3, "Stage Box Monitor"))))
    # command that never gets answered -> AEM 250 ms timeout
    pk.append((0.30, eth(tm, cm, ETYPE_AVTP,
                         aecp(0, 0, t, c, 4, 0x0002))))  # ENTITY_AVAILABLE cmd
    # unsolicited response (u bit set)
    pk.append((0.90, eth(cm, tm, ETYPE_AVTP,
                         aecp(1, 0, t, c, 99, 0x0011,
                              struct.pack(">HHHH", 0, 0, 0, 0)
                              + name64("Stage Box Monitor"), unsol=True))))
    # the entity announces itself so /state shows it with its learned name
    pk.append((0.95, eth(ADP_MC, tm, ETYPE_AVTP, adp(0, 62, t, avail_idx=1))))
    write_pcap("testdata/aecp.pcap", pk)


def scenario_acmp():
    lm, tm, cm = LISTENER_MAC, TALKER_MAC, CTRL_MAC
    pk = []
    pk.append((0.00, eth(lm, cm, ETYPE_AVTP,
                         acmp(6, 0, 0, E_CTRL, E_TALKER, E_LISTENER, seq=1))))
    pk.append((0.01, eth(tm, lm, ETYPE_AVTP,
                         acmp(0, 0, 0, E_CTRL, E_TALKER, E_LISTENER, seq=2))))
    pk.append((0.02, eth(lm, tm, ETYPE_AVTP,
                         acmp(1, 0, STREAM_ID, E_CTRL, E_TALKER, E_LISTENER,
                              dest=STREAM_DEST, conn_count=1, seq=2, vlan=VLAN))))
    pk.append((0.03, eth(cm, lm, ETYPE_AVTP,
                         acmp(7, 0, STREAM_ID, E_CTRL, E_TALKER, E_LISTENER,
                              dest=STREAM_DEST, conn_count=1, seq=1, vlan=VLAN))))
    # disconnect
    pk.append((5.00, eth(lm, cm, ETYPE_AVTP,
                         acmp(8, 0, STREAM_ID, E_CTRL, E_TALKER, E_LISTENER, seq=3))))
    pk.append((5.01, eth(tm, lm, ETYPE_AVTP,
                         acmp(2, 0, STREAM_ID, E_CTRL, E_TALKER, E_LISTENER, seq=4))))
    pk.append((5.02, eth(lm, tm, ETYPE_AVTP,
                         acmp(3, 0, STREAM_ID, E_CTRL, E_TALKER, E_LISTENER, seq=4))))
    pk.append((5.03, eth(cm, lm, ETYPE_AVTP,
                         acmp(9, 0, STREAM_ID, E_CTRL, E_TALKER, E_LISTENER,
                              conn_count=0, seq=3))))
    # failed connect on a second pair (no bandwidth)
    pk.append((6.00, eth(lm, cm, ETYPE_AVTP,
                         acmp(6, 0, 0, E_CTRL, E_TALKER, E_LISTENER,
                              t_uid=1, l_uid=1, seq=5))))
    pk.append((6.01, eth(cm, lm, ETYPE_AVTP,
                         acmp(7, 5, 0, E_CTRL, E_TALKER, E_LISTENER,
                              t_uid=1, l_uid=1, seq=5))))
    # connect command that never completes -> 4.5 s CONNECT_RX timeout
    pk.append((7.00, eth(lm, cm, ETYPE_AVTP,
                         acmp(6, 0, 0, E_CTRL, E_TALKER, E_LISTENER,
                              t_uid=2, l_uid=2, seq=6))))
    pk.append((12.0, eth(ADP_MC, CTRL_MAC, ETYPE_AVTP, adp(2, 0, 0))))  # advance time
    write_pcap("testdata/acmp.pcap", pk)


def scenario_malformed():
    pk = []
    # ADP truncated mid-PDU
    good_adp = adp(0, 62, E_TALKER)
    pk.append((0.0, (mac(ADP_MC) + mac(TALKER_MAC) + struct.pack(">H", ETYPE_AVTP)
                     + good_adp[:20])))
    # MSRP: attribute list length overruns the frame
    bad = b"\x00" + struct.pack(">BBH", 1, 25, 0xFFF0)
    pk.append((0.1, eth(MSRP_MC, TALKER_MAC, ETYPE_MSRP, bad)))
    # MVRP: unsupported attribute length
    bad2 = b"\x00" + struct.pack(">BB", 1, 3) + mrp_vector(b"\x00\x01\x02", [JOININ]) + b"\x00\x00\x00\x00"
    pk.append((0.2, eth(MVRP_MC, TALKER_MAC, ETYPE_MVRP, bad2)))
    # AECP truncated after the AVTP control header
    pk.append((0.3, (mac(TALKER_MAC) + mac(CTRL_MAC) + struct.pack(">H", ETYPE_AVTP)
                     + avtp_ctrl(0xFB, 0, 0, 20) + b"\x00\x01")))
    # one valid frame to prove the pipeline continues (PA-5)
    pk.append((0.4, eth(ADP_MC, TALKER_MAC, ETYPE_AVTP, adp(0, 62, E_TALKER))))
    write_pcap("testdata/malformed.pcap", pk)


def scenario_milan():
    """The demo trace: a Milan device pair boots, is enumerated, reserves a
    stream, connects, streams, then tears down."""
    pk = []
    vid_fv = struct.pack(">H", VLAN)
    t = 0.0
    # VLAN + SR domain
    for src in (TALKER_MAC, LISTENER_MAC):
        pk.append((t, eth(MVRP_MC, src, ETYPE_MVRP,
                          mvrp_pdu([mrp_vector(vid_fv, [JOININ])]))))
        t += 0.02
    pk.append((t, eth(MSRP_MC, BRIDGE_MAC, ETYPE_MSRP,
                      msrp_pdu([(4, 4, [mrp_vector(domain_fv(6, 3, VLAN), [JOININ])])]))))
    # discovery
    pk.append((0.50, eth(ADP_MC, CTRL_MAC, ETYPE_AVTP, adp(2, 0, 0))))
    pk.append((0.55, eth(ADP_MC, TALKER_MAC, ETYPE_AVTP, adp(0, 62, E_TALKER, avail_idx=1))))
    pk.append((0.60, eth(ADP_MC, LISTENER_MAC, ETYPE_AVTP, adp(0, 62, E_LISTENER, avail_idx=1))))
    # enumeration: names
    pk.append((0.70, eth(TALKER_MAC, CTRL_MAC, ETYPE_AVTP, read_desc_cmd(E_TALKER, E_CTRL, 1))))
    pk.append((0.71, eth(CTRL_MAC, TALKER_MAC, ETYPE_AVTP,
                         read_desc_entity_resp(E_TALKER, E_CTRL, 1, "Stage Box FOH"))))
    pk.append((0.80, eth(LISTENER_MAC, CTRL_MAC, ETYPE_AVTP, read_desc_cmd(E_LISTENER, E_CTRL, 2))))
    pk.append((0.81, eth(CTRL_MAC, LISTENER_MAC, ETYPE_AVTP,
                         read_desc_entity_resp(E_LISTENER, E_CTRL, 2, "Monitor Desk"))))
    # talker claims multicast addresses
    for i in range(3):
        pk.append((1.0 + 0.1 * i, eth(MAAP_MC, TALKER_MAC, ETYPE_AVTP,
                                      maap(1, STREAM_DEST, 8))))
    pk.append((1.4, eth(MAAP_MC, TALKER_MAC, ETYPE_AVTP, maap(3, STREAM_DEST, 8))))
    # stream reservation
    pk.append((2.0, msrp_talker([JOININ])))
    pk.append((2.1, eth(MSRP_MC, LISTENER_MAC, ETYPE_MSRP,
                        msrp_pdu([(3, 8, [mrp_vector(listener_fv(STREAM_ID), [JOININ],
                                                     listener_events=[READY])])]))))
    # controller connects the stream
    pk.append((3.00, eth(LISTENER_MAC, CTRL_MAC, ETYPE_AVTP,
                         acmp(6, 0, 0, E_CTRL, E_TALKER, E_LISTENER, seq=1))))
    pk.append((3.01, eth(TALKER_MAC, LISTENER_MAC, ETYPE_AVTP,
                         acmp(0, 0, 0, E_CTRL, E_TALKER, E_LISTENER, seq=2))))
    pk.append((3.02, eth(LISTENER_MAC, TALKER_MAC, ETYPE_AVTP,
                         acmp(1, 0, STREAM_ID, E_CTRL, E_TALKER, E_LISTENER,
                              dest=STREAM_DEST, conn_count=1, seq=2, vlan=VLAN))))
    pk.append((3.03, eth(CTRL_MAC, LISTENER_MAC, ETYPE_AVTP,
                         acmp(7, 0, STREAM_ID, E_CTRL, E_TALKER, E_LISTENER,
                              dest=STREAM_DEST, conn_count=1, seq=1, vlan=VLAN))))
    # steady state: re-announces and re-declarations
    for i in range(3):
        base = 10.0 + 10.0 * i
        pk.append((base, eth(ADP_MC, TALKER_MAC, ETYPE_AVTP,
                             adp(0, 62, E_TALKER, avail_idx=1))))
        pk.append((base + 0.1, eth(ADP_MC, LISTENER_MAC, ETYPE_AVTP,
                                   adp(0, 62, E_LISTENER, avail_idx=1))))
        pk.append((base + 0.2, msrp_talker([JOININ])))
    # teardown
    pk.append((40.0, eth(LISTENER_MAC, CTRL_MAC, ETYPE_AVTP,
                         acmp(8, 0, STREAM_ID, E_CTRL, E_TALKER, E_LISTENER, seq=3))))
    pk.append((40.01, eth(TALKER_MAC, LISTENER_MAC, ETYPE_AVTP,
                          acmp(2, 0, STREAM_ID, E_CTRL, E_TALKER, E_LISTENER, seq=4))))
    pk.append((40.02, eth(LISTENER_MAC, TALKER_MAC, ETYPE_AVTP,
                          acmp(3, 0, STREAM_ID, E_CTRL, E_TALKER, E_LISTENER, seq=4))))
    pk.append((40.03, eth(CTRL_MAC, LISTENER_MAC, ETYPE_AVTP,
                          acmp(9, 0, STREAM_ID, E_CTRL, E_TALKER, E_LISTENER, seq=3))))
    pk.append((40.5, msrp_talker([LV])))
    pk.append((41.0, eth(ADP_MC, TALKER_MAC, ETYPE_AVTP, adp(1, 62, E_TALKER, avail_idx=2))))
    pk.append((41.1, eth(ADP_MC, LISTENER_MAC, ETYPE_AVTP, adp(1, 62, E_LISTENER, avail_idx=2))))
    write_pcap("testdata/milan_scenario.pcap", pk)


def main():
    os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    os.makedirs("testdata", exist_ok=True)
    print("generating golden pcaps:")
    scenario_msrp_basic()
    scenario_msrp_failure()
    scenario_mvrp()
    scenario_maap()
    scenario_adp()
    scenario_aecp()
    scenario_acmp()
    scenario_malformed()
    scenario_milan()
    return 0


if __name__ == "__main__":
    sys.exit(main())
