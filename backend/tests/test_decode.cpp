/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * Wire-format decoder tests over hand-built frames (PA-1, PA-5).
 */
#include <cstring>
#include <vector>

#include "decode/decode.h"
#include "test.h"
#include "util/bytes.h"

using namespace avb;

namespace {

struct Buf {
    std::vector<uint8_t> b;
    Buf& u8(uint8_t v) {
        b.push_back(v);
        return *this;
    }
    Buf& u16(uint16_t v) { return u8((uint8_t)(v >> 8)).u8((uint8_t)v); }
    Buf& u32(uint32_t v) { return u16((uint16_t)(v >> 16)).u16((uint16_t)v); }
    Buf& u48(uint64_t v) {
        for (int i = 5; i >= 0; --i) u8((uint8_t)(v >> (i * 8)));
        return *this;
    }
    Buf& u64(uint64_t v) {
        for (int i = 7; i >= 0; --i) u8((uint8_t)(v >> (i * 8)));
        return *this;
    }
    Buf& pad(size_t n) {
        b.insert(b.end(), n, 0);
        return *this;
    }
    Buf& append(const Buf& o) {
        b.insert(b.end(), o.b.begin(), o.b.end());
        return *this;
    }
};

Buf ethFrame(uint64_t dst, uint64_t src, uint16_t etype, const Buf& payload) {
    Buf f;
    f.u48(dst).u48(src).u16(etype).append(payload);
    if (f.b.size() < 60) f.pad(60 - f.b.size());
    return f;
}

Buf avtpCtrl(uint8_t subtype, uint8_t msgType, uint8_t status5, uint16_t cdl) {
    Buf h;
    h.u8(subtype).u8((uint8_t)(msgType & 0xf)).u16(
        (uint16_t)((status5 << 11) | cdl));
    return h;
}

constexpr uint64_t kTalkerMac = 0x001b92000001;
constexpr uint64_t kMsrpMc = 0x0180c200000e;
constexpr uint64_t kMvrpMc = 0x0180c2000021;
constexpr uint64_t kAdpMc = 0x91e0f0010000;
constexpr uint64_t kEntity = 0x001b92fffe000001ull;
constexpr uint64_t kStream = 0x001b920000010001ull;

} // namespace

TEST(decode_mvrp_joinin) {
    Buf pdu;
    pdu.u8(0);            // protocol version
    pdu.u8(1).u8(2);      // VID attribute, length 2
    pdu.u16(1);           // vector header: numValues 1
    pdu.u16(2);           // FirstValue: VID 2
    pdu.u8(1 * 36);       // three-packed: JoinIn, 0, 0
    pdu.u16(0).u16(0);    // endmarks

    DecodedPacket d;
    decodePacket({ethFrame(kMvrpMc, kTalkerMac, 0x88F5, pdu).b}, d);
    CHECK(d.ok && d.interesting);
    CHECK_EQ((int)d.proto, (int)Proto::MVRP);
    CHECK_EQ(d.logicCtxs.size(), (size_t)1);
    CHECK_EQ(d.logicCtxs[0].at("vid"), (uint64_t)2);
    CHECK_EQ(d.logicCtxs[0].at("mrp_event"), (uint64_t)1);
    CHECK_EQ(d.logicCtxs[0].at("src_mac"), kTalkerMac);
    CHECK_EQ(d.type, std::string("VID_VECTOR"));
}

TEST(decode_msrp_talker_advertise_vector) {
    Buf fv; // 25-byte talker FirstValue
    fv.u64(kStream).u48(0x91e0f0000e80).u16(2).u16(224).u16(1)
        .u8((3 << 5) | (1 << 4)).u32(125000);
    Buf pdu;
    pdu.u8(0);
    pdu.u8(1).u8(25); // TalkerAdvertise
    Buf vec;
    vec.u16(2).append(fv).u8((uint8_t)(1 * 36 + 1 * 6)); // two JoinIn values
    pdu.u16((uint16_t)(vec.b.size() + 2)).append(vec).u16(0); // list + EndMark
    pdu.u16(0);

    DecodedPacket d;
    decodePacket({ethFrame(kMsrpMc, kTalkerMac, 0x22EA, pdu).b}, d);
    CHECK(d.ok);
    CHECK_EQ((int)d.proto, (int)Proto::MSRP);
    CHECK_EQ(d.logicCtxs.size(), (size_t)2); // vector of 2 -> 2 declarations
    CHECK_EQ(d.logicCtxs[0].at("stream_id"), kStream);
    CHECK_EQ(d.logicCtxs[1].at("stream_id"), kStream + 1); // FirstValue+1
    CHECK_EQ(d.logicCtxs[0].at("vlan_id"), (uint64_t)2);
    CHECK_EQ(d.logicCtxs[0].at("priority"), (uint64_t)3);
    CHECK_EQ(d.logicCtxs[0].at("max_frame_size"), (uint64_t)224);
    CHECK_EQ(d.stream, idStr(kStream));
}

TEST(decode_msrp_listener_four_packed) {
    Buf pdu;
    pdu.u8(0);
    pdu.u8(3).u8(8); // Listener
    Buf vec;
    vec.u16(1).u64(kStream).u8(1 * 36).u8(2 << 6); // JoinIn + Ready
    pdu.u16((uint16_t)(vec.b.size() + 2)).append(vec).u16(0);
    pdu.u16(0);

    DecodedPacket d;
    decodePacket({ethFrame(kMsrpMc, kTalkerMac, 0x22EA, pdu).b}, d);
    CHECK(d.ok);
    CHECK_EQ(d.logicCtxs.size(), (size_t)1);
    CHECK_EQ(d.logicCtxs[0].at("four_packed_event"), (uint64_t)2); // Ready
}

TEST(decode_adp_available) {
    Buf pdu = avtpCtrl(0xFA, 0, 31, 56); // valid_time 62 s
    pdu.u64(kEntity).u64(0x001b92fffe112233ull).u32(0x8508).u16(2).u16(0x4801)
        .u16(2).u16(0x4801).u32(1).u32(7).u64(0xaaaa).u8(0).pad(3).u16(0)
        .u16(0).u64(0).pad(4);

    DecodedPacket d;
    decodePacket({ethFrame(kAdpMc, kTalkerMac, 0x22F0, pdu).b}, d);
    CHECK(d.ok);
    CHECK_EQ((int)d.proto, (int)Proto::ADP);
    CHECK_EQ(d.entity, idStr(kEntity));
    CHECK_EQ(d.logicCtxs[0].at("valid_time"), (uint64_t)62);
    CHECK_EQ(d.logicCtxs[0].at("available_index"), (uint64_t)7);
    CHECK_EQ(d.type, std::string("ENTITY_AVAILABLE"));
}

TEST(decode_acmp_connect_rx) {
    Buf pdu = avtpCtrl(0xFC, 6, 0, 44);
    pdu.u64(0).u64(0x99).u64(kEntity).u64(kEntity + 1).u16(0).u16(0)
        .u48(0).u16(0).u16(1).u16(0).u16(0).u16(0);

    DecodedPacket d;
    decodePacket({ethFrame(kTalkerMac, kTalkerMac + 1, 0x22F0, pdu).b}, d);
    CHECK(d.ok);
    CHECK_EQ((int)d.proto, (int)Proto::ACMP);
    CHECK_EQ(d.type, std::string("CONNECT_RX_COMMAND"));
    CHECK_EQ(d.entity, idStr(kEntity + 1)); // RX -> listener is the subject
    CHECK_EQ(d.logicCtxs[0].at("sequence_id"), (uint64_t)1);
}

TEST(decode_maap_probe) {
    Buf pdu = avtpCtrl(0xFE, 1, 1, 16);
    pdu.u64(0).u48(0x91e0f0003800).u16(8).u48(0).u16(0);

    DecodedPacket d;
    decodePacket({ethFrame(0x91e0f000ff00, kTalkerMac, 0x22F0, pdu).b}, d);
    CHECK(d.ok);
    CHECK_EQ((int)d.proto, (int)Proto::MAAP);
    CHECK_EQ(d.logicCtxs[0].at("requested_count"), (uint64_t)8);
    CHECK_EQ(d.type, std::string("MAAP_PROBE"));
}

TEST(decode_aecp_entity_name) {
    Buf pdu = avtpCtrl(0xFB, 1, 0, 0); // AEM_RESPONSE, SUCCESS
    pdu.u64(kEntity).u64(0x99).u16(1).u16(0x0004); // READ_DESCRIPTOR
    pdu.u16(0).u16(0);                             // configuration, reserved
    pdu.u16(0x0000).u16(0);                        // ENTITY descriptor
    pdu.u64(kEntity).u64(0x1122).u32(0).u16(2).u16(0).u16(2).u16(0).u32(0)
        .u32(1).u64(0);
    const char* name = "Stage Box FOH";
    Buf nm;
    for (const char* p = name; *p; ++p) nm.u8((uint8_t)*p);
    nm.pad(64 - strlen(name));
    pdu.append(nm);

    DecodedPacket d;
    decodePacket({ethFrame(kTalkerMac, kTalkerMac + 5, 0x22F0, pdu).b}, d);
    CHECK(d.ok);
    std::string got;
    CHECK(d.logicCtxs[0].getBytes("entity_name", got));
    CHECK_EQ(got, std::string("Stage Box FOH"));
    CHECK(d.summary.find("Stage Box FOH") != std::string::npos);
}

TEST(decode_malformed_never_throws) {
    // Truncated ADP: claims cdl 56 but the frame ends early.
    Buf pdu = avtpCtrl(0xFA, 0, 31, 56);
    pdu.u64(kEntity); // and nothing else
    Buf frame;
    frame.u48(kAdpMc).u48(kTalkerMac).u16(0x22F0).append(pdu); // no padding
    DecodedPacket d;
    decodePacket({frame.b}, d);
    CHECK(d.interesting);
    CHECK(!d.ok);
    CHECK(!d.error.empty());
    CHECK(d.logicCtxs.empty()); // partial decodes never reach the state pass

    // Garbage bytes must not throw either.
    DecodedPacket g;
    Buf junk;
    junk.u8(0xde).u8(0xad);
    decodePacket({junk.b}, g);
    CHECK(!g.ok);
}

TEST(decode_uninteresting_frame) {
    Buf pdu;
    pdu.pad(46);
    DecodedPacket d;
    decodePacket({ethFrame(kTalkerMac, kTalkerMac + 1, 0x0800, pdu).b}, d);
    CHECK(d.ok);
    CHECK(!d.interesting);
    CHECK(d.logicCtxs.empty());
}

TEST(inspector_layers) {
    Buf pdu = avtpCtrl(0xFE, 1, 1, 16);
    pdu.u64(0).u48(0x91e0f0003800).u16(8).u48(0).u16(0);
    auto layers = inspectPacket({ethFrame(0x91e0f000ff00, kTalkerMac, 0x22F0, pdu).b});
    CHECK_EQ(layers.size(), (size_t)3);
    CHECK_EQ(layers[0].service, std::string("ethernet_mac_frame"));
    CHECK_EQ(layers[1].service, std::string("1722_avtp_control"));
    CHECK_EQ(layers[2].service, std::string("1722_maap"));
    CHECK(!layers[2].fields.empty());

    // Malformed input yields a decode_error pseudo-layer, never a throw.
    Buf junk;
    junk.u48(kAdpMc).u48(kTalkerMac).u16(0x22F0).u8(0xFA);
    auto bad = inspectPacket({junk.b});
    CHECK(!bad.empty());
    CHECK_EQ(bad.back().service, std::string("decode_error"));
}
