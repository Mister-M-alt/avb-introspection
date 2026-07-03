/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 */
#include "decode.h"

#include <optional>

#include "../util/bytes.h"
#include "names.h"

namespace avb {

namespace {

constexpr uint16_t kEtypeMsrp = 0x22EA;
constexpr uint16_t kEtypeMvrp = 0x88F5;
constexpr uint16_t kEtypeAvtp = 0x22F0;
constexpr uint16_t kEtypeGptp = 0x88F7;
constexpr uint16_t kEtypeVlan = 0x8100;
constexpr uint16_t kEtypeQinQ = 0x88A8;

constexpr uint8_t kSubtypeAdp = 0xFA;
constexpr uint8_t kSubtypeAecp = 0xFB;
constexpr uint8_t kSubtypeAcmp = 0xFC;
constexpr uint8_t kSubtypeMaap = 0xFE;

// Defensive caps against absurd vector sizes in hostile frames (PA-5).
constexpr unsigned kMaxVectorValues = 4096;
constexpr unsigned kMaxDeclsPerPacket = 8192;

/** Writes each parsed field to the logic vars and/or the inspector list. */
struct Sink {
    VarLayerContext* vars = nullptr;
    std::vector<DisplayField>* disp = nullptr;

    void num(const char* n, uint64_t v) {
        if (vars) vars->setValue(n, v);
        if (disp) disp->push_back({n, std::to_string(v)});
    }
    void numd(const char* n, uint64_t v, std::string display) {
        if (vars) vars->setValue(n, v);
        if (disp) disp->push_back({n, std::move(display)});
    }
    void hexf(const char* n, uint64_t v, int digits) { numd(n, v, hexStr(v, digits)); }
    void mac(const char* n, uint64_t v) { numd(n, v, macStr(v)); }
    void id(const char* n, uint64_t v) { numd(n, v, idStr(v)); }
    void str(const char* n, const std::string& s) {
        if (vars) vars->setBytes(n, s);
        if (disp) disp->push_back({n, s});
    }
    void info(const char* n, std::string s) {
        if (disp) disp->push_back({n, std::move(s)});
    }
};

struct EthHeader {
    uint64_t dst = 0, src = 0;
    uint16_t etype = 0;
    std::optional<uint16_t> vlan;
};

EthHeader parseEth(BeReader& r, std::vector<DisplayField>* disp) {
    EthHeader h;
    h.dst = r.u48("ethernet dst");
    h.src = r.u48("ethernet src");
    h.etype = r.u16("ethertype");
    while (h.etype == kEtypeVlan || h.etype == kEtypeQinQ) {
        uint16_t tci = r.u16("802.1Q TCI");
        h.vlan = tci & 0x0fff;
        h.etype = r.u16("ethertype");
    }
    if (disp) {
        disp->push_back({"dst_mac", macStr(h.dst)});
        disp->push_back({"src_mac", macStr(h.src)});
        if (h.vlan) disp->push_back({"vlan_id", std::to_string(*h.vlan)});
        std::string et = hexStr(h.etype, 4);
        if (h.etype == kEtypeAvtp) et += " (AVTP)";
        else if (h.etype == kEtypeMsrp) et += " (MSRP)";
        else if (h.etype == kEtypeMvrp) et += " (MVRP)";
        else if (h.etype == kEtypeGptp) et += " (gPTP)";
        disp->push_back({"ethertype", et});
    }
    return h;
}

struct AvtpCtrlHeader {
    uint8_t subtype = 0, sv = 0, version = 0, msgType = 0, status5 = 0;
    uint16_t cdl = 0;
};

AvtpCtrlHeader parseAvtpCtrl(BeReader& r) {
    AvtpCtrlHeader h;
    h.subtype = r.u8("AVTP subtype");
    uint8_t b1 = r.u8("AVTP control byte");
    h.sv = (b1 >> 7) & 1;
    h.version = (b1 >> 4) & 7;
    h.msgType = b1 & 0x0f;
    uint16_t w = r.u16("status/control_data_length");
    h.status5 = (uint8_t)((w >> 11) & 0x1f);
    h.cdl = w & 0x07ff;
    return h;
}

void avtpCtrlLayer(const AvtpCtrlHeader& h, const char* statusName,
                   std::string statusDisplay, std::vector<DisplayField>* disp) {
    if (!disp) return;
    std::string st = hexStr(h.subtype, 2);
    switch (h.subtype) {
    case kSubtypeAdp: st += " (ADP)"; break;
    case kSubtypeAecp: st += " (AECP)"; break;
    case kSubtypeAcmp: st += " (ACMP)"; break;
    case kSubtypeMaap: st += " (MAAP)"; break;
    }
    disp->push_back({"subtype", st});
    disp->push_back({"sv", std::to_string(h.sv)});
    disp->push_back({"version", std::to_string(h.version)});
    disp->push_back({statusName, std::move(statusDisplay)});
    disp->push_back({"control_data_length", std::to_string(h.cdl)});
}

// ---------------------------------------------------------------- ADP ----

void parseAdp(BeReader& r, const AvtpCtrlHeader& h, Sink& s) {
    s.numd("message_type", h.msgType, adpMsgName(h.msgType));
    s.numd("valid_time", (uint64_t)h.status5 * 2, std::to_string(h.status5 * 2) + " s");
    s.id("entity_id", r.u64("entity_id"));
    s.id("entity_model_id", r.u64("entity_model_id"));
    s.hexf("entity_capabilities", r.u32("entity_capabilities"), 8);
    s.num("talker_stream_sources", r.u16("talker_stream_sources"));
    s.hexf("talker_capabilities", r.u16("talker_capabilities"), 4);
    s.num("listener_stream_sinks", r.u16("listener_stream_sinks"));
    s.hexf("listener_capabilities", r.u16("listener_capabilities"), 4);
    s.hexf("controller_capabilities", r.u32("controller_capabilities"), 8);
    s.num("available_index", r.u32("available_index"));
    s.id("gptp_grandmaster_id", r.u64("gptp_grandmaster_id"));
    s.num("gptp_domain_number", r.u8("gptp_domain_number"));
    r.skip(3, "adp reserved");
    s.num("identify_control_index", r.u16("identify_control_index"));
    s.num("interface_index", r.u16("interface_index"));
    s.id("association_id", r.u64("association_id"));
}

// ---------------------------------------------------------------- AECP ---

void parseAemPayload(BeReader& r, uint8_t msgType, uint16_t cmd, Sink& s) {
    bool isResponse = (msgType == 1);
    switch (cmd) {
    case 0x0000:   // ACQUIRE_ENTITY
    case 0x0001: { // LOCK_ENTITY
        s.hexf("flags", r.u32("flags"), 8);
        s.id(cmd == 0 ? "owner_id" : "locked_id", r.u64("owner/locked id"));
        uint16_t dt = r.u16("descriptor_type");
        s.numd("descriptor_type", dt, descriptorTypeName(dt));
        s.num("descriptor_index", r.u16("descriptor_index"));
        break;
    }
    case 0x0004: { // READ_DESCRIPTOR
        s.num("configuration_index", r.u16("configuration_index"));
        r.skip(2, "reserved");
        if (!isResponse) {
            uint16_t dt = r.u16("descriptor_type");
            s.numd("descriptor_type", dt, descriptorTypeName(dt));
            s.num("descriptor_index", r.u16("descriptor_index"));
            break;
        }
        uint16_t dt = r.u16("descriptor_type");
        s.numd("descriptor_type", dt, descriptorTypeName(dt));
        s.num("descriptor_index", r.u16("descriptor_index"));
        if (dt == 0x0000) { // ENTITY descriptor: extract identity + name (PA-6)
            s.id("entity_id", r.u64("entity_id"));
            s.id("entity_model_id", r.u64("entity_model_id"));
            s.hexf("entity_capabilities", r.u32("entity_capabilities"), 8);
            s.num("talker_stream_sources", r.u16("talker_stream_sources"));
            s.hexf("talker_capabilities", r.u16("talker_capabilities"), 4);
            s.num("listener_stream_sinks", r.u16("listener_stream_sinks"));
            s.hexf("listener_capabilities", r.u16("listener_capabilities"), 4);
            s.hexf("controller_capabilities", r.u32("controller_capabilities"), 8);
            s.num("available_index", r.u32("available_index"));
            s.id("association_id", r.u64("association_id"));
            s.str("entity_name", paddedStr(r.bytes(64, "entity_name")));
            // Optional tail (don't fail on shorter, still-valid encodings).
            if (r.remaining() >= 2 + 2 + 64 * 3 + 4) {
                s.num("vendor_name_string", r.u16());
                s.num("model_name_string", r.u16());
                s.str("firmware_version", paddedStr(r.bytes(64)));
                s.str("group_name", paddedStr(r.bytes(64)));
                s.str("serial_number", paddedStr(r.bytes(64)));
                s.num("configurations_count", r.u16());
                s.num("current_configuration", r.u16());
            }
        }
        break;
    }
    case 0x0010:   // SET_NAME
    case 0x0011: { // GET_NAME
        uint16_t dt = r.u16("descriptor_type");
        s.numd("descriptor_type", dt, descriptorTypeName(dt));
        s.num("descriptor_index", r.u16("descriptor_index"));
        s.num("name_index", r.u16("name_index"));
        s.num("configuration_index", r.u16("configuration_index"));
        if (cmd == 0x0010 || isResponse)
            s.str("name", paddedStr(r.bytes(64, "name")));
        break;
    }
    default:
        s.info("payload_length", std::to_string(r.remaining()) + " bytes (not decoded)");
        break;
    }
}

void parseAecp(BeReader& r, const AvtpCtrlHeader& h, Sink& s) {
    s.numd("message_type", h.msgType, aecpMsgName(h.msgType));
    s.numd("status", h.status5, aemStatusName(h.status5));
    s.id("target_entity_id", r.u64("target_entity_id"));
    s.id("controller_entity_id", r.u64("controller_entity_id"));
    s.num("sequence_id", r.u16("sequence_id"));
    if (h.msgType == 0 || h.msgType == 1) { // AEM_COMMAND / AEM_RESPONSE
        uint16_t uc = r.u16("u/command_type");
        uint16_t cmd = uc & 0x7fff;
        s.num("unsolicited", (uc >> 15) & 1);
        s.numd("command_type", cmd, aemCommandName(cmd));
        parseAemPayload(r, h.msgType, cmd, s);
    } else {
        s.info("payload_length", std::to_string(r.remaining()) + " bytes (not decoded)");
    }
}

// ---------------------------------------------------------------- ACMP ---

void parseAcmp(BeReader& r, const AvtpCtrlHeader& h, Sink& s) {
    s.numd("message_type", h.msgType, acmpMsgName(h.msgType));
    s.numd("status", h.status5, acmpStatusName(h.status5));
    s.id("stream_id", r.u64("stream_id"));
    s.id("controller_entity_id", r.u64("controller_entity_id"));
    s.id("talker_entity_id", r.u64("talker_entity_id"));
    s.id("listener_entity_id", r.u64("listener_entity_id"));
    s.num("talker_unique_id", r.u16("talker_unique_id"));
    s.num("listener_unique_id", r.u16("listener_unique_id"));
    s.mac("stream_dest_mac", r.u48("stream_dest_mac"));
    s.num("connection_count", r.u16("connection_count"));
    s.num("sequence_id", r.u16("sequence_id"));
    s.hexf("flags", r.u16("flags"), 4);
    s.num("stream_vlan_id", r.u16("stream_vlan_id"));
}

// ---------------------------------------------------------------- MAAP ---

void parseMaap(BeReader& r, const AvtpCtrlHeader& h, Sink& s) {
    s.numd("message_type", h.msgType, maapMsgName(h.msgType));
    s.num("maap_version", h.status5);
    s.id("stream_id", r.u64("stream_id"));
    s.mac("requested_start_address", r.u48("requested_start_address"));
    s.num("requested_count", r.u16("requested_count"));
    s.mac("conflict_start_address", r.u48("conflict_start_address"));
    s.num("conflict_count", r.u16("conflict_count"));
}

// ----------------------------------------------------------------- MRP ---

struct MrpVector {
    bool leaveAll = false;
    unsigned numValues = 0;
    std::span<const uint8_t> firstValue;
    std::span<const uint8_t> threePacked;
    std::span<const uint8_t> fourPacked;
};

struct MrpMessage {
    uint8_t attrType = 0;
    uint8_t attrLen = 0;
    std::vector<MrpVector> vectors;
};

/** Walk an MRP PDU (shared by MVRP and MSRP; MSRP adds AttributeListLength
 *  and the four-packed listener events). */
std::vector<MrpMessage> parseMrpPdu(BeReader& r, bool isMsrp, uint8_t& version) {
    version = r.u8("MRP protocol version");
    std::vector<MrpMessage> msgs;
    while (r.remaining() >= 2) {
        uint8_t attrType = r.u8("attribute type");
        if (attrType == 0) break; // EndMark
        MrpMessage m;
        m.attrType = attrType;
        m.attrLen = r.u8("attribute length");
        if (m.attrLen == 0 || m.attrLen > 64)
            throw ShortFrame("implausible MRP attribute length " +
                             std::to_string(m.attrLen));
        size_t vecEnd = 0;
        if (isMsrp) {
            uint16_t listLen = r.u16("attribute list length");
            if (listLen > r.remaining())
                throw ShortFrame("MSRP attribute list length exceeds frame");
            vecEnd = r.pos() + listLen;
        }
        while (r.remaining() >= 2 && (!isMsrp || r.pos() < vecEnd)) {
            uint16_t header = r.u16("vector header");
            if (header == 0) break; // EndMark
            MrpVector v;
            v.leaveAll = ((header >> 13) & 0x7) == 1;
            v.numValues = header & 0x1fff;
            if (v.numValues > kMaxVectorValues)
                throw ShortFrame("implausible MRP vector size " +
                                 std::to_string(v.numValues));
            v.firstValue = r.bytes(m.attrLen, "first value");
            v.threePacked = r.bytes((v.numValues + 2) / 3, "three-packed events");
            if (isMsrp && m.attrType == 3)
                v.fourPacked = r.bytes((v.numValues + 3) / 4, "four-packed events");
            m.vectors.push_back(v);
        }
        if (isMsrp) {
            if (r.pos() > vecEnd)
                throw ShortFrame("MSRP vector list overruns attribute list length");
            r.skip(vecEnd - r.pos(), "attribute list padding");
        }
        msgs.push_back(std::move(m));
        if (msgs.size() > 256)
            throw ShortFrame("runaway MRP message list");
    }
    return msgs;
}

int threePackedEvent(std::span<const uint8_t> packed, unsigned idx) {
    uint8_t b = packed[idx / 3];
    switch (idx % 3) {
    case 0: return b / 36;
    case 1: return (b / 6) % 6;
    default: return b % 6;
    }
}

int fourPackedEvent(std::span<const uint8_t> packed, unsigned idx) {
    uint8_t b = packed[idx / 4];
    return (b >> (6 - 2 * (idx % 4))) & 0x3;
}

struct MsrpFirstValue {
    uint64_t streamId = 0, destMac = 0, failBridge = 0;
    uint16_t vlan = 0, maxFrameSize = 0, maxIntervalFrames = 0, classVid = 0;
    uint32_t accLatency = 0;
    uint8_t priority = 0, rank = 0, failCode = 0, classId = 0, classPrio = 0;
};

MsrpFirstValue parseMsrpFirstValue(uint8_t attrType, std::span<const uint8_t> fv) {
    BeReader r(fv);
    MsrpFirstValue v;
    switch (attrType) {
    case 1:   // TalkerAdvertise (25 B)
    case 2: { // TalkerFailed (34 B)
        v.streamId = r.u64("stream id");
        v.destMac = r.u48("dataframe dest mac");
        v.vlan = r.u16("dataframe vlan") & 0x0fff;
        v.maxFrameSize = r.u16("tspec max frame size");
        v.maxIntervalFrames = r.u16("tspec max interval frames");
        uint8_t pr = r.u8("priority and rank");
        v.priority = (pr >> 5) & 0x7;
        v.rank = (pr >> 4) & 0x1;
        v.accLatency = r.u32("accumulated latency");
        if (attrType == 2) {
            v.failBridge = r.u64("failure bridge id");
            v.failCode = r.u8("failure code");
        }
        break;
    }
    case 3: // Listener (8 B)
        v.streamId = r.u64("stream id");
        break;
    case 4: // Domain (4 B)
        v.classId = r.u8("sr class id");
        v.classPrio = r.u8("sr class priority");
        v.classVid = r.u16("sr class vid") & 0x0fff;
        break;
    default:
        break;
    }
    return v;
}

std::string srClassName(uint8_t classId) {
    if (classId == 6) return "A";
    if (classId == 5) return "B";
    return std::to_string(classId);
}

/** Expand parsed MRP messages into per-declaration logic contexts and build
 *  the packet-event material. Returns the number of declarations. */
unsigned emitMrpDecls(const std::vector<MrpMessage>& msgs, bool isMsrp,
                      DecodedPacket& out) {
    unsigned count = 0;
    bool valueLabeled = false; // a value declaration provided type/stream
    std::string firstDesc;
    const char* service = isMsrp ? kSvcMsrp : kSvcMvrp;

    auto addCtx = [&](const MrpMessage& m, int mrpEvent, int fourPk,
                      const MsrpFirstValue& v, uint16_t vid,
                      unsigned k) -> VarLayerContext& {
        out.logicCtxs.emplace_back(service);
        auto& ctx = out.logicCtxs.back();
        ctx.setValue("attribute_type", m.attrType);
        ctx.setValue("mrp_event", (uint64_t)mrpEvent);
        if (fourPk >= 0) ctx.setValue("four_packed_event", (uint64_t)fourPk);
        if (isMsrp) {
            switch (m.attrType) {
            case 1:
            case 2:
                ctx.setValue("stream_id", v.streamId + k);
                ctx.setValue("dest_mac", v.destMac + k);
                ctx.setValue("vlan_id", v.vlan);
                ctx.setValue("max_frame_size", v.maxFrameSize);
                ctx.setValue("max_interval_frames", v.maxIntervalFrames);
                ctx.setValue("priority", v.priority);
                ctx.setValue("rank", v.rank);
                ctx.setValue("accumulated_latency", v.accLatency);
                if (m.attrType == 2) {
                    ctx.setValue("failure_bridge_id", v.failBridge);
                    ctx.setValue("failure_code", v.failCode);
                }
                break;
            case 3:
                ctx.setValue("stream_id", v.streamId + k);
                break;
            case 4:
                ctx.setValue("sr_class_id", v.classId + k);
                ctx.setValue("sr_class_priority", v.classPrio);
                ctx.setValue("sr_class_vid", v.classVid);
                break;
            }
        } else {
            ctx.setValue("vid", (uint64_t)(vid + k) & 0x0fff);
        }
        return ctx;
    };

    for (auto& m : msgs) {
        for (auto& vec : m.vectors) {
            MsrpFirstValue fv;
            uint16_t vid = 0;
            if (isMsrp)
                fv = parseMsrpFirstValue(m.attrType, vec.firstValue);
            else
                vid = (uint16_t)((vec.firstValue[0] << 8) | vec.firstValue[1]);

            if (vec.leaveAll) {
                addCtx(m, 6 /* LeaveAll */, -1, fv, vid, 0);
                ++count;
                if (firstDesc.empty()) {
                    firstDesc = std::string("LeaveAll (") +
                                (isMsrp ? msrpAttrName(m.attrType) : "VID") + ")";
                    out.type = "LEAVEALL";
                }
            }
            for (unsigned k = 0; k < vec.numValues; ++k) {
                if (count >= kMaxDeclsPerPacket)
                    throw ShortFrame("too many MRP declarations in one PDU");
                int ev = threePackedEvent(vec.threePacked, k);
                int fp = (isMsrp && m.attrType == 3)
                             ? fourPackedEvent(vec.fourPacked, k)
                             : -1;
                addCtx(m, ev, fp, fv, vid, k);
                ++count;

                if (!valueLabeled) {
                    valueLabeled = true;
                    std::string d;
                    if (!isMsrp) {
                        d = "VLAN " + std::to_string((vid + k) & 0x0fff) + " " +
                            mrpEventName(ev);
                    } else {
                        switch (m.attrType) {
                        case 1:
                        case 2:
                            d = std::string(m.attrType == 1 ? "TalkerAdvertise "
                                                            : "TalkerFailed ") +
                                mrpEventName(ev) + " stream " +
                                idStr(fv.streamId + k) + " dst " +
                                macStr(fv.destMac + k) + " vlan " +
                                std::to_string(fv.vlan);
                            if (m.attrType == 2)
                                d += " (" + msrpFailureName(fv.failCode) + ")";
                            break;
                        case 3:
                            d = std::string("Listener ") + fourPackedName(fp) + " " +
                                mrpEventName(ev) + " stream " + idStr(fv.streamId + k);
                            break;
                        case 4:
                            d = "Domain " + std::string(mrpEventName(ev)) + " class " +
                                srClassName(fv.classId + k) + " prio " +
                                std::to_string(fv.classPrio) + " vid " +
                                std::to_string(fv.classVid);
                            break;
                        }
                    }
                    if (firstDesc.empty()) firstDesc = d;
                    out.type = isMsrp ? msrpAttrName(m.attrType) : "VID_VECTOR";
                    if (isMsrp && m.attrType != 4)
                        out.stream = idStr(fv.streamId + k);
                }
            }
        }
    }

    if (out.type.empty()) out.type = isMsrp ? "MSRP" : "MVRP";
    out.summary = firstDesc.empty() ? "empty MRP PDU" : firstDesc;
    if (count > 1)
        out.summary += " (+" + std::to_string(count - 1) + " more declaration" +
                       (count > 2 ? "s)" : ")");
    return count;
}

void mrpInspectorFields(const std::vector<MrpMessage>& msgs, bool isMsrp,
                        uint8_t version, std::vector<DisplayField>& disp) {
    disp.push_back({"protocol_version", std::to_string(version)});
    for (size_t mi = 0; mi < msgs.size(); ++mi) {
        auto& m = msgs[mi];
        std::string p = "msg" + std::to_string(mi) + ".";
        disp.push_back({p + "attribute_type",
                        std::to_string(m.attrType) + " (" +
                            (isMsrp ? msrpAttrName(m.attrType) : "VID") + ")"});
        disp.push_back({p + "attribute_length", std::to_string(m.attrLen)});
        for (size_t vi = 0; vi < m.vectors.size(); ++vi) {
            auto& vec = m.vectors[vi];
            std::string q = p + "vec" + std::to_string(vi) + ".";
            disp.push_back({q + "leave_all", vec.leaveAll ? "1" : "0"});
            disp.push_back({q + "number_of_values", std::to_string(vec.numValues)});
            if (isMsrp) {
                auto fv = parseMsrpFirstValue(m.attrType, vec.firstValue);
                switch (m.attrType) {
                case 1:
                case 2:
                    disp.push_back({q + "stream_id", idStr(fv.streamId)});
                    disp.push_back({q + "dest_mac", macStr(fv.destMac)});
                    disp.push_back({q + "vlan_id", std::to_string(fv.vlan)});
                    disp.push_back({q + "max_frame_size", std::to_string(fv.maxFrameSize)});
                    disp.push_back(
                        {q + "max_interval_frames", std::to_string(fv.maxIntervalFrames)});
                    disp.push_back({q + "priority", std::to_string(fv.priority)});
                    disp.push_back({q + "rank", std::to_string(fv.rank)});
                    disp.push_back(
                        {q + "accumulated_latency", std::to_string(fv.accLatency)});
                    if (m.attrType == 2) {
                        disp.push_back({q + "failure_bridge_id", idStr(fv.failBridge)});
                        disp.push_back({q + "failure_code",
                                        std::to_string(fv.failCode) + " (" +
                                            msrpFailureName(fv.failCode) + ")"});
                    }
                    break;
                case 3:
                    disp.push_back({q + "stream_id", idStr(fv.streamId)});
                    break;
                case 4:
                    disp.push_back({q + "sr_class_id",
                                    std::to_string(fv.classId) + " (class " +
                                        srClassName(fv.classId) + ")"});
                    disp.push_back({q + "sr_class_priority", std::to_string(fv.classPrio)});
                    disp.push_back({q + "sr_class_vid", std::to_string(fv.classVid)});
                    break;
                }
            } else {
                uint16_t vid =
                    (uint16_t)((vec.firstValue[0] << 8) | vec.firstValue[1]);
                disp.push_back({q + "first_vid", std::to_string(vid)});
            }
            std::string events;
            for (unsigned k = 0; k < vec.numValues; ++k) {
                if (!events.empty()) events += ", ";
                events += mrpEventName(threePackedEvent(vec.threePacked, k));
                if (isMsrp && m.attrType == 3)
                    events += std::string("/") +
                              fourPackedName(fourPackedEvent(vec.fourPacked, k));
            }
            if (!events.empty()) disp.push_back({q + "events", events});
        }
    }
}

// ---------------------------------------------------------------- gPTP ---

/** PTP timestamp: 48-bit seconds + 32-bit nanoseconds. */
void gptpTimestamp(BeReader& r, const char* prefix, Sink& s) {
    uint64_t sec = r.u48("ptp timestamp seconds");
    uint32_t ns = r.u32("ptp timestamp ns");
    char buf[48];
    std::snprintf(buf, sizeof buf, "%llu.%09u s", (unsigned long long)sec, ns);
    s.numd((std::string(prefix) + "_seconds").c_str(), sec, buf);
    if (s.vars) s.vars->setValue(std::string(prefix) + "_ns", ns);
}

struct GptpHeader {
    uint8_t majorSdoId = 0, msgType = 0, version = 0, domain = 0;
    uint16_t msgLen = 0, flags = 0, srcPort = 0, seq = 0;
    uint64_t correction = 0, srcClock = 0;
    uint8_t control = 0, logInterval = 0;
};

/** IEEE 802.1AS frame (ethertype 0x88F7). One Sink path for analysis vars
 *  and inspector display, bounded strictly by messageLength (PA-5) — real
 *  captures (ProfiShark) carry trailing FCS bytes past the PDU. */
void parseGptp(BeReader& r, Sink& s, DecodedPacket* out) {
    GptpHeader h;
    uint8_t b0 = r.u8("gPTP byte 0");
    h.majorSdoId = (b0 >> 4) & 0xf;
    h.msgType = b0 & 0xf;
    h.version = r.u8("gPTP version") & 0xf;
    if (h.version != 2)
        throw ShortFrame("gPTP: unsupported PTP version " +
                         std::to_string(h.version));
    h.msgLen = r.u16("gPTP messageLength");
    h.domain = r.u8("gPTP domainNumber");
    r.skip(1, "gPTP minorSdoId");
    h.flags = r.u16("gPTP flags");
    h.correction = r.u64("gPTP correctionField");
    r.skip(4, "gPTP messageTypeSpecific");
    h.srcClock = r.u64("gPTP sourcePortIdentity.clockIdentity");
    h.srcPort = r.u16("gPTP sourcePortIdentity.portNumber");
    h.seq = r.u16("gPTP sequenceId");
    h.control = r.u8("gPTP control");
    h.logInterval = r.u8("gPTP logMessageInterval");

    if (h.msgLen < 34)
        throw ShortFrame("gPTP: messageLength " + std::to_string(h.msgLen) +
                         " shorter than the common header");
    // The PDU body: exactly messageLength-34 bytes; anything after is
    // padding/FCS and must never be parsed.
    BeReader body(r.bytes(h.msgLen - 34, "gPTP body"));

    bool twoStep = (h.flags >> 9) & 1;
    s.numd("message_type", h.msgType, gptpMsgName(h.msgType));
    s.num("transport_specific", h.majorSdoId);
    s.num("version", h.version);
    s.num("message_length", h.msgLen);
    s.num("domain_number", h.domain);
    s.hexf("flags", h.flags, 4);
    s.num("two_step", twoStep ? 1 : 0);
    {
        char buf[40];
        std::snprintf(buf, sizeof buf, "%.3f ns",
                      (double)(int64_t)h.correction / 65536.0);
        s.numd("correction_field", h.correction, buf);
    }
    s.id("source_clock_id", h.srcClock);
    s.num("source_port_number", h.srcPort);
    s.num("sequence_id", h.seq);
    s.num("control", h.control);
    s.numd("log_message_interval", h.logInterval,
           gptpLogIntervalStr(h.logInterval));

    std::string portStr = idStr(h.srcClock) + ":" + std::to_string(h.srcPort);

    switch (h.msgType) {
    case 0x0: // SYNC — originTimestamp present (zero for two-step)
        if (body.remaining() >= 10) gptpTimestamp(body, "origin", s);
        break;
    case 0x8: { // FOLLOW_UP — preciseOriginTimestamp + 802.1AS info TLV
        gptpTimestamp(body, "origin", s);
        while (body.remaining() >= 4) {
            uint16_t tlvType = body.u16("tlv type");
            uint16_t tlvLen = body.u16("tlv length");
            if (tlvLen > body.remaining())
                throw ShortFrame("gPTP: Follow_Up TLV overruns messageLength");
            BeReader tlv(body.bytes(tlvLen, "tlv value"));
            if (tlvType == 0x0003 && tlvLen >= 28) { // org extension
                uint64_t orgSub = tlv.u48("org id + subtype");
                if (orgSub == 0x0080C2000001ull) { // 00-80-C2, subtype 1
                    s.num("has_as_tlv", 1);
                    uint32_t csro = tlv.u32("cumulativeScaledRateOffset");
                    char buf[40];
                    std::snprintf(buf, sizeof buf, "%.3f ppm",
                                  (double)(int32_t)csro / 2199023255552.0 * 1e6);
                    s.numd("cumulative_scaled_rate_offset", csro, buf);
                    s.num("gm_time_base_indicator", tlv.u16("gmTimeBaseIndicator"));
                    // lastGmPhaseChange (12) + scaledLastGmFreqChange (4):
                    // informational only.
                }
            }
        }
        break;
    }
    case 0x2: // PDELAY_REQ — 20 reserved bytes
        break;
    case 0x3: // PDELAY_RESP
        gptpTimestamp(body, "req_receipt", s);
        s.id("requesting_clock_id", body.u64("requestingPortIdentity"));
        s.num("requesting_port_number", body.u16("requesting port"));
        break;
    case 0xA: // PDELAY_RESP_FOLLOW_UP
        gptpTimestamp(body, "resp_origin", s);
        s.id("requesting_clock_id", body.u64("requestingPortIdentity"));
        s.num("requesting_port_number", body.u16("requesting port"));
        break;
    case 0xB: { // ANNOUNCE
        body.skip(10, "announce originTimestamp");
        uint16_t utc = body.u16("currentUtcOffset");
        s.numd("current_utc_offset", utc, std::to_string((int16_t)utc));
        body.skip(1, "reserved");
        s.num("gm_priority1", body.u8("grandmasterPriority1"));
        uint8_t cls = body.u8("clockClass");
        s.numd("gm_clock_class", cls, gptpClockClassName(cls));
        s.hexf("gm_clock_accuracy", body.u8("clockAccuracy"), 2);
        s.num("gm_clock_variance", body.u16("offsetScaledLogVariance"));
        s.num("gm_priority2", body.u8("grandmasterPriority2"));
        s.id("gm_identity", body.u64("grandmasterIdentity"));
        s.num("steps_removed", body.u16("stepsRemoved"));
        uint8_t tsrc = body.u8("timeSource");
        s.numd("time_source", tsrc, gptpTimeSourceName(tsrc));
        // Path-trace TLV (0x0008): N clockIdentities.
        while (body.remaining() >= 4) {
            uint16_t tlvType = body.u16("tlv type");
            uint16_t tlvLen = body.u16("tlv length");
            if (tlvLen > body.remaining())
                throw ShortFrame("gPTP: Announce TLV overruns messageLength");
            BeReader tlv(body.bytes(tlvLen, "tlv value"));
            if (tlvType == 0x0008) {
                unsigned n = tlvLen / 8;
                if (n > 32)
                    throw ShortFrame("gPTP: implausible path trace length");
                s.num("path_trace_count", n);
                std::string trace;
                for (unsigned i = 0; i < n; ++i) {
                    if (!trace.empty()) trace += ", ";
                    trace += idStr(tlv.u64("path trace clockIdentity"));
                }
                s.str("path_trace", trace);
            }
        }
        break;
    }
    case 0xC: // SIGNALING — targetPortIdentity + TLVs (display only)
        if (body.remaining() >= 10) {
            s.id("target_clock_id", body.u64("targetPortIdentity"));
            s.num("target_port_number", body.u16("target port"));
        }
        s.info("tlv_bytes", std::to_string(body.remaining()) + " bytes");
        break;
    default:
        break;
    }

    if (out) {
        out->type = gptpMsgName(h.msgType);
        out->entity = idStr(h.srcClock);
        std::string dom = " dom " + std::to_string(h.domain);
        auto& ctx = out->logicCtxs.back();
        switch (h.msgType) {
        case 0x0:
            out->summary = "SYNC seq " + std::to_string(h.seq) + dom + " from " +
                           portStr + (twoStep ? " (two-step)" : " (one-step)");
            break;
        case 0x8:
            out->summary = "FOLLOW_UP seq " + std::to_string(h.seq) + dom +
                           " from " + portStr;
            break;
        case 0xB:
            out->summary = "ANNOUNCE" + dom + " GM " + idStr(ctx.at("gm_identity")) +
                           " prio1 " + std::to_string(ctx.at("gm_priority1")) +
                           " class " + std::to_string(ctx.at("gm_clock_class")) +
                           " steps " + std::to_string(ctx.at("steps_removed"));
            break;
        case 0x2:
            out->summary = "PDELAY_REQ seq " + std::to_string(h.seq) + " from " +
                           portStr;
            break;
        case 0x3:
        case 0xA:
            out->summary = std::string(gptpMsgName(h.msgType)) + " seq " +
                           std::to_string(h.seq) + " to " +
                           idStr(ctx.at("requesting_clock_id")) + ":" +
                           std::to_string(ctx.at("requesting_port_number"));
            break;
        default:
            out->summary = std::string(gptpMsgName(h.msgType)) + " seq " +
                           std::to_string(h.seq) + dom + " from " + portStr;
            break;
        }
        out->eventFields.emplace_back("sequence_id", std::to_string(h.seq));
        out->eventFields.emplace_back("domain", std::to_string(h.domain));
        if (h.msgType == 0xB) {
            out->eventFields.emplace_back("gm_identity",
                                          idStr(ctx.at("gm_identity")));
            out->eventFields.emplace_back(
                "priority1", std::to_string(ctx.at("gm_priority1")));
            out->eventFields.emplace_back(
                "steps_removed", std::to_string(ctx.at("steps_removed")));
        }
    }
}

// ------------------------------------------------------------ front door -

/** Shared frame walk. Analysis path passes `out`; inspector passes `layers`. */
void decodeInner(std::span<const uint8_t> frame, DecodedPacket* out,
                 std::vector<InspectorLayer>* layers) {
    BeReader r(frame);

    std::vector<DisplayField>* ethDisp = nullptr;
    if (layers) {
        layers->push_back({kSvcEthernet, {}});
        ethDisp = &layers->back().fields;
    }
    EthHeader eth = parseEth(r, ethDisp);
    if (out) {
        out->src = macStr(eth.src);
        out->dst = macStr(eth.dst);
        out->srcMac = eth.src;
        out->dstMac = eth.dst;
    }

    auto protoOf = [](uint8_t subtype) {
        switch (subtype) {
        case kSubtypeAdp: return Proto::ADP;
        case kSubtypeAecp: return Proto::AECP;
        case kSubtypeAcmp: return Proto::ACMP;
        case kSubtypeMaap: return Proto::MAAP;
        }
        return Proto::ETH;
    };

    if (eth.etype == kEtypeMsrp || eth.etype == kEtypeMvrp) {
        bool isMsrp = (eth.etype == kEtypeMsrp);
        if (out) {
            out->interesting = true;
            out->proto = isMsrp ? Proto::MSRP : Proto::MVRP;
        }
        uint8_t version = 0;
        auto msgs = parseMrpPdu(r, isMsrp, version);
        if (!isMsrp)
            for (auto& m : msgs)
                if (m.attrType != 1 || m.attrLen != 2)
                    throw ShortFrame("MVRP: unsupported attribute type " +
                                     std::to_string(m.attrType) + " / length " +
                                     std::to_string(m.attrLen));
        if (isMsrp)
            for (auto& m : msgs) {
                static const uint8_t kLens[5] = {0, 25, 34, 8, 4};
                if (m.attrType >= 1 && m.attrType <= 4 &&
                    m.attrLen != kLens[m.attrType])
                    throw ShortFrame("MSRP: attribute length " +
                                     std::to_string(m.attrLen) +
                                     " does not match type " +
                                     msrpAttrName(m.attrType));
            }
        if (out) {
            unsigned n = emitMrpDecls(msgs, isMsrp, *out);
            out->eventFields.emplace_back("protocol_version", std::to_string(version));
            out->eventFields.emplace_back("declarations", std::to_string(n));
            for (auto& ctx : out->logicCtxs) {
                ctx.setValue("src_mac", eth.src);
                ctx.setValue("dst_mac", eth.dst);
            }
        }
        if (layers) {
            layers->push_back({isMsrp ? kSvcMsrp : kSvcMvrp, {}});
            mrpInspectorFields(msgs, isMsrp, version, layers->back().fields);
        }
        return;
    }

    if (eth.etype == kEtypeGptp) {
        if (out) {
            out->interesting = true;
            out->proto = Proto::GPTP;
        }
        Sink s;
        if (out) {
            out->logicCtxs.emplace_back(kSvcGptp);
            s.vars = &out->logicCtxs.back();
        }
        if (layers) {
            layers->push_back({kSvcGptp, {}});
            s.disp = &layers->back().fields;
        }
        parseGptp(r, s, out);
        if (out) {
            auto& ctx = out->logicCtxs.back();
            ctx.setValue("src_mac", eth.src);
            ctx.setValue("dst_mac", eth.dst);
        }
        return;
    }

    if (eth.etype == kEtypeAvtp) {
        AvtpCtrlHeader h = parseAvtpCtrl(r);
        Proto proto = protoOf(h.subtype);
        if (proto == Proto::ETH) return; // AVTP but not a protocol of interest
        if (out) {
            out->interesting = true;
            out->proto = proto;
        }

        const char* service = nullptr;
        const char* statusName = "status";
        std::string statusDisp;
        switch (proto) {
        case Proto::ADP:
            service = kSvcAdp;
            statusName = "valid_time";
            statusDisp = std::to_string(h.status5 * 2) + " s";
            break;
        case Proto::AECP:
            service = kSvcAecp;
            statusDisp = std::to_string(h.status5) + " (" + aemStatusName(h.status5) + ")";
            break;
        case Proto::ACMP:
            service = kSvcAcmp;
            statusDisp = std::to_string(h.status5) + " (" + acmpStatusName(h.status5) + ")";
            break;
        case Proto::MAAP:
            service = kSvcMaap;
            statusName = "maap_version";
            statusDisp = std::to_string(h.status5);
            break;
        default:
            return;
        }

        Sink s;
        VarLayerContext* ctx = nullptr;
        if (out) {
            out->logicCtxs.emplace_back(service);
            ctx = &out->logicCtxs.back();
            s.vars = ctx;
        }
        if (layers) {
            layers->push_back({kSvcAvtpControl, {}});
            avtpCtrlLayer(h, statusName, statusDisp, &layers->back().fields);
            layers->push_back({service, {}});
            s.disp = &layers->back().fields;
        }

        switch (proto) {
        case Proto::ADP: parseAdp(r, h, s); break;
        case Proto::AECP: parseAecp(r, h, s); break;
        case Proto::ACMP: parseAcmp(r, h, s); break;
        case Proto::MAAP: parseMaap(r, h, s); break;
        default: break;
        }

        if (out && ctx) {
            ctx->setValue("src_mac", eth.src);
            ctx->setValue("dst_mac", eth.dst);

            switch (proto) {
            case Proto::ADP: {
                uint64_t eid = ctx->at("entity_id");
                out->type = adpMsgName(h.msgType);
                out->entity = idStr(eid);
                out->summary = out->type + " " + idStr(eid);
                if (h.msgType == 0)
                    out->summary += " valid " + std::to_string(h.status5 * 2) +
                                    "s idx " + std::to_string(ctx->at("available_index"));
                if (h.msgType == 2 && eid == 0)
                    out->summary = "ENTITY_DISCOVER (all entities)";
                out->eventFields.emplace_back("message_type", adpMsgName(h.msgType));
                out->eventFields.emplace_back("valid_time",
                                              std::to_string(h.status5 * 2));
                out->eventFields.emplace_back(
                    "available_index", std::to_string(ctx->at("available_index")));
                break;
            }
            case Proto::AECP: {
                out->entity = idStr(ctx->at("target_entity_id"));
                std::string cmd = aemCommandName((uint16_t)ctx->at("command_type"));
                bool rsp = (h.msgType == 1);
                out->type = cmd + (rsp ? "_RESPONSE" : "_COMMAND");
                if (h.msgType > 1) out->type = aecpMsgName(h.msgType);
                out->summary = out->type + " target " + out->entity;
                if (rsp) out->summary += " (" + aemStatusName(h.status5) + ")";
                std::string nm;
                if (ctx->getBytes("entity_name", nm) && !nm.empty())
                    out->summary += " name \"" + nm + "\"";
                out->eventFields.emplace_back("message_type", aecpMsgName(h.msgType));
                out->eventFields.emplace_back("command", cmd);
                out->eventFields.emplace_back("status", aemStatusName(h.status5));
                out->eventFields.emplace_back("sequence_id",
                                              std::to_string(ctx->at("sequence_id")));
                break;
            }
            case Proto::ACMP: {
                out->type = acmpMsgName(h.msgType);
                out->stream = idStr(ctx->at("stream_id"));
                bool rx = (h.msgType >= 6 && h.msgType <= 11);
                out->entity = idStr(rx ? ctx->at("listener_entity_id")
                                       : ctx->at("talker_entity_id"));
                out->summary =
                    out->type + " talker " + idStr(ctx->at("talker_entity_id")) + "[" +
                    std::to_string(ctx->at("talker_unique_id")) + "] -> listener " +
                    idStr(ctx->at("listener_entity_id")) + "[" +
                    std::to_string(ctx->at("listener_unique_id")) + "]";
                if (h.msgType & 1) out->summary += " (" + acmpStatusName(h.status5) + ")";
                out->eventFields.emplace_back("message_type", acmpMsgName(h.msgType));
                out->eventFields.emplace_back("status", acmpStatusName(h.status5));
                out->eventFields.emplace_back("sequence_id",
                                              std::to_string(ctx->at("sequence_id")));
                out->eventFields.emplace_back("stream_id", out->stream);
                break;
            }
            case Proto::MAAP: {
                out->type = maapMsgName(h.msgType);
                out->stream = macStr(ctx->at("requested_start_address"));
                out->summary = out->type + " range " +
                               macStr(ctx->at("requested_start_address")) + " ×" +
                               std::to_string(ctx->at("requested_count"));
                if (h.msgType == 2)
                    out->summary += " conflict " +
                                    macStr(ctx->at("conflict_start_address")) + " ×" +
                                    std::to_string(ctx->at("conflict_count"));
                out->eventFields.emplace_back("message_type", maapMsgName(h.msgType));
                out->eventFields.emplace_back(
                    "requested_start", macStr(ctx->at("requested_start_address")));
                out->eventFields.emplace_back(
                    "requested_count", std::to_string(ctx->at("requested_count")));
                break;
            }
            default:
                break;
            }
        }
        return;
    }

    // Not a protocol of interest.
    if (layers) {
        layers->push_back(
            {"payload", {{"length", std::to_string(r.remaining()) + " bytes"}}});
    }
}

} // namespace

void decodePacket(std::span<const uint8_t> frame, DecodedPacket& out) {
    try {
        decodeInner(frame, &out, nullptr);
        out.ok = true;
    } catch (const ShortFrame& e) {
        out.ok = false;
        out.interesting = true;
        out.error = e.what();
        out.logicCtxs.clear(); // never feed partial decodes to the state pass
    } catch (const std::exception& e) {
        out.ok = false;
        out.interesting = true;
        out.error = std::string("decode failure: ") + e.what();
        out.logicCtxs.clear();
    }
}

std::vector<InspectorLayer> inspectPacket(std::span<const uint8_t> frame) {
    std::vector<InspectorLayer> layers;
    try {
        decodeInner(frame, nullptr, &layers);
    } catch (const std::exception& e) {
        layers.push_back({"decode_error", {{"message", e.what()}}});
    }
    return layers;
}

} // namespace avb
