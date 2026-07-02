/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * Wire-format decoders for the Milan v1.2 protocol set (PA-1):
 * MSRP/MVRP (802.1Q MRP), MAAP (1722), ADP/AECP/ACMP (1722.1),
 * gPTP (802.1AS).
 *
 * One parse path serves two renderings:
 *  - analysis: named vars in VarLayerContext instances consumed by the
 *    TSN-GEN logic modules (the field-layout role of TSN-GEN's parser);
 *  - inspector: formatted display fields for the packet detail view (FE-4).
 */
#pragma once

#include <span>
#include <string>
#include <vector>

#include "../model/event.h"
#include "../tsn_gen/var_context.h"

namespace avb {

// TSN-GEN service names (docs/API.md, "Packet inspector").
inline constexpr const char* kSvcEthernet = "ethernet_mac_frame";
inline constexpr const char* kSvcAvtpControl = "1722_avtp_control";
inline constexpr const char* kSvcMsrp = "mrp_msrp";
inline constexpr const char* kSvcMvrp = "mrp_mvrp";
inline constexpr const char* kSvcMaap = "1722_maap";
inline constexpr const char* kSvcAdp = "atdecc_adp";
inline constexpr const char* kSvcAecp = "atdecc_aecp";
inline constexpr const char* kSvcAcmp = "atdecc_acmp";
inline constexpr const char* kSvcGptp = "8021as_gptp";

struct DisplayField {
    std::string name, value;
};

struct InspectorLayer {
    std::string service;
    std::vector<DisplayField> fields;
};

/**
 * Analysis-side result for one frame. When `interesting` is false the frame
 * carries none of the six protocols and produces no event. When `ok` is
 * false the frame claimed one of our protocols but is malformed (PA-5) —
 * `error` says why and an error event is emitted.
 */
struct DecodedPacket {
    uint32_t num = 0;
    double ts = 0;
    std::string src, dst;
    Proto proto = Proto::ETH;
    bool interesting = false;
    bool ok = false;
    std::string error;

    // Packet-event material (PA-3).
    std::string type, summary, entity, stream;
    std::vector<std::pair<std::string, std::string>> eventFields;

    /**
     * Contexts for the state pass, in PDU order. AVTP protocols yield one;
     * an MRP PDU yields one per attribute declaration (a vector attribute
     * expands into per-value declarations, LeaveAll into its own).
     */
    std::vector<VarLayerContext> logicCtxs;
};

/** Decode for analysis. Populates everything except num/ts. Never throws. */
void decodePacket(std::span<const uint8_t> frame, DecodedPacket& out);

/** Decode for the packet inspector. Never throws; malformed input yields a
 *  "decode_error" pseudo-layer after whatever parsed cleanly. */
std::vector<InspectorLayer> inspectPacket(std::span<const uint8_t> frame);

} // namespace avb
