/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 */
#include "names.h"

#include "../util/bytes.h"

namespace avb {

const char* mrpEventName(int e) {
    switch (e) {
    case 0: return "New";
    case 1: return "JoinIn";
    case 2: return "In";
    case 3: return "JoinMt";
    case 4: return "Mt";
    case 5: return "Lv";
    case 6: return "LeaveAll";
    }
    return "?";
}

const char* fourPackedName(int e) {
    switch (e) {
    case 0: return "Ignore";
    case 1: return "AskingFailed";
    case 2: return "Ready";
    case 3: return "ReadyFailed";
    }
    return "?";
}

const char* msrpAttrName(uint8_t t) {
    switch (t) {
    case 1: return "TALKER_ADVERTISE";
    case 2: return "TALKER_FAILED";
    case 3: return "LISTENER";
    case 4: return "DOMAIN";
    }
    return "UNKNOWN_ATTR";
}

std::string msrpFailureName(uint8_t code) {
    switch (code) {
    case 1: return "INSUFFICIENT_BANDWIDTH";
    case 2: return "INSUFFICIENT_BRIDGE_RESOURCES";
    case 3: return "INSUFFICIENT_TRAFFIC_CLASS_BANDWIDTH";
    case 4: return "STREAM_ID_IN_USE";
    case 5: return "STREAM_DESTINATION_ADDRESS_IN_USE";
    case 6: return "STREAM_PREEMPTED_BY_HIGHER_RANK";
    case 7: return "LATENCY_HAS_CHANGED";
    case 8: return "EGRESS_PORT_NOT_AVB_CAPABLE";
    case 9: return "USE_DIFFERENT_DESTINATION_ADDRESS";
    case 10: return "OUT_OF_MSRP_RESOURCES";
    case 11: return "OUT_OF_MMRP_RESOURCES";
    case 12: return "CANNOT_STORE_DESTINATION_ADDRESS";
    case 13: return "PRIORITY_IS_NOT_AN_SR_CLASS";
    case 14: return "MAX_FRAME_SIZE_TOO_LARGE";
    case 15: return "MAX_FAN_IN_PORTS_LIMIT_REACHED";
    case 16: return "CHANGE_IN_FIRST_VALUE_FOR_REGISTERED_STREAM";
    case 17: return "VLAN_BLOCKED_ON_EGRESS";
    case 18: return "VLAN_TAGGING_DISABLED_ON_EGRESS";
    case 19: return "SR_CLASS_PRIORITY_MISMATCH";
    }
    return "FAILURE_" + std::to_string(code);
}

const char* maapMsgName(uint8_t t) {
    switch (t) {
    case 1: return "MAAP_PROBE";
    case 2: return "MAAP_DEFEND";
    case 3: return "MAAP_ANNOUNCE";
    }
    return "MAAP_UNKNOWN";
}

const char* adpMsgName(uint8_t t) {
    switch (t) {
    case 0: return "ENTITY_AVAILABLE";
    case 1: return "ENTITY_DEPARTING";
    case 2: return "ENTITY_DISCOVER";
    }
    return "ADP_UNKNOWN";
}

const char* aecpMsgName(uint8_t t) {
    switch (t) {
    case 0: return "AEM_COMMAND";
    case 1: return "AEM_RESPONSE";
    case 2: return "ADDRESS_ACCESS_COMMAND";
    case 3: return "ADDRESS_ACCESS_RESPONSE";
    case 4: return "AVC_COMMAND";
    case 5: return "AVC_RESPONSE";
    case 6: return "VENDOR_UNIQUE_COMMAND";
    case 7: return "VENDOR_UNIQUE_RESPONSE";
    case 14: return "EXTENDED_COMMAND";
    case 15: return "EXTENDED_RESPONSE";
    }
    return "AECP_UNKNOWN";
}

std::string aemCommandName(uint16_t cmd) {
    switch (cmd) {
    case 0x0000: return "ACQUIRE_ENTITY";
    case 0x0001: return "LOCK_ENTITY";
    case 0x0002: return "ENTITY_AVAILABLE";
    case 0x0003: return "CONTROLLER_AVAILABLE";
    case 0x0004: return "READ_DESCRIPTOR";
    case 0x0005: return "WRITE_DESCRIPTOR";
    case 0x0006: return "SET_CONFIGURATION";
    case 0x0007: return "GET_CONFIGURATION";
    case 0x0008: return "SET_STREAM_FORMAT";
    case 0x0009: return "GET_STREAM_FORMAT";
    case 0x000E: return "SET_STREAM_INFO";
    case 0x000F: return "GET_STREAM_INFO";
    case 0x0010: return "SET_NAME";
    case 0x0011: return "GET_NAME";
    case 0x0012: return "SET_ASSOCIATION_ID";
    case 0x0013: return "GET_ASSOCIATION_ID";
    case 0x0014: return "SET_SAMPLING_RATE";
    case 0x0015: return "GET_SAMPLING_RATE";
    case 0x0016: return "SET_CLOCK_SOURCE";
    case 0x0017: return "GET_CLOCK_SOURCE";
    case 0x0018: return "SET_CONTROL";
    case 0x0019: return "GET_CONTROL";
    case 0x0022: return "START_STREAMING";
    case 0x0023: return "STOP_STREAMING";
    case 0x0024: return "REGISTER_UNSOLICITED_NOTIFICATION";
    case 0x0025: return "DEREGISTER_UNSOLICITED_NOTIFICATION";
    case 0x0026: return "IDENTIFY_NOTIFICATION";
    case 0x0027: return "GET_AVB_INFO";
    case 0x0028: return "GET_AS_PATH";
    case 0x0029: return "GET_COUNTERS";
    case 0x002A: return "REBOOT";
    case 0x002B: return "GET_AUDIO_MAP";
    case 0x002C: return "ADD_AUDIO_MAPPINGS";
    case 0x002D: return "REMOVE_AUDIO_MAPPINGS";
    case 0x004B: return "GET_DYNAMIC_INFO";
    }
    return "AEM_CMD_" + hexStr(cmd, 4);
}

std::string aemStatusName(uint8_t status) {
    switch (status) {
    case 0: return "SUCCESS";
    case 1: return "NOT_IMPLEMENTED";
    case 2: return "NO_SUCH_DESCRIPTOR";
    case 3: return "ENTITY_LOCKED";
    case 4: return "ENTITY_ACQUIRED";
    case 5: return "NOT_AUTHENTICATED";
    case 6: return "AUTHENTICATION_DISABLED";
    case 7: return "BAD_ARGUMENTS";
    case 8: return "NO_RESOURCES";
    case 9: return "IN_PROGRESS";
    case 10: return "ENTITY_MISBEHAVING";
    case 11: return "NOT_SUPPORTED";
    case 12: return "STREAM_IS_RUNNING";
    }
    return "STATUS_" + std::to_string(status);
}

std::string descriptorTypeName(uint16_t t) {
    switch (t) {
    case 0x0000: return "ENTITY";
    case 0x0001: return "CONFIGURATION";
    case 0x0002: return "AUDIO_UNIT";
    case 0x0003: return "VIDEO_UNIT";
    case 0x0005: return "STREAM_INPUT";
    case 0x0006: return "STREAM_OUTPUT";
    case 0x0007: return "JACK_INPUT";
    case 0x0008: return "JACK_OUTPUT";
    case 0x0009: return "AVB_INTERFACE";
    case 0x000A: return "CLOCK_SOURCE";
    case 0x000B: return "MEMORY_OBJECT";
    case 0x000C: return "LOCALE";
    case 0x000D: return "STRINGS";
    case 0x000E: return "STREAM_PORT_INPUT";
    case 0x000F: return "STREAM_PORT_OUTPUT";
    case 0x0024: return "CLOCK_DOMAIN";
    }
    return "DESC_" + hexStr(t, 4);
}

std::string acmpMsgName(uint8_t t) {
    switch (t) {
    case 0: return "CONNECT_TX_COMMAND";
    case 1: return "CONNECT_TX_RESPONSE";
    case 2: return "DISCONNECT_TX_COMMAND";
    case 3: return "DISCONNECT_TX_RESPONSE";
    case 4: return "GET_TX_STATE_COMMAND";
    case 5: return "GET_TX_STATE_RESPONSE";
    case 6: return "CONNECT_RX_COMMAND";
    case 7: return "CONNECT_RX_RESPONSE";
    case 8: return "DISCONNECT_RX_COMMAND";
    case 9: return "DISCONNECT_RX_RESPONSE";
    case 10: return "GET_RX_STATE_COMMAND";
    case 11: return "GET_RX_STATE_RESPONSE";
    case 12: return "GET_TX_CONNECTION_COMMAND";
    case 13: return "GET_TX_CONNECTION_RESPONSE";
    }
    return "ACMP_MSG_" + std::to_string(t);
}

const char* gptpMsgName(uint8_t t) {
    switch (t) {
    case 0x0: return "SYNC";
    case 0x2: return "PDELAY_REQ";
    case 0x3: return "PDELAY_RESP";
    case 0x8: return "FOLLOW_UP";
    case 0xA: return "PDELAY_RESP_FOLLOW_UP";
    case 0xB: return "ANNOUNCE";
    case 0xC: return "SIGNALING";
    }
    return "GPTP_UNKNOWN";
}

std::string gptpTimeSourceName(uint8_t t) {
    switch (t) {
    case 0x10: return "ATOMIC_CLOCK";
    case 0x20: return "GNSS";
    case 0x30: return "TERRESTRIAL_RADIO";
    case 0x40: return "PTP";
    case 0x50: return "NTP";
    case 0x60: return "HAND_SET";
    case 0x90: return "OTHER";
    case 0xA0: return "INTERNAL_OSCILLATOR";
    }
    return hexStr(t, 2);
}

std::string gptpClockClassName(uint8_t c) {
    switch (c) {
    case 6: return "6 (primary sync)";
    case 7: return "7 (holdover)";
    case 248: return "248 (default)";
    case 255: return "255 (slave-only)";
    }
    return std::to_string(c);
}

std::string gptpLogIntervalStr(uint8_t raw) {
    int8_t v = (int8_t)raw;
    if (raw == 0x7F) return "127 (not used)";
    if (v < -30 || v > 30) return std::to_string(v) + " (out of range)";
    double s = (v >= 0) ? (double)(1ull << v) : 1.0 / (double)(1ull << -v);
    char buf[48];
    if (s >= 1.0)
        std::snprintf(buf, sizeof buf, "%d (%.0f s)", v, s);
    else
        std::snprintf(buf, sizeof buf, "%d (%.0f ms)", v, s * 1e3);
    return buf;
}

std::string acmpStatusName(uint8_t status) {
    switch (status) {
    case 0: return "SUCCESS";
    case 1: return "LISTENER_UNKNOWN_ID";
    case 2: return "TALKER_UNKNOWN_ID";
    case 3: return "TALKER_DEST_MAC_FAIL";
    case 4: return "TALKER_NO_STREAM_INDEX";
    case 5: return "TALKER_NO_BANDWIDTH";
    case 6: return "TALKER_EXCLUSIVE";
    case 7: return "LISTENER_TALKER_TIMEOUT";
    case 8: return "LISTENER_EXCLUSIVE";
    case 9: return "STATE_UNAVAILABLE";
    case 10: return "NOT_CONNECTED";
    case 11: return "NO_SUCH_CONNECTION";
    case 12: return "COULD_NOT_SEND_MESSAGE";
    case 13: return "TALKER_MISBEHAVING";
    case 14: return "LISTENER_MISBEHAVING";
    case 16: return "CONTROLLER_NOT_AUTHORIZED";
    case 17: return "INCOMPATIBLE_REQUEST";
    case 31: return "NOT_SUPPORTED";
    }
    return "STATUS_" + std::to_string(status);
}

} // namespace avb
