/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * Human-readable names for protocol constants, per IEEE 802.1Q (MRP/MSRP/
 * MVRP), IEEE 1722 (MAAP) and IEEE 1722.1 (ADP/AECP/ACMP), Milan v1.2 terms.
 */
#pragma once

#include <cstdint>
#include <string>

namespace avb {

// MRP AttributeEvent (three-packed): New JoinIn In JoinMt Mt Lv
const char* mrpEventName(int e); // 6 = LeaveAll (internal convention)
// MSRP listener declaration (four-packed)
const char* fourPackedName(int e);
const char* msrpAttrName(uint8_t t);
std::string msrpFailureName(uint8_t code);

const char* maapMsgName(uint8_t t);
const char* adpMsgName(uint8_t t);

const char* aecpMsgName(uint8_t t);
std::string aemCommandName(uint16_t cmd);
std::string aemStatusName(uint8_t status);
std::string descriptorTypeName(uint16_t t);

std::string acmpMsgName(uint8_t t);
std::string acmpStatusName(uint8_t status);

// gPTP (IEEE 802.1AS)
const char* gptpMsgName(uint8_t t);
std::string gptpTimeSourceName(uint8_t t);
std::string gptpClockClassName(uint8_t c);
std::string gptpLogIntervalStr(uint8_t raw);

} // namespace avb
