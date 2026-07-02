/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * The event model (PA-3/PA-4): every decoded packet, state transition and
 * decode error becomes one Event, serialized per docs/API.md.
 */
#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "../util/json.h"

namespace avb {

enum class Proto : uint8_t { ETH = 0, MSRP, MVRP, MAAP, ADP, AECP, ACMP, GPTP };
constexpr int kProtoCount = 8;

inline const char* protoName(Proto p) {
    switch (p) {
    case Proto::ETH: return "ETH";
    case Proto::MSRP: return "MSRP";
    case Proto::MVRP: return "MVRP";
    case Proto::MAAP: return "MAAP";
    case Proto::ADP: return "ADP";
    case Proto::AECP: return "AECP";
    case Proto::ACMP: return "ACMP";
    case Proto::GPTP: return "GPTP";
    }
    return "ETH";
}

enum class Kind : uint8_t { Packet = 0, Transition, Error };

inline const char* kindName(Kind k) {
    switch (k) {
    case Kind::Packet: return "packet";
    case Kind::Transition: return "transition";
    case Kind::Error: return "error";
    }
    return "packet";
}

struct Event {
    uint32_t i = 0;  // dense event index
    uint32_t n = 0;  // 1-based packet number; 0 = derived (e.g. timeout)
    double ts = 0;   // seconds since first packet
    Kind kind = Kind::Packet;
    Proto proto = Proto::ETH;
    std::string type;
    std::string src, dst;
    std::string summary;
    std::string entity, stream;
    std::vector<std::pair<std::string, std::string>> fields;

    void toJson(JsonWriter& w) const {
        w.beginObj();
        w.kv("i", (uint64_t)i);
        w.kv("n", (uint64_t)n);
        w.kv("ts", ts);
        w.kv("kind", kindName(kind));
        w.kv("proto", protoName(proto));
        w.kv("type", type);
        w.kv("src", src);
        w.kv("dst", dst);
        w.kv("summary", summary);
        w.kv("entity", entity);
        w.kv("stream", stream);
        w.key("fields").beginObj();
        for (auto& [k, v] : fields) {
            if (isNumeric(v))
                w.key(k).raw(v);
            else
                w.kv(k, v);
        }
        w.endObj();
        w.endObj();
    }

private:
    static bool isNumeric(const std::string& s) {
        if (s.empty() || s.size() > 18) return false;
        size_t start = (s[0] == '-') ? 1 : 0;
        if (start == s.size()) return false;
        if (s[start] == '0' && s.size() > start + 1) return false; // keep "007" a string
        for (size_t i = start; i < s.size(); ++i)
            if (s[i] < '0' || s[i] > '9') return false;
        return true;
    }
};

/** One state-machine transition reported by a logic module (PA-4). */
struct Transition {
    Proto proto = Proto::ETH;
    std::string object;  // state-object key, e.g. "reservation 0x…"
    std::string from, to, why;
    std::string summary;
    std::string entity, stream;
};

} // namespace avb
