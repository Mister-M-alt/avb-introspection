/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * MRP Registrar state machine (IEEE 802.1Q 10.7.8), reconstructed passively
 * from observed MRP AttributeEvents. This is the registration layer beneath
 * MSRP and MVRP: for each declared attribute value, per declaring source, a
 * Registrar sits in IN (registered), LV (leaving — leavetimer running) or MT
 * (empty). It is driven purely by the events on the wire, so it is fully
 * observable from a single tap.
 */
#include "avb_logic.h"

#include "../decode/names.h"

namespace avb {

namespace {
// IEEE 802.1Q 10.7.11: LeaveTime — the Registrar leavetimer. Range 600–1000
// ms; default taken as 1.0 s (must be >= 2x worst-case JoinTime).
constexpr double kMrpLeaveTimeS = 1.0;
constexpr size_t kMrpLogCap = 500;
constexpr size_t kMrpHistCap = 200;

template <typename V>
void capBack(std::vector<V>& v, size_t cap) {
    if (v.size() > cap) v.erase(v.begin());
}
} // namespace

void SharedModel::mrpSetRegistrar(MrpAttr& a, const std::string& to, double ts,
                                  uint32_t n, const std::string& why) {
    std::string from = a.registrar.empty() ? "MT" : a.registrar;
    if (from == to) return;
    if (from == "LV" && mrpLvCount) --mrpLvCount;
    if (to == "LV") ++mrpLvCount;
    a.registrar = to;
    a.hist.push_back({ts, n, from, to, why});
    capBack(a.hist, kMrpHistCap);
}

void SharedModel::mrpEvent(Proto proto, const std::string& kind,
                           const std::string& key, uint64_t source, int ev,
                           double ts, uint32_t n) {
    auto& a = mrpAttrs[std::make_tuple((int)proto, key, source)];
    a.proto = proto;
    a.kind = kind;
    a.key = key;
    a.source = source;
    a.lastEventTs = ts;
    a.eventCount++;
    a.lastEvent = mrpEventName(ev);
    if (a.registrar.empty()) a.registrar = "MT";

    switch (ev) {
    case 0: // New   -> rNew!
        mrpSetRegistrar(a, "IN", ts, n, "rNew (New) — new registration");
        a.leaveTimerStart = -1;
        break;
    case 1: // JoinIn -> rJoinIn!
    case 3: // JoinMt -> rJoinMt!
        mrpSetRegistrar(a, "IN", ts, n,
                        std::string("rJoin (") + mrpEventName(ev) +
                            ") — registered");
        a.leaveTimerStart = -1;
        break;
    case 5: // Lv -> rLv!
        if (a.registrar == "IN") {
            a.leaveTimerStart = ts;
            mrpSetRegistrar(a, "LV", ts, n,
                            "rLv (Lv) — leaving, leavetimer started");
        }
        break;
    case 2: // In -> rIn: no registrar change
    case 4: // Mt -> rMt: no registrar change
        // ev==6 (LeaveAll) never reaches here — both feed sites route it to
        // mrpLeaveAll(), which is scoped to the attribute type.
    default:
        break;
    }

    a.log.push_back({ts, n, mrpEventName(ev), a.registrar});
    capBack(a.log, kMrpLogCap);
}

void SharedModel::mrpLeaveAll(Proto proto, const std::string& kind, double ts,
                              uint32_t n) {
    for (auto& [k, a] : mrpAttrs) {
        if (a.proto != proto || a.kind != kind || a.registrar != "IN") continue;
        a.leaveTimerStart = ts;
        a.lastEvent = "LeaveAll";
        a.lastEventTs = ts;
        a.eventCount++;
        mrpSetRegistrar(a, "LV", ts, n,
                        "rLA (LeaveAll) — leaving, leavetimer started");
        a.log.push_back({ts, n, "LeaveAll", "LV"});
        capBack(a.log, kMrpLogCap);
    }
}

void SharedModel::mrpTick(double ts) {
    if (mrpLvCount == 0) return; // nothing can expire
    for (auto& [k, a] : mrpAttrs) {
        if (a.registrar == "LV" && a.leaveTimerStart >= 0 &&
            ts > a.leaveTimerStart + kMrpLeaveTimeS) {
            mrpSetRegistrar(a, "MT", ts, 0,
                            "leavetimer expired — deregistered");
            a.leaveTimerStart = -1;
        }
    }
}

void SharedModel::snapshotMrp(JsonWriter& w) const {
    w.key("mrp").beginArr();
    for (auto& [k, a] : mrpAttrs) {
        w.beginObj();
        w.kv("proto", protoName(a.proto));
        w.kv("kind", a.kind);
        w.kv("attribute", a.key);
        w.kv("source", macStr(a.source));
        w.kv("registrar", a.registrar.empty() ? "MT" : a.registrar);
        w.kv("last_event", a.lastEvent);
        w.kv("last_event_ts", a.lastEventTs);
        w.kv("events", (uint64_t)a.eventCount);
        w.key("log").beginArr();
        for (auto& e : a.log) {
            w.beginObj();
            w.kv("ts", e.ts);
            w.kv("n", (uint64_t)e.n);
            w.kv("event", e.event);
            w.kv("state", e.registrarAfter); // registrar state after this event
            w.endObj();
        }
        w.endArr();
        histJson(w, a.hist);
        w.endObj();
    }
    w.endArr();
}

} // namespace avb
