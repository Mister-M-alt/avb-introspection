/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * Base class for the protocol state machines (PA-2), implemented as TSN-GEN
 * logic modules (BE-2): each subclasses ILogicModule, registers itself via
 * REGISTER_LOGIC under its service name, and reconstructs protocol state in
 * onDecode(). Everything beyond the ILogicModule contract (transition
 * draining, state snapshots, the shared entity-name model, time ticks for
 * timeout tracking) is reached by the runtime via dynamic_cast — the
 * introspection pattern TSN-GEN's logic README documents.
 */
#pragma once

#include <map>
#include <set>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>

#include "../model/event.h"
#include "../tsn_gen/logic_module.h"
#include "../tsn_gen/logic_registry.h"
#include "../tsn_gen/var_context.h"
#include "../util/bytes.h"
#include "../util/json.h"

namespace avb {

/** One state-object history entry (docs/API.md "State"). */
struct HistEntry {
    double ts = 0;
    uint32_t n = 0;
    std::string from, to, why;
};

inline void histJson(JsonWriter& w, const std::vector<HistEntry>& hist) {
    w.key("history").beginArr();
    for (auto& h : hist) {
        w.beginObj();
        w.kv("ts", h.ts);
        w.kv("n", (uint64_t)h.n);
        w.kv("from", h.from);
        w.kv("to", h.to);
        w.kv("why", h.why);
        w.endObj();
    }
    w.endArr();
}

/** Cross-protocol knowledge shared by all modules of one analysis (PA-6).
 *  Written and read only inside the single-threaded state pass (CO-3), so no
 *  locking is needed. */
class SharedModel {
public:
    std::unordered_map<uint64_t, std::string> entityNames;

    /** Observed gPTP truth per domain, written by GptpLogic. Consumers (ADP
     *  gm_in_sync check, MSRP sync annotation) read, never write. */
    struct GptpDomainTruth {
        bool gmKnown = false;    // an Announce has been observed
        uint64_t gmIdentity = 0; // last observed grandmasterIdentity
        int syncState = 0;       // 0 unknown, 1 healthy, 2 lost
    };
    std::map<uint8_t, GptpDomainTruth> gptpDomains;

    /** StreamIDs of currently ESTABLISHED reservations, kept by MsrpLogic;
     *  GptpLogic cites the count when sync is lost. */
    std::set<uint64_t> establishedStreams;

    /** Entities currently AVAILABLE per ADP (kept by AdpLogic) — drives the
     *  Milan sink EVT_TK_DISCOVERED/EVT_TK_DEPARTED events in AcmpLogic. */
    std::set<uint64_t> adpAvailable;

    /** Active MSRP talker declaration per StreamID (kept by MsrpLogic):
     *  0 none, 1 Advertise, 2 Failed — drives the Milan sink
     *  EVT_TK_REGISTERED/EVT_TK_UNREGISTERED events. */
    std::map<uint64_t, int> msrpTalkerDecl;

    /** MRP Registrar state machine (IEEE 802.1Q 10.7.8) — the registration
     *  layer beneath MSRP and MVRP. One instance per (protocol, attribute
     *  value, declaring source), reconstructed from the observed MRP events
     *  (New/JoinIn/In/JoinMt/Mt/Lv/LeaveAll). Both MsrpLogic and MvrpLogic
     *  feed it via mrpEvent(); the registrar's leavetimer is advanced by
     *  mrpTick(). This is fully observable from a passive tap. */
    struct MrpAttr {
        Proto proto = Proto::MSRP;
        std::string kind;      // VID | TALKER_ADVERTISE | LISTENER | DOMAIN…
        std::string key;       // human attribute label
        uint64_t source = 0;   // declaring MAC
        std::string registrar; // "" -> MT (initial) / IN / LV / MT
        std::string lastEvent; // last observed MRP AttributeEvent
        double lastEventTs = -1, leaveTimerStart = -1;
        uint32_t eventCount = 0;
        struct LogEntry {      // observed event log for the step-through UI
            double ts;
            uint32_t n;
            std::string event;
            std::string registrarAfter;
        };
        std::vector<LogEntry> log;
        std::vector<HistEntry> hist; // registrar state transitions only
    };
    std::map<std::tuple<int, std::string, uint64_t>, MrpAttr> mrpAttrs;

    /** Record one observed MRP AttributeEvent for an attribute declaration
     *  and advance the Registrar state machine. `ev` is the decode event id
     *  (0 New, 1 JoinIn, 2 In, 3 JoinMt, 4 Mt, 5 Lv, 6 LeaveAll). */
    void mrpEvent(Proto proto, const std::string& kind, const std::string& key,
                  uint64_t source, int ev, double ts, uint32_t n);
    /** A LeaveAll is scoped to the attribute TYPE of the MRP Message it is
     *  carried in (802.1Q): apply rLA only to registrars of that (protocol,
     *  kind), asking them to re-declare. */
    void mrpLeaveAll(Proto proto, const std::string& kind, double ts,
                     uint32_t n);
    /** Advance registrar leavetimers (LV -> MT). Idempotent; O(1) when no
     *  registrar is currently leaving. */
    void mrpTick(double ts);
    void snapshotMrp(JsonWriter& w) const;

    /** Move a registrar to `to`, record the transition, and keep mrpLvCount
     *  (the number of registrars currently in LV) in step. */
    void mrpSetRegistrar(MrpAttr& a, const std::string& to, double ts,
                         uint32_t n, const std::string& why);
    size_t mrpLvCount = 0;

    std::string nameOf(uint64_t entityId) const {
        auto it = entityNames.find(entityId);
        return it == entityNames.end() ? std::string() : it->second;
    }

    /** Sync state for annotations: domain 0 first, else the single observed
     *  domain, else unknown (rule documented in API.md). */
    int syncStateForAnnotation() const {
        if (auto it = gptpDomains.find(0); it != gptpDomains.end())
            return it->second.syncState;
        if (gptpDomains.size() == 1) return gptpDomains.begin()->second.syncState;
        return 0;
    }
};

class AvbLogicBase : public ILogicModule {
public:
    void attach(SharedModel* shared) { mShared = shared; }

    /** Transitions produced since the last drain (PA-4). */
    std::vector<Transition> drain() { return std::move(mPending); }

    /** Capture time advanced to `ts` — expire whatever timed out. */
    virtual void onTimeTick(double /*ts*/) {}

    /** Write this module's top-level state keys (inside the state object). */
    virtual void snapshot(JsonWriter& w) const = 0;

protected:
    static double tsOf(const VarLayerContext& c) {
        return (double)c.at("ts_ns") / 1e9;
    }
    static uint32_t numOf(const VarLayerContext& c) {
        return (uint32_t)c.at("pkt_num");
    }

    void emit(Transition t) { mPending.push_back(std::move(t)); }

    SharedModel* mShared = nullptr;
    std::vector<Transition> mPending;
};

} // namespace avb
