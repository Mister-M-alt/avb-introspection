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
