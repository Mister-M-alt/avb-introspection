/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * One analysis session: the ordered event log, packet index for the
 * inspector, live state machines, and stats. Multiple clients may read the
 * same session concurrently (BE-7); the event log is append-only under
 * `mu`, with `cv` waking streaming readers.
 */
#pragma once

#include <array>
#include <atomic>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "../logic/avb_logic.h"
#include "../model/event.h"
#include "../pcapio/pcap_reader.h"

namespace avb {

/** The seven protocol state machines of one session, from the registry. */
struct AnalysisState {
    SharedModel shared;
    // Snapshot order defines the /state key order ("gptp" last).
    std::vector<std::pair<std::string, std::unique_ptr<ILogicModule>>> modules;
    std::unordered_map<std::string, AvbLogicBase*> byService;

    static std::unique_ptr<AnalysisState> create() {
        auto st = std::make_unique<AnalysisState>();
        static const char* kServices[] = {"atdecc_adp", "mrp_msrp", "mrp_mvrp",
                                          "1722_maap", "atdecc_acmp",
                                          "atdecc_aecp", "8021as_gptp"};
        for (const char* svc : kServices) {
            auto mod = LogicRegistry::instance().create(svc);
            if (!mod) continue; // registry test covers this; keep running
            if (auto* base = dynamic_cast<AvbLogicBase*>(mod.get())) {
                base->attach(&st->shared);
                st->byService[svc] = base;
            }
            st->modules.emplace_back(svc, std::move(mod));
        }
        return st;
    }

    void snapshotJson(JsonWriter& w) const {
        w.beginObj();
        for (auto& [svc, mod] : modules)
            if (auto* base = dynamic_cast<AvbLogicBase*>(mod.get()))
                base->snapshot(w);
        shared.snapshotMrp(w); // MRP registrar layer (fed by MSRP + MVRP)
        w.endObj();
    }
};

struct Session {
    std::string id, name, pcapId, path, createdAt;
    std::string pcapFilePath; // resolved file the analysis ran on
    std::string domain = "default"; // owning tenant domain (SE-5)

    enum Status { Running = 0, Done = 1, Error = 2 };
    std::atomic<int> status{Running};
    std::string errorMsg;

    // Event log: append-only while Running; readers take shared locks.
    mutable std::shared_mutex mu;
    mutable std::condition_variable_any cv;
    std::vector<Event> events;

    // Packet index for the inspector (offsets into pcapFilePath).
    std::vector<PcapPacket> pindex;
    uint64_t firstTsNanos = 0, lastTsNanos = 0;

    /** Devices observed as frame sources (guarded by stateMu). */
    struct DeviceInfo {
        uint64_t packets = 0;
        uint32_t protoMask = 0;  // bit i = (Proto)i seen from this source
        uint64_t entityId = 0;   // ATDECC entity associated via ADP/AECP
        // Every entity id proven to originate from this MAC (controller ids in
        // AECP/ACMP commands, talker/listener ids in ACMP responses, ...).
        // Controllers such as certification test machines never send ADP
        // ENTITY_AVAILABLE, so this is how their state gets attached to them.
        std::set<uint64_t> assocIds;
    };
    std::map<uint64_t, DeviceInfo> devices;

    // State machines (guarded by stateMu; the state pass is single-threaded
    // per CO-3, but /state may be requested concurrently).
    mutable std::mutex stateMu;
    std::unique_ptr<AnalysisState> logic;

    // Stats (NF-2).
    std::atomic<uint64_t> packets{0}, decodeErrors{0};
    std::array<std::atomic<uint64_t>, kProtoCount> protoCounts{};
    std::atomic<uint64_t> analysisMs{0};
    double duration = 0;

    size_t eventCount() const {
        std::shared_lock lk(mu);
        return events.size();
    }

    std::string stateJson() const {
        std::lock_guard lk(stateMu);
        if (!logic) return "{}";
        JsonWriter w;
        logic->snapshotJson(w);
        return w.take();
    }
};

} // namespace avb
