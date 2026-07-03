/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * MVRP VLAN registration view (IEEE 802.1Q MRP): per-VID membership as
 * observed on the wire — REGISTERED / LEAVING (after LeaveAll) / WITHDRAWN.
 */
#include <map>
#include <set>

#include "../decode/names.h"
#include "avb_logic.h"

namespace avb {
namespace {

class MvrpLogic final : public AvbLogicBase {
public:
    void onDecode(LayerContext& ctx) override {
        auto* v = dynamic_cast<VarLayerContext*>(&ctx);
        if (!v) return;
        double ts = tsOf(*v);
        uint32_t n = numOf(*v);
        int ev = (int)v->at("mrp_event");
        uint64_t member = v->at("src_mac");

        if (ev == 6) { // LeaveAll: every registration must be re-declared
            for (auto& [vid, vl] : mVlans) {
                if (vl.state == "REGISTERED")
                    transition(vl, vid, ts, n, "LEAVING",
                               "LeaveAll from " + macStr(member));
            }
            if (mShared) mShared->mrpLeaveAll(Proto::MVRP, "VID", ts, n);
            return;
        }

        uint16_t vid = (uint16_t)v->at("vid");
        if (mShared)
            mShared->mrpEvent(Proto::MVRP, "VID", "VLAN " + std::to_string(vid),
                              member, ev, ts, n);
        auto& vl = mVlans[vid];

        switch (ev) {
        case 0: // New
        case 1: // JoinIn
        case 3: // JoinMt
            vl.members.insert(member);
            if (vl.state != "REGISTERED")
                transition(vl, vid, ts, n, "REGISTERED",
                           std::string(mrpEventName(ev)) + " from " +
                               macStr(member));
            break;
        case 5: // Lv
            vl.members.erase(member);
            if (vl.members.empty() && vl.state != "WITHDRAWN")
                transition(vl, vid, ts, n, "WITHDRAWN",
                           "Lv from " + macStr(member) + ", no members left");
            break;
        case 2: // In — declared, no registrar change observed
        case 4: // Mt — empty
        default:
            break;
        }
    }

    void onTimeTick(double ts) override {
        // Drives the shared MRP registrar leavetimer (covers MSRP attrs too,
        // since mrpTick walks the whole map). MvrpLogic always exists.
        if (mShared) mShared->mrpTick(ts);
    }

    void snapshot(JsonWriter& w) const override {
        w.key("vlans").beginArr();
        for (auto& [vid, vl] : mVlans) {
            w.beginObj();
            w.kv("vid", (uint64_t)vid);
            w.kv("state", vl.state.empty() ? "UNKNOWN" : vl.state);
            w.key("members").beginArr();
            for (uint64_t m : vl.members) w.value(macStr(m));
            w.endArr();
            histJson(w, vl.hist);
            w.endObj();
        }
        w.endArr();
    }

private:
    struct Vlan {
        std::set<uint64_t> members;
        std::string state;
        std::vector<HistEntry> hist;
    };

    void transition(Vlan& vl, uint16_t vid, double ts, uint32_t n,
                    const std::string& to, const std::string& why) {
        std::string from = vl.state.empty() ? "UNKNOWN" : vl.state;
        vl.state = to;
        vl.hist.push_back({ts, n, from, to, why});
        Transition t;
        t.proto = Proto::MVRP;
        t.object = "vlan " + std::to_string(vid);
        t.from = from;
        t.to = to;
        t.why = why;
        t.summary = "VLAN " + std::to_string(vid) + ": " + from + " -> " + to +
                    " — " + why;
        emit(std::move(t));
    }

    std::map<uint16_t, Vlan> mVlans;
};

REGISTER_LOGIC("mrp_mvrp", MvrpLogic)

} // namespace
} // namespace avb
