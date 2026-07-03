/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * MSRP stream reservation view (IEEE 802.1Q / Milan v1.2): per-StreamID
 * reservation state reconstructed from talker and listener declarations,
 * plus the SR class domain table.
 */
#include <map>

#include "../decode/names.h"
#include "avb_logic.h"

namespace avb {
namespace {

class MsrpLogic final : public AvbLogicBase {
public:
    void onDecode(LayerContext& ctx) override {
        auto* v = dynamic_cast<VarLayerContext*>(&ctx);
        if (!v) return;
        double ts = tsOf(*v);
        uint32_t n = numOf(*v);
        uint8_t attr = (uint8_t)v->at("attribute_type");
        int ev = (int)v->at("mrp_event");
        uint64_t src = v->at("src_mac");

        // Attribute-type descriptors for the MRP registrar layer. Each MSRP
        // attribute type is a distinct 802.1Q Registrar, so the key must
        // separate them (TalkerAdvertise vs TalkerFailed) and fully identify
        // the attribute value (Domain by class+priority+vid).
        auto mrpKind = [&]() -> std::string {
            switch (attr) {
            case 1: return "TALKER_ADVERTISE";
            case 2: return "TALKER_FAILED";
            case 3: return "LISTENER";
            case 4: return "DOMAIN";
            }
            return "";
        };
        auto mrpKey = [&]() -> std::string {
            switch (attr) {
            case 1: return "Talker Advertise " + idStr(v->at("stream_id"));
            case 2: return "Talker Failed " + idStr(v->at("stream_id"));
            case 3: return "Listener " + idStr(v->at("stream_id"));
            case 4:
                return "Domain class " + std::to_string(v->at("sr_class_id")) +
                       " prio " + std::to_string(v->at("sr_class_priority")) +
                       " vid " + std::to_string(v->at("sr_class_vid"));
            }
            return "";
        };

        if (ev == 6) { // LeaveAll — scoped to this attribute type (802.1Q)
            std::string kind = mrpKind();
            if (mShared && !kind.empty())
                mShared->mrpLeaveAll(Proto::MSRP, kind, ts, n);
            return;
        }

        // Feed the MRP registrar layer (802.1Q 10.7.8) with this declaration.
        if (mShared) {
            std::string key = mrpKey();
            // A Listener declaring "Ignore" (four-packed 0) expresses no
            // interest — treat it as a leave so the registrar view agrees
            // with the reservation view.
            int regEv = ev;
            if (attr == 3 && (int)v->at("four_packed_event") == 0) regEv = 5;
            if (!key.empty())
                mShared->mrpEvent(Proto::MSRP, mrpKind(), key, src, regEv, ts, n);
        }

        switch (attr) {
        case 1:   // TalkerAdvertise
        case 2: { // TalkerFailed
            auto& res = mRes[v->at("stream_id")];
            res.streamId = v->at("stream_id");
            res.talkerMac = src;
            res.destMac = v->at("dest_mac");
            res.vlan = (uint16_t)v->at("vlan_id");
            res.maxFrameSize = (uint16_t)v->at("max_frame_size");
            res.maxIntervalFrames = (uint16_t)v->at("max_interval_frames");
            res.priority = (uint8_t)v->at("priority");
            res.rank = (uint8_t)v->at("rank");
            res.accLatency = (uint32_t)v->at("accumulated_latency");
            std::string why;
            if (ev == 5) { // Lv — talker withdraws
                res.decl = DeclNone;
                why = "Talker Lv from " + macStr(src);
            } else if (attr == 1) {
                res.decl = DeclAdvertise;
                why = std::string("TalkerAdvertise ") + mrpEventName(ev) +
                      " from " + macStr(src);
            } else {
                res.decl = DeclFailed;
                res.failBridge = v->at("failure_bridge_id");
                res.failCode = (uint8_t)v->at("failure_code");
                why = std::string("TalkerFailed ") + mrpEventName(ev) + " (" +
                      msrpFailureName(res.failCode) + ")";
            }
            if (mShared) { // talker-attribute truth for the Milan sink SM
                if (res.decl == DeclNone)
                    mShared->msrpTalkerDecl.erase(res.streamId);
                else
                    mShared->msrpTalkerDecl[res.streamId] = res.decl;
            }
            recompute(res, ts, n, why, ev == 5);
            break;
        }
        case 3: { // Listener
            auto& res = mRes[v->at("stream_id")];
            res.streamId = v->at("stream_id");
            int fp = (int)v->at("four_packed_event");
            std::string why;
            if (ev == 5 || fp == 0) {
                res.listeners.erase(src);
                why = std::string("Listener ") +
                      (ev == 5 ? "Lv" : "Ignore") + " from " + macStr(src);
            } else {
                res.listeners[src] = fp;
                why = std::string("Listener ") + fourPackedName(fp) + " " +
                      mrpEventName(ev) + " from " + macStr(src);
            }
            recompute(res, ts, n, why, false);
            break;
        }
        case 4: { // Domain
            Domain d;
            d.classId = (uint8_t)v->at("sr_class_id");
            d.classPrio = (uint8_t)v->at("sr_class_priority");
            d.vid = (uint16_t)v->at("sr_class_vid");
            d.declarer = src;
            bool known = false;
            for (auto& e : mDomains)
                if (e.classId == d.classId && e.classPrio == d.classPrio &&
                    e.vid == d.vid && e.declarer == d.declarer)
                    known = true;
            if (!known && ev != 5) mDomains.push_back(d);
            break;
        }
        default:
            break;
        }
    }

    void snapshot(JsonWriter& w) const override {
        w.key("reservations").beginArr();
        for (auto& [sid, res] : mRes) {
            w.beginObj();
            w.kv("stream_id", idStr(sid));
            w.kv("talker_mac", res.talkerMac ? macStr(res.talkerMac) : "");
            w.kv("dest_mac", res.destMac ? macStr(res.destMac) : "");
            w.kv("vlan", (uint64_t)res.vlan);
            w.kv("max_frame_size", (uint64_t)res.maxFrameSize);
            w.kv("max_interval_frames", (uint64_t)res.maxIntervalFrames);
            w.kv("priority", (uint64_t)res.priority);
            w.kv("rank", (uint64_t)res.rank);
            w.kv("accumulated_latency", (uint64_t)res.accLatency);
            w.kv("state", res.state.empty() ? "PENDING" : res.state);
            w.kv("declaration", res.decl == DeclAdvertise ? "ADVERTISE"
                                : res.decl == DeclFailed  ? "FAILED"
                                                          : "");
            w.kv("failure_bridge", res.failBridge ? idStr(res.failBridge) : "");
            w.kv("failure_code", (uint64_t)res.failCode);
            // Live annotation from observed gPTP truth — never a state change
            // of the reservation itself (see API.md).
            {
                int sync = mShared ? mShared->syncStateForAnnotation() : 0;
                w.kv("gptp_sync", sync == 1   ? "HEALTHY"
                                  : sync == 2 ? "LOST"
                                              : "UNKNOWN");
            }
            w.key("listeners").beginArr();
            for (auto& [mac, fp] : res.listeners) {
                w.beginObj();
                w.kv("mac", macStr(mac));
                w.kv("state", listenerStateName(fp));
                w.endObj();
            }
            w.endArr();
            histJson(w, res.hist);
            w.endObj();
        }
        w.endArr();

        w.key("domains").beginArr();
        for (auto& d : mDomains) {
            w.beginObj();
            w.kv("class_id", (uint64_t)d.classId);
            w.kv("priority", (uint64_t)d.classPrio);
            w.kv("vid", (uint64_t)d.vid);
            w.kv("declarer", macStr(d.declarer));
            w.endObj();
        }
        w.endArr();
    }

private:
    enum Decl { DeclNone = 0, DeclAdvertise, DeclFailed };

    struct Res {
        uint64_t streamId = 0, talkerMac = 0, destMac = 0, failBridge = 0;
        uint16_t vlan = 0, maxFrameSize = 0, maxIntervalFrames = 0;
        uint32_t accLatency = 0;
        uint8_t priority = 0, rank = 0, failCode = 0;
        int decl = DeclNone;
        bool talkerSeen = false;
        std::map<uint64_t, int> listeners; // mac -> four-packed state
        std::string state;
        std::vector<HistEntry> hist;
    };

    struct Domain {
        uint8_t classId = 0, classPrio = 0;
        uint16_t vid = 0;
        uint64_t declarer = 0;
    };

    static const char* listenerStateName(int fp) {
        switch (fp) {
        case 1: return "ASKING_FAILED";
        case 2: return "READY";
        case 3: return "READY_FAILED";
        }
        return "?";
    }

    void recompute(Res& res, double ts, uint32_t n, const std::string& why,
                   bool talkerWithdrew) {
        if (res.decl != DeclNone) res.talkerSeen = true;

        bool anyReady = false, anyAskFailed = false;
        for (auto& [mac, fp] : res.listeners) {
            if (fp == 2 || fp == 3) anyReady = true;
            if (fp == 1 || fp == 3) anyAskFailed = true;
        }

        std::string to;
        if (talkerWithdrew || (res.talkerSeen && res.decl == DeclNone))
            to = "WITHDRAWN";
        else if (res.decl == DeclFailed)
            to = "TALKER_FAILED";
        else if (res.decl == DeclAdvertise)
            to = anyReady ? "ESTABLISHED"
                          : (anyAskFailed ? "LISTENER_FAILED" : "PENDING");
        else
            to = "PENDING"; // listener waiting, talker not yet seen

        std::string from = res.state.empty() ? "NEW" : res.state;
        if (from == to) {
            // Listener churn without an overall state change still matters
            // for the object history, but is not a transition event.
            res.hist.push_back({ts, n, from, to, why});
            if (res.hist.size() > 200) res.hist.erase(res.hist.begin());
            return;
        }
        res.state = to;
        res.hist.push_back({ts, n, from, to, why});

        // Cross-effect: gPTP cites how many established reservations depend
        // on the clock when sync is lost (read by GptpLogic).
        if (mShared) {
            if (to == "ESTABLISHED")
                mShared->establishedStreams.insert(res.streamId);
            else
                mShared->establishedStreams.erase(res.streamId);
        }

        Transition t;
        t.proto = Proto::MSRP;
        t.object = "reservation " + idStr(res.streamId);
        t.from = from;
        t.to = to;
        t.why = why;
        t.stream = idStr(res.streamId);
        t.summary = "Reservation " + idStr(res.streamId) + ": " + from + " -> " +
                    to + " — " + why;
        emit(std::move(t));
    }

    std::map<uint64_t, Res> mRes;
    std::vector<Domain> mDomains;
};

REGISTER_LOGIC("mrp_msrp", MsrpLogic)

} // namespace
} // namespace avb
