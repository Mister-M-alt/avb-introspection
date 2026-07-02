/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * ADP entity lifecycle (IEEE 1722.1 discovery, Milan v1.2): AVAILABLE /
 * DEPARTING / TIMED_OUT with valid_time expiry driven by capture time.
 */
#include <map>

#include "../decode/names.h"
#include "avb_logic.h"

namespace avb {
namespace {

class AdpLogic final : public AvbLogicBase {
public:
    void onDecode(LayerContext& ctx) override {
        auto* v = dynamic_cast<VarLayerContext*>(&ctx);
        if (!v) return;
        double ts = tsOf(*v);
        uint32_t n = numOf(*v);
        uint8_t msg = (uint8_t)v->at("message_type");
        uint64_t id = v->at("entity_id");

        if (msg == 2) return; // ENTITY_DISCOVER carries no entity state

        auto& e = mEntities[id];
        e.entityId = id;
        std::string prev = e.state.empty() ? "UNKNOWN" : e.state;

        if (msg == 0) { // ENTITY_AVAILABLE
            uint32_t idx = (uint32_t)v->at("available_index");
            if (e.state == "AVAILABLE" && idx < e.availIdx) {
                transition(e, ts, n, "AVAILABLE",
                           "available_index went backwards (" +
                               std::to_string(e.availIdx) + " -> " +
                               std::to_string(idx) + "), device restarted?");
            } else if (e.state != "AVAILABLE") {
                transition(e, ts, n, "AVAILABLE", "ENTITY_AVAILABLE received");
            }
            e.availIdx = idx;
            e.validTime = (double)v->at("valid_time");
            e.lastSeen = ts;
            e.modelId = v->at("entity_model_id");
            e.gmId = v->at("gptp_grandmaster_id");
            e.gptpDomain = (uint8_t)v->at("gptp_domain_number");
            e.talkerSources = (uint16_t)v->at("talker_stream_sources");
            e.listenerSinks = (uint16_t)v->at("listener_stream_sinks");
            checkGmAgainstObserved(e, ts, n);
        } else if (msg == 1) { // ENTITY_DEPARTING
            e.lastSeen = ts;
            if (e.state != "DEPARTING")
                transition(e, ts, n, "DEPARTING", "ENTITY_DEPARTING received");
        }
        (void)prev;
    }

    void onTimeTick(double ts) override {
        for (auto& [id, e] : mEntities) {
            if (e.state == "AVAILABLE" && e.validTime > 0 &&
                ts > e.lastSeen + e.validTime) {
                transition(e, ts, 0, "TIMED_OUT",
                           "no re-announce within valid_time (" +
                               std::to_string((int)e.validTime) + " s)");
            }
        }
    }

    void snapshot(JsonWriter& w) const override {
        w.key("entities").beginArr();
        for (auto& [id, e] : mEntities) {
            w.beginObj();
            w.kv("entity_id", idStr(id));
            w.kv("name", mShared ? mShared->nameOf(id) : "");
            w.kv("model_id", idStr(e.modelId));
            w.kv("state", e.state.empty() ? "UNKNOWN" : e.state);
            w.kv("last_seen", e.lastSeen);
            w.kv("available_index", (uint64_t)e.availIdx);
            w.kv("talker_sources", (uint64_t)e.talkerSources);
            w.kv("listener_sinks", (uint64_t)e.listenerSinks);
            w.kv("gptp_gm", idStr(e.gmId));
            w.kv("gptp_domain", (uint64_t)e.gptpDomain);
            w.kv("gm_in_sync", gmInSync(e));
            histJson(w, e.hist);
            w.endObj();
        }
        w.endArr();
    }

private:
    struct Entity {
        uint64_t entityId = 0, modelId = 0, gmId = 0;
        uint32_t availIdx = 0;
        uint16_t talkerSources = 0, listenerSinks = 0;
        uint8_t gptpDomain = 0;
        bool gmMismatch = false;
        double validTime = 0, lastSeen = 0;
        std::string state; // "" until first observation
        std::vector<HistEntry> hist;
    };

    /** Cross-effect (PA-6): compare the grandmaster this entity announces in
     *  ADP against the grandmaster actually observed on the wire via gPTP. */
    void checkGmAgainstObserved(Entity& e, double ts, uint32_t n) {
        if (!mShared || e.gmId == 0) return;
        auto it = mShared->gptpDomains.find(e.gptpDomain);
        if (it == mShared->gptpDomains.end() || !it->second.gmKnown) return;
        uint64_t observed = it->second.gmIdentity;
        if (e.gmId != observed && !e.gmMismatch) {
            e.gmMismatch = true;
            transition(e, ts, n, e.state,
                       "announces gPTP grandmaster " + idStr(e.gmId) +
                           " but the observed grandmaster on domain " +
                           std::to_string(e.gptpDomain) + " is " +
                           idStr(observed) + " (stale gPTP info?)");
        } else if (e.gmId == observed && e.gmMismatch) {
            e.gmMismatch = false;
            transition(e, ts, n, e.state,
                       "gPTP grandmaster now matches the observed grandmaster " +
                           idStr(observed));
        }
    }

    /** Live gm_in_sync for /state — evaluated against current shared truth. */
    std::string gmInSync(const Entity& e) const {
        if (!mShared || e.gmId == 0) return "UNKNOWN";
        auto it = mShared->gptpDomains.find(e.gptpDomain);
        if (it == mShared->gptpDomains.end() || !it->second.gmKnown)
            return "UNKNOWN";
        return e.gmId == it->second.gmIdentity ? "MATCH" : "MISMATCH";
    }

    void transition(Entity& e, double ts, uint32_t n, const std::string& to,
                    const std::string& why) {
        std::string from = e.state.empty() ? "UNKNOWN" : e.state;
        e.state = to;
        e.hist.push_back({ts, n, from, to, why});
        Transition t;
        t.proto = Proto::ADP;
        t.object = "entity " + idStr(e.entityId);
        t.from = from;
        t.to = to;
        t.why = why;
        t.entity = idStr(e.entityId);
        std::string nm = mShared ? mShared->nameOf(e.entityId) : "";
        t.summary = "Entity " + idStr(e.entityId) +
                    (nm.empty() ? "" : " (" + nm + ")") + ": " + from + " -> " + to +
                    " — " + why;
        emit(std::move(t));
    }

    std::map<uint64_t, Entity> mEntities;
};

REGISTER_LOGIC("atdecc_adp", AdpLogic)

} // namespace
} // namespace avb
