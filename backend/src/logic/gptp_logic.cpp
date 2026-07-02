/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * gPTP (IEEE 802.1AS) observer: per-domain grandmaster lifecycle and sync
 * health, per-port role / asCapable / pdelay tracking — reconstructed
 * passively from a single tap point, so role and asCapable are labelled
 * inferences. Writes the observed truth into SharedModel for the ADP
 * gm_in_sync check and the MSRP sync annotation (PA-6 cross-effects).
 */
#include <algorithm>
#include <cstdio>
#include <map>

#include "../decode/names.h"
#include "avb_logic.h"

namespace avb {
namespace {

// 802.1AS-2020 10.7.3.1: syncReceiptTimeout default = 3 sync intervals.
constexpr int kSyncReceiptTimeoutN = 3;
// 802.1AS-2020 10.7.3.2: announceReceiptTimeout default = 3 announce intervals.
constexpr int kAnnounceReceiptTimeoutN = 3;
// 802.1AS-2011 11.5.3 / Avnu gPTP profile: allowedLostResponses = 3.
// (802.1AS-2020 relaxed this to 9; 3 flags problems earlier — this is a
// diagnostic threshold, not a conformance verdict.)
constexpr int kAllowedLostResponses = 3;
// Defaults when logMessageInterval is 0x7F ("not used") or implausible:
constexpr double kDefaultSyncIntervalS = 0.125; // logSyncInterval -3 (Milan)
constexpr double kDefaultAnnounceIntervalS = 1.0; // logAnnounceInterval 0
constexpr double kDefaultPdelayIntervalS = 1.0;   // logPdelayReqInterval 0
// Avnu gPTP test plan: pdelay responder turnaround limit.
constexpr double kPdelayTurnaroundLimitS = 0.010;
constexpr size_t kMaxHist = 200;

double intervalFromLog(uint64_t raw, double dflt) {
    int8_t v = (int8_t)(uint8_t)raw;
    if ((uint8_t)raw == 0x7F || v < -7 || v > 5) return dflt;
    return (v >= 0) ? (double)(1 << v) : 1.0 / (double)(1 << -v);
}

std::string fmtGap(double s) {
    char buf[32];
    if (s < 1.0)
        std::snprintf(buf, sizeof buf, "%.0f ms", s * 1e3);
    else
        std::snprintf(buf, sizeof buf, "%.2f s", s);
    return buf;
}

class GptpLogic final : public AvbLogicBase {
public:
    void onDecode(LayerContext& ctx) override {
        auto* v = dynamic_cast<VarLayerContext*>(&ctx);
        if (!v) return;
        double ts = tsOf(*v);
        uint32_t n = numOf(*v);
        uint8_t msg = (uint8_t)v->at("message_type");
        bool cmlds = v->at("transport_specific") == 2; // 802.1AS-2020 CMLDS

        uint8_t dom = (uint8_t)v->at("domain_number");
        auto& port = getPort(v->at("source_clock_id"),
                             (uint16_t)v->at("source_port_number"));
        port.srcMac = v->at("src_mac");
        if (!cmlds) port.domain = dom;

        switch (msg) {
        case 0x0: onSync(*v, ts, n, dom, port); break;
        case 0x8: onFollowUp(*v, ts, n, dom); break;
        case 0x2: onPdelayReq(*v, ts, port); break;
        case 0x3: onPdelayResp(*v, ts); break;
        case 0xA: onPdelayRespFu(*v, ts, n); break;
        case 0xB: onAnnounce(*v, ts, n, dom, port); break;
        case 0xC: port.signalingSent++; break;
        default: break;
        }
    }

    void onTimeTick(double ts) override {
        for (auto& [num, d] : mDomains) {
            if (d.syncState == "HEALTHY" &&
                ts > d.lastSync + kSyncReceiptTimeoutN * d.syncIntervalS) {
                std::string why =
                    "no Sync for " + fmtGap(ts - d.lastSync) + " (> " +
                    std::to_string(kSyncReceiptTimeoutN) + " × " +
                    fmtGap(d.syncIntervalS) + " syncReceiptTimeout)";
                size_t k = mShared ? mShared->establishedStreams.size() : 0;
                if (k)
                    why += "; " + std::to_string(k) +
                           " established stream reservation(s) depend on this"
                           " clock";
                syncTransition(d, ts, 0, "LOST", why);
            }
            if (d.gmState == "GM_PRESENT" &&
                ts > d.lastAnnounce +
                         kAnnounceReceiptTimeoutN * d.announceIntervalS) {
                domTransition(d, ts, 0, "GM_TIMED_OUT",
                              "no Announce within announceReceiptTimeout (" +
                                  std::to_string(kAnnounceReceiptTimeoutN) +
                                  " × " + fmtGap(d.announceIntervalS) + ")");
                // gmIdentity stays in SharedModel: last-known truth remains
                // the best comparison basis for ADP.
            }
        }
        // Expire pdelay exchanges the responder never completed.
        for (auto it = mExchanges.begin(); it != mExchanges.end();) {
            auto pIt = mPorts.find(it->first);
            double limit = pIt != mPorts.end()
                               ? std::max(pIt->second.reqIntervalS, 1.0)
                               : 1.0;
            if (ts > it->second.reqTs + limit) {
                if (pIt != mPorts.end()) pdelayLost(pIt->second, ts);
                it = mExchanges.erase(it);
            } else {
                ++it;
            }
        }
    }

    void snapshot(JsonWriter& w) const override {
        w.key("gptp").beginObj();

        w.key("domains").beginArr();
        for (auto& [num, d] : mDomains) {
            w.beginObj();
            w.kv("domain", (uint64_t)num);
            w.kv("state", d.gmState.empty() ? "NO_GM" : d.gmState);
            w.kv("sync", d.syncState.empty() ? "UNKNOWN" : d.syncState);
            w.key("grandmaster").beginObj();
            w.kv("clock_identity", d.gmId ? idStr(d.gmId) : "");
            w.kv("name", mShared ? mShared->nameOf(d.gmId) : "");
            w.kv("priority1", (uint64_t)d.p1);
            w.kv("priority2", (uint64_t)d.p2);
            w.kv("clock_class", (uint64_t)d.clockClass);
            w.kv("clock_accuracy", hexStr(d.clockAccuracy, 2));
            w.kv("offset_scaled_log_variance", (uint64_t)d.variance);
            w.kv("steps_removed", (uint64_t)d.stepsRemoved);
            w.kv("time_source", gptpTimeSourceName(d.timeSource));
            w.kv("current_utc_offset", (int64_t)d.utcOffset);
            w.endObj();
            w.kv("sync_interval_ms", d.syncIntervalS * 1e3);
            w.kv("announce_interval_ms", d.announceIntervalS * 1e3);
            w.kv("last_sync", d.lastSync);
            w.kv("last_announce", d.lastAnnounce);
            w.kv("last_sync_gap_ms", d.lastGapS * 1e3);
            w.kv("sync_count", (uint64_t)d.syncCount);
            w.kv("follow_up_count", (uint64_t)d.followUpCount);
            w.kv("unmatched_follow_ups", (uint64_t)d.unmatchedFollowUps);
            w.kv("announce_count", (uint64_t)d.announceCount);
            w.kv("cumulative_rate_offset_ppm", d.rateOffsetPpm);
            w.kv("gm_time_base_indicator", (uint64_t)d.gmTimeBaseIndicator);
            w.kv("path_trace", d.pathTrace);
            histJson(w, d.hist);
            w.endObj();
        }
        w.endArr();

        w.key("ports").beginArr();
        for (auto& [key, p] : mPorts) {
            w.beginObj();
            w.kv("port", portStr(p));
            w.kv("clock_identity", idStr(p.clockId));
            w.kv("port_number", (uint64_t)p.portNum);
            w.kv("src_mac", p.srcMac ? macStr(p.srcMac) : "");
            w.kv("name", mShared ? mShared->nameOf(p.clockId) : "");
            w.kv("domain", (uint64_t)p.domain);
            w.kv("role", p.role.empty() ? "UNKNOWN" : p.role);
            w.kv("as_capable", p.asCapable.empty() ? "UNKNOWN" : p.asCapable);
            w.kv("sync_sent", (uint64_t)p.syncSent);
            w.kv("announce_sent", (uint64_t)p.announceSent);
            w.kv("signaling_sent", (uint64_t)p.signalingSent);
            w.key("pdelay").beginObj();
            w.kv("initiated", (uint64_t)p.pdelayInitiated);
            w.kv("complete", (uint64_t)p.pdelayComplete);
            w.kv("lost", (uint64_t)p.pdelayLost);
            w.kv("consecutive_lost", (uint64_t)p.consecutiveLost);
            w.kv("req_interval_ms", p.reqIntervalS * 1e3);
            w.kv("last_turnaround_us", p.lastTurnaroundUs);
            w.kv("last_observed_gap_ms", p.lastObservedGapMs);
            w.endObj();
            histJson(w, p.hist);
            w.endObj();
        }
        w.endArr();

        w.endObj();
    }

private:
    struct Domain {
        uint8_t num = 0;
        std::string gmState;   // "" -> NO_GM / GM_PRESENT / GM_TIMED_OUT
        std::string syncState; // "" -> UNKNOWN / HEALTHY / LOST
        uint64_t gmId = 0;
        uint8_t p1 = 0, p2 = 0, clockClass = 0, clockAccuracy = 0,
                timeSource = 0;
        uint16_t variance = 0, stepsRemoved = 0, gmTimeBaseIndicator = 0;
        int16_t utcOffset = 0;
        double lastAnnounce = -1, announceIntervalS = kDefaultAnnounceIntervalS;
        double lastSync = -1, syncIntervalS = kDefaultSyncIntervalS;
        double lastGapS = 0, rateOffsetPpm = 0;
        uint64_t syncSender = 0; // port key of the current Sync sender
        uint32_t syncCount = 0, followUpCount = 0, announceCount = 0,
                 unmatchedFollowUps = 0;
        bool haveTimeBase = false;
        std::string pathTrace;
        std::map<uint16_t, double> pendingSyncs; // seq -> ts (two-step)
        std::vector<HistEntry> hist;
    };
    struct Port {
        uint64_t clockId = 0;
        uint16_t portNum = 0;
        uint64_t srcMac = 0;
        uint8_t domain = 0;
        std::string role;      // "" -> UNKNOWN / MASTER / SLAVE
        std::string asCapable; // "" -> UNKNOWN / AS_CAPABLE / NOT_AS_CAPABLE
        uint32_t syncSent = 0, announceSent = 0, signalingSent = 0;
        uint32_t pdelayInitiated = 0, pdelayComplete = 0, pdelayLost = 0,
                 consecutiveLost = 0;
        double reqIntervalS = kDefaultPdelayIntervalS;
        double lastSyncSentTs = -1;
        double lastTurnaroundUs = -1, lastObservedGapMs = -1;
        std::vector<HistEntry> hist;
    };
    struct Exchange { // one outstanding pdelay exchange per requester port
        uint16_t seq = 0;
        double reqTs = 0, respTs = -1;
        uint64_t responderKey = 0;
        uint64_t reqReceiptNs = 0; // responder wire clock
        bool haveResp = false;
    };

    static uint64_t portKey(uint64_t clockId, uint16_t portNum) {
        return (clockId << 16) | portNum;
    }
    static std::string portStr(const Port& p) {
        return idStr(p.clockId) + ":" + std::to_string(p.portNum);
    }

    Port& getPort(uint64_t clockId, uint16_t portNum) {
        auto& p = mPorts[portKey(clockId, portNum)];
        p.clockId = clockId;
        p.portNum = portNum;
        return p;
    }
    Domain& getDomain(uint8_t num) {
        auto& d = mDomains[num];
        d.num = num;
        return d;
    }

    static void setGmAttrs(Domain& d, VarLayerContext& v) {
        d.gmId = v.at("gm_identity");
        d.p1 = (uint8_t)v.at("gm_priority1");
        d.p2 = (uint8_t)v.at("gm_priority2");
        d.clockClass = (uint8_t)v.at("gm_clock_class");
        d.clockAccuracy = (uint8_t)v.at("gm_clock_accuracy");
        d.variance = (uint16_t)v.at("gm_clock_variance");
        d.stepsRemoved = (uint16_t)v.at("steps_removed");
        d.timeSource = (uint8_t)v.at("time_source");
        d.utcOffset = (int16_t)(uint16_t)v.at("current_utc_offset");
    }

    void publish(const Domain& d) {
        if (!mShared) return;
        auto& t = mShared->gptpDomains[d.num];
        if (d.gmId) {
            t.gmKnown = true;
            t.gmIdentity = d.gmId;
        }
        if (d.syncState == "HEALTHY") t.syncState = 1;
        else if (d.syncState == "LOST") t.syncState = 2;
    }

    // ---- transition plumbing ----------------------------------------------

    void emitDom(Domain& d, double ts, uint32_t n, const std::string& from,
                 const std::string& to, const std::string& why) {
        d.hist.push_back({ts, n, from, to, why});
        if (d.hist.size() > kMaxHist) d.hist.erase(d.hist.begin());
        Transition t;
        t.proto = Proto::GPTP;
        t.object = "gptp domain " + std::to_string(d.num);
        t.from = from;
        t.to = to;
        t.why = why;
        t.entity = d.gmId ? idStr(d.gmId) : "";
        t.summary = "gPTP domain " + std::to_string(d.num) + ": " + from +
                    " -> " + to + " — " + why;
        emit(std::move(t));
    }

    void domTransition(Domain& d, double ts, uint32_t n, const std::string& to,
                       const std::string& why) {
        std::string from = d.gmState.empty() ? "NO_GM" : d.gmState;
        if (from == to) return;
        d.gmState = to;
        emitDom(d, ts, n, from, to, why);
        publish(d);
    }

    void syncTransition(Domain& d, double ts, uint32_t n, const std::string& to,
                        const std::string& why) {
        std::string from =
            d.syncState.empty() ? "SYNC_UNKNOWN" : "SYNC_" + d.syncState;
        if (from == "SYNC_" + to) return;
        d.syncState = to;
        emitDom(d, ts, n, from, "SYNC_" + to, why);
        publish(d);
    }

    void portTransition(Port& p, std::string Port::*field, double ts,
                        uint32_t n, const std::string& emptyLabel,
                        const std::string& to, const std::string& why) {
        std::string from = (p.*field).empty() ? emptyLabel : (p.*field);
        if (from == to) return;
        p.*field = to;
        p.hist.push_back({ts, n, from, to, why});
        if (p.hist.size() > kMaxHist) p.hist.erase(p.hist.begin());
        Transition t;
        t.proto = Proto::GPTP;
        t.object = "gptp port " + portStr(p);
        t.from = from;
        t.to = to;
        t.why = why;
        t.entity = idStr(p.clockId);
        std::string nm = mShared ? mShared->nameOf(p.clockId) : "";
        t.summary = "gPTP port " + portStr(p) +
                    (nm.empty() ? "" : " (" + nm + ")") + ": " + from + " -> " +
                    to + " — " + why;
        emit(std::move(t));
    }

    void portWarning(Port& p, double ts, uint32_t n, const std::string& why) {
        std::string state = p.role.empty() ? "UNKNOWN" : p.role;
        p.hist.push_back({ts, n, state, state, why});
        if (p.hist.size() > kMaxHist) p.hist.erase(p.hist.begin());
        Transition t;
        t.proto = Proto::GPTP;
        t.object = "gptp port " + portStr(p);
        t.from = state;
        t.to = state;
        t.why = why;
        t.entity = idStr(p.clockId);
        t.summary = "gPTP port " + portStr(p) + ": " + why;
        emit(std::move(t));
    }

    // ---- message handlers ---------------------------------------------------

    void becomeMaster(Port& p, uint8_t dom, double ts, uint32_t n,
                      const std::string& why) {
        portTransition(p, &Port::role, ts, n, "UNKNOWN", "MASTER", why);
        // Pdelay-only ports on the same domain sit on the receiving side.
        uint64_t self = portKey(p.clockId, p.portNum);
        for (auto& [key, other] : mPorts) {
            if (key == self || other.domain != dom) continue;
            if (other.syncSent == 0 && other.announceSent == 0 &&
                other.role.empty()) {
                portTransition(other, &Port::role, ts, n, "UNKNOWN", "SLAVE",
                               "initiates pdelay but sends no Sync/Announce; " +
                                   portStr(p) +
                                   " is the observed master (single tap point"
                                   " — inferred)");
            }
        }
    }

    void onSync(VarLayerContext& v, double ts, uint32_t n, uint8_t dom,
                Port& port) {
        auto& d = getDomain(dom);
        double prevSync = d.lastSync;
        d.lastSync = ts;
        if (prevSync >= 0) d.lastGapS = ts - prevSync;
        d.syncIntervalS =
            intervalFromLog(v.at("log_message_interval"), kDefaultSyncIntervalS);
        d.syncCount++;
        port.syncSent++;
        port.lastSyncSentTs = ts;

        uint64_t senderKey = portKey(port.clockId, port.portNum);
        if (d.syncSender != senderKey) {
            d.syncSender = senderKey;
            d.pendingSyncs.clear();
        }
        becomeMaster(port, dom, ts, n,
                     "sent Sync seq " + std::to_string(v.at("sequence_id")) +
                         " on domain " + std::to_string(dom));

        // Demote masters that went silent after a takeover: checked on every
        // Sync so the transition fires once the silence exceeds the timeout.
        for (auto& [key, other] : mPorts) {
            if (key == senderKey || other.domain != dom) continue;
            if (other.role == "MASTER" && other.lastSyncSentTs >= 0 &&
                ts > other.lastSyncSentTs +
                         kSyncReceiptTimeoutN * d.syncIntervalS) {
                portTransition(other, &Port::role, ts, n, "MASTER", "SLAVE",
                               portStr(port) + " took over as Sync sender; no "
                               "Sync from this port for " +
                                   fmtGap(ts - other.lastSyncSentTs));
            }
        }

        if (d.syncState.empty()) {
            syncTransition(d, ts, n, "HEALTHY",
                           "first Sync observed (seq " +
                               std::to_string(v.at("sequence_id")) + ", " +
                               fmtGap(d.syncIntervalS) + " interval)");
        } else if (d.syncState == "LOST") {
            syncTransition(d, ts, n, "HEALTHY",
                           "Sync resumed after " + fmtGap(d.lastGapS) + " gap");
        }

        if (v.at("two_step")) {
            d.pendingSyncs[(uint16_t)v.at("sequence_id")] = ts;
            if (d.pendingSyncs.size() > 64)
                d.pendingSyncs.erase(d.pendingSyncs.begin());
        }
        publish(d);
    }

    void onFollowUp(VarLayerContext& v, double ts, uint32_t n, uint8_t dom) {
        auto& d = getDomain(dom);
        auto it = d.pendingSyncs.find((uint16_t)v.at("sequence_id"));
        if (it != d.pendingSyncs.end()) {
            d.followUpCount++;
            d.pendingSyncs.erase(it);
        } else {
            d.unmatchedFollowUps++; // tap may have started mid-pair — no event
        }
        if (v.at("has_as_tlv")) {
            uint32_t csro = (uint32_t)v.at("cumulative_scaled_rate_offset");
            d.rateOffsetPpm = (double)(int32_t)csro / 2199023255552.0 * 1e6;
            uint16_t tbi = (uint16_t)v.at("gm_time_base_indicator");
            if (d.haveTimeBase && tbi != d.gmTimeBaseIndicator) {
                emitDom(d, ts, n,
                        "TIMEBASE " + std::to_string(d.gmTimeBaseIndicator),
                        "TIMEBASE " + std::to_string(tbi),
                        "gmTimeBaseIndicator changed (GM time base step)");
            }
            d.gmTimeBaseIndicator = tbi;
            d.haveTimeBase = true;
        }
    }

    void onAnnounce(VarLayerContext& v, double ts, uint32_t n, uint8_t dom,
                    Port& port) {
        auto& d = getDomain(dom);
        double sinceLast = d.lastAnnounce >= 0 ? ts - d.lastAnnounce : 0;
        d.lastAnnounce = ts;
        d.announceIntervalS = intervalFromLog(v.at("log_message_interval"),
                                              kDefaultAnnounceIntervalS);
        d.announceCount++;
        port.announceSent++;
        becomeMaster(port, dom, ts, n,
                     "sent Announce on domain " + std::to_string(dom));

        uint64_t gm = v.at("gm_identity");
        uint8_t p1 = (uint8_t)v.at("gm_priority1");

        if (d.gmState.empty()) {
            setGmAttrs(d, v);
            domTransition(d, ts, n, "GM_PRESENT",
                          "Announce: grandmaster " + idStr(gm) +
                              " (priority1 " + std::to_string(p1) + ", class " +
                              std::to_string(v.at("gm_clock_class")) +
                              ", steps " +
                              std::to_string(v.at("steps_removed")) + ")");
        } else if (d.gmState == "GM_TIMED_OUT") {
            setGmAttrs(d, v);
            domTransition(d, ts, n, "GM_PRESENT",
                          "Announce resumed after " + fmtGap(sinceLast));
        } else if (d.gmId != gm) {
            std::string why = "Announce carries a different"
                              " grandmasterIdentity (BMCA reselection";
            if (p1 != d.p1)
                why += ": priority1 " + std::to_string(p1) +
                       (p1 < d.p1 ? " < " : " > ") + std::to_string(d.p1);
            why += ")";
            std::string from = "GM " + idStr(d.gmId);
            std::string to = "GM " + idStr(gm);
            std::string nm = mShared ? mShared->nameOf(gm) : "";
            setGmAttrs(d, v);
            emitDom(d, ts, n, from, to,
                    why + (nm.empty() ? "" : " — new GM is \"" + nm + "\""));
        } else {
            setGmAttrs(d, v); // refresh attributes
        }

        std::string trace;
        if (v.getBytes("path_trace", trace)) d.pathTrace = trace;
        publish(d);
    }

    void onPdelayReq(VarLayerContext& v, double ts, Port& port) {
        port.pdelayInitiated++;
        port.reqIntervalS = intervalFromLog(v.at("log_message_interval"),
                                            kDefaultPdelayIntervalS);
        uint64_t key = portKey(port.clockId, port.portNum);
        auto it = mExchanges.find(key);
        if (it != mExchanges.end()) {
            // Previous exchange never completed.
            pdelayLost(port, ts);
            mExchanges.erase(it);
        }
        Exchange e;
        e.seq = (uint16_t)v.at("sequence_id");
        e.reqTs = ts;
        mExchanges[key] = e;
    }

    void onPdelayResp(VarLayerContext& v, double ts) {
        uint64_t reqKey = portKey(v.at("requesting_clock_id"),
                                  (uint16_t)v.at("requesting_port_number"));
        auto it = mExchanges.find(reqKey);
        if (it == mExchanges.end() ||
            it->second.seq != (uint16_t)v.at("sequence_id"))
            return;
        it->second.respTs = ts;
        it->second.haveResp = true;
        it->second.responderKey = portKey(
            v.at("source_clock_id"), (uint16_t)v.at("source_port_number"));
        it->second.reqReceiptNs = v.at("req_receipt_seconds") * 1000000000ull +
                                  v.at("req_receipt_ns");
    }

    void onPdelayRespFu(VarLayerContext& v, double ts, uint32_t n) {
        uint64_t reqKey = portKey(v.at("requesting_clock_id"),
                                  (uint16_t)v.at("requesting_port_number"));
        auto it = mExchanges.find(reqKey);
        if (it == mExchanges.end() || !it->second.haveResp ||
            it->second.seq != (uint16_t)v.at("sequence_id"))
            return;

        auto pIt = mPorts.find(reqKey);
        if (pIt == mPorts.end()) {
            mExchanges.erase(it);
            return;
        }
        Port& req = pIt->second;
        req.pdelayComplete++;
        req.consecutiveLost = 0;

        // Exact: both timestamps are from the responder's wire clock.
        uint64_t respOriginNs = v.at("resp_origin_seconds") * 1000000000ull +
                                v.at("resp_origin_ns");
        double turnaroundS =
            (double)(int64_t)(respOriginNs - it->second.reqReceiptNs) / 1e9;
        req.lastTurnaroundUs = turnaroundS * 1e6;
        // Approximate: capture-clock request->response gap.
        if (it->second.respTs >= 0)
            req.lastObservedGapMs = (it->second.respTs - it->second.reqTs) * 1e3;

        portTransition(req, &Port::asCapable, ts, n, "UNKNOWN", "AS_CAPABLE",
                       "pdelay exchange seq " +
                           std::to_string(v.at("sequence_id")) +
                           " complete (req -> resp -> resp_follow_up)");

        if (turnaroundS > kPdelayTurnaroundLimitS) {
            auto rIt = mPorts.find(it->second.responderKey);
            if (rIt != mPorts.end()) {
                char buf[80];
                std::snprintf(buf, sizeof buf,
                              "pdelay turnaround %.1f ms exceeds the 10 ms"
                              " limit (Avnu gPTP)",
                              turnaroundS * 1e3);
                portWarning(rIt->second, ts, n, buf);
            }
        }
        mExchanges.erase(it);
    }

    void pdelayLost(Port& p, double ts) {
        p.pdelayLost++;
        p.consecutiveLost++;
        if (p.consecutiveLost >= (uint32_t)kAllowedLostResponses)
            portTransition(p, &Port::asCapable, ts, 0, "UNKNOWN",
                           "NOT_AS_CAPABLE",
                           std::to_string(kAllowedLostResponses) +
                               " consecutive Pdelay_Req without"
                               " Resp/Resp_Follow_Up (allowedLostResponses)");
    }

    std::map<uint8_t, Domain> mDomains;
    std::map<uint64_t, Port> mPorts;
    std::map<uint64_t, Exchange> mExchanges; // requester port key -> exchange
};

REGISTER_LOGIC("8021as_gptp", GptpLogic)

} // namespace
} // namespace avb
