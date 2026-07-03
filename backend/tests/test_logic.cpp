/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * State-machine tests (PA-2/PA-4): drive the TSN-GEN logic modules
 * directly through VarLayerContext vars, no wire format involved.
 */
#include "logic/avb_logic.h"
#include "test.h"

using namespace avb;

namespace {

struct Rig {
    SharedModel shared;
    std::unique_ptr<ILogicModule> mod;
    AvbLogicBase* base = nullptr;

    explicit Rig(const char* service) {
        mod = LogicRegistry::instance().create(service);
        base = dynamic_cast<AvbLogicBase*>(mod.get());
        if (base) base->attach(&shared);
    }

    std::vector<Transition> feed(const std::string& service, double ts,
                                 const std::vector<std::pair<std::string, uint64_t>>& vars,
                                 std::initializer_list<std::pair<const char*, const char*>> bytes = {}) {
        VarLayerContext ctx(service);
        ctx.setValue("ts_ns", (uint64_t)(ts * 1e9));
        ctx.setValue("pkt_num", 1);
        for (auto& [k, v] : vars) ctx.setValue(k, v);
        for (auto& [k, v] : bytes) ctx.setBytes(k, v);
        base->onDecode(ctx);
        return base->drain();
    }

    std::vector<Transition> tick(double ts) {
        base->onTimeTick(ts);
        return base->drain();
    }

    std::string snap() {
        JsonWriter w;
        w.beginObj();
        base->snapshot(w);
        w.endObj();
        return w.take();
    }
};

} // namespace

TEST(registry_has_all_modules) {
    for (const char* svc : {"atdecc_adp", "atdecc_aecp", "atdecc_acmp",
                            "1722_maap", "mrp_msrp", "mrp_mvrp",
                            "8021as_gptp"})
        CHECK(LogicRegistry::instance().has(svc));
}

TEST(adp_lifecycle_and_timeout) {
    Rig r("atdecc_adp");
    auto t1 = r.feed("atdecc_adp", 0.1,
                     {{"message_type", 0}, {"entity_id", 42},
                      {"available_index", 5}, {"valid_time", 4},
                      {"entity_model_id", 1}, {"gptp_grandmaster_id", 2},
                      {"talker_stream_sources", 2}, {"listener_stream_sinks", 0}});
    CHECK_EQ(t1.size(), (size_t)1);
    CHECK_EQ(t1[0].from, std::string("UNKNOWN"));
    CHECK_EQ(t1[0].to, std::string("AVAILABLE"));

    // Re-announce: no transition.
    auto t2 = r.feed("atdecc_adp", 1.0,
                     {{"message_type", 0}, {"entity_id", 42},
                      {"available_index", 6}, {"valid_time", 4}});
    CHECK(t2.empty());

    // available_index going backwards flags a restart.
    auto t3 = r.feed("atdecc_adp", 2.0,
                     {{"message_type", 0}, {"entity_id", 42},
                      {"available_index", 1}, {"valid_time", 4}});
    CHECK_EQ(t3.size(), (size_t)1);
    CHECK(t3[0].why.find("restarted") != std::string::npos);

    // valid_time (4 s) expires without re-announce.
    auto t4 = r.tick(7.5);
    CHECK_EQ(t4.size(), (size_t)1);
    CHECK_EQ(t4[0].to, std::string("TIMED_OUT"));

    CHECK(r.snap().find("\"state\":\"TIMED_OUT\"") != std::string::npos);
}

TEST(adp_departing) {
    Rig r("atdecc_adp");
    r.feed("atdecc_adp", 0.1,
           {{"message_type", 0}, {"entity_id", 7}, {"available_index", 1},
            {"valid_time", 62}});
    auto t = r.feed("atdecc_adp", 1.0, {{"message_type", 1}, {"entity_id", 7}});
    CHECK_EQ(t.size(), (size_t)1);
    CHECK_EQ(t[0].to, std::string("DEPARTING"));
}

TEST(acmp_connect_disconnect) {
    Rig r("atdecc_acmp");
    auto common = [&](uint64_t msg, uint64_t status, double ts, uint64_t seq) {
        return r.feed("atdecc_acmp", ts,
                      {{"message_type", msg}, {"status", status},
                       {"talker_entity_id", 100}, {"talker_unique_id", 0},
                       {"listener_entity_id", 200}, {"listener_unique_id", 0},
                       {"controller_entity_id", 99}, {"sequence_id", seq},
                       {"stream_id", 0xabcd}, {"stream_dest_mac", 0x91e0f0000e80},
                       {"stream_vlan_id", 2}, {"connection_count", 1}});
    };
    auto has = [](const std::vector<Transition>& v, const char* to) {
        for (auto& t : v)
            if (t.to == to) return true;
        return false;
    };
    // Each wire message now drives two machines: the generic 1722.1
    // connection view and the Milan v1.2 sink state machine.
    auto t1 = common(6, 0, 0.0, 1); // BIND_RX / CONNECT_RX_COMMAND
    CHECK(has(t1, "CONNECTING"));
    CHECK(has(t1, "PRB_W_AVAIL")); // talker not ADP-available in this rig
    auto t2 = common(7, 0, 0.1, 1); // CONNECT_RX_RESPONSE SUCCESS
    CHECK(has(t2, "CONNECTED"));
    auto t3 = common(8, 0, 5.0, 2); // UNBIND_RX / DISCONNECT_RX_COMMAND
    CHECK(has(t3, "DISCONNECTING"));
    CHECK(has(t3, "UNBOUND"));
    auto t4 = common(9, 0, 5.1, 2);
    CHECK(has(t4, "DISCONNECTED"));
}

TEST(acmp_milan_sink_state_machine) {
    Rig r("atdecc_acmp");
    auto feed = [&](uint64_t msg, uint64_t status, double ts,
                    uint64_t stream = 0) {
        return r.feed("atdecc_acmp", ts,
                      {{"message_type", msg}, {"status", status},
                       {"talker_entity_id", 100}, {"talker_unique_id", 0},
                       {"listener_entity_id", 200}, {"listener_unique_id", 0},
                       {"controller_entity_id", 99}, {"sequence_id", 1},
                       {"stream_id", stream},
                       {"stream_dest_mac", 0x91e0f0000e80},
                       {"stream_vlan_id", 2}, {"connection_count", 0}});
    };
    auto has = [](const std::vector<Transition>& v, const char* to) {
        for (auto& t : v)
            if (t.to == to) return true;
        return false;
    };

    // Talker already ADP-available -> BIND goes straight to PRB_W_DELAY.
    r.shared.adpAvailable.insert(100);
    auto t1 = feed(6, 0, 0.0); // BIND_RX_COMMAND
    CHECK(has(t1, "PRB_W_DELAY"));

    auto t2 = feed(0, 0, 0.3); // PROBE_TX_COMMAND (TMR_DELAY expired)
    CHECK(has(t2, "PRB_W_RESP"));

    // No response; second probe after ~200 ms -> PRB_W_RESP2.
    auto t3 = feed(0, 0, 0.51);
    CHECK(has(t3, "PRB_W_RESP2"));

    // Still no response -> PRB_W_RETRY (via time tick).
    auto t4 = r.tick(0.8);
    CHECK(has(t4, "PRB_W_RETRY"));

    // Retry after TMR_RETRY, then a SUCCESS probe response -> settled.
    auto t5 = feed(0, 0, 4.9);
    CHECK(has(t5, "PRB_W_RESP"));
    auto t6 = feed(1, 0, 4.95, 0xbeef); // PROBE_TX_RESPONSE SUCCESS
    CHECK(has(t6, "SETTLED_NO_RSV"));

    // MSRP talker attribute appears -> SETTLED_RSV_OK.
    r.shared.msrpTalkerDecl[0xbeef] = 1;
    auto t7 = r.tick(5.2);
    CHECK(has(t7, "SETTLED_RSV_OK"));

    // Talker departs (ADP) -> back to passive probing from any state.
    r.shared.adpAvailable.erase(100);
    auto t8 = r.tick(6.0);
    CHECK(has(t8, "PRB_W_AVAIL"));

    // Talker returns -> PRB_W_DELAY (EVT_TK_DISCOVERED).
    r.shared.adpAvailable.insert(100);
    auto t9 = r.tick(6.5);
    CHECK(has(t9, "PRB_W_DELAY"));

    // Controller unbinds -> UNBOUND.
    auto t10 = feed(8, 0, 7.0); // UNBIND_RX_COMMAND
    CHECK(has(t10, "UNBOUND"));

    std::string st = r.snap();
    CHECK(st.find("\"probing_status\":\"PROBING_DISABLED\"") != std::string::npos);
    CHECK(st.find("\"probes_sent\":3") != std::string::npos);
    CHECK(st.find("\"milan_talkers\"") != std::string::npos);
    CHECK(st.find("\"probes_received\":3") != std::string::npos);
}

TEST(acmp_milan_saved_binding_and_talker_warnings) {
    Rig r("atdecc_acmp");
    auto feed = [&](uint64_t msg, uint64_t status, double ts) {
        return r.feed("atdecc_acmp", ts,
                      {{"message_type", msg}, {"status", status},
                       {"talker_entity_id", 100}, {"talker_unique_id", 0},
                       {"listener_entity_id", 200}, {"listener_unique_id", 0},
                       {"controller_entity_id", 99}, {"sequence_id", 1},
                       {"stream_id", 0}, {"stream_dest_mac", 0},
                       {"stream_vlan_id", 0}, {"connection_count", 0}});
    };
    // Probe without an observed BIND: Milan saved-binding startup.
    auto t1 = feed(0, 0, 0.0);
    bool saved = false;
    for (auto& t : t1)
        if (t.to == "PRB_W_RESP" &&
            t.why.find("saved binding") != std::string::npos)
            saved = true;
    CHECK(saved);

    // GET_TX_CONNECTION is not implemented in Milan -> warning.
    auto t2 = feed(12, 0, 1.0);
    CHECK(!t2.empty());
    CHECK(t2.back().why.find("not") != std::string::npos);
    CHECK(t2.back().object.find("milan talker") != std::string::npos);
}

TEST(acmp_failure_and_timeout) {
    Rig r("atdecc_acmp");
    auto feed = [&](uint64_t msg, uint64_t status, double ts, uint64_t tuid) {
        return r.feed("atdecc_acmp", ts,
                      {{"message_type", msg}, {"status", status},
                       {"talker_entity_id", 100}, {"talker_unique_id", tuid},
                       {"listener_entity_id", 200}, {"listener_unique_id", tuid},
                       {"controller_entity_id", 99}, {"sequence_id", tuid}});
    };
    feed(6, 0, 0.0, 1);
    auto t = feed(7, 5, 0.1, 1); // TALKER_NO_BANDWIDTH
    CHECK_EQ(t.back().to, std::string("FAILED"));
    CHECK(t.back().why.find("TALKER_NO_BANDWIDTH") != std::string::npos);

    feed(6, 0, 1.0, 2);          // command, never answered
    auto t2 = r.tick(6.0);       // > 4.5 s CONNECT_RX timeout
    CHECK_EQ(t2.size(), (size_t)1);
    CHECK_EQ(t2[0].to, std::string("FAILED"));
    CHECK(t2[0].why.find("timed out") != std::string::npos);
}

TEST(aecp_correlation_naming_timeout) {
    Rig r("atdecc_aecp");
    auto cmd = [&](uint64_t seq, double ts, uint64_t c) {
        return r.feed("atdecc_aecp", ts,
                      {{"message_type", 0}, {"status", 0},
                       {"target_entity_id", 42}, {"controller_entity_id", 99},
                       {"sequence_id", seq}, {"command_type", c},
                       {"unsolicited", 0}});
    };
    cmd(1, 0.0, 0x0004);
    // READ_DESCRIPTOR ENTITY response carrying the name.
    auto t = r.feed("atdecc_aecp", 0.05,
                    {{"message_type", 1}, {"status", 0},
                     {"target_entity_id", 42}, {"controller_entity_id", 99},
                     {"sequence_id", 1}, {"command_type", 0x0004},
                     {"unsolicited", 0}, {"descriptor_type", 0},
                     {"entity_id", 42}},
                    {{"entity_name", "Stage Box FOH"}});
    CHECK_EQ(t.size(), (size_t)1);
    CHECK_EQ(t[0].to, std::string("Stage Box FOH"));
    CHECK_EQ(r.shared.nameOf(42), std::string("Stage Box FOH"));

    cmd(2, 1.0, 0x0002);
    auto t2 = r.tick(1.5); // > 250 ms
    CHECK_EQ(t2.size(), (size_t)1);
    CHECK_EQ(t2[0].to, std::string("TIMED_OUT"));
    CHECK(r.snap().find("\"timeouts\":1") != std::string::npos);
    CHECK(r.snap().find("\"rtt_ms\":") != std::string::npos);
}

TEST(msrp_reservation_flow) {
    Rig r("mrp_msrp");
    auto t1 = r.feed("mrp_msrp", 0.0,
                     {{"attribute_type", 1}, {"mrp_event", 1},
                      {"stream_id", 0xbeef}, {"src_mac", 0x1},
                      {"dest_mac", 0x91e0f0000e80}, {"vlan_id", 2},
                      {"max_frame_size", 224}, {"max_interval_frames", 1},
                      {"priority", 3}, {"rank", 1},
                      {"accumulated_latency", 125000}});
    CHECK_EQ(t1.size(), (size_t)1);
    CHECK_EQ(t1[0].from, std::string("NEW"));
    CHECK_EQ(t1[0].to, std::string("PENDING"));

    auto t2 = r.feed("mrp_msrp", 0.1,
                     {{"attribute_type", 3}, {"mrp_event", 1},
                      {"four_packed_event", 2}, {"stream_id", 0xbeef},
                      {"src_mac", 0x2}});
    CHECK_EQ(t2.size(), (size_t)1);
    CHECK_EQ(t2[0].to, std::string("ESTABLISHED"));

    auto t3 = r.feed("mrp_msrp", 1.0,
                     {{"attribute_type", 1}, {"mrp_event", 5}, // Lv
                      {"stream_id", 0xbeef}, {"src_mac", 0x1},
                      {"dest_mac", 0x91e0f0000e80}, {"vlan_id", 2}});
    CHECK_EQ(t3.size(), (size_t)1);
    CHECK_EQ(t3[0].to, std::string("WITHDRAWN"));

    CHECK(r.snap().find("\"listeners\":[{\"mac\":\"00:00:00:00:00:02\",\"state\":\"READY\"}") !=
          std::string::npos);
}

TEST(msrp_talker_failed) {
    Rig r("mrp_msrp");
    auto t = r.feed("mrp_msrp", 0.0,
                    {{"attribute_type", 2}, {"mrp_event", 1},
                     {"stream_id", 0xbeef}, {"src_mac", 0x10},
                     {"dest_mac", 0x91e0f0000e80}, {"vlan_id", 2},
                     {"failure_bridge_id", 0x77}, {"failure_code", 1}});
    CHECK_EQ(t.size(), (size_t)1);
    CHECK_EQ(t[0].to, std::string("TALKER_FAILED"));
    CHECK(t[0].why.find("INSUFFICIENT_BANDWIDTH") != std::string::npos);
}

TEST(mvrp_join_leaveall_withdraw) {
    Rig r("mrp_mvrp");
    auto t1 = r.feed("mrp_mvrp", 0.0,
                     {{"mrp_event", 1}, {"vid", 2}, {"src_mac", 0x1},
                      {"attribute_type", 1}});
    CHECK_EQ(t1.size(), (size_t)1);
    CHECK_EQ(t1[0].to, std::string("REGISTERED"));

    auto t2 = r.feed("mrp_mvrp", 1.0,
                     {{"mrp_event", 6}, {"src_mac", 0x3}, {"attribute_type", 1}});
    CHECK_EQ(t2.size(), (size_t)1);
    CHECK_EQ(t2[0].to, std::string("LEAVING"));

    auto t3 = r.feed("mrp_mvrp", 1.1,
                     {{"mrp_event", 1}, {"vid", 2}, {"src_mac", 0x1},
                      {"attribute_type", 1}});
    CHECK_EQ(t3[0].to, std::string("REGISTERED"));

    auto t4 = r.feed("mrp_mvrp", 2.0,
                     {{"mrp_event", 5}, {"vid", 2}, {"src_mac", 0x1},
                      {"attribute_type", 1}});
    CHECK_EQ(t4[0].to, std::string("WITHDRAWN"));
}

namespace {

/** Feed helpers for gPTP vars. */
std::vector<std::pair<std::string, uint64_t>> gptpCommon(
    uint64_t msg, uint64_t clock, uint64_t seq, uint64_t dom = 0,
    uint64_t logIval = 0xFD /* -3 = 125 ms */) {
    return {{"message_type", msg},     {"source_clock_id", clock},
            {"source_port_number", 1}, {"sequence_id", seq},
            {"domain_number", dom},    {"log_message_interval", logIval},
            {"transport_specific", 1}, {"src_mac", clock & 0xffffffffffff}};
}

} // namespace

TEST(gptp_gm_lifecycle) {
    Rig r("8021as_gptp");
    auto announce = [&](uint64_t gm, uint64_t p1, double ts) {
        auto vars = gptpCommon(0xB, gm, 1, 0, 0 /* 1 s */);
        vars.insert(vars.end(),
                    {{"gm_identity", gm}, {"gm_priority1", p1},
                     {"gm_priority2", 248}, {"gm_clock_class", 248},
                     {"gm_clock_accuracy", 0x21}, {"gm_clock_variance", 100},
                     {"steps_removed", 0}, {"time_source", 0xA0},
                     {"current_utc_offset", 0}});
        return r.feed("8021as_gptp", ts, vars);
    };

    auto t1 = announce(0xAAAA, 248, 0.0);
    CHECK_EQ(t1.size(), (size_t)2); // port -> MASTER, domain NO_GM -> GM_PRESENT
    bool sawGm = false;
    for (auto& t : t1)
        if (t.to == "GM_PRESENT" && t.from == "NO_GM") sawGm = true;
    CHECK(sawGm);
    CHECK(r.shared.gptpDomains[0].gmKnown);
    CHECK_EQ(r.shared.gptpDomains[0].gmIdentity, (uint64_t)0xAAAA);

    // Better clock takes over -> GM change transition.
    auto t2 = announce(0xBBBB, 200, 1.0);
    bool sawChange = false;
    for (auto& t : t2)
        if (t.from == "GM 0x000000000000aaaa" && t.to == "GM 0x000000000000bbbb")
            sawChange = true;
    CHECK(sawChange);
    CHECK(!t2.empty() && t2.back().why.find("BMCA") != std::string::npos);
    CHECK_EQ(r.shared.gptpDomains[0].gmIdentity, (uint64_t)0xBBBB);

    // Announce silence -> GM_TIMED_OUT (plus per-port announce AGED, 10.2.12).
    auto t3 = r.tick(5.0);
    bool timedOut = false, aged = false;
    for (auto& t : t3) {
        if (t.to == "GM_TIMED_OUT") timedOut = true;
        if (t.to == "AGED") aged = true;
    }
    CHECK(timedOut);
    CHECK(aged);
    CHECK(r.snap().find("\"state\":\"GM_TIMED_OUT\"") != std::string::npos);
    // Last-known GM stays published for the ADP comparison.
    CHECK(r.shared.gptpDomains[0].gmKnown);
}

TEST(gptp_sync_health) {
    Rig r("8021as_gptp");
    auto sync = [&](uint64_t seq, double ts) {
        auto vars = gptpCommon(0x0, 0x11, seq);
        vars.push_back({"two_step", 1});
        return r.feed("8021as_gptp", ts, vars);
    };
    auto t1 = sync(1, 0.0);
    bool healthy = false;
    for (auto& t : t1)
        if (t.to == "SYNC_HEALTHY") healthy = true;
    CHECK(healthy);
    sync(2, 0.125);
    sync(3, 0.250);

    // > 3 × 125 ms without Sync -> LOST (derived event, n = 0).
    auto t2 = r.tick(0.7);
    CHECK_EQ(t2.size(), (size_t)1);
    CHECK_EQ(t2[0].to, std::string("SYNC_LOST"));
    CHECK(t2[0].why.find("3 × 125 ms syncReceiptTimeout") != std::string::npos);
    CHECK_EQ(r.shared.gptpDomains[0].syncState, 2);

    auto t3 = sync(4, 1.0);
    bool resumed = false;
    for (auto& t : t3)
        if (t.to == "SYNC_HEALTHY" && t.why.find("resumed") != std::string::npos)
            resumed = true;
    CHECK(resumed);
    CHECK_EQ(r.shared.gptpDomains[0].syncState, 1);
}

TEST(gptp_two_step_pairing) {
    Rig r("8021as_gptp");
    auto vars = gptpCommon(0x0, 0x11, 10);
    vars.push_back({"two_step", 1});
    r.feed("8021as_gptp", 0.0, vars);
    auto fu = gptpCommon(0x8, 0x11, 10);
    r.feed("8021as_gptp", 0.01, fu);
    CHECK(r.snap().find("\"follow_up_count\":1") != std::string::npos);

    auto orphan = gptpCommon(0x8, 0x11, 99);
    auto t = r.feed("8021as_gptp", 0.02, orphan);
    CHECK(t.empty()); // no transition for an unmatched FU
    CHECK(r.snap().find("\"unmatched_follow_ups\":1") != std::string::npos);
}

TEST(gptp_pdelay_ascapable) {
    Rig r("8021as_gptp");
    auto req = [&](uint64_t seq, double ts) {
        return r.feed("8021as_gptp", ts, gptpCommon(0x2, 0x22, seq, 0, 0));
    };
    auto resp = [&](uint64_t seq, double ts, uint64_t receiptNs) {
        auto vars = gptpCommon(0x3, 0x33, seq);
        vars.insert(vars.end(), {{"requesting_clock_id", 0x22},
                                 {"requesting_port_number", 1},
                                 {"req_receipt_seconds", 0},
                                 {"req_receipt_ns", receiptNs}});
        return r.feed("8021as_gptp", ts, vars);
    };
    auto respFu = [&](uint64_t seq, double ts, uint64_t originNs) {
        auto vars = gptpCommon(0xA, 0x33, seq);
        vars.insert(vars.end(), {{"requesting_clock_id", 0x22},
                                 {"requesting_port_number", 1},
                                 {"resp_origin_seconds", 0},
                                 {"resp_origin_ns", originNs}});
        return r.feed("8021as_gptp", ts, vars);
    };

    req(1, 0.0);
    CHECK(r.snap().find("\"pdelay_req_state\":\"WAITING_FOR_PDELAY_RESP\"") !=
          std::string::npos);
    resp(1, 0.001, 1000000);
    CHECK(r.snap().find("\"pdelay_resp_state\":"
                        "\"SENT_PDELAY_RESP_WAITING_FOR_TIMESTAMP\"") !=
          std::string::npos);
    auto t1 = respFu(1, 0.002, 1800000); // 800 µs turnaround
    bool capable = false;
    for (auto& t : t1)
        if (t.to == "AS_CAPABLE") capable = true;
    CHECK(capable);
    CHECK(r.snap().find("\"last_turnaround_us\":800") != std::string::npos);
    // MD machines rest: requester waits the interval, responder waits reqs.
    CHECK(r.snap().find("\"pdelay_req_state\":"
                        "\"WAITING_FOR_PDELAY_INTERVAL_TIMER\"") !=
          std::string::npos);
    CHECK(r.snap().find("\"pdelay_resp_state\":\"WAITING_FOR_PDELAY_REQ\"") !=
          std::string::npos);

    // Slow responder: > 10 ms turnaround -> warning on the responder port.
    req(2, 1.0);
    resp(2, 1.001, 1000000);
    auto t2 = respFu(2, 1.002, 13300000); // 12.3 ms
    CHECK(!t2.empty());
    CHECK(t2.back().why.find("12.3 ms") != std::string::npos);
    CHECK(t2.back().object.find("0x0000000000000033") != std::string::npos);

    // 3 consecutive unanswered requests -> NOT_AS_CAPABLE, with the
    // MDPdelayReq machine passing through RESET each time (802.1AS 11.2.19).
    req(3, 2.0);
    auto lost1 = req(4, 3.5); // closes 3 as lost (1)
    bool sawReset = false;
    for (auto& t : lost1)
        if (t.why.find("MDPdelayReq -> RESET") != std::string::npos)
            sawReset = true;
    CHECK(sawReset);
    req(5, 5.0);  // closes 4 as lost (2)
    auto t3 = r.tick(7.0); // expires 5 (3)
    bool notCapable = false;
    for (auto& t : t3)
        if (t.to == "NOT_AS_CAPABLE") notCapable = true;
    CHECK(notCapable);
    CHECK(r.snap().find("\"pdelay_req_state\":\"RESET\"") != std::string::npos);
    CHECK(r.snap().find("\"resets\":3") != std::string::npos);
}

TEST(gptp_roles) {
    Rig r("8021as_gptp");
    // A pdelay-only port first...
    r.feed("8021as_gptp", 0.0, gptpCommon(0x2, 0x22, 1, 0, 0));
    // ...then another port sends Sync -> it is MASTER, the first is SLAVE.
    auto vars = gptpCommon(0x0, 0x11, 1);
    vars.push_back({"two_step", 1});
    auto t = r.feed("8021as_gptp", 0.1, vars);
    bool master = false, slave = false;
    for (auto& tr : t) {
        if (tr.to == "MASTER" &&
            tr.object.find("0x0000000000000011") != std::string::npos)
            master = true;
        if (tr.to == "SLAVE" &&
            tr.object.find("0x0000000000000022") != std::string::npos) {
            slave = true;
            CHECK(tr.why.find("inferred") != std::string::npos);
        }
    }
    CHECK(master);
    CHECK(slave);
}

TEST(gptp_bmca_readout) {
    Rig r("8021as_gptp");
    auto announce = [&](uint64_t clock, uint64_t gm, uint64_t p1, double ts) {
        auto vars = gptpCommon(0xB, clock, 1, 0, 0);
        vars.insert(vars.end(),
                    {{"gm_identity", gm}, {"gm_priority1", p1},
                     {"gm_priority2", 248}, {"gm_clock_class", 248},
                     {"gm_clock_accuracy", 0x21}, {"gm_clock_variance", 100},
                     {"steps_removed", 0}, {"time_source", 0xA0},
                     {"current_utc_offset", 0}});
        return r.feed("8021as_gptp", ts, vars);
    };
    auto sync = [&](uint64_t clock, uint64_t seq, double ts) {
        auto vars = gptpCommon(0x0, clock, seq);
        vars.push_back({"two_step", 1});
        return r.feed("8021as_gptp", ts, vars);
    };

    // A (prio1 248) announces and drives Sync — converged on A.
    announce(0xA1, 0xA1, 248, 0.0);
    sync(0xA1, 1, 0.1);
    CHECK(r.snap().find("\"bmca\":\"CONVERGED\"") != std::string::npos);

    // B announces a better vector (prio1 200) but Sync still comes from A:
    // a priority inversion — reported as /state only, never as an event.
    announce(0xB2, 0xB2, 200, 0.5);
    sync(0xA1, 2, 0.6);
    CHECK(r.snap().find("\"bmca\":\"PRIORITY_INVERSION\"") != std::string::npos);
    CHECK(r.snap().find("\"expected_gm\":\"0x00000000000000b2\"") !=
          std::string::npos);

    // Two equal-priority (prio1 248) clocks: the winner is a clockIdentity
    // tiebreak, not a fault. C1 (lower id) is "expected", C9 drives Sync.
    Rig r2("8021as_gptp");
    auto ann2 = [&](uint64_t clock) {
        auto v = gptpCommon(0xB, clock, 1);
        v.insert(v.end(), {{"gm_identity", clock}, {"gm_priority1", 248},
                           {"gm_priority2", 248}, {"gm_clock_class", 248},
                           {"gm_clock_accuracy", 0x21}, {"gm_clock_variance", 100},
                           {"steps_removed", 0}, {"time_source", 0xA0},
                           {"current_utc_offset", 0}});
        return v;
    };
    r2.feed("8021as_gptp", 0.0, ann2(0xC1));
    r2.feed("8021as_gptp", 0.05, ann2(0xC9));
    auto s = gptpCommon(0x0, 0xC9, 1);
    s.push_back({"two_step", 1});
    r2.feed("8021as_gptp", 0.1, s); // C9 syncs; C1 (lower id) is "expected"
    CHECK(r2.snap().find("\"bmca\":\"TIEBREAK\"") != std::string::npos);

    // No BMCA text events are ever emitted (only GM_CHANGED narrates).
    auto all = r.snap();
    CHECK(all.find("election not converged") == std::string::npos);
}

TEST(gptp_bmca_no_stale_sync_gm) {
    // Regression: when Sync moves to a port whose Announce hasn't been seen,
    // the driving GM must read UNKNOWN, never the previous sender's GM.
    Rig r("8021as_gptp");
    auto announce = [&](uint64_t clock, uint64_t p1, double ts) {
        auto v = gptpCommon(0xB, clock, 1, 0, 0);
        v.insert(v.end(), {{"gm_identity", clock}, {"gm_priority1", p1},
                           {"gm_priority2", 248}, {"gm_clock_class", 248},
                           {"gm_clock_accuracy", 0x21}, {"gm_clock_variance", 100},
                           {"steps_removed", 0}, {"time_source", 0xA0},
                           {"current_utc_offset", 0}});
        return r.feed("8021as_gptp", ts, v);
    };
    auto sync = [&](uint64_t clock, uint64_t seq, double ts) {
        auto v = gptpCommon(0x0, clock, seq);
        v.push_back({"two_step", 1});
        return r.feed("8021as_gptp", ts, v);
    };
    announce(0xA1, 248, 0.0);
    sync(0xA1, 1, 0.1);
    CHECK(r.snap().find("\"bmca\":\"CONVERGED\"") != std::string::npos);
    // Port B (never announced) takes over Sync — driving GM is now unknown.
    sync(0xB2, 2, 0.5);
    CHECK(r.snap().find("\"sync_gm\":\"\"") != std::string::npos);
    CHECK(r.snap().find("\"bmca\":\"UNKNOWN\"") != std::string::npos);
    CHECK(r.snap().find("\"bmca\":\"CONVERGED\"") == std::string::npos);
}

TEST(gptp_bmca_clock_class_inversion) {
    // Regression: equal priority1 but different clockClass must read as a
    // PRIORITY_INVERSION, not a benign TIEBREAK.
    Rig r("8021as_gptp");
    auto ann = [&](uint64_t clock, uint64_t clockClass, double ts) {
        auto v = gptpCommon(0xB, clock, 1);
        v.insert(v.end(), {{"gm_identity", clock}, {"gm_priority1", 248},
                           {"gm_priority2", 248}, {"gm_clock_class", clockClass},
                           {"gm_clock_accuracy", 0x21}, {"gm_clock_variance", 100},
                           {"steps_removed", 0}, {"time_source", 0xA0},
                           {"current_utc_offset", 0}});
        return r.feed("8021as_gptp", ts, v);
    };
    ann(0xC6, 6, 0.0);    // GPS-quality clock (better clockClass)
    ann(0xF8, 248, 0.05); // free-running crystal
    auto s = gptpCommon(0x0, 0xF8, 1);
    s.push_back({"two_step", 1});
    r.feed("8021as_gptp", 0.1, s); // the worse clock drives Sync
    CHECK(r.snap().find("\"bmca\":\"PRIORITY_INVERSION\"") != std::string::npos);
}

TEST(gptp_announce_aging_is_per_port) {
    // Regression: a fast announcer must not age out a slower healthy one.
    Rig r("8021as_gptp");
    auto ann = [&](uint64_t clock, uint64_t logIval, double ts) {
        auto v = gptpCommon(0xB, clock, 1, 0, logIval);
        v.insert(v.end(), {{"gm_identity", clock}, {"gm_priority1", 248},
                           {"gm_priority2", 248}, {"gm_clock_class", 248},
                           {"gm_clock_accuracy", 0x21}, {"gm_clock_variance", 100},
                           {"steps_removed", 0}, {"time_source", 0xA0},
                           {"current_utc_offset", 0}});
        return r.feed("8021as_gptp", ts, v);
    };
    // Fast port F: 0.125 s (logInterval -3); slow port S: 1 s (logInterval 0).
    ann(0xFF, 0xFD, 0.0);
    ann(0x55, 0x00, 0.0);
    for (int i = 1; i <= 3; ++i) ann(0xFF, 0xFD, i * 0.125); // F keeps up
    // S is on schedule (1 s cadence): a tick just before its next announce
    // must NOT age it out.
    auto t = r.tick(0.9);
    for (auto& tr : t)
        CHECK(!(tr.to == "AGED" &&
                tr.object.find("0x0000000000000055") != std::string::npos));
}

TEST(gptp_capable_and_interval_request) {
    Rig r("8021as_gptp");
    auto capable = [&](double ts) {
        auto vars = gptpCommon(0xC, 0x11, 1);
        vars.insert(vars.end(), {{"signaling_gptp_capable", 1},
                                 {"gptp_capable_interval", 0}});
        return r.feed("8021as_gptp", ts, vars);
    };
    auto t1 = capable(0.0);
    CHECK(!t1.empty());
    CHECK_EQ(t1[0].to, std::string("GPTP_CAPABLE"));
    capable(1.0);

    // Interval request from the other port is exposed in /state.
    auto vars = gptpCommon(0xC, 0x22, 2);
    vars.insert(vars.end(), {{"signaling_interval_request", 1},
                             {"req_link_delay_interval", 0},
                             {"req_time_sync_interval", 0xFD /* -3 */},
                             {"req_announce_interval", 0}});
    r.feed("8021as_gptp", 1.5, vars);
    CHECK(r.snap().find("\"requested_intervals\"") != std::string::npos);
    CHECK(r.snap().find("\"time_sync\":\"-3 (125 ms)\"") != std::string::npos);

    // Silence > 9 intervals -> CAPABLE_TIMED_OUT (10.7.3.3).
    auto t2 = r.tick(11.0);
    bool timedOut = false;
    for (auto& tr : t2)
        if (tr.to == "CAPABLE_TIMED_OUT") timedOut = true;
    CHECK(timedOut);
}

TEST(gptp_md_sync_send_state) {
    Rig r("8021as_gptp");
    auto vars = gptpCommon(0x0, 0x11, 7);
    vars.push_back({"two_step", 1});
    r.feed("8021as_gptp", 0.0, vars);
    CHECK(r.snap().find("\"sync_send_state\":\"FOLLOW_UP_PENDING\"") !=
          std::string::npos);
    r.feed("8021as_gptp", 0.01, gptpCommon(0x8, 0x11, 7));
    CHECK(r.snap().find("\"sync_send_state\":\"IDLE\"") != std::string::npos);
}

TEST(adp_gm_mismatch_cross_check) {
    Rig r("atdecc_adp");
    // Observed gPTP truth: GM on domain 0 is 0xBEEF.
    r.shared.gptpDomains[0] = {true, 0xBEEF, 1};

    auto avail = [&](uint64_t gm, double ts) {
        return r.feed("atdecc_adp", ts,
                      {{"message_type", 0}, {"entity_id", 42},
                       {"available_index", 1}, {"valid_time", 62},
                       {"gptp_grandmaster_id", gm}, {"gptp_domain_number", 0}});
    };

    auto t1 = avail(0xAAAA, 0.1); // stale GM
    CHECK_EQ(t1.size(), (size_t)2); // AVAILABLE + mismatch warning
    CHECK(t1[1].why.find("observed grandmaster") != std::string::npos);
    CHECK(r.snap().find("\"gm_in_sync\":\"MISMATCH\"") != std::string::npos);

    auto t2 = avail(0xBEEF, 1.0); // corrected
    CHECK_EQ(t2.size(), (size_t)1);
    CHECK(t2[0].why.find("now matches") != std::string::npos);
    CHECK(r.snap().find("\"gm_in_sync\":\"MATCH\"") != std::string::npos);

    // Unknown domain -> UNKNOWN, no warning.
    Rig r2("atdecc_adp");
    auto t3 = r2.feed("atdecc_adp", 0.1,
                      {{"message_type", 0}, {"entity_id", 7},
                       {"available_index", 1}, {"valid_time", 62},
                       {"gptp_grandmaster_id", 0xAAAA},
                       {"gptp_domain_number", 0}});
    CHECK_EQ(t3.size(), (size_t)1);
    CHECK(r2.snap().find("\"gm_in_sync\":\"UNKNOWN\"") != std::string::npos);
}

TEST(msrp_gptp_annotation) {
    Rig r("mrp_msrp");
    r.feed("mrp_msrp", 0.0,
           {{"attribute_type", 1}, {"mrp_event", 1}, {"stream_id", 0xbeef},
            {"src_mac", 0x1}, {"dest_mac", 0x91e0f0000e80}, {"vlan_id", 2},
            {"max_frame_size", 224}, {"max_interval_frames", 1},
            {"priority", 3}, {"rank", 1}, {"accumulated_latency", 125000}});
    r.feed("mrp_msrp", 0.1,
           {{"attribute_type", 3}, {"mrp_event", 1}, {"four_packed_event", 2},
            {"stream_id", 0xbeef}, {"src_mac", 0x2}});
    CHECK_EQ(r.shared.establishedStreams.size(), (size_t)1);

    r.shared.gptpDomains[0] = {true, 0xBEEF, 2}; // sync LOST
    CHECK(r.snap().find("\"gptp_sync\":\"LOST\"") != std::string::npos);

    // Talker withdraws -> reservation leaves the established set.
    r.feed("mrp_msrp", 1.0,
           {{"attribute_type", 1}, {"mrp_event", 5}, {"stream_id", 0xbeef},
            {"src_mac", 0x1}, {"dest_mac", 0x91e0f0000e80}, {"vlan_id", 2}});
    CHECK(r.shared.establishedStreams.empty());
}

TEST(mrp_registrar_state_machine) {
    // The MRP Registrar (802.1Q 10.7.8) is driven by the observed events and
    // shared across MSRP/MVRP. Drive it directly through SharedModel.
    SharedModel sm;
    auto reg = [&](const char* proto) {
        JsonWriter w;
        sm.snapshotMrp(w);
        std::string s = w.str();
        (void)proto;
        return s;
    };

    // JoinIn -> IN (register).
    sm.mrpEvent(Proto::MVRP, "VID", "VLAN 2", 0x1, 1 /*JoinIn*/, 0.0, 1);
    CHECK(reg("").find("\"registrar\":\"IN\"") != std::string::npos);
    CHECK(reg("").find("\"attribute\":\"VLAN 2\"") != std::string::npos);

    // In / Mt do not change the registrar.
    sm.mrpEvent(Proto::MVRP, "VID", "VLAN 2", 0x1, 2 /*In*/, 0.5, 2);
    CHECK(reg("").find("\"registrar\":\"IN\"") != std::string::npos);

    // Lv -> LV (leavetimer started); leavetimer expiry -> MT.
    sm.mrpEvent(Proto::MVRP, "VID", "VLAN 2", 0x1, 5 /*Lv*/, 1.0, 3);
    CHECK(reg("").find("\"registrar\":\"LV\"") != std::string::npos);
    sm.mrpTick(1.5); // < LeaveTime (1.0 s): not yet
    CHECK(reg("").find("\"registrar\":\"LV\"") != std::string::npos);
    sm.mrpTick(2.1); // > 1.0 s after the Lv
    CHECK(reg("").find("\"registrar\":\"MT\"") != std::string::npos);

    // The event log records each observed event + resulting registrar.
    CHECK(reg("").find("\"event\":\"JoinIn\"") != std::string::npos);
    CHECK(reg("").find("\"event\":\"Lv\"") != std::string::npos);

    // LeaveAll is scoped to one attribute type: a DOMAIN LeaveAll moves the
    // DOMAIN registrar to LV but leaves the TALKER registrar untouched.
    sm.mrpEvent(Proto::MSRP, "DOMAIN", "Domain class 6", 0x9, 1, 0.0, 1);
    sm.mrpEvent(Proto::MSRP, "TALKER_ADVERTISE", "Talker Advertise 0xbeef", 0x9,
                1, 0.1, 2);
    sm.mrpLeaveAll(Proto::MSRP, "DOMAIN", 0.2, 3);
    std::string s = reg("");
    size_t lv = 0, pos = 0;
    while ((pos = s.find("\"registrar\":\"LV\"", pos)) != std::string::npos) {
        ++lv;
        pos += 4;
    }
    CHECK_EQ(lv, (size_t)1); // only the DOMAIN registrar left; the TALKER stays IN
    CHECK(s.find("\"kind\":\"TALKER_ADVERTISE\"") != std::string::npos &&
          s.find("\"registrar\":\"IN\"") != std::string::npos);
}

TEST(maap_probe_announce_defend_lost) {
    Rig r("1722_maap");
    auto feed = [&](uint64_t msg, uint64_t start, uint64_t count, double ts) {
        return r.feed("1722_maap", ts,
                      {{"message_type", msg}, {"src_mac", 0xa},
                       {"requested_start_address", start},
                       {"requested_count", count},
                       {"conflict_start_address", start},
                       {"conflict_count", count}});
    };
    auto t1 = feed(1, 0x91e0f0003800, 8, 0.0);
    CHECK_EQ(t1[0].to, std::string("PROBING"));
    auto t2 = feed(3, 0x91e0f0003800, 8, 0.3);
    CHECK_EQ(t2[0].to, std::string("ACQUIRED"));
    auto t3 = feed(2, 0x91e0f0003800, 8, 1.0);
    CHECK_EQ(t3[0].to, std::string("DEFENDING"));
    // Abandons the contested range, probes another -> LOST + PROBING.
    auto t4 = feed(1, 0x91e0f0007700, 4, 2.0);
    CHECK_EQ(t4.size(), (size_t)2);
    CHECK_EQ(t4[0].to, std::string("LOST"));
    CHECK_EQ(t4[1].to, std::string("PROBING"));
}
