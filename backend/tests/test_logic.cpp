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
                                 std::initializer_list<std::pair<const char*, uint64_t>> vars,
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
                            "1722_maap", "mrp_msrp", "mrp_mvrp"})
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
    auto t1 = common(6, 0, 0.0, 1); // CONNECT_RX_COMMAND
    CHECK_EQ(t1.size(), (size_t)1);
    CHECK_EQ(t1[0].to, std::string("CONNECTING"));
    auto t2 = common(7, 0, 0.1, 1); // CONNECT_RX_RESPONSE SUCCESS
    CHECK_EQ(t2.size(), (size_t)1);
    CHECK_EQ(t2[0].to, std::string("CONNECTED"));
    auto t3 = common(8, 0, 5.0, 2); // DISCONNECT_RX_COMMAND
    CHECK_EQ(t3[0].to, std::string("DISCONNECTING"));
    auto t4 = common(9, 0, 5.1, 2);
    CHECK_EQ(t4[0].to, std::string("DISCONNECTED"));
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
