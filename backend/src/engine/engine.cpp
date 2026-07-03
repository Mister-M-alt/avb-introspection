/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 */
#include "engine.h"

#include <algorithm>
#include <chrono>
#include <numeric>
#include <thread>

#include "../decode/decode.h"

namespace avb {

void Engine::add(std::shared_ptr<Session> session) {
    std::lock_guard lk(mMu);
    mSessions[session->id] = std::move(session);
}

void Engine::start(std::shared_ptr<Session> session) {
    {
        std::lock_guard lk(mMu);
        mSessions[session->id] = session;
        ++mRunning;
    }
    std::thread([this, session] {
        analyze(session);
        {
            std::lock_guard lk(mMu);
            --mRunning;
        }
        mDrainCv.notify_all();
    }).detach();
}

std::shared_ptr<Session> Engine::find(const std::string& id) const {
    std::lock_guard lk(mMu);
    auto it = mSessions.find(id);
    return it == mSessions.end() ? nullptr : it->second;
}

std::vector<std::shared_ptr<Session>> Engine::list() const {
    std::lock_guard lk(mMu);
    std::vector<std::shared_ptr<Session>> out;
    out.reserve(mSessions.size());
    for (auto& [id, s] : mSessions) out.push_back(s);
    return out;
}

bool Engine::remove(const std::string& id) {
    std::lock_guard lk(mMu);
    return mSessions.erase(id) != 0;
}

void Engine::drain() {
    std::unique_lock lk(mMu);
    mDrainCv.wait(lk, [this] { return mRunning == 0; });
}

namespace {

void failSession(Session& s, const std::string& msg) {
    s.errorMsg = msg;
    s.status.store(Session::Error);
    s.cv.notify_all();
}

} // namespace

void Engine::analyze(std::shared_ptr<Session> sp) {
    Session& s = *sp;
    auto t0 = std::chrono::steady_clock::now();

    PcapFile pcap;
    std::string err;
    if (!pcap.open(s.pcapFilePath, err)) {
        failSession(s, err);
        return;
    }

    const auto& pkts = pcap.packets();
    s.pindex = pkts;
    s.firstTsNanos = pkts.front().tsNanos;
    s.lastTsNanos = pkts.back().tsNanos;
    s.duration = pcap.duration();
    s.packets.store(pkts.size());

    // ---- CO-2: partition the capture across cores, decode in parallel ----
    size_t count = pkts.size();
    unsigned workers = std::max(1u, std::thread::hardware_concurrency());
    workers = (unsigned)std::min<size_t>(workers, (count + 511) / 512);
    std::vector<DecodedPacket> decoded(count);
    {
        std::vector<std::thread> threads;
        size_t chunk = (count + workers - 1) / workers;
        for (unsigned w = 0; w < workers; ++w) {
            size_t begin = w * chunk;
            size_t end = std::min(count, begin + chunk);
            if (begin >= end) break;
            threads.emplace_back([&, begin, end] {
                for (size_t i = begin; i < end; ++i) {
                    DecodedPacket& d = decoded[i];
                    d.num = (uint32_t)i + 1;
                    d.ts = pcap.relTs(i);
                    decodePacket({pcap.packetData(i), pkts[i].caplen}, d);
                }
            });
        }
        for (auto& t : threads) t.join();
    }

    // ---- CO-3: restore strict capture-timestamp order before the state
    // pass; state reconstruction is order-sensitive. -----------------------
    std::vector<uint32_t> order(count);
    std::iota(order.begin(), order.end(), 0u);
    std::stable_sort(order.begin(), order.end(), [&](uint32_t a, uint32_t b) {
        return pkts[a].tsNanos < pkts[b].tsNanos;
    });

    // ---- Single-threaded state pass in capture order ----------------------
    s.logic = AnalysisState::create();
    uint32_t eventIndex = 0;
    std::vector<Event> batch;
    auto flush = [&] {
        if (batch.empty()) return;
        {
            std::unique_lock lk(s.mu);
            for (auto& e : batch) s.events.push_back(std::move(e));
        }
        batch.clear();
        s.cv.notify_all();
    };

    for (size_t oi = 0; oi < count; ++oi) {
        DecodedPacket& d = decoded[order[oi]];
        if (!d.interesting) continue;

        // Device inventory: who sends what (served by /info).
        if (d.srcMac) {
            std::lock_guard st(s.stateMu);
            auto& dev = s.devices[d.srcMac];
            dev.packets++;
            dev.protoMask |= 1u << (int)d.proto;
            // Associate the source with its ATDECC entity where the frame
            // proves it: ADP announcements and AECP responses originate from
            // the entity itself.
            for (auto& ctx : d.logicCtxs) {
                if (d.proto == Proto::ADP && ctx.at("message_type") != 2)
                    dev.entityId = ctx.at("entity_id");
                else if (d.proto == Proto::AECP && ctx.at("message_type") == 1)
                    dev.entityId = ctx.at("target_entity_id");
            }
        }

        if (!d.ok) {
            s.decodeErrors.fetch_add(1);
            Event e;
            e.i = eventIndex++;
            e.n = d.num;
            e.ts = d.ts;
            e.kind = Kind::Error;
            e.proto = d.proto;
            e.type = "DECODE_ERROR";
            e.src = d.src;
            e.dst = d.dst;
            e.summary = d.error;
            batch.push_back(std::move(e));
        } else {
            s.protoCounts[(size_t)d.proto].fetch_add(1);
            Event e;
            e.i = eventIndex++;
            e.n = d.num;
            e.ts = d.ts;
            e.kind = Kind::Packet;
            e.proto = d.proto;
            e.type = d.type;
            e.src = d.src;
            e.dst = d.dst;
            e.summary = d.summary;
            e.entity = d.entity;
            e.stream = d.stream;
            e.fields = d.eventFields;
            batch.push_back(std::move(e));

            std::lock_guard st(s.stateMu);
            for (auto& ctx : d.logicCtxs) {
                ctx.setValue("ts_ns", (uint64_t)(d.ts * 1e9));
                ctx.setValue("pkt_num", d.num);
                auto it = s.logic->byService.find(ctx.getServiceName());
                if (it == s.logic->byService.end()) continue;
                it->second->onDecode(ctx);
                for (auto& tr : it->second->drain()) {
                    Event te;
                    te.i = eventIndex++;
                    te.n = d.num;
                    te.ts = d.ts;
                    te.kind = Kind::Transition;
                    te.proto = tr.proto;
                    te.type = "STATE";
                    te.src = d.src;
                    te.dst = d.dst;
                    te.summary = tr.summary;
                    te.entity = tr.entity;
                    te.stream = tr.stream;
                    te.fields = {{"object", tr.object},
                                 {"from", tr.from},
                                 {"to", tr.to},
                                 {"why", tr.why}};
                    batch.push_back(std::move(te));
                }
            }
        }

        // Advance observation time for timeout tracking on every packet.
        {
            std::lock_guard st(s.stateMu);
            for (auto& [svc, base] : s.logic->byService) {
                base->onTimeTick(d.ts);
                for (auto& tr : base->drain()) {
                    Event te;
                    te.i = eventIndex++;
                    te.n = 0; // derived, not caused by one packet
                    te.ts = d.ts;
                    te.kind = Kind::Transition;
                    te.proto = tr.proto;
                    te.type = "STATE";
                    te.summary = tr.summary;
                    te.entity = tr.entity;
                    te.stream = tr.stream;
                    te.fields = {{"object", tr.object},
                                 {"from", tr.from},
                                 {"to", tr.to},
                                 {"why", tr.why}};
                    batch.push_back(std::move(te));
                }
            }
        }

        if (batch.size() >= 256) flush();
    }
    flush();

    auto t1 = std::chrono::steady_clock::now();
    s.analysisMs.store(
        (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0)
            .count());
    s.status.store(Session::Done);
    s.cv.notify_all();
}

} // namespace avb
