/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * FlowGuard (SE-7): samples every API request flow and judges whether it
 * looks like normal usage. Per actor (a logged-in user, or a client IP for
 * unauthenticated traffic) it keeps a rolling 60 s window of counters plus
 * a slow EWMA baseline of the actor's own request rate, and raises alerts
 * on rule violations:
 *
 *   auth-bruteforce   repeated 401s against login
 *   probe             bursts of 403/404 (endpoint scanning / object probing)
 *   path-traversal    a ".." path component anywhere in the request path
 *   rate-anomaly      request rate far above the actor's own baseline
 *   limit-hammering   continuing to hammer through 429 responses
 *   upload-flood      excessive upload volume (non-admin)
 *
 * Alerts are kept in a ring for the admin UI, appended to
 * <data>/security.log (JSONL), and raise the actor's rate-limit penalty for
 * a few minutes. A sample of flows (every suspect one + 1-in-16 of normal
 * traffic) is retained so the admin can see what "normal" looked like when
 * judging an alert.
 */
#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <deque>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>

namespace avb {

class JsonWriter;

class FlowGuard {
public:
    /** `logPath` receives one JSON line per alert (append-only audit). */
    void init(const std::string& logPath) { mLogPath = logPath; }

    /** Record one finished API request. `actor` is "u:<user>" or
     *  "ip:<addr>". Thread-safe; cheap (a few counter bumps + rules). */
    void record(const std::string& actor, const std::string& domain,
                const std::string& role, const std::string& method,
                const std::string& path, int status, uint64_t bytesIn);

    /** Rate-limit penalty for the actor: 1.0 = normal, 4.0 while the actor
     *  has a recent alert (throttles them to a quarter of the normal rate). */
    double penalty(const std::string& actor);

    /** {"alerts":[...],"samples":[...],"actors":[...]} for the admin UI. */
    void snapshot(JsonWriter& w);

private:
    static constexpr int kBuckets = 12;   // 12 x 5 s = 60 s window
    static constexpr int kBucketSec = 5;

    struct Counts {
        uint32_t req = 0, e401 = 0, e403 = 0, e404 = 0, e429 = 0;
        uint64_t bytesIn = 0;
    };
    struct Actor {
        std::array<Counts, kBuckets> win{};
        int64_t winStart = -1; // bucket index of win[0]'s time slot
        double ewmaRpm = -1;   // learned baseline (requests/minute)
        std::string domain, role;
        std::chrono::steady_clock::time_point lastSeen{};
        std::chrono::steady_clock::time_point penaltyUntil{};
        std::chrono::steady_clock::time_point lastAlert{};
        std::string lastAlertKind;
    };
    struct Alert {
        std::string ts, actor, domain, kind, detail, path;
    };
    struct Sample {
        std::string ts, actor, domain, method, path;
        int status = 0;
        bool suspect = false;
    };

    Counts sum(const Actor& a) const;
    void rotate(Actor& a, int64_t bucket);
    void raise(Actor& a, const std::string& actor, const std::string& kind,
               const std::string& detail, const std::string& path,
               std::chrono::steady_clock::time_point now);

    std::mutex mMu;
    std::unordered_map<std::string, Actor> mActors;
    std::deque<Alert> mAlerts;   // newest at back, capped
    std::deque<Sample> mSamples; // newest at back, capped
    uint64_t mSampleTick = 0;
    uint64_t mTotalRecorded = 0, mTotalSuspect = 0;
    std::string mLogPath;
};

} // namespace avb
