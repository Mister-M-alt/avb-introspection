/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 */
#include "flowguard.h"

#include <ctime>
#include <fstream>

#include "../util/json.h"

namespace avb {

namespace {

std::string nowIso() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

int64_t bucketOf(std::chrono::steady_clock::time_point t) {
    return std::chrono::duration_cast<std::chrono::seconds>(
               t.time_since_epoch())
               .count() /
           5; // kBucketSec
}

} // namespace

FlowGuard::Counts FlowGuard::sum(const Actor& a) const {
    Counts s;
    for (auto& c : a.win) {
        s.req += c.req;
        s.e401 += c.e401;
        s.e403 += c.e403;
        s.e404 += c.e404;
        s.e429 += c.e429;
        s.bytesIn += c.bytesIn;
    }
    return s;
}

void FlowGuard::rotate(Actor& a, int64_t bucket) {
    if (a.winStart < 0) {
        a.winStart = bucket;
        return;
    }
    int64_t shift = bucket - a.winStart;
    if (shift <= 0) return;
    if (shift >= kBuckets) {
        // Full window elapsed idle — fold the old rate into the baseline
        // before clearing (an idle actor's baseline decays toward zero).
        Counts s = sum(a);
        double rpm = (double)s.req; // 60 s window -> per minute
        a.ewmaRpm = a.ewmaRpm < 0 ? rpm : 0.7 * a.ewmaRpm + 0.3 * rpm * 0.2;
        a.win.fill({});
        a.winStart = bucket;
        return;
    }
    // Slide: update the baseline with the completed window's rate, then drop
    // the oldest `shift` buckets.
    double rpm = (double)sum(a).req;
    a.ewmaRpm = a.ewmaRpm < 0 ? rpm : 0.8 * a.ewmaRpm + 0.2 * rpm;
    for (int i = 0; i < kBuckets - shift; ++i) a.win[(size_t)i] = a.win[(size_t)(i + shift)];
    for (int i = kBuckets - (int)shift; i < kBuckets; ++i) a.win[(size_t)i] = {};
    a.winStart = bucket;
}

void FlowGuard::raise(Actor& a, const std::string& actor,
                      const std::string& kind, const std::string& detail,
                      const std::string& path,
                      std::chrono::steady_clock::time_point now) {
    // Cooldown: the same kind for the same actor at most every 2 minutes.
    if (a.lastAlertKind == kind &&
        now - a.lastAlert < std::chrono::seconds(120))
        return;
    a.lastAlert = now;
    a.lastAlertKind = kind;
    a.penaltyUntil = now + std::chrono::minutes(5);

    Alert al{nowIso(), actor, a.domain, kind, detail, path};
    mAlerts.push_back(al);
    if (mAlerts.size() > 256) mAlerts.pop_front();

    if (!mLogPath.empty()) {
        JsonWriter w;
        w.beginObj();
        w.kv("ts", al.ts);
        w.kv("actor", al.actor);
        w.kv("domain", al.domain);
        w.kv("kind", al.kind);
        w.kv("detail", al.detail);
        w.kv("path", al.path);
        w.endObj();
        std::ofstream f(mLogPath, std::ios::app);
        if (f) f << w.str() << "\n";
    }
}

void FlowGuard::record(const std::string& actor, const std::string& domain,
                       const std::string& role, const std::string& method,
                       const std::string& path, int status, uint64_t bytesIn) {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard lk(mMu);
    ++mTotalRecorded;

    // Bound the actor table (an address-rotating scanner would otherwise
    // grow it without limit).
    if (mActors.size() > 4096) {
        for (auto it = mActors.begin(); it != mActors.end();)
            it = (now - it->second.lastSeen > std::chrono::minutes(10))
                     ? mActors.erase(it)
                     : std::next(it);
    }

    Actor& a = mActors[actor];
    a.domain = domain;
    a.role = role;
    a.lastSeen = now;
    rotate(a, bucketOf(now));
    Counts& cur = a.win[kBuckets - 1];
    cur.req++;
    cur.bytesIn += bytesIn;
    if (status == 401) cur.e401++;
    if (status == 403) cur.e403++;
    if (status == 404) cur.e404++;
    if (status == 429) cur.e429++;

    // ---- rules over the rolling 60 s window ----
    bool suspect = false;
    Counts s = sum(a);
    if (path.find("..") != std::string::npos) {
        raise(a, actor, "path-traversal",
              "request path contains a '..' component", path, now);
        suspect = true;
    }
    if (s.e401 >= 8) {
        raise(a, actor, "auth-bruteforce",
              std::to_string(s.e401) + " authentication failures in 60 s",
              path, now);
        suspect = true;
    }
    if (s.e403 + s.e404 >= 15) {
        raise(a, actor, "probe",
              std::to_string(s.e403 + s.e404) +
                  " denied/unknown responses in 60 s (endpoint or object "
                  "scanning)",
              path, now);
        suspect = true;
    }
    if (s.e429 >= 20) {
        raise(a, actor, "limit-hammering",
              "keeps sending while rate-limited (" + std::to_string(s.e429) +
                  " x 429 in 60 s)",
              path, now);
        suspect = true;
    }
    // Rate anomaly: only once a baseline exists, and never below an absolute
    // floor a human clicking around could reach.
    if (a.ewmaRpm >= 1.0 && (double)s.req > 8.0 * a.ewmaRpm &&
        s.req >= 240) {
        raise(a, actor, "rate-anomaly",
              std::to_string(s.req) + " req/min vs baseline " +
                  std::to_string((int)a.ewmaRpm) + " req/min",
              path, now);
        suspect = true;
    }
    if (role != "admin" && s.bytesIn > (uint64_t)512 * 1024 * 1024) {
        raise(a, actor, "upload-flood",
              std::to_string(s.bytesIn / (1024 * 1024)) +
                  " MiB uploaded in 60 s",
              path, now);
        suspect = true;
    }
    if (a.penaltyUntil > now) suspect = true;
    if (suspect) ++mTotalSuspect;

    // ---- flow sampling: every suspect flow + 1-in-16 of normal traffic ----
    if (suspect || (mSampleTick++ % 16) == 0) {
        mSamples.push_back(
            {nowIso(), actor, domain, method, path, status, suspect});
        if (mSamples.size() > 200) mSamples.pop_front();
    }
}

double FlowGuard::penalty(const std::string& actor) {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard lk(mMu);
    auto it = mActors.find(actor);
    if (it == mActors.end()) return 1.0;
    return it->second.penaltyUntil > now ? 4.0 : 1.0;
}

void FlowGuard::snapshot(JsonWriter& w) {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard lk(mMu);
    w.beginObj();
    w.kv("recorded", mTotalRecorded);
    w.kv("suspect", mTotalSuspect);

    w.key("alerts").beginArr();
    for (auto it = mAlerts.rbegin(); it != mAlerts.rend(); ++it) {
        w.beginObj();
        w.kv("ts", it->ts);
        w.kv("actor", it->actor);
        w.kv("domain", it->domain);
        w.kv("kind", it->kind);
        w.kv("detail", it->detail);
        w.kv("path", it->path);
        w.endObj();
    }
    w.endArr();

    w.key("samples").beginArr();
    int n = 0;
    for (auto it = mSamples.rbegin(); it != mSamples.rend() && n < 100;
         ++it, ++n) {
        w.beginObj();
        w.kv("ts", it->ts);
        w.kv("actor", it->actor);
        w.kv("domain", it->domain);
        w.kv("method", it->method);
        w.kv("path", it->path);
        w.kv("status", (uint64_t)it->status);
        w.kv("verdict", it->suspect ? "suspect" : "legit");
        w.endObj();
    }
    w.endArr();

    w.key("actors").beginArr();
    for (auto& [key, a] : mActors) {
        if (now - a.lastSeen > std::chrono::minutes(5)) continue;
        Counts s = sum(a);
        w.beginObj();
        w.kv("actor", key);
        w.kv("domain", a.domain);
        w.kv("role", a.role);
        w.kv("req_per_min", (uint64_t)s.req);
        w.kv("baseline_rpm", a.ewmaRpm < 0 ? 0.0 : a.ewmaRpm);
        w.kv("penalty", a.penaltyUntil > now ? 4.0 : 1.0);
        w.kv("idle_s",
             std::chrono::duration<double>(now - a.lastSeen).count());
        w.endObj();
    }
    w.endArr();
    w.endObj();
}

} // namespace avb
