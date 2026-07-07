/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * Token-bucket rate limiter (SE-6): per-actor buckets refill continuously at
 * `ratePerSec` up to `burst`. Used per user for API traffic and per client
 * IP for the unauthenticated login/register endpoints.
 */
#pragma once

#include <chrono>
#include <mutex>
#include <string>
#include <unordered_map>

namespace avb {

class RateLimiter {
public:
    /** Take one token from `key`'s bucket. Returns false when the bucket is
     *  empty; `retryAfter` (seconds until one token is back) is set either
     *  way. `penalty` divides the refill rate — the flow guard raises it for
     *  actors that look abusive. */
    bool allow(const std::string& key, double ratePerSec, double burst,
               double penalty = 1.0, double* retryAfter = nullptr) {
        if (ratePerSec <= 0 || burst <= 0) return true; // limiting disabled
        double rate = ratePerSec / (penalty < 1.0 ? 1.0 : penalty);
        auto now = std::chrono::steady_clock::now();
        std::lock_guard lk(mMu);
        if (mBuckets.size() > 8192) prune(burst);
        auto [it, fresh] = mBuckets.try_emplace(key, Bucket{burst, now});
        Bucket& b = it->second;
        if (!fresh) {
            double dt = std::chrono::duration<double>(now - b.last).count();
            b.tokens = std::min(burst, b.tokens + dt * rate);
            b.last = now;
        }
        if (b.tokens >= 1.0) {
            b.tokens -= 1.0;
            if (retryAfter) *retryAfter = 0;
            return true;
        }
        if (retryAfter) *retryAfter = (1.0 - b.tokens) / rate;
        return false;
    }

private:
    struct Bucket {
        double tokens;
        std::chrono::steady_clock::time_point last;
    };

    /** Drop actors whose bucket has long refilled — they carry no state. */
    void prune(double burst) {
        auto now = std::chrono::steady_clock::now();
        for (auto it = mBuckets.begin(); it != mBuckets.end();) {
            double dt =
                std::chrono::duration<double>(now - it->second.last).count();
            it = (dt > 300 || it->second.tokens >= burst) ? mBuckets.erase(it)
                                                          : std::next(it);
        }
    }

    std::mutex mMu;
    std::unordered_map<std::string, Bucket> mBuckets;
};

} // namespace avb
