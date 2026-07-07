/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * REST + WebSocket API per docs/API.md (frozen contract), plus static
 * serving of the frontend. All /api endpoints except register/login
 * require a bearer token (SE-3).
 *
 * Multi-tenancy (SE-5): every caller resolves to a (user, role, domain)
 * triple; data endpoints only ever see the caller's own domain, and
 * cross-domain object access answers 404 so existence does not leak.
 * Rate limiting (SE-6) and flow monitoring (SE-7) wrap every API request.
 */
#pragma once

#include <array>
#include <chrono>
#include <memory>
#include <string>

#include "../auth/auth.h"
#include "../engine/engine.h"
#include "../net/http.h"
#include "../sec/flowguard.h"
#include "../store/store.h"
#include "../util/ratelimit.h"

namespace avb {

class Api {
public:
    Api(Engine& engine, Auth& auth, Store& store, ThreadPool& pool,
        ClientRegistry& clients, std::string frontendDir);

    void handle(HttpRequest& req, HttpResponse& resp,
                std::shared_ptr<ClientInfo> client);
    /** WebSocket upgrade — takes ownership of fd, always. */
    bool handleUpgrade(HttpRequest& req, int fd);

private:
    /** Resolved caller identity: who, which role, which tenant domain. */
    struct Caller {
        std::string user, role, domain;
        bool admin() const { return role == "admin"; }
    };

    void handleApi(HttpRequest& req, HttpResponse& resp,
                   std::shared_ptr<ClientInfo> client);
    /** The actual routing; handleApi wraps it with rate limiting and flow
     *  recording. `actor`/`caller` report who handled the request. */
    void routeApi(HttpRequest& req, HttpResponse& resp,
                  std::shared_ptr<ClientInfo> client, const std::string& ip,
                  std::string& actor, Caller& caller);
    void handleStatic(HttpRequest& req, HttpResponse& resp);

    /** Session lookup with tenancy enforcement: nullptr when the id does not
     *  exist in the caller's domain (indistinguishable from absent). */
    std::shared_ptr<Session> findScoped(const std::string& id,
                                        const Caller& c) const;

    void handleRegister(HttpRequest&, HttpResponse&);
    void handleLogin(HttpRequest&, HttpResponse&);
    void handlePcapsGet(const Caller&, HttpResponse&);
    void handlePcapsPost(HttpRequest&, const Caller&, HttpResponse&);
    void handlePcapDelete(const std::string& id, const Caller&, HttpResponse&);
    void handlePcapMove(HttpRequest&, const std::string& id, const Caller&,
                        HttpResponse&);
    void handleFolderPost(HttpRequest&, const Caller&, HttpResponse&);
    void handleFolderDelete(const std::string& name, const Caller&,
                            HttpResponse&);
    void handleSessionsGet(const Caller&, HttpResponse&);
    void handleSessionsPost(HttpRequest&, const Caller&, HttpResponse&);
    void handleSessionGet(const std::string& id, const Caller&, HttpResponse&);
    void handleSessionDelete(const std::string& id, const Caller&,
                             HttpResponse&);
    void handleEvents(HttpRequest&, const std::string& id, const Caller&,
                      HttpResponse&);
    void handleNotesGet(const std::string& id, const Caller&, HttpResponse&);
    void handleNotesPut(HttpRequest&, const std::string& id, const Caller&,
                        HttpResponse&);
    void handlePacket(const std::string& id, const std::string& nStr,
                      const Caller&, HttpResponse&);
    void handleSourceAlias(HttpRequest&, const std::string& id,
                           const std::string& idxStr, const Caller&,
                           HttpResponse&);
    void handleSrcMap(const std::string& id, const Caller&, HttpResponse&);
    void handleState(const std::string& id, const Caller&, HttpResponse&);
    void handleInfo(const std::string& id, const Caller&, HttpResponse&);
    void handleDeviceNamePut(HttpRequest&, const Caller&, HttpResponse&);
    void handleMetrics(const Caller&, HttpResponse&);
    void handlePresencePut(HttpRequest&, const Caller&,
                           const std::string& token, HttpResponse&);
    void handlePresenceGet(const Caller&, HttpResponse&);
    void handleAdmin(HttpRequest&, const Caller&, HttpResponse&);
    void handleAdminMonitor(HttpResponse&);
    /** Domain self-service: owners manage the users of their own domain. */
    void handleDomainApi(HttpRequest&, const Caller&, HttpResponse&);

    void streamSession(int fd, const std::string& sessionId,
                       const std::string& user, const std::string& addr);

    Engine& mEngine;
    Auth& mAuth;
    Store& mStore;
    ThreadPool& mPool;
    ClientRegistry& mClients;
    std::string mFrontendDir;
    std::chrono::steady_clock::time_point mStart;
    std::atomic<uint64_t> mUploadSeq{0};

    // SE-6: request rate limiting. General per-user limit for non-admins,
    // a stricter bucket for expensive operations (upload, analysis start),
    // and a per-IP bucket for the unauthenticated login/register endpoints.
    RateLimiter mLimiter;
    double mRateRps = 30.0, mRateBurst = 90.0;    // AVB_RATE_RPS / AVB_RATE_BURST
    double mLoginRps = 0.5, mLoginBurst = 6.0;    // AVB_LOGIN_RPS / AVB_LOGIN_BURST
    bool mRegistrationDisabled = false;           // AVB_DISABLE_REGISTRATION=1

    // SE-7: flow sampling + anomaly detection.
    FlowGuard mGuard;

    // Per-domain request counters for the admin monitor (last 60 s ring).
    struct DomainTraffic {
        std::array<uint32_t, 60> slots{};
        int64_t lastSec = 0;
        uint64_t total = 0;
    };
    std::mutex mTrafficMu;
    std::map<std::string, DomainTraffic> mTraffic;
    void trafficHit(const std::string& domain);
    double trafficPerMin(DomainTraffic& t, int64_t nowSec) const;

    // CPU sampling state for /api/admin/monitor (delta between two calls).
    std::mutex mCpuMu;
    uint64_t mCpuProcJiffies = 0, mCpuTotalJiffies = 0, mCpuIdleJiffies = 0;
    std::chrono::steady_clock::time_point mCpuAt{};
    double mCpuProcPct = 0, mCpuSysPct = 0;

    /** Who is looking at what — in-memory, heartbeat-driven, 60 s expiry. */
    struct Presence {
        std::string user, view, domain;
        std::chrono::steady_clock::time_point seen;
    };
    std::mutex mPresenceMu;
    std::map<std::string, Presence> mPresence; // keyed by token
};

} // namespace avb
