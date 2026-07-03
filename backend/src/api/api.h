/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * REST + WebSocket API per docs/API.md (frozen contract), plus static
 * serving of the frontend. All /api endpoints except register/login
 * require a bearer token (SE-3).
 */
#pragma once

#include <chrono>
#include <memory>
#include <string>

#include "../auth/auth.h"
#include "../engine/engine.h"
#include "../net/http.h"
#include "../store/store.h"

namespace avb {

class Api {
public:
    Api(Engine& engine, Auth& auth, Store& store, ThreadPool& pool,
        ClientRegistry& clients, std::string frontendDir)
        : mEngine(engine), mAuth(auth), mStore(store), mPool(pool),
          mClients(clients), mFrontendDir(std::move(frontendDir)),
          mStart(std::chrono::steady_clock::now()) {}

    void handle(HttpRequest& req, HttpResponse& resp,
                std::shared_ptr<ClientInfo> client);
    /** WebSocket upgrade — takes ownership of fd, always. */
    bool handleUpgrade(HttpRequest& req, int fd);

private:
    void handleApi(HttpRequest& req, HttpResponse& resp,
                   std::shared_ptr<ClientInfo> client);
    void handleStatic(HttpRequest& req, HttpResponse& resp);

    void handleRegister(HttpRequest&, HttpResponse&);
    void handleLogin(HttpRequest&, HttpResponse&);
    void handlePcapsGet(HttpResponse&);
    void handlePcapsPost(HttpRequest&, HttpResponse&);
    void handleSessionsGet(HttpResponse&);
    void handleSessionsPost(HttpRequest&, HttpResponse&);
    void handleSessionGet(const std::string& id, HttpResponse&);
    void handleSessionDelete(const std::string& id, HttpResponse&);
    void handleEvents(HttpRequest&, const std::string& id, HttpResponse&);
    void handleNotesGet(const std::string& id, HttpResponse&);
    void handleNotesPut(HttpRequest&, const std::string& id, HttpResponse&);
    void handlePacket(const std::string& id, const std::string& nStr,
                      HttpResponse&);
    void handleState(const std::string& id, HttpResponse&);
    void handleInfo(const std::string& id, HttpResponse&);
    void handleDeviceNamePut(HttpRequest&, HttpResponse&);
    void handleMetrics(HttpResponse&);

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
};

} // namespace avb
