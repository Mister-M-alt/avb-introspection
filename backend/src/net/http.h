/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * Minimal HTTP/1.1 server over POSIX sockets (BE-4): connections are served
 * by the demand-grown thread pool (CO-1), keep-alive supported, WebSocket
 * upgrades hand the socket over to the API layer.
 */
#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "../engine/thread_pool.h"

namespace avb {

struct HttpRequest {
    std::string method;
    std::string path;                         // decoded path, no query
    std::map<std::string, std::string> query; // decoded query params
    std::map<std::string, std::string> headers; // lowercase names
    std::string body;
    std::string clientAddr;

    std::string header(const std::string& name) const {
        auto it = headers.find(name);
        return it == headers.end() ? std::string() : it->second;
    }
    std::string queryParam(const std::string& name) const {
        auto it = query.find(name);
        return it == query.end() ? std::string() : it->second;
    }
};

struct HttpResponse {
    int status = 200;
    std::string contentType = "application/json";
    std::string body;
    std::vector<std::pair<std::string, std::string>> extraHeaders;
};

/** Connected-client bookkeeping for GET /api/metrics (NF-2), and the
 *  handle the server needs to wake an idle connection at shutdown. */
struct ClientInfo {
    std::string addr, kind; // kind: "http" | "ws"
    std::string user;
    int fd = -1;
    // True while a request is being handled (between a fully read request
    // and its response). Idle keep-alive connections are not busy and are
    // shut down at drain(); busy ones finish their response first.
    std::atomic<bool> busy{false};
    std::atomic<uint64_t> messages{0}, bytesSent{0};
    std::chrono::steady_clock::time_point since =
        std::chrono::steady_clock::now();
    std::mutex userMu; // user is set after auth
    void setUser(const std::string& u) {
        std::lock_guard lk(userMu);
        user = u;
    }
    std::string getUser() {
        std::lock_guard lk(userMu);
        return user;
    }
};

class ClientRegistry {
public:
    std::shared_ptr<ClientInfo> add(std::string addr, std::string kind,
                                    int fd = -1) {
        auto c = std::make_shared<ClientInfo>();
        c->addr = std::move(addr);
        c->kind = std::move(kind);
        c->fd = fd;
        std::lock_guard lk(mMu);
        mClients.push_back(c);
        return c;
    }
    void remove(const std::shared_ptr<ClientInfo>& c) {
        std::lock_guard lk(mMu);
        std::erase(mClients, c);
    }
    std::vector<std::shared_ptr<ClientInfo>> list() const {
        std::lock_guard lk(mMu);
        return mClients;
    }

private:
    mutable std::mutex mMu;
    std::vector<std::shared_ptr<ClientInfo>> mClients;
};

class HttpServer {
public:
    using Handler = std::function<void(HttpRequest&, HttpResponse&,
                                       std::shared_ptr<ClientInfo>)>;
    /** Return true when the upgrade was handled (fd ownership transferred). */
    using UpgradeHandler = std::function<bool(HttpRequest&, int fd,
                                              std::shared_ptr<ClientInfo>)>;

    /** `bindAddr` is an IPv4 or IPv6 literal ("0.0.0.0", "127.0.0.1",
     *  "::" for dual-stack, "::1"). */
    HttpServer(std::string bindAddr, uint16_t port, ThreadPool& pool,
               size_t maxBodyBytes, ClientRegistry& clients)
        : mBindAddr(std::move(bindAddr)), mPort(port), mPool(pool),
          mMaxBody(maxBodyBytes), mClients(clients) {}

    void setHandler(Handler h) { mHandler = std::move(h); }
    void setUpgradeHandler(UpgradeHandler h) { mUpgrade = std::move(h); }

    /** Bind + listen. Once this returns true the port accepts connections
     *  (they queue until serve() runs), so it is the readiness point. */
    bool listen(std::string& err);
    /** Blocks in the accept loop until stop(). */
    void serve();
    bool listenAndServe(std::string& err) {
        if (!listen(err)) return false;
        serve();
        return true;
    }
    /** Async-signal-safe: stops accepting and makes serve() return. */
    void stop();
    /** After serve() returned: wake every connection that is not busy
     *  handling a request (idle keep-alives, WebSocket streams) so their
     *  serving threads exit instead of sitting in a socket timeout. Busy
     *  connections finish their in-flight response and then exit on their
     *  own (they re-check the stop flag). Not signal-safe. */
    void drain();

    uint16_t port() const { return mPort; }
    /** Bound port — differs from port() only when 0 was requested. */
    uint16_t boundPort() const { return mBoundPort; }

private:
    void handleConnection(int fd, const std::string& addr);
    bool readRequest(int fd, std::string& buffered, HttpRequest& req,
                     int& httpErr);
    static void writeResponse(int fd, const HttpResponse& resp, bool close,
                              ClientInfo* client);

    std::string mBindAddr;
    uint16_t mPort;
    uint16_t mBoundPort = 0;
    ThreadPool& mPool;
    size_t mMaxBody;
    ClientRegistry& mClients;
    Handler mHandler;
    UpgradeHandler mUpgrade;
    std::atomic<int> mListenFd{-1};
    std::atomic<bool> mStopping{false};
};

std::string urlDecode(const std::string& s);

} // namespace avb
