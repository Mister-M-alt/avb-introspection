/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * avb-introspectd — Milan/AVB protocol introspection backend.
 * Controlled exclusively over the network API (BE-4); see docs/API.md.
 */
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <thread>

#include "api/api.h"
#include "auth/auth.h"
#include "engine/engine.h"
#include "net/http.h"
#include "store/store.h"
#include "util/netaddr.h"

#ifndef AVB_VERSION
#define AVB_VERSION "dev"
#endif

namespace {

avb::HttpServer* gServer = nullptr;
std::atomic<int> gSignals{0};

// Async-signal-safe: the first SIGTERM/SIGINT starts the graceful drain
// (listener closed, streams told to close, idle connections woken); a
// second one exits immediately for an operator who cannot wait.
void onSignal(int sig) {
    if (gSignals.fetch_add(1) == 0) {
        if (gServer) gServer->stop();
        return;
    }
    _exit(128 + sig);
}

void usage(const char* argv0) {
    std::printf(
        "usage: %s [options]\n"
        "  --bind ADDR        listen address (default 0.0.0.0; 127.0.0.1 behind a\n"
        "                     same-host proxy, :: for IPv6 dual-stack)\n"
        "  --port N           listen port (default 8342)\n"
        "  --data DIR         persistent data directory (default ./data)\n"
        "  --frontend DIR     static frontend directory (default ./frontend)\n"
        "  --max-threads N    serving thread cap (default 64)\n"
        "  --max-upload-mb N  pcap upload limit in MiB (default 1024)\n"
        "  --version          print the build version and exit\n"
        "\n"
        "environment: AVB_ADMIN_USER / AVB_ADMIN_PASSWORD (provision the admin),\n"
        "  AVB_DISABLE_REGISTRATION=1, AVB_RATE_RPS / AVB_RATE_BURST,\n"
        "  AVB_LOGIN_RPS / AVB_LOGIN_BURST, AVB_TRUSTED_PROXIES (CIDR list of\n"
        "  reverse proxies whose X-Real-IP / X-Forwarded-For is honoured;\n"
        "  loopback is always trusted). See docs/DEPLOYMENT.md.\n",
        argv0);
}

/** Strictly positive integer in [lo, hi]; false on junk, sign or range. */
bool parseUInt(const char* text, long lo, long hi, long& out) {
    if (!text || !*text) return false;
    char* end = nullptr;
    long v = std::strtol(text, &end, 10);
    if (!end || *end != '\0' || v < lo || v > hi) return false;
    out = v;
    return true;
}

} // namespace

int main(int argc, char** argv) {
    std::string bindAddr = "0.0.0.0";
    uint16_t port = 8342;
    std::string dataDir = "./data";
    std::string frontendDir = "./frontend";
    unsigned maxThreads = 64;
    size_t maxUploadMb = 1024;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> const char* {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "%s: %s needs a value\n", argv[0], a.c_str());
                usage(argv[0]);
                std::exit(2);
            }
            return argv[++i];
        };
        auto bad = [&](const char* what) {
            std::fprintf(stderr, "%s: bad %s value \"%s\"\n", argv[0], what,
                         argv[i]);
            std::exit(2);
        };
        long v = 0;
        if (a == "--bind") bindAddr = next();
        else if (a == "--port") {
            if (!parseUInt(next(), 1, 65535, v)) bad("--port");
            port = (uint16_t)v;
        } else if (a == "--data") dataDir = next();
        else if (a == "--frontend") frontendDir = next();
        else if (a == "--max-threads") {
            if (!parseUInt(next(), 1, 65536, v)) bad("--max-threads");
            maxThreads = (unsigned)v;
        } else if (a == "--max-upload-mb") {
            if (!parseUInt(next(), 1, 1024L * 1024, v)) bad("--max-upload-mb");
            maxUploadMb = (size_t)v;
        } else if (a == "--version" || a == "-V") {
            std::printf("avb-introspectd %s\n", AVB_VERSION);
            return 0;
        } else if (a == "--help" || a == "-h") {
            usage(argv[0]);
            return 0;
        } else {
            std::fprintf(stderr, "%s: unknown option %s\n", argv[0], a.c_str());
            usage(argv[0]);
            return 2;
        }
    }

    // Fail fast on a mistyped proxy list rather than silently trusting
    // nobody (which would collapse every per-IP limit onto the proxy).
    std::vector<avb::IpNet> trustedProxies;
    std::string err;
    if (const char* tp = std::getenv("AVB_TRUSTED_PROXIES"); tp && *tp) {
        if (!avb::parseCidrList(tp, trustedProxies, err)) {
            std::fprintf(stderr, "fatal: AVB_TRUSTED_PROXIES: %s\n", err.c_str());
            return 2;
        }
    }

    avb::Store store;
    if (!store.init(dataDir, err)) {
        std::fprintf(stderr, "fatal: %s\n", err.c_str());
        return 1;
    }
    avb::Auth auth;
    if (!auth.init(store.usersFile(), err)) {
        std::fprintf(stderr, "fatal: %s\n", err.c_str());
        return 1;
    }

    // Deployment admin provisioning: create (or promote) the admin account
    // from the environment. The password is only used when the account does
    // not exist yet.
    const char* adminUser = std::getenv("AVB_ADMIN_USER");
    const char* adminPass = std::getenv("AVB_ADMIN_PASSWORD");
    if (adminUser && *adminUser) {
        if (!auth.ensureAdmin(adminUser, adminPass ? adminPass : "", err))
            std::fprintf(stderr, "warning: admin provisioning failed: %s\n",
                         err.c_str());
        else
            std::printf("admin account: %s\n", adminUser);
    }
    if (!auth.hasAdmin()) {
        // Loud, because AVB_DISABLE_REGISTRATION does not close this window:
        // until an admin exists, whoever registers first becomes one.
        std::fprintf(stderr,
                     "WARNING: no admin account exists — the first account "
                     "registered through the UI becomes the administrator. "
                     "On anything exposed, provision one with AVB_ADMIN_USER / "
                     "AVB_ADMIN_PASSWORD instead.\n");
    }

    avb::Engine engine;

    // BE-8: sessions survive restarts — re-run analysis from stored pcaps.
    unsigned restored = 0;
    for (auto& meta : store.sessions()) {
        auto s = std::make_shared<avb::Session>();
        s->id = meta.id;
        s->name = meta.name;
        s->pcapId = meta.pcapId;
        s->path = meta.path;
        s->createdAt = meta.createdAt;
        s->domain = meta.domain;
        s->pcapFilePath = store.sessionPcapPath(meta.id);
        engine.start(s);
        ++restored;
    }

    avb::ThreadPool pool(maxThreads);
    avb::ClientRegistry clients;
    avb::HttpServer server(bindAddr, port, pool, maxUploadMb * 1024 * 1024,
                           clients);
    avb::Api api(engine, auth, store, pool, clients, frontendDir);
    api.setTrustedProxies(std::move(trustedProxies));

    server.setHandler([&](avb::HttpRequest& req, avb::HttpResponse& resp,
                          std::shared_ptr<avb::ClientInfo> c) {
        api.handle(req, resp, std::move(c));
    });
    server.setUpgradeHandler([&](avb::HttpRequest& req, int fd,
                                 std::shared_ptr<avb::ClientInfo>) {
        return api.handleUpgrade(req, fd);
    });

    gServer = &server;
    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);
    std::signal(SIGPIPE, SIG_IGN);

    // Bind first, announce second: once the banner is out the port really
    // does accept connections, so it can serve as a readiness signal.
    if (!server.listen(err)) {
        std::fprintf(stderr, "fatal: %s\n", err.c_str());
        return 1;
    }
    std::printf("avb-introspectd %s listening on %s:%u\n"
                "  data:      %s\n"
                "  frontend:  %s\n"
                "  sessions restored: %u\n",
                AVB_VERSION, bindAddr.c_str(), server.boundPort(),
                dataDir.c_str(), frontendDir.c_str(), restored);
    std::fflush(stdout);

    server.serve(); // returns once a signal called stop()

    // Graceful shutdown: tell WebSocket streams to close (1001 Going Away)
    // and give them a moment to do so politely, then wake every connection
    // still parked in a socket call (idle keep-alives, a stream blocked on a
    // stalled client), then join the serving threads. In-flight responses
    // complete; nothing here waits longer than one request.
    std::printf("shutting down\n");
    std::fflush(stdout);
    api.stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    server.drain();
    pool.stop();
    std::printf("bye\n");
    std::fflush(stdout);
    // Restore analyses run on detached threads that may still be mid-file;
    // skip static/stack destruction rather than race them at exit. All
    // persistent state was written synchronously long before this point.
    _exit(0);
}
