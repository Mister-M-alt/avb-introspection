/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * avb-introspectd — Milan/AVB protocol introspection backend.
 * Controlled exclusively over the network API (BE-4); see docs/API.md.
 */
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>

#include "api/api.h"
#include "auth/auth.h"
#include "engine/engine.h"
#include "net/http.h"
#include "store/store.h"

namespace {

avb::HttpServer* gServer = nullptr;

void onSignal(int) {
    if (gServer) gServer->stop();
}

void usage(const char* argv0) {
    std::printf(
        "usage: %s [options]\n"
        "  --port N           listen port (default 8342)\n"
        "  --data DIR         persistent data directory (default ./data)\n"
        "  --frontend DIR     static frontend directory (default ./frontend)\n"
        "  --max-threads N    serving thread cap (default 64)\n"
        "  --max-upload-mb N  pcap upload limit in MiB (default 1024)\n",
        argv0);
}

} // namespace

int main(int argc, char** argv) {
    uint16_t port = 8342;
    std::string dataDir = "./data";
    std::string frontendDir = "./frontend";
    unsigned maxThreads = 64;
    size_t maxUploadMb = 1024;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> const char* {
            if (i + 1 >= argc) {
                usage(argv[0]);
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "--port") port = (uint16_t)std::atoi(next());
        else if (a == "--data") dataDir = next();
        else if (a == "--frontend") frontendDir = next();
        else if (a == "--max-threads") maxThreads = (unsigned)std::atoi(next());
        else if (a == "--max-upload-mb") maxUploadMb = (size_t)std::atoll(next());
        else {
            usage(argv[0]);
            return a == "--help" || a == "-h" ? 0 : 2;
        }
    }

    std::string err;
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
        s->pcapFilePath = store.sessionPcapPath(meta.id);
        engine.start(s);
        ++restored;
    }

    avb::ThreadPool pool(maxThreads);
    avb::ClientRegistry clients;
    avb::HttpServer server(port, pool, maxUploadMb * 1024 * 1024, clients);
    avb::Api api(engine, auth, store, pool, clients, frontendDir);

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

    std::printf("avb-introspectd listening on :%u\n"
                "  data:      %s\n"
                "  frontend:  %s\n"
                "  sessions restored: %u\n",
                port, dataDir.c_str(), frontendDir.c_str(), restored);
    std::fflush(stdout);

    if (!server.listenAndServe(err)) {
        std::fprintf(stderr, "fatal: %s\n", err.c_str());
        return 1;
    }
    pool.stop();
    std::printf("bye\n");
    return 0;
}
