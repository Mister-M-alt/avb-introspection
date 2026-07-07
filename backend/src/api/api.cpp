/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 */
#include "api.h"

#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstring>
#include <ctime>

#include <fstream>
#include <shared_mutex>
#include <sstream>

#include "../decode/decode.h"
#include "../net/websocket.h"
#include "../pcapio/pcap_reader.h"
#include "../util/crypto_util.h"
#include "../util/decompress.h"
#include "../util/json.h"

namespace avb {

namespace {

void jsonError(HttpResponse& resp, int status, const std::string& msg) {
    resp.status = status;
    JsonWriter w;
    w.beginObj().kv("error", msg).endObj();
    resp.body = w.take();
}

std::string bearerToken(const HttpRequest& req) {
    std::string h = req.header("authorization");
    const std::string prefix = "Bearer ";
    if (h.rfind(prefix, 0) == 0) return h.substr(prefix.size());
    return {};
}

const char* statusName(int st) {
    switch (st) {
    case Session::Running: return "running";
    case Session::Done: return "done";
    default: return "error";
    }
}

void sessionSummary(JsonWriter& w, const Session& s) {
    w.kv("id", s.id);
    w.kv("name", s.name);
    w.kv("pcap_id", s.pcapId);
    int st = s.status.load();
    w.kv("status", statusName(st));
    w.kv("error", st == Session::Error ? s.errorMsg : "");
    w.kv("packets", s.packets.load());
    w.kv("events", (uint64_t)s.eventCount());
    w.kv("decode_errors", s.decodeErrors.load());
    w.kv("duration", s.duration);
    // Epoch nanoseconds of the first packet, as a string: JS doubles cannot
    // hold ns-precision epoch values, the frontend needs BigInt.
    w.kv("start_ts_ns", std::to_string(s.firstTsNanos));
    w.kv("created_at", s.createdAt);
}

bool splitSessionPath(const std::string& path, std::string& id,
                      std::string& tail) {
    // path is "/api/sessions/{id}[/tail...]"
    const std::string prefix = "/api/sessions/";
    if (path.rfind(prefix, 0) != 0) return false;
    std::string rest = path.substr(prefix.size());
    size_t slash = rest.find('/');
    if (slash == std::string::npos) {
        id = rest;
        tail.clear();
    } else {
        id = rest.substr(0, slash);
        tail = rest.substr(slash + 1);
    }
    return !id.empty();
}

std::string baseName(const std::string& path) {
    size_t slash = path.find_last_of('/');
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

/** Client IP for rate limiting / flow monitoring. Behind the nginx proxy the
 *  socket peer is always the proxy — trust X-Real-IP only when the
 *  connection actually comes from localhost (a remote client cannot spoof
 *  its way past the limiter by sending the header directly). */
std::string clientIp(const HttpRequest& req) {
    std::string sock = req.clientAddr;
    size_t colon = sock.find(':');
    if (colon != std::string::npos) sock.resize(colon);
    if (sock == "127.0.0.1") {
        std::string real = req.header("x-real-ip");
        if (!real.empty() && real.size() <= 45) return real;
    }
    return sock;
}

double envDouble(const char* name, double dflt) {
    const char* v = std::getenv(name);
    if (!v || !*v) return dflt;
    char* end = nullptr;
    double d = std::strtod(v, &end);
    return end && *end == '\0' ? d : dflt;
}

void tooMany(HttpResponse& resp, double retryAfter) {
    int ra = (int)retryAfter + 1;
    resp.extraHeaders.emplace_back("Retry-After", std::to_string(ra));
    jsonError(resp, 429,
              "rate limit exceeded — retry in " + std::to_string(ra) + " s");
}

} // namespace

Api::Api(Engine& engine, Auth& auth, Store& store, ThreadPool& pool,
         ClientRegistry& clients, std::string frontendDir)
    : mEngine(engine), mAuth(auth), mStore(store), mPool(pool),
      mClients(clients), mFrontendDir(std::move(frontendDir)),
      mStart(std::chrono::steady_clock::now()) {
    mRateRps = envDouble("AVB_RATE_RPS", 30.0);
    mRateBurst = envDouble("AVB_RATE_BURST", 90.0);
    mLoginRps = envDouble("AVB_LOGIN_RPS", 0.5);
    mLoginBurst = envDouble("AVB_LOGIN_BURST", 6.0);
    const char* noReg = std::getenv("AVB_DISABLE_REGISTRATION");
    mRegistrationDisabled = noReg && *noReg && std::string(noReg) != "0";
    mGuard.init(store.dataDir() + "/security.log");
}

void Api::handle(HttpRequest& req, HttpResponse& resp,
                 std::shared_ptr<ClientInfo> client) {
    if (req.path.rfind("/api/", 0) == 0 || req.path == "/api") {
        handleApi(req, resp, client);
        return;
    }
    handleStatic(req, resp);
}

void Api::handleApi(HttpRequest& req, HttpResponse& resp,
                    std::shared_ptr<ClientInfo> client) {
    // Captured before routing: upload handlers move the body away.
    uint64_t bytesIn = req.body.size();
    std::string method = req.method, path = req.path;
    std::string ip = clientIp(req);

    std::string actor = "ip:" + ip; // refined to "u:<user>" once authed
    Caller c;
    routeApi(req, resp, client, ip, actor, c);

    // Every API request feeds the flow monitor + per-domain traffic counters
    // (SE-7) — including rejected ones; failure patterns are the signal.
    trafficHit(c.domain.empty() ? "(unauthenticated)" : c.domain);
    mGuard.record(actor, c.domain, c.role, method, path, resp.status, bytesIn);
}

void Api::routeApi(HttpRequest& req, HttpResponse& resp,
                   std::shared_ptr<ClientInfo> client, const std::string& ip,
                   std::string& actor, Caller& c) {
    const std::string& p = req.path;
    const std::string& m = req.method;

    // Unauthenticated endpoints (SE-1).
    if (p == "/api/bootstrap" && m == "GET") {
        // Fresh deployment with no admin yet? The login screen offers to
        // create the first admin account when this is true.
        JsonWriter w;
        w.beginObj().kv("needs_admin", !mAuth.hasAdmin()).endObj();
        resp.body = w.take();
        return;
    }
    if ((p == "/api/register" || p == "/api/login") && m == "POST") {
        // Brute-force protection: per-IP bucket, tightened further while the
        // flow guard flags the address (SE-6/SE-7).
        double retry = 0;
        if (!mLimiter.allow("ip:" + ip, mLoginRps, mLoginBurst,
                            mGuard.penalty("ip:" + ip), &retry))
            return tooMany(resp, retry);
        if (p == "/api/register") return handleRegister(req, resp);
        return handleLogin(req, resp);
    }

    // Everything else requires a valid token (SE-3).
    std::string token = bearerToken(req);
    std::string user = mAuth.check(token);
    if (user.empty()) return jsonError(resp, 401, "missing or invalid token");
    if (client) client->setUser(user);
    Auth::UserInfo info = mAuth.infoOf(user);
    c = {user, info.role, info.domain.empty() ? "default" : info.domain};
    actor = "u:" + user;

    // SE-6: admins are exempt; everyone else takes from a general per-user
    // bucket, and expensive operations (upload, analysis start) from a much
    // smaller one. The flow-guard penalty throttles flagged actors harder.
    if (!c.admin()) {
        double pen = mGuard.penalty(actor), retry = 0;
        if (!mLimiter.allow(actor, mRateRps, mRateBurst, pen, &retry))
            return tooMany(resp, retry);
        bool expensive = (p == "/api/pcaps" || p == "/api/sessions") &&
                         m == "POST";
        if (expensive &&
            !mLimiter.allow("op:" + user, 0.2, 8, pen, &retry))
            return tooMany(resp, retry);
    }

    if (p == "/api/logout" && m == "POST") {
        mAuth.logout(token);
        resp.body = "{\"ok\":true}";
        return;
    }
    if (p == "/api/me" && m == "GET") {
        JsonWriter w;
        w.beginObj().kv("username", user).kv("role", c.role)
            .kv("domain", c.domain)
            .kv("domain_owner", mStore.domainOwner(c.domain) == user)
            .endObj();
        resp.body = w.take();
        return;
    }
    if (p == "/api/presence" && m == "PUT")
        return handlePresencePut(req, c, token, resp);
    if (p == "/api/presence" && m == "GET") return handlePresenceGet(c, resp);
    if (p.rfind("/api/admin/", 0) == 0) return handleAdmin(req, c, resp);
    if (p == "/api/domain" || p.rfind("/api/domain/", 0) == 0)
        return handleDomainApi(req, c, resp);
    if (p == "/api/pcaps" && m == "GET") return handlePcapsGet(c, resp);
    if (p == "/api/pcaps" && m == "POST") return handlePcapsPost(req, c, resp);
    if (p == "/api/pcaps/folders" && m == "POST")
        return handleFolderPost(req, c, resp);
    if (p.rfind("/api/pcaps/folders/", 0) == 0 && m == "DELETE")
        return handleFolderDelete(p.substr(sizeof "/api/pcaps/folders/" - 1),
                                  c, resp);
    if (p.rfind("/api/pcaps/", 0) == 0) {
        std::string pid = p.substr(sizeof "/api/pcaps/" - 1);
        if (pid.find('/') == std::string::npos && !pid.empty()) {
            if (m == "DELETE") return handlePcapDelete(pid, c, resp);
            if (m == "PUT") return handlePcapMove(req, pid, c, resp);
        }
    }
    if (p == "/api/sessions" && m == "GET") return handleSessionsGet(c, resp);
    if (p == "/api/sessions" && m == "POST")
        return handleSessionsPost(req, c, resp);
    if (p == "/api/metrics" && m == "GET") return handleMetrics(c, resp);
    if (p == "/api/devices" && m == "PUT")
        return handleDeviceNamePut(req, c, resp);

    std::string id, tail;
    if (splitSessionPath(p, id, tail)) {
        if (tail.empty() && m == "GET") return handleSessionGet(id, c, resp);
        if (tail.empty() && m == "DELETE")
            return handleSessionDelete(id, c, resp);
        if (tail == "events" && m == "GET")
            return handleEvents(req, id, c, resp);
        if (tail == "state" && m == "GET") return handleState(id, c, resp);
        if (tail == "notes" && m == "GET") return handleNotesGet(id, c, resp);
        if (tail == "notes" && m == "PUT")
            return handleNotesPut(req, id, c, resp);
        if (tail == "info" && m == "GET") return handleInfo(id, c, resp);
        if (tail.rfind("packets/", 0) == 0 && m == "GET")
            return handlePacket(id, tail.substr(8), c, resp);
        if (tail == "srcmap" && m == "GET") return handleSrcMap(id, c, resp);
        if (tail.rfind("sources/", 0) == 0 && m == "PUT")
            return handleSourceAlias(req, id, tail.substr(8), c, resp);
    }

    jsonError(resp, 404, "no such endpoint: " + m + " " + p);
}

std::shared_ptr<Session> Api::findScoped(const std::string& id,
                                         const Caller& c) const {
    auto s = mEngine.find(id);
    // Cross-domain access answers exactly like a missing id (404 upstream)
    // so object existence does not leak between tenants (SE-5).
    if (s && s->domain != c.domain) return nullptr;
    return s;
}

// ------------------------------------------------------------------ auth -

void Api::handleRegister(HttpRequest& req, HttpResponse& resp) {
    std::string perr;
    JsonValue body = JsonValue::parse(req.body, &perr);
    std::string username = body.getStr("username");
    std::string password = body.getStr("password");
    // Bootstrap: with no admin yet (fresh deployment, no AVB_ADMIN_USER), the
    // first account created IS the admin. Once an admin exists, registration
    // creates regular users as before — unless the deployment disabled open
    // registration (AVB_DISABLE_REGISTRATION=1; recommended when exposed).
    bool bootstrap = !mAuth.hasAdmin();
    if (mRegistrationDisabled && !bootstrap)
        return jsonError(resp, 403,
                         "open registration is disabled on this deployment — "
                         "ask an administrator or your domain owner for an "
                         "account");
    std::string err;
    if (!mAuth.registerUser(username, password, err,
                            bootstrap ? "admin" : "user")) {
        jsonError(resp, err == "username already exists" ? 409 : 400, err);
        return;
    }
    resp.status = 201;
    JsonWriter w;
    w.beginObj().kv("ok", true).kv("role", bootstrap ? "admin" : "user").endObj();
    resp.body = w.take();
}

void Api::handleLogin(HttpRequest& req, HttpResponse& resp) {
    JsonValue body = JsonValue::parse(req.body);
    std::string token;
    if (!mAuth.login(body.getStr("username"), body.getStr("password"), token)) {
        jsonError(resp, 401, "bad username or password");
        return;
    }
    JsonWriter w;
    w.beginObj().kv("token", token).kv("username", body.getStr("username")).endObj();
    resp.body = w.take();
}

// ----------------------------------------------------------------- pcaps -

void Api::handlePcapsGet(const Caller& c, HttpResponse& resp) {
    JsonWriter w;
    w.beginObj().key("pcaps").beginArr();
    for (auto& p : mStore.pcaps(c.domain)) {
        w.beginObj();
        w.kv("id", p.id);
        w.kv("name", p.name);
        w.kv("size", p.size);
        w.kv("uploaded_at", p.uploadedAt);
        w.kv("folder", p.folder);
        w.endObj();
    }
    w.endArr();
    w.key("folders").beginArr();
    for (auto& f : mStore.pcapFolders(c.domain)) w.value(f);
    w.endArr();
    w.endObj();
    resp.body = w.take();
}

void Api::handlePcapsPost(HttpRequest& req, const Caller& c,
                          HttpResponse& resp) {
    if (req.body.empty()) return jsonError(resp, 400, "empty upload");
    std::string name = req.queryParam("name");
    if (name.empty()) name = "capture.pcap";
    // Land the upload in the folder the user is viewing ("" = library root).
    std::string folder = req.queryParam("folder");

    std::string tmp = mStore.dataDir() + "/.upload-" +
                      std::to_string(mUploadSeq.fetch_add(1)) + ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) return jsonError(resp, 500, "cannot write temp file");
        f.write(req.body.data(), (std::streamsize)req.body.size());
    }

    // Compressed capture? Inflate through the matching system tool and store
    // the decompressed bytes — everything downstream sees a plain capture.
    std::string bytes = std::move(req.body);
    std::string tool = compressionTool(bytes);
    if (!tool.empty()) {
        std::string plain = tmp + ".plain";
        std::string derr;
        if (!decompressFile(tool, tmp, plain, derr)) {
            std::remove(tmp.c_str());
            return jsonError(resp, 400, derr);
        }
        std::ifstream f(plain, std::ios::binary);
        std::stringstream ss;
        ss << f.rdbuf();
        bytes = ss.str();
        std::remove(tmp.c_str());
        if (std::rename(plain.c_str(), tmp.c_str()) != 0) {
            std::remove(plain.c_str());
            return jsonError(resp, 500, "cannot stage decompressed capture");
        }
        name = stripCompressionSuffix(name);
    }

    // Validate before persisting: parse the (now plain) temp file.
    PcapFile probe;
    std::string perr;
    bool ok = probe.open(tmp, perr);
    std::remove(tmp.c_str());
    if (!ok) return jsonError(resp, 400, "not a valid capture: " + perr);

    std::string err;
    std::string id = mStore.addPcap(name, bytes, folder, c.domain, err);
    if (id.empty())
        return jsonError(resp, err.rfind("folder name", 0) == 0 ? 400 : 500, err);

    resp.status = 201;
    JsonWriter w;
    w.beginObj().kv("id", id).kv("name", name).kv("size", (uint64_t)bytes.size())
        .kv("folder", folder).endObj();
    resp.body = w.take();
}

void Api::handlePcapDelete(const std::string& id, const Caller& c,
                           HttpResponse& resp) {
    // Admins and the owner of the domain may delete captures — inside their
    // own domain only. Unknown and foreign ids answer the same 404.
    if (mStore.pcapDomain(id) != c.domain)
        return jsonError(resp, 404, "no such pcap " + id);
    if (!c.admin() && mStore.domainOwner(c.domain) != c.user)
        return jsonError(resp, 403,
                         "admin role or domain ownership required to delete "
                         "pcaps");
    std::string err;
    if (!mStore.removePcap(id, err))
        return jsonError(resp, err.rfind("no such", 0) == 0 ? 404 : 500, err);
    resp.body = "{\"ok\":true}";
}

void Api::handlePcapMove(HttpRequest& req, const std::string& id,
                         const Caller& c, HttpResponse& resp) {
    if (mStore.pcapDomain(id) != c.domain)
        return jsonError(resp, 404, "no such pcap " + id);
    JsonValue body = JsonValue::parse(req.body);
    const JsonValue* f = body.get("folder");
    if (!f || f->type != JsonValue::Type::String)
        return jsonError(resp, 400, "body must be {\"folder\": \"...\"} (\"\" = root)");
    std::string err;
    if (!mStore.setPcapFolder(id, f->str, err))
        return jsonError(resp, err.rfind("no such", 0) == 0 ? 404 : 400, err);
    resp.body = "{\"ok\":true}";
}

void Api::handleFolderPost(HttpRequest& req, const Caller& c,
                           HttpResponse& resp) {
    JsonValue body = JsonValue::parse(req.body);
    std::string err;
    if (!mStore.addPcapFolder(c.domain, body.getStr("name"), err))
        return jsonError(resp, 400, err);
    resp.status = 201;
    resp.body = "{\"ok\":true}";
}

void Api::handleFolderDelete(const std::string& name, const Caller& c,
                             HttpResponse& resp) {
    std::string err;
    if (!mStore.removePcapFolder(c.domain, name, err))
        return jsonError(resp, 400, err);
    resp.body = "{\"ok\":true}";
}

// -------------------------------------------------------------- sessions -

void Api::handleSessionsGet(const Caller& c, HttpResponse& resp) {
    JsonWriter w;
    w.beginObj().key("sessions").beginArr();
    for (auto& s : mEngine.list()) {
        if (s->domain != c.domain) continue; // tenancy (SE-5)
        w.beginObj();
        sessionSummary(w, *s);
        w.endObj();
    }
    w.endArr().endObj();
    resp.body = w.take();
}

void Api::handleSessionsPost(HttpRequest& req, const Caller& c,
                             HttpResponse& resp) {
    JsonValue body = JsonValue::parse(req.body);
    std::string pcapId = body.getStr("pcap_id");
    std::string path = body.getStr("path");
    // Combine several library pcaps into one timeline (merged by capture time).
    std::vector<std::string> pcapIds;
    if (auto* arr = body.get("pcap_ids"); arr)
        for (auto& v : arr->arr)
            if (!v.str.empty()) pcapIds.push_back(v.str);

    auto s = std::make_shared<Session>();
    Store::SessionMeta meta;
    meta.domain = c.domain;
    s->domain = c.domain;
    bool combine = pcapIds.size() > 1;
    if (!pcapIds.empty()) {
        for (auto& pid : pcapIds)
            if (mStore.pcapDomain(pid) != c.domain)
                return jsonError(resp, 404, "unknown pcap_id " + pid);
        meta.pcapIds = pcapIds;
        s->pcapId = meta.pcapId = pcapIds.front();
        s->name = mStore.pcapName(pcapIds.front());
        if (combine)
            s->name += " + " + std::to_string(pcapIds.size() - 1) + " more";
        meta.name = s->name;
    } else if (!pcapId.empty()) {
        if (mStore.pcapDomain(pcapId) != c.domain)
            return jsonError(resp, 404, "unknown pcap_id " + pcapId);
        s->pcapId = meta.pcapId = pcapId;
        s->name = meta.name = mStore.pcapName(pcapId);
    } else if (!path.empty()) {
        // Opening an arbitrary server-side file is a host-filesystem read —
        // administrators only (SE-5); the UI uses the upload library.
        if (!c.admin())
            return jsonError(resp, 403,
                             "opening captures by server path requires the "
                             "admin role — upload the file instead");
        struct stat st{};
        if (::stat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode))
            return jsonError(resp, 404, "no such file on backend: " + path);
        s->path = meta.path = path;
        s->name = meta.name = baseName(path);
    } else {
        return jsonError(resp, 400, "body must contain pcap_id, pcap_ids, or path");
    }

    // A compressed server-path capture is inflated to a staging file; the
    // session copies from there (its own copy stays a plain capture).
    std::string staged;
    if (!meta.path.empty()) {
        std::string tool = compressionToolForFile(meta.path);
        if (!tool.empty()) {
            staged = mStore.dataDir() + "/.open-" +
                     std::to_string(mUploadSeq.fetch_add(1)) + ".tmp";
            std::string derr;
            if (!decompressFile(tool, meta.path, staged, derr))
                return jsonError(resp, 400, derr);
            meta.resolvedPath = staged;
            s->name = meta.name = stripCompressionSuffix(meta.name);
        }
    }

    std::string serr;
    s->id = mStore.addSession(meta, serr);
    if (!staged.empty()) std::remove(staged.c_str());
    // A failed combine is a user error (overlapping / non-absolute timestamps).
    if (s->id.empty()) return jsonError(resp, combine ? 400 : 500, serr);
    s->createdAt = Store::nowIso8601();
    // Analyze the session's own copy — the folder is self-contained.
    s->pcapFilePath = mStore.sessionPcapPath(s->id);
    mEngine.start(s);

    resp.status = 201;
    JsonWriter w;
    w.beginObj().kv("id", s->id).kv("status", "running").endObj();
    resp.body = w.take();
}

void Api::handleSessionGet(const std::string& id, const Caller& c,
                           HttpResponse& resp) {
    auto s = findScoped(id, c);
    if (!s) return jsonError(resp, 404, "no such session " + id);
    JsonWriter w;
    w.beginObj();
    sessionSummary(w, *s);
    w.key("protocols").beginObj();
    for (int p = 1; p < kProtoCount; ++p) // skip ETH
        w.kv(protoName((Proto)p), s->protoCounts[(size_t)p].load());
    w.endObj();
    w.endObj();
    resp.body = w.take();
}

void Api::handleSessionDelete(const std::string& id, const Caller& c,
                              HttpResponse& resp) {
    if (!findScoped(id, c))
        return jsonError(resp, 404, "no such session " + id);
    if (!mEngine.remove(id)) return jsonError(resp, 404, "no such session " + id);
    mStore.removeSession(id);
    resp.body = "{\"ok\":true}";
}

// ---------------------------------------------------------------- events -

void Api::handleEvents(HttpRequest& req, const std::string& id,
                       const Caller& c, HttpResponse& resp) {
    auto s = findScoped(id, c);
    if (!s) return jsonError(resp, 404, "no such session " + id);

    if (req.queryParam("compact") == "1") {
        JsonWriter w;
        w.beginObj();
        w.key("protos").beginArr();
        for (int p = 0; p < kProtoCount; ++p) w.value(protoName((Proto)p));
        w.endArr();
        w.key("kinds").beginArr();
        w.value("packet").value("transition").value("error");
        w.endArr();
        {
            std::shared_lock lk(s->mu);
            w.key("events").beginArr();
            for (auto& e : s->events) {
                w.beginArr();
                w.value((uint64_t)e.i);
                w.value((uint64_t)e.n);
                w.value(e.ts);
                w.value((uint64_t)e.proto);
                w.value((uint64_t)e.kind);
                w.value(e.type);
                w.endArr();
            }
            w.endArr();
        }
        w.endObj();
        resp.body = w.take();
        return;
    }

    // Filters.
    uint32_t protoMask = 0, kindMask = 0;
    auto parseList = [](const std::string& csv, auto nameToBit) -> uint32_t {
        if (csv.empty()) return ~0u;
        uint32_t mask = 0;
        size_t start = 0;
        while (start <= csv.size()) {
            size_t comma = csv.find(',', start);
            std::string item = csv.substr(
                start, comma == std::string::npos ? std::string::npos
                                                  : comma - start);
            int bit = nameToBit(item);
            if (bit >= 0) mask |= (1u << bit);
            if (comma == std::string::npos) break;
            start = comma + 1;
        }
        return mask;
    };
    protoMask = parseList(req.queryParam("proto"), [](const std::string& n) {
        for (int p = 0; p < kProtoCount; ++p)
            if (n == protoName((Proto)p)) return p;
        return -1;
    });
    kindMask = parseList(req.queryParam("kind"), [](const std::string& n) {
        if (n == "packet") return 0;
        if (n == "transition") return 1;
        if (n == "error") return 2;
        return -1;
    });

    size_t offset = 0, limit = 1000;
    if (auto v = req.queryParam("offset"); !v.empty())
        offset = (size_t)std::strtoull(v.c_str(), nullptr, 10);
    if (auto v = req.queryParam("limit"); !v.empty())
        limit = (size_t)std::strtoull(v.c_str(), nullptr, 10);
    if (limit > 10000) limit = 10000;

    JsonWriter w;
    w.beginObj();
    {
        std::shared_lock lk(s->mu);
        size_t matched = 0, written = 0;
        std::string eventsJson;
        JsonWriter ew;
        ew.beginArr();
        for (auto& e : s->events) {
            bool match = (protoMask & (1u << (int)e.proto)) &&
                         (kindMask & (1u << (int)e.kind));
            if (!match) continue;
            if (matched >= offset && written < limit) {
                e.toJson(ew);
                ++written;
            }
            ++matched;
        }
        ew.endArr();
        w.kv("total", (uint64_t)s->events.size());
        w.kv("matched", (uint64_t)matched);
        w.kv("offset", (uint64_t)offset);
        w.key("events").raw(ew.take());
    }
    w.endObj();
    resp.body = w.take();
}

// --------------------------------------------------------------- packets -

void Api::handlePacket(const std::string& id, const std::string& nStr,
                       const Caller& c, HttpResponse& resp) {
    auto s = findScoped(id, c);
    if (!s) return jsonError(resp, 404, "no such session " + id);
    char* end = nullptr;
    unsigned long long n = std::strtoull(nStr.c_str(), &end, 10);
    if (!end || *end != '\0' || n == 0 || n > s->pindex.size())
        return jsonError(resp, 404, "no such packet " + nStr);

    const PcapPacket& p = s->pindex[n - 1];
    std::ifstream f(s->pcapFilePath, std::ios::binary);
    if (!f) return jsonError(resp, 500, "capture file unavailable");
    std::vector<uint8_t> bytes(p.caplen);
    f.seekg((std::streamoff)p.offset);
    f.read(reinterpret_cast<char*>(bytes.data()), p.caplen);
    if (!f) return jsonError(resp, 500, "capture file truncated");

    auto layers = inspectPacket(bytes);

    // Which source capture this packet came from (combined sessions only): the
    // sidecar holds one uint16 per packet, in capture order.
    int srcIdx = -1;
    {
        std::ifstream sf(mStore.sessionSrcMapPath(id), std::ios::binary);
        if (sf) {
            sf.seekg((std::streamoff)((n - 1) * 2));
            uint16_t v = 0;
            if (sf.read(reinterpret_cast<char*>(&v), 2)) srcIdx = (int)v;
        }
    }

    JsonWriter w;
    w.beginObj();
    w.kv("n", (uint64_t)n);
    w.kv("ts", (double)(p.tsNanos - s->firstTsNanos) / 1e9);
    w.kv("len", (uint64_t)p.origlen);
    w.kv("caplen", (uint64_t)p.caplen);
    if (srcIdx >= 0) {
        auto sources = mStore.sessionSources(id);
        if ((size_t)srcIdx < sources.size()) {
            w.kv("source_index", (uint64_t)srcIdx);
            w.kv("source_alias", sources[srcIdx].alias);
            w.kv("source_name", sources[srcIdx].name);
        }
    }
    w.key("layers").beginArr();
    for (auto& l : layers) {
        w.beginObj();
        w.kv("service", l.service);
        w.key("fields").beginArr();
        for (auto& fl : l.fields) {
            w.beginObj();
            w.kv("name", fl.name);
            w.kv("value", fl.value);
            w.endObj();
        }
        w.endArr();
        w.endObj();
    }
    w.endArr();
    w.kv("hex", hexDump(bytes));
    w.endObj();
    resp.body = w.take();
}

void Api::handleSrcMap(const std::string& id, const Caller& c,
                       HttpResponse& resp) {
    if (!findScoped(id, c))
        return jsonError(resp, 404, "no such session " + id);
    std::ifstream f(mStore.sessionSrcMapPath(id), std::ios::binary);
    if (!f) return jsonError(resp, 404, "session has no source map (single capture)");
    std::stringstream ss;
    ss << f.rdbuf();
    resp.contentType = "application/octet-stream";
    resp.body = ss.str();
}

void Api::handleSourceAlias(HttpRequest& req, const std::string& id,
                            const std::string& idxStr, const Caller& c,
                            HttpResponse& resp) {
    if (!findScoped(id, c))
        return jsonError(resp, 404, "no such session " + id);
    char* end = nullptr;
    unsigned long long idx = std::strtoull(idxStr.c_str(), &end, 10);
    if (!end || *end != '\0')
        return jsonError(resp, 400, "bad source index " + idxStr);
    JsonValue body = JsonValue::parse(req.body);
    std::string alias = body.getStr("alias");
    std::string err;
    if (!mStore.setSessionAlias(id, (size_t)idx, alias, err))
        return jsonError(resp, err.find("out of range") != std::string::npos ? 400 : 500, err);
    JsonWriter w;
    w.beginObj().kv("index", (uint64_t)idx).kv("alias", alias).endObj();
    resp.body = w.take();
}

// ----------------------------------------------------------------- notes -

namespace {

/** Notes revision: 16 hex chars of SHA-1 over the content. Stateless, so it
 *  stays consistent across restarts and between concurrent editors. */
std::string notesRev(const std::string& markdown) {
    auto d = sha1(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(markdown.data()), markdown.size()));
    return hexDump(std::span<const uint8_t>(d.data(), 8));
}

} // namespace

void Api::handleNotesGet(const std::string& id, const Caller& c,
                         HttpResponse& resp) {
    if (!findScoped(id, c))
        return jsonError(resp, 404, "no such session " + id);
    std::string md = mStore.readNotes(id);
    JsonWriter w;
    w.beginObj().kv("markdown", md).kv("rev", notesRev(md)).endObj();
    resp.body = w.take();
}

void Api::handleNotesPut(HttpRequest& req, const std::string& id,
                         const Caller& c, HttpResponse& resp) {
    if (!findScoped(id, c))
        return jsonError(resp, 404, "no such session " + id);
    std::string perr;
    JsonValue body = JsonValue::parse(req.body, &perr);
    const JsonValue* md = body.get("markdown");
    if (!md || md->type != JsonValue::Type::String)
        return jsonError(resp, 400, "body must be {\"markdown\": \"...\"}");

    // Optimistic concurrency: when the client sends the revision its edit
    // was based on, a mismatch means someone else saved in between (409
    // with the current content so the client can merge). A PUT without
    // `rev` keeps the old last-write-wins behavior.
    std::string baseRev = body.getStr("rev");
    if (!baseRev.empty()) {
        std::string current = mStore.readNotes(id);
        std::string currentRev = notesRev(current);
        if (baseRev != currentRev) {
            resp.status = 409;
            JsonWriter w;
            w.beginObj();
            w.kv("error", "conflict — the notes were modified by someone else");
            w.kv("rev", currentRev);
            w.kv("markdown", current);
            w.endObj();
            resp.body = w.take();
            return;
        }
    }

    std::string err;
    if (!mStore.writeNotes(id, md->str, err)) return jsonError(resp, 500, err);
    JsonWriter w;
    w.beginObj().kv("ok", true).kv("rev", notesRev(md->str)).endObj();
    resp.body = w.take();
}

// ----------------------------------------------------------------- state -

void Api::handleState(const std::string& id, const Caller& c,
                      HttpResponse& resp) {
    auto s = findScoped(id, c);
    if (!s) return jsonError(resp, 404, "no such session " + id);
    resp.body = s->stateJson();
}

// -------------------------------------------------------------- presence -

void Api::handlePresencePut(HttpRequest& req, const Caller& c,
                            const std::string& token, HttpResponse& resp) {
    JsonValue body = JsonValue::parse(req.body);
    std::string view = body.getStr("view");
    if (view.size() > 128) view.resize(128);
    auto now = std::chrono::steady_clock::now();
    {
        std::lock_guard lk(mPresenceMu);
        mPresence[token] = {c.user, view, c.domain, now};
        // Lazy expiry of stale entries (closed tabs, logouts).
        for (auto it = mPresence.begin(); it != mPresence.end();) {
            if (now - it->second.seen > std::chrono::seconds(60))
                it = mPresence.erase(it);
            else
                ++it;
        }
    }
    resp.body = "{\"ok\":true}";
}

void Api::handlePresenceGet(const Caller& c, HttpResponse& resp) {
    auto now = std::chrono::steady_clock::now();
    JsonWriter w;
    w.beginObj().key("users").beginArr();
    {
        std::lock_guard lk(mPresenceMu);
        for (auto& [token, pr] : mPresence) {
            // Presence is domain-scoped; only global admins see everyone.
            if (!c.admin() && pr.domain != c.domain) continue;
            double idle = std::chrono::duration<double>(now - pr.seen).count();
            if (idle > 60) continue;
            w.beginObj();
            w.kv("username", pr.user);
            w.kv("view", pr.view);
            w.kv("idle_s", idle);
            if (c.admin()) w.kv("domain", pr.domain);
            w.endObj();
        }
    }
    w.endArr().endObj();
    resp.body = w.take();
}

// ----------------------------------------------------------------- admin -

void Api::handleAdmin(HttpRequest& req, const Caller& c, HttpResponse& resp) {
    if (!c.admin()) return jsonError(resp, 403, "admin role required");
    const std::string& p = req.path;
    const std::string& m = req.method;

    if (p == "/api/admin/users" && m == "GET") {
        // Presence snapshot keyed by user for the online/view columns.
        std::map<std::string, std::pair<std::string, double>> online;
        auto now = std::chrono::steady_clock::now();
        {
            std::lock_guard lk(mPresenceMu);
            for (auto& [token, pr] : mPresence) {
                double idle =
                    std::chrono::duration<double>(now - pr.seen).count();
                if (idle > 60) continue;
                auto it = online.find(pr.user);
                if (it == online.end() || idle < it->second.second)
                    online[pr.user] = {pr.view, idle};
            }
        }
        JsonWriter w;
        w.beginObj().key("users").beginArr();
        for (auto& u : mAuth.users()) {
            w.beginObj();
            w.kv("username", u.username);
            w.kv("role", u.role);
            w.kv("domain", u.domain);
            auto it = online.find(u.username);
            w.kv("online", it != online.end());
            w.kv("view", it != online.end() ? it->second.first : "");
            w.endObj();
        }
        w.endArr().endObj();
        resp.body = w.take();
        return;
    }
    if (p == "/api/admin/users" && m == "POST") {
        JsonValue body = JsonValue::parse(req.body);
        std::string domain = body.getStr("domain", "default");
        if (domain.empty()) domain = "default";
        if (!mStore.hasDomain(domain))
            return jsonError(resp, 400, "no such domain " + domain);
        std::string err;
        if (!mAuth.registerUser(body.getStr("username"),
                                body.getStr("password"), err,
                                body.getStr("role", "user"), domain))
            return jsonError(resp, err == "username already exists" ? 409 : 400,
                             err);
        resp.status = 201;
        resp.body = "{\"ok\":true}";
        return;
    }
    // ---- domain lifecycle (SE-5): the global admin creates a domain and
    // names its owner; the owner then manages its users via /api/domain. ----
    if (p == "/api/admin/domains" && m == "GET") {
        auto pcaps = mStore.pcaps();
        auto sessions = mStore.sessions();
        auto users = mAuth.users();
        JsonWriter w;
        w.beginObj().key("domains").beginArr();
        for (auto& d : mStore.domains()) {
            uint64_t bytes = 0, np = 0, ns = 0, nu = 0;
            for (auto& pm : pcaps)
                if (pm.domain == d.id) { ++np; bytes += pm.size; }
            for (auto& sm : sessions)
                if (sm.domain == d.id) ++ns;
            for (auto& u : users)
                if (u.domain == d.id) ++nu;
            w.beginObj();
            w.kv("id", d.id);
            w.kv("name", d.name);
            w.kv("owner", d.owner);
            w.kv("created_at", d.createdAt);
            w.kv("users", nu);
            w.kv("sessions", ns);
            w.kv("pcaps", np);
            w.kv("pcap_bytes", bytes);
            w.endObj();
        }
        w.endArr().endObj();
        resp.body = w.take();
        return;
    }
    if (p == "/api/admin/domains" && m == "POST") {
        JsonValue body = JsonValue::parse(req.body);
        std::string id = body.getStr("id");
        std::string name = body.getStr("name");
        std::string owner = body.getStr("owner");
        std::string ownerPass = body.getStr("owner_password");
        if (owner.empty())
            return jsonError(resp, 400,
                             "body must contain id, owner (username) and, for "
                             "a new owner account, owner_password");
        std::string err;
        bool ownerExists = !mAuth.roleOf(owner).empty();
        if (!ownerExists && ownerPass.empty())
            return jsonError(resp, 400,
                             "owner " + owner +
                                 " does not exist — provide owner_password to "
                                 "create the account");
        if (!mStore.addDomain(id, name, owner, err))
            return jsonError(resp, err == "domain already exists" ? 409 : 400,
                             err);
        // Owner account: created inside the domain, or moved into it.
        if (!ownerExists) {
            if (!mAuth.registerUser(owner, ownerPass, err, "user", id)) {
                std::vector<std::string> none;
                std::string derr;
                mStore.removeDomain(id, false, none, derr);
                return jsonError(resp, 400, "cannot create owner: " + err);
            }
        } else if (!mAuth.setDomain(owner, id, err)) {
            return jsonError(resp, 500, err);
        }
        resp.status = 201;
        JsonWriter w;
        w.beginObj().kv("ok", true).kv("id", id).kv("owner", owner).endObj();
        resp.body = w.take();
        return;
    }
    const std::string domPrefix = "/api/admin/domains/";
    if (p.rfind(domPrefix, 0) == 0 && m == "DELETE") {
        std::string id = p.substr(domPrefix.size());
        bool force = req.queryParam("force") == "1";
        std::vector<std::string> removedSessions;
        std::string err;
        if (!mStore.removeDomain(id, force, removedSessions, err))
            return jsonError(resp, err == "no such domain" ? 404 : 400, err);
        for (auto& sid : removedSessions) mEngine.remove(sid);
        // Its users fall back into the built-in domain (accounts are not
        // deleted — the admin can remove them explicitly).
        std::string uerr;
        for (auto& u : mAuth.users())
            if (u.domain == id) mAuth.setDomain(u.username, "default", uerr);
        resp.body = "{\"ok\":true}";
        return;
    }
    if (p == "/api/admin/monitor" && m == "GET")
        return handleAdminMonitor(resp);
    if (p == "/api/admin/security" && m == "GET") {
        JsonWriter w;
        mGuard.snapshot(w);
        resp.body = w.take();
        return;
    }
    if (p == "/api/admin/storage" && m == "GET") {
        JsonWriter w;
        w.beginObj();
        w.kv("pcap_root", mStore.pcapRoot());
        w.kv("default_root", mStore.defaultPcapRoot());
        w.kv("pcap_count", (uint64_t)mStore.pcaps().size());
        w.endObj();
        resp.body = w.take();
        return;
    }
    if (p == "/api/admin/storage" && m == "PUT") {
        JsonValue body = JsonValue::parse(req.body);
        const JsonValue* root = body.get("pcap_root");
        if (!root || root->type != JsonValue::Type::String)
            return jsonError(resp, 400,
                             "body must be {\"pcap_root\": \"/abs/path\"} "
                             "(\"\" resets to the default)");
        std::string err;
        if (!mStore.setPcapRoot(root->str, err)) return jsonError(resp, 400, err);
        JsonWriter w;
        w.beginObj().kv("ok", true).kv("pcap_root", mStore.pcapRoot()).endObj();
        resp.body = w.take();
        return;
    }
    const std::string prefix = "/api/admin/users/";
    if (p.rfind(prefix, 0) == 0 && m == "DELETE") {
        std::string name = p.substr(prefix.size());
        if (name == c.user)
            return jsonError(resp, 400, "cannot delete your own account");
        std::string err;
        if (!mAuth.deleteUser(name, err))
            return jsonError(resp, err == "no such user" ? 404 : 400, err);
        resp.body = "{\"ok\":true}";
        return;
    }
    jsonError(resp, 404, "no such admin endpoint: " + m + " " + p);
}

// ---------------------------------------------------- domain self-service -

void Api::handleDomainApi(HttpRequest& req, const Caller& c,
                          HttpResponse& resp) {
    const std::string& p = req.path;
    const std::string& m = req.method;
    bool owner = mStore.domainOwner(c.domain) == c.user || c.admin();

    if (p == "/api/domain" && m == "GET") {
        std::string domName = c.domain;
        for (auto& d : mStore.domains())
            if (d.id == c.domain) { domName = d.name; break; }
        JsonWriter w;
        w.beginObj();
        w.kv("id", c.domain);
        w.kv("name", domName);
        w.kv("owner", mStore.domainOwner(c.domain));
        w.kv("is_owner", owner);
        if (owner) {
            w.key("users").beginArr();
            for (auto& u : mAuth.users()) {
                if (u.domain != c.domain) continue;
                w.beginObj();
                w.kv("username", u.username);
                w.kv("role", u.role);
                w.kv("owner", u.username == mStore.domainOwner(c.domain));
                w.endObj();
            }
            w.endArr();
        }
        w.endObj();
        resp.body = w.take();
        return;
    }
    if (!owner)
        return jsonError(resp, 403,
                         "domain ownership (or admin role) required");
    if (p == "/api/domain/users" && m == "POST") {
        JsonValue body = JsonValue::parse(req.body);
        std::string err;
        // Owners only ever mint regular users, always inside their domain.
        if (!mAuth.registerUser(body.getStr("username"),
                                body.getStr("password"), err, "user",
                                c.domain))
            return jsonError(resp, err == "username already exists" ? 409 : 400,
                             err);
        resp.status = 201;
        resp.body = "{\"ok\":true}";
        return;
    }
    const std::string prefix = "/api/domain/users/";
    if (p.rfind(prefix, 0) == 0 && m == "DELETE") {
        std::string name = p.substr(prefix.size());
        Auth::UserInfo victim = mAuth.infoOf(name);
        if (victim.username.empty() || victim.domain != c.domain)
            return jsonError(resp, 404, "no such user in your domain");
        if (name == c.user)
            return jsonError(resp, 400, "cannot delete your own account");
        if (victim.role == "admin" ||
            name == mStore.domainOwner(c.domain))
            return jsonError(resp, 403,
                             "cannot delete admins or the domain owner");
        std::string err;
        if (!mAuth.deleteUser(name, err))
            return jsonError(resp, err == "no such user" ? 404 : 400, err);
        resp.body = "{\"ok\":true}";
        return;
    }
    jsonError(resp, 404, "no such endpoint: " + m + " " + p);
}

// ---------------------------------------------------------------- monitor -

void Api::trafficHit(const std::string& domain) {
    int64_t nowSec = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::steady_clock::now().time_since_epoch())
                         .count();
    std::lock_guard lk(mTrafficMu);
    DomainTraffic& t = mTraffic[domain];
    if (t.lastSec != nowSec) {
        // Clear every slot skipped since the last hit, then move on.
        int64_t gap = nowSec - t.lastSec;
        if (t.lastSec == 0 || gap >= 60) {
            t.slots.fill(0);
        } else {
            for (int64_t s = t.lastSec + 1; s <= nowSec; ++s)
                t.slots[(size_t)(s % 60)] = 0;
        }
        t.lastSec = nowSec;
    }
    t.slots[(size_t)(nowSec % 60)]++;
    t.total++;
}

double Api::trafficPerMin(DomainTraffic& t, int64_t nowSec) const {
    if (t.lastSec == 0 || nowSec - t.lastSec >= 60) return 0;
    double sum = 0;
    for (int64_t s = nowSec - 59; s <= nowSec; ++s)
        if (s > t.lastSec - 60 && s <= t.lastSec)
            sum += t.slots[(size_t)(s % 60)];
    return sum;
}

void Api::handleAdminMonitor(HttpResponse& resp) {
    // ---- CPU: deltas between two /proc samples (min 200 ms apart) ----
    double procPct, sysPct;
    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (cores < 1) cores = 1;
    {
        std::lock_guard lk(mCpuMu);
        auto now = std::chrono::steady_clock::now();
        double dt = std::chrono::duration<double>(now - mCpuAt).count();
        if (mCpuAt.time_since_epoch().count() == 0 || dt > 0.2) {
            uint64_t proc = 0, total = 0, idle = 0;
            {
                std::ifstream f("/proc/self/stat");
                std::string tok;
                // fields 14 (utime) and 15 (stime); field 2 (comm) may hold
                // spaces, so skip past the closing paren first.
                std::string all;
                std::getline(f, all);
                size_t par = all.rfind(')');
                if (par != std::string::npos) {
                    std::istringstream ss(all.substr(par + 2));
                    std::string v;
                    for (int i = 3; i <= 15 && ss >> v; ++i) {
                        if (i == 14 || i == 15)
                            proc += std::strtoull(v.c_str(), nullptr, 10);
                    }
                }
            }
            {
                std::ifstream f("/proc/stat");
                std::string cpu;
                f >> cpu; // "cpu"
                uint64_t v = 0;
                for (int i = 0; i < 8 && (f >> v); ++i) {
                    total += v;
                    if (i == 3) idle = v; // idle column
                }
            }
            long hz = sysconf(_SC_CLK_TCK);
            if (hz < 1) hz = 100;
            if (mCpuAt.time_since_epoch().count() != 0 && dt > 0) {
                double dproc = (double)(proc - mCpuProcJiffies) / (double)hz;
                mCpuProcPct = 100.0 * dproc / dt; // % of one core, like top
                uint64_t dtot = total - mCpuTotalJiffies;
                uint64_t didl = idle - mCpuIdleJiffies;
                mCpuSysPct =
                    dtot ? 100.0 * (double)(dtot - didl) / (double)dtot : 0;
            }
            mCpuProcJiffies = proc;
            mCpuTotalJiffies = total;
            mCpuIdleJiffies = idle;
            mCpuAt = now;
        }
        procPct = mCpuProcPct;
        sysPct = mCpuSysPct;
    }

    uint64_t rssKb = 0;
    {
        std::ifstream f("/proc/self/status");
        std::string line;
        while (std::getline(f, line))
            if (line.rfind("VmRSS:", 0) == 0)
                rssKb = std::strtoull(line.c_str() + 6, nullptr, 10);
    }
    uint64_t memTotalKb = 0, memAvailKb = 0;
    {
        std::ifstream f("/proc/meminfo");
        std::string line;
        while (std::getline(f, line)) {
            if (line.rfind("MemTotal:", 0) == 0)
                memTotalKb = std::strtoull(line.c_str() + 9, nullptr, 10);
            else if (line.rfind("MemAvailable:", 0) == 0)
                memAvailKb = std::strtoull(line.c_str() + 13, nullptr, 10);
        }
    }

    // ---- per-domain inventory + activity ----
    auto pcaps = mStore.pcaps();
    auto sessionsMeta = mStore.sessions();
    auto users = mAuth.users();
    auto engineSessions = mEngine.list();
    std::map<std::string, int> online, wsClients;
    {
        auto now = std::chrono::steady_clock::now();
        std::lock_guard lk(mPresenceMu);
        for (auto& [token, pr] : mPresence)
            if (std::chrono::duration<double>(now - pr.seen).count() <= 60)
                online[pr.domain]++;
    }
    for (auto& cl : mClients.list())
        if (cl->kind == "ws") wsClients[mAuth.domainOf(cl->getUser())]++;
    int64_t nowSec = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::steady_clock::now().time_since_epoch())
                         .count();

    JsonWriter w;
    w.beginObj();
    w.key("cpu").beginObj();
    w.kv("process_pct", procPct); // % of one core
    w.kv("system_pct", sysPct);   // % of all cores
    w.kv("cores", (uint64_t)cores);
    w.endObj();
    w.key("mem").beginObj();
    w.kv("rss_kb", rssKb);
    w.kv("total_kb", memTotalKb);
    w.kv("available_kb", memAvailKb);
    w.endObj();
    w.kv("uptime_s", std::chrono::duration<double>(
                         std::chrono::steady_clock::now() - mStart)
                         .count());

    w.key("domains").beginArr();
    for (auto& d : mStore.domains()) {
        uint64_t np = 0, bytes = 0, ns = 0, running = 0, nu = 0;
        for (auto& pm : pcaps)
            if (pm.domain == d.id) { ++np; bytes += pm.size; }
        for (auto& sm : sessionsMeta)
            if (sm.domain == d.id) ++ns;
        for (auto& es : engineSessions)
            if (es->domain == d.id && es->status.load() == Session::Running)
                ++running;
        for (auto& u : users)
            if (u.domain == d.id) ++nu;
        double rpm = 0;
        {
            std::lock_guard lk(mTrafficMu);
            auto it = mTraffic.find(d.id);
            if (it != mTraffic.end()) rpm = trafficPerMin(it->second, nowSec);
        }
        w.beginObj();
        w.kv("id", d.id);
        w.kv("name", d.name);
        w.kv("owner", d.owner);
        w.kv("users", nu);
        w.kv("online", (uint64_t)online[d.id]);
        w.kv("sessions", ns);
        w.kv("running", running);
        w.kv("pcaps", np);
        w.kv("pcap_bytes", bytes);
        w.kv("req_per_min", rpm);
        w.kv("ws_clients", (uint64_t)wsClients[d.id]);
        w.endObj();
    }
    w.endArr();
    w.endObj();
    resp.body = w.take();
}

// ------------------------------------------------------------------ info -

namespace {

std::string isoFromSec(time_t t) {
    if (t <= 0) return "";
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

} // namespace

void Api::handleInfo(const std::string& id, const Caller& c,
                     HttpResponse& resp) {
    auto s = findScoped(id, c);
    if (!s) return jsonError(resp, 404, "no such session " + id);

    JsonWriter w;
    w.beginObj();

    // The session's own capture copy (BE-9) — creation time via statx when
    // the filesystem provides a birth time.
    w.key("file").beginObj();
    w.kv("path", s->pcapFilePath);
    struct stat st{};
    if (::stat(s->pcapFilePath.c_str(), &st) == 0) {
        w.kv("size", (uint64_t)st.st_size);
        w.kv("modified", isoFromSec(st.st_mtime));
        w.kv("accessed", isoFromSec(st.st_atime));
        struct statx stx{};
        std::string created;
        if (::statx(AT_FDCWD, s->pcapFilePath.c_str(), 0, STATX_BTIME, &stx) == 0 &&
            (stx.stx_mask & STATX_BTIME))
            created = isoFromSec((time_t)stx.stx_btime.tv_sec);
        w.kv("created", created);
    } else {
        w.kv("size", (uint64_t)0);
        w.kv("modified", "");
        w.kv("accessed", "");
        w.kv("created", "");
    }
    w.endObj();

    w.key("capture").beginObj();
    w.kv("start_ts_ns", std::to_string(s->firstTsNanos));
    w.kv("end_ts_ns", std::to_string(s->lastTsNanos));
    w.kv("start_iso", isoFromSec((time_t)(s->firstTsNanos / 1000000000ull)));
    w.kv("end_iso", isoFromSec((time_t)(s->lastTsNanos / 1000000000ull)));
    w.kv("duration", s->duration);
    w.kv("packets", s->packets.load());
    w.endObj();

    w.key("session").beginObj();
    w.kv("id", s->id);
    w.kv("name", s->name);
    w.kv("created_at", s->createdAt);
    w.endObj();

    // Source captures this session was combined from (empty for a single pcap).
    w.key("sources").beginArr();
    {
        auto sources = mStore.sessionSources(id);
        for (size_t i = 0; i < sources.size(); ++i) {
            w.beginObj();
            w.kv("index", (uint64_t)i);
            w.kv("pcap_id", sources[i].pcapId);
            w.kv("name", sources[i].name);
            w.kv("alias", sources[i].alias);
            w.endObj();
        }
    }
    w.endArr();

    auto userNames = mStore.deviceNames(c.domain);
    w.key("devices").beginArr();
    {
        std::lock_guard st2(s->stateMu);
        for (auto& [mac, dev] : s->devices) {
            std::string macS = macStr(mac);
            w.beginObj();
            w.kv("mac", macS);
            w.kv("packets", dev.packets);
            w.key("protocols").beginArr();
            for (int p = 1; p < kProtoCount; ++p)
                if (dev.protoMask & (1u << p)) w.value(protoName((Proto)p));
            w.endArr();
            w.kv("entity_id", dev.entityId ? idStr(dev.entityId) : "");
            // Secondary entity ids proven to originate from this MAC —
            // lets the frontend attach controller/listener state (ACMP,
            // AECP) to devices that never advertise via ADP.
            w.key("assoc_entity_ids").beginArr();
            for (uint64_t aid : dev.assocIds)
                if (aid != dev.entityId) w.value(idStr(aid));
            w.endArr();
            std::string autoName;
            if (dev.entityId && s->logic)
                autoName = s->logic->shared.nameOf(dev.entityId);
            w.kv("entity_name", autoName);
            auto it = userNames.find(macS);
            w.kv("name", it == userNames.end() ? "" : it->second);
            w.endObj();
        }
    }
    w.endArr();

    w.endObj();
    resp.body = w.take();
}

void Api::handleDeviceNamePut(HttpRequest& req, const Caller& c,
                              HttpResponse& resp) {
    JsonValue body = JsonValue::parse(req.body);
    std::string mac = body.getStr("mac");
    const JsonValue* nameV = body.get("name");
    if (mac.size() != 17 || !nameV || nameV->type != JsonValue::Type::String)
        return jsonError(resp, 400,
                         "body must be {\"mac\": \"aa:bb:cc:dd:ee:ff\", "
                         "\"name\": \"...\"}");
    for (char& ch : mac)
        if (ch >= 'A' && ch <= 'F') ch = (char)(ch - 'A' + 'a');
    std::string name = nameV->str;
    if (name.size() > 64) return jsonError(resp, 400, "name too long (max 64)");
    std::string err;
    if (!mStore.setDeviceName(c.domain, mac, name, err))
        return jsonError(resp, 500, err);
    resp.body = "{\"ok\":true}";
}

// --------------------------------------------------------------- metrics -

void Api::handleMetrics(const Caller& c, HttpResponse& resp) {
    JsonWriter w;
    w.beginObj();

    rusage ru{};
    getrusage(RUSAGE_SELF, &ru);
    uint64_t rssKb = 0, threads = 0;
    {
        std::ifstream f("/proc/self/status");
        std::string line;
        while (std::getline(f, line)) {
            if (line.rfind("VmRSS:", 0) == 0)
                rssKb = std::strtoull(line.c_str() + 6, nullptr, 10);
            else if (line.rfind("Threads:", 0) == 0)
                threads = std::strtoull(line.c_str() + 8, nullptr, 10);
        }
    }
    double uptime = std::chrono::duration<double>(
                        std::chrono::steady_clock::now() - mStart)
                        .count();
    w.key("process").beginObj();
    w.kv("cpu_user_s", ru.ru_utime.tv_sec + ru.ru_utime.tv_usec / 1e6);
    w.kv("cpu_sys_s", ru.ru_stime.tv_sec + ru.ru_stime.tv_usec / 1e6);
    w.kv("rss_kb", rssKb);
    w.kv("uptime_s", uptime);
    w.kv("threads", threads);
    w.endObj();

    w.key("pool").beginObj();
    w.kv("threads", (uint64_t)mPool.threadCount());
    w.kv("max_threads", (uint64_t)mPool.maxThreads());
    w.kv("queued", (uint64_t)mPool.queued());
    w.kv("active", (uint64_t)mPool.active());
    w.endObj();

    w.key("sessions").beginArr();
    for (auto& s : mEngine.list()) {
        if (s->domain != c.domain && !c.admin()) continue; // tenancy (SE-5)
        uint64_t ms = s->analysisMs.load();
        w.beginObj();
        w.kv("id", s->id);
        w.kv("packets", s->packets.load());
        w.kv("events", (uint64_t)s->eventCount());
        w.kv("decode_errors", s->decodeErrors.load());
        w.kv("analysis_ms", ms);
        w.kv("pps", ms ? (double)s->packets.load() * 1000.0 / (double)ms : 0.0);
        w.endObj();
    }
    w.endArr();

    // The connected-clients list names users and addresses across all
    // domains — admins only.
    w.key("clients").beginArr();
    if (c.admin()) {
        for (auto& cl : mClients.list()) {
            w.beginObj();
            w.kv("addr", cl->addr);
            w.kv("user", cl->getUser());
            w.kv("kind", cl->kind);
            w.kv("messages", cl->messages.load());
            w.kv("bytes_sent", cl->bytesSent.load());
            w.kv("connected_s",
                 std::chrono::duration<double>(
                     std::chrono::steady_clock::now() - cl->since)
                     .count());
            w.endObj();
        }
    }
    w.endArr();

    w.endObj();
    resp.body = w.take();
}

// ------------------------------------------------------------- websocket -

bool Api::handleUpgrade(HttpRequest& req, int fd) {
    // We always own fd from here on.
    std::string key = req.header("sec-websocket-key");
    if (req.path != "/api/ws" || key.empty()) {
        ::close(fd);
        return true;
    }
    if (!WebSocket::handshake(fd, key)) {
        ::close(fd);
        return true;
    }

    WebSocket ws(fd);
    std::string user = mAuth.check(req.queryParam("token"));
    if (user.empty()) {
        ws.sendClose(4001, "bad token");
        ::close(fd);
        return true;
    }
    std::string sessionId = req.queryParam("session");
    auto s = mEngine.find(sessionId);
    // Same tenancy rule as the REST endpoints: a foreign session is
    // indistinguishable from a missing one (SE-5).
    if (!s || s->domain != mAuth.domainOf(user)) {
        ws.sendClose(4004, "unknown session");
        ::close(fd);
        return true;
    }

    streamSession(fd, sessionId, user, req.clientAddr);
    ::close(fd);
    return true;
}

void Api::streamSession(int fd, const std::string& sessionId,
                        const std::string& user, const std::string& addr) {
    auto s = mEngine.find(sessionId);
    if (!s) return;
    auto client = mClients.add(addr, "ws");
    client->setUser(user);
    WebSocket ws(fd);

    size_t sent = 0;
    auto lastProgress = std::chrono::steady_clock::now();
    bool alive = true;

    while (alive) {
        // Drain available events in batches of <= 500 (docs/API.md).
        std::vector<Event> chunk;
        int st;
        {
            std::shared_lock lk(s->mu);
            st = s->status.load();
            size_t avail = s->events.size();
            if (sent < avail) {
                size_t end = std::min(avail, sent + 500);
                chunk.assign(s->events.begin() + (long)sent,
                             s->events.begin() + (long)end);
                sent = end;
            }
        }
        if (!chunk.empty()) {
            JsonWriter w;
            w.beginObj().kv("type", "batch").key("events").beginArr();
            for (auto& e : chunk) e.toJson(w);
            w.endArr().endObj();
            if (!ws.sendJsonDeflated(w.take())) break;
            client->messages = ws.messagesSent();
            client->bytesSent = ws.bytesSent();
            // Consume any client frames without blocking.
            std::string msg;
            int opcode;
            if (ws.poll(msg, opcode, 0) < 0) break;
            continue;
        }

        if (st != Session::Running) {
            JsonWriter w;
            if (st == Session::Error)
                w.beginObj().kv("type", "error").kv("error", s->errorMsg).endObj();
            else
                w.beginObj().kv("type", "complete").kv("total", (uint64_t)sent)
                    .endObj();
            ws.sendJsonDeflated(w.take());
            // Linger briefly answering pings so an in-flight client message
            // is not lost to an immediate close.
            for (int i = 0; i < 20; ++i) {
                std::string msg;
                int opcode;
                int pr = ws.poll(msg, opcode, 50);
                if (pr < 0) break;
                if (pr == 1 && opcode == 0x1 &&
                    JsonValue::parse(msg).getStr("type") == "ping") {
                    JsonWriter pw;
                    pw.beginObj().kv("type", "pong").endObj();
                    if (!ws.sendJsonDeflated(pw.take())) break;
                }
            }
            ws.sendClose(1000);
            break;
        }

        auto now = std::chrono::steady_clock::now();
        if (now - lastProgress > std::chrono::seconds(1)) {
            lastProgress = now;
            JsonWriter w;
            w.beginObj().kv("type", "progress").kv("packets", s->packets.load())
                .kv("events", (uint64_t)sent).endObj();
            if (!ws.sendJsonDeflated(w.take())) break;
        }

        // Wait for either new events (cv) or client traffic (poll).
        std::string msg;
        int opcode;
        int pr = ws.poll(msg, opcode, 50);
        if (pr < 0) break;
        if (pr == 1 && opcode == 0x1) {
            JsonValue m = JsonValue::parse(msg);
            if (m.getStr("type") == "ping") {
                JsonWriter w;
                w.beginObj().kv("type", "pong").endObj();
                if (!ws.sendJsonDeflated(w.take())) break;
            }
        }
        {
            std::shared_lock lk(s->mu);
            s->cv.wait_for(lk, std::chrono::milliseconds(50), [&] {
                return s->events.size() > sent ||
                       s->status.load() != Session::Running;
            });
        }
    }

    mClients.remove(client);
}

// ---------------------------------------------------------------- static -

void Api::handleStatic(HttpRequest& req, HttpResponse& resp) {
    if (req.method != "GET" && req.method != "HEAD") {
        jsonError(resp, 405, "method not allowed");
        return;
    }
    std::string rel = req.path == "/" ? "/index.html" : req.path;
    if (rel.find("..") != std::string::npos) {
        jsonError(resp, 403, "forbidden");
        return;
    }
    std::string full = mFrontendDir + rel;
    std::ifstream f(full, std::ios::binary);
    if (!f) {
        // SPA fallback for non-asset paths.
        if (rel.find('.') == std::string::npos) {
            full = mFrontendDir + "/index.html";
            f.open(full, std::ios::binary);
        }
        if (!f) {
            resp.status = 404;
            resp.contentType = "text/plain";
            resp.body = "not found";
            return;
        }
    }
    std::stringstream ss;
    ss << f.rdbuf();
    resp.body = ss.str();

    auto ends = [&](const char* ext) {
        size_t n = strlen(ext);
        return full.size() >= n && full.compare(full.size() - n, n, ext) == 0;
    };
    if (ends(".html")) resp.contentType = "text/html; charset=utf-8";
    else if (ends(".js")) resp.contentType = "text/javascript; charset=utf-8";
    else if (ends(".css")) resp.contentType = "text/css; charset=utf-8";
    else if (ends(".svg")) resp.contentType = "image/svg+xml";
    else if (ends(".png")) resp.contentType = "image/png";
    else if (ends(".ico")) resp.contentType = "image/x-icon";
    else if (ends(".json")) resp.contentType = "application/json";
    else resp.contentType = "application/octet-stream";
    resp.extraHeaders.emplace_back("Cache-Control", "no-cache");
}

} // namespace avb
