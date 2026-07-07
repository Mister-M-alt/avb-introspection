/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 */
#include "store.h"

#include <sys/stat.h>

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "../pcapio/pcap_reader.h"
#include "../util/json.h"

namespace avb {

std::string Store::nowIso8601() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

namespace {
// Library folder names: 1-64 chars, flat (no '/'), not a dotfile.
bool validFolderName(const std::string& name) {
    if (name.empty() || name.size() > 64 || name[0] == '.') return false;
    for (char c : name)
        if (c == '/' || c == '\\' || (unsigned char)c < 0x20) return false;
    return true;
}
} // namespace

bool Store::validDomainId(const std::string& id) {
    // Used as a path component and an API path segment — keep it strict.
    if (id.size() < 1 || id.size() > 32) return false;
    if (id[0] < 'a' || id[0] > 'z') return false;
    for (char c : id) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
        if (!ok) return false;
    }
    // Reserved: the built-in domain and names used in the on-disk layout.
    return id != "default" && id != "domains" && id != "pcaps" &&
           id != "sessions";
}

bool Store::init(const std::string& dataDir, std::string& err) {
    mDataDir = dataDir;
    if (::mkdir(dataDir.c_str(), 0755) != 0 && errno != EEXIST) {
        err = "cannot create data directory " + dataDir;
        return false;
    }
    for (const char* sub : {"/pcaps", "/sessions"}) {
        std::string dir = dataDir + sub;
        if (::mkdir(dir.c_str(), 0755) != 0 && errno != EEXIST) {
            err = "cannot create " + dir;
            return false;
        }
    }

    // Device names (survive restarts; independent of sessions). Nested
    // {domain: {mac: name}}; a flat pre-domain file maps to "default".
    {
        std::ifstream f(dataDir + "/devices.json");
        if (f) {
            std::stringstream ss;
            ss << f.rdbuf();
            JsonValue root = JsonValue::parse(ss.str());
            for (auto& [key, v] : root.obj) {
                if (v.type == JsonValue::Type::String) {
                    if (!v.str.empty()) mDeviceNames["default"][key] = v.str;
                } else if (v.type == JsonValue::Type::Object) {
                    for (auto& [mac, name] : v.obj)
                        if (name.type == JsonValue::Type::String &&
                            !name.str.empty())
                            mDeviceNames[key][mac] = name.str;
                }
            }
        }
    }

    std::ifstream f(dataDir + "/meta.json");
    if (!f) return true; // fresh data dir
    std::stringstream ss;
    ss << f.rdbuf();
    std::string perr;
    JsonValue root = JsonValue::parse(ss.str(), &perr);
    if (root.isNull()) {
        err = "cannot parse meta.json: " + perr;
        return false;
    }
    mNextPcap = (uint64_t)root.getNum("next_pcap", 1);
    mNextSession = (uint64_t)root.getNum("next_session", 1);
    mPcapRoot = root.getStr("pcap_root");
    if (!mPcapRoot.empty()) {
        // The configured root must exist (e.g. an unmounted volume after a
        // reboot) — otherwise fall back to the default so the app still runs.
        std::error_code ec;
        std::filesystem::create_directories(mPcapRoot, ec);
        if (ec) mPcapRoot.clear();
    }
    if (auto* arr = root.get("domains"); arr)
        for (auto& d : arr->arr) {
            std::string id = d.getStr("id");
            if (!id.empty())
                mDomains.push_back({id, d.getStr("name"), d.getStr("owner"),
                                    d.getStr("created_at")});
        }
    if (auto* arr = root.get("pcap_folders"); arr)
        for (auto& v : arr->arr) {
            if (v.type == JsonValue::Type::String) {
                // Pre-domain format: a plain name in the built-in domain.
                if (!v.str.empty()) mPcapFolders.emplace_back("default", v.str);
            } else {
                std::string dom = v.getStr("domain", "default");
                std::string name = v.getStr("name");
                if (!name.empty())
                    mPcapFolders.emplace_back(dom.empty() ? "default" : dom,
                                              name);
            }
        }
    std::sort(mPcapFolders.begin(), mPcapFolders.end());
    if (auto* arr = root.get("pcaps"); arr)
        for (auto& p : arr->arr) {
            std::string dom = p.getStr("domain", "default");
            mPcaps.push_back({p.getStr("id"), p.getStr("name"),
                              p.getStr("uploaded_at"),
                              (uint64_t)p.getNum("size"), p.getStr("folder"),
                              dom.empty() ? "default" : dom});
        }
    if (auto* arr = root.get("sessions"); arr)
        for (auto& s : arr->arr) {
            SessionMeta sm{s.getStr("id"), s.getStr("name"), s.getStr("pcap_id"),
                           s.getStr("path"), s.getStr("created_at"),
                           {},          {},          {},
                           s.getStr("domain", "default")};
            if (sm.domain.empty()) sm.domain = "default";
            if (auto* ids = s.get("pcap_ids"); ids)
                for (auto& v : ids->arr) sm.pcapIds.push_back(v.str);
            if (auto* al = s.get("pcap_aliases"); al)
                for (auto& v : al->arr) sm.pcapAliases.push_back(v.str);
            sm.pcapAliases.resize(sm.pcapIds.size());  // keep parallel
            mSessions.push_back(std::move(sm));
        }
    return true;
}

bool Store::save(std::string& err) {
    JsonWriter w;
    w.beginObj();
    w.kv("next_pcap", mNextPcap);
    w.kv("next_session", mNextSession);
    if (!mPcapRoot.empty()) w.kv("pcap_root", mPcapRoot);
    if (!mDomains.empty()) {
        w.key("domains").beginArr();
        for (auto& d : mDomains) {
            w.beginObj();
            w.kv("id", d.id);
            w.kv("name", d.name);
            w.kv("owner", d.owner);
            w.kv("created_at", d.createdAt);
            w.endObj();
        }
        w.endArr();
    }
    if (!mPcapFolders.empty()) {
        w.key("pcap_folders").beginArr();
        for (auto& [dom, name] : mPcapFolders) {
            w.beginObj();
            w.kv("domain", dom);
            w.kv("name", name);
            w.endObj();
        }
        w.endArr();
    }
    w.key("pcaps").beginArr();
    for (auto& p : mPcaps) {
        w.beginObj();
        w.kv("id", p.id);
        w.kv("name", p.name);
        w.kv("uploaded_at", p.uploadedAt);
        w.kv("size", p.size);
        if (!p.folder.empty()) w.kv("folder", p.folder);
        if (p.domain != "default") w.kv("domain", p.domain);
        w.endObj();
    }
    w.endArr();
    w.key("sessions").beginArr();
    for (auto& s : mSessions) {
        w.beginObj();
        w.kv("id", s.id);
        w.kv("name", s.name);
        w.kv("pcap_id", s.pcapId);
        w.kv("path", s.path);
        w.kv("created_at", s.createdAt);
        if (s.domain != "default") w.kv("domain", s.domain);
        if (!s.pcapIds.empty()) {
            w.key("pcap_ids").beginArr();
            for (auto& pid : s.pcapIds) w.value(pid);
            w.endArr();
            w.key("pcap_aliases").beginArr();
            for (auto& a : s.pcapAliases) w.value(a);
            w.endArr();
        }
        w.endObj();
    }
    w.endArr();
    w.endObj();

    std::string path = mDataDir + "/meta.json";
    std::string tmp = path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::trunc);
        if (!f) {
            err = "cannot write " + tmp;
            return false;
        }
        f << w.str();
    }
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        err = "cannot replace " + path;
        return false;
    }
    return true;
}

// ---------------------------------------------------------------- domains -

std::vector<Store::DomainMeta> Store::domains() const {
    std::lock_guard lk(mMu);
    std::vector<DomainMeta> out;
    out.push_back({"default", "Default", "", ""});
    out.insert(out.end(), mDomains.begin(), mDomains.end());
    return out;
}

bool Store::hasDomain(const std::string& id) const {
    if (id == "default") return true;
    std::lock_guard lk(mMu);
    for (auto& d : mDomains)
        if (d.id == id) return true;
    return false;
}

std::string Store::domainOwner(const std::string& id) const {
    std::lock_guard lk(mMu);
    for (auto& d : mDomains)
        if (d.id == id) return d.owner;
    return {};
}

bool Store::addDomain(const std::string& id, const std::string& name,
                      const std::string& owner, std::string& err) {
    if (!validDomainId(id)) {
        err = "domain id must match [a-z][a-z0-9-]{0,31} and not be reserved";
        return false;
    }
    std::lock_guard lk(mMu);
    for (auto& d : mDomains)
        if (d.id == id) {
            err = "domain already exists";
            return false;
        }
    // Its pcap subtree — created up front so overlap with anything existing
    // would fail loudly here rather than at first upload.
    std::error_code ec;
    std::filesystem::create_directories(pcapRootLocked() + "/domains/" + id,
                                        ec);
    if (ec) {
        err = "cannot create domain storage: " + ec.message();
        return false;
    }
    mDomains.push_back({id, name.empty() ? id : name, owner, nowIso8601()});
    if (!save(err)) {
        mDomains.pop_back();
        return false;
    }
    return true;
}

bool Store::removeDomain(const std::string& id, bool force,
                         std::vector<std::string>& removedSessions,
                         std::string& err) {
    if (id == "default") {
        err = "the built-in domain cannot be deleted";
        return false;
    }
    std::lock_guard lk(mMu);
    auto it = std::find_if(mDomains.begin(), mDomains.end(),
                           [&](const DomainMeta& d) { return d.id == id; });
    if (it == mDomains.end()) {
        err = "no such domain";
        return false;
    }
    size_t nPcaps = 0, nSessions = 0;
    for (auto& p : mPcaps)
        if (p.domain == id) ++nPcaps;
    for (auto& s : mSessions)
        if (s.domain == id) ++nSessions;
    if (!force && (nPcaps || nSessions)) {
        err = "domain still holds " + std::to_string(nPcaps) + " pcap(s) and " +
              std::to_string(nSessions) +
              " session(s) — delete them first or force";
        return false;
    }
    for (auto& p : mPcaps)
        if (p.domain == id) std::remove(pcapPathLocked(p).c_str());
    std::erase_if(mPcaps, [&](const PcapMeta& p) { return p.domain == id; });
    for (auto& s : mSessions)
        if (s.domain == id) {
            removedSessions.push_back(s.id);
            std::error_code ec;
            std::filesystem::remove_all(mDataDir + "/sessions/" + s.id, ec);
        }
    std::erase_if(mSessions,
                  [&](const SessionMeta& s) { return s.domain == id; });
    std::erase_if(mPcapFolders, [&](auto& f) { return f.first == id; });
    mDeviceNames.erase(id);
    mDomains.erase(it);
    std::error_code ec;
    std::filesystem::remove_all(pcapRootLocked() + "/domains/" + id, ec);
    std::string derr;
    saveDeviceNames(derr);
    return save(err);
}

// ------------------------------------------------------------------ pcaps -

std::string Store::addPcap(const std::string& name, const std::string& bytes,
                           const std::string& folder,
                           const std::string& domain, std::string& err) {
    if (!folder.empty() && !validFolderName(folder)) {
        err = "folder name must be 1-64 chars without '/'";
        return "";
    }
    std::lock_guard lk(mMu);
    std::string id = "p" + std::to_string(mNextPcap);
    PcapMeta meta{id, name, nowIso8601(), bytes.size(), folder,
                  domain.empty() ? "default" : domain};
    std::string path = pcapPathLocked(meta);
    if (meta.domain != "default") {
        std::error_code ec;
        std::filesystem::create_directories(
            pcapRootLocked() + "/domains/" + meta.domain, ec);
    }
    {
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        if (!f) {
            err = "cannot write " + path;
            return "";
        }
        f.write(bytes.data(), (std::streamsize)bytes.size());
        if (!f) {
            err = "short write to " + path + " (disk full?)";
            return "";
        }
    }
    mNextPcap++;
    mPcaps.push_back(meta);
    // Uploading into a not-yet-explicit folder creates it (so it survives the
    // pcap being moved back out).
    auto key = std::make_pair(meta.domain, folder);
    if (!folder.empty() &&
        std::find(mPcapFolders.begin(), mPcapFolders.end(), key) ==
            mPcapFolders.end()) {
        mPcapFolders.push_back(key);
        std::sort(mPcapFolders.begin(), mPcapFolders.end());
    }
    if (!save(err)) {
        std::remove(path.c_str());
        mPcaps.pop_back();
        return "";
    }
    return id;
}

bool Store::removePcap(const std::string& id, std::string& err) {
    std::lock_guard lk(mMu);
    auto it = std::find_if(mPcaps.begin(), mPcaps.end(),
                           [&](const PcapMeta& p) { return p.id == id; });
    if (it == mPcaps.end()) {
        err = "no such pcap " + id;
        return false;
    }
    std::string path = pcapPathLocked(*it);
    mPcaps.erase(it);
    if (!save(err)) return false;
    // Sessions are self-contained (own capture copy) — deleting the library
    // file never breaks an existing investigation.
    std::remove(path.c_str());
    return true;
}

// -------------------------------------------------------- library folders -

std::vector<std::string> Store::pcapFolders(const std::string& domain) const {
    std::lock_guard lk(mMu);
    std::vector<std::string> out;
    for (auto& [dom, name] : mPcapFolders)
        if (dom == domain) out.push_back(name);
    for (auto& p : mPcaps)
        if (p.domain == domain && !p.folder.empty() &&
            std::find(out.begin(), out.end(), p.folder) == out.end())
            out.push_back(p.folder);
    std::sort(out.begin(), out.end());
    return out;
}

bool Store::addPcapFolder(const std::string& domain, const std::string& name,
                          std::string& err) {
    if (!validFolderName(name)) {
        err = "folder name must be 1-64 chars without '/'";
        return false;
    }
    std::lock_guard lk(mMu);
    auto key = std::make_pair(domain, name);
    if (std::find(mPcapFolders.begin(), mPcapFolders.end(), key) !=
        mPcapFolders.end())
        return true; // already exists — idempotent
    mPcapFolders.push_back(key);
    std::sort(mPcapFolders.begin(), mPcapFolders.end());
    return save(err);
}

bool Store::removePcapFolder(const std::string& domain,
                             const std::string& name, std::string& err) {
    std::lock_guard lk(mMu);
    for (auto& p : mPcaps)
        if (p.domain == domain && p.folder == name) {
            err = "folder still contains captures — move them out first";
            return false;
        }
    std::erase(mPcapFolders, std::make_pair(domain, name));
    return save(err);
}

bool Store::setPcapFolder(const std::string& id, const std::string& folder,
                          std::string& err) {
    if (!folder.empty() && !validFolderName(folder)) {
        err = "folder name must be 1-64 chars without '/'";
        return false;
    }
    std::lock_guard lk(mMu);
    for (auto& p : mPcaps) {
        if (p.id != id) continue;
        p.folder = folder;
        // Moving into a new name creates the folder implicitly; make it
        // explicit so it survives moving the pcap back out.
        auto key = std::make_pair(p.domain, folder);
        if (!folder.empty() &&
            std::find(mPcapFolders.begin(), mPcapFolders.end(), key) ==
                mPcapFolders.end()) {
            mPcapFolders.push_back(key);
            std::sort(mPcapFolders.begin(), mPcapFolders.end());
        }
        return save(err);
    }
    err = "no such pcap " + id;
    return false;
}

// ------------------------------------------------------------- pcap root -

std::string Store::pcapRoot() const {
    std::lock_guard lk(mMu);
    return pcapRootLocked();
}

bool Store::setPcapRoot(const std::string& path, std::string& err) {
    std::lock_guard lk(mMu);
    std::string next = path;
    while (next.size() > 1 && next.back() == '/') next.pop_back();
    if (next.empty()) next = mDataDir + "/pcaps"; // reset to the default
    if (next[0] != '/') {
        err = "pcap root must be an absolute path";
        return false;
    }
    std::string cur = pcapRootLocked();
    if (next == cur) return true;

    std::error_code ec;
    std::filesystem::create_directories(next, ec);
    if (ec) {
        err = "cannot create " + next + ": " + ec.message() +
              " (is the path writable by the service? see ReadWritePaths in "
              "the systemd unit)";
        return false;
    }
    // Writability probe — a clear error beats ofstream failures later.
    {
        std::string probe = next + "/.avb-write-test";
        std::ofstream f(probe, std::ios::trunc);
        if (!f) {
            err = next + " is not writable by the service (see ReadWritePaths "
                  "in the systemd unit)";
            return false;
        }
        f.close();
        std::remove(probe.c_str());
    }
    // Copy-first migration: only after every file arrived do we switch the
    // root and delete the originals, so a failure never strands the library.
    // Each domain keeps its subtree under the new root.
    std::vector<std::string> copied;
    for (auto& p : mPcaps) {
        std::string rel = pcapRelPath(p);
        std::string from = cur + "/" + rel;
        std::string to = next + "/" + rel;
        std::filesystem::create_directories(
            std::filesystem::path(to).parent_path(), ec);
        std::filesystem::copy_file(
            from, to, std::filesystem::copy_options::overwrite_existing, ec);
        if (ec) {
            for (auto& c : copied) std::remove(c.c_str());
            err = "cannot move " + p.id + ".pcap to " + next + ": " +
                  ec.message();
            return false;
        }
        copied.push_back(to);
    }
    std::string prev = mPcapRoot;
    mPcapRoot = (next == mDataDir + "/pcaps") ? "" : next;
    if (!save(err)) {
        mPcapRoot = prev;
        for (auto& c : copied) std::remove(c.c_str());
        return false;
    }
    for (auto& p : mPcaps)
        std::remove((cur + "/" + pcapRelPath(p)).c_str());
    return true;
}

std::vector<Store::PcapMeta> Store::pcaps() const {
    std::lock_guard lk(mMu);
    return mPcaps;
}

std::vector<Store::PcapMeta> Store::pcaps(const std::string& domain) const {
    std::lock_guard lk(mMu);
    std::vector<PcapMeta> out;
    for (auto& p : mPcaps)
        if (p.domain == domain) out.push_back(p);
    return out;
}

bool Store::hasPcap(const std::string& id) const {
    std::lock_guard lk(mMu);
    for (auto& p : mPcaps)
        if (p.id == id) return true;
    return false;
}

std::string Store::pcapDomain(const std::string& id) const {
    std::lock_guard lk(mMu);
    for (auto& p : mPcaps)
        if (p.id == id) return p.domain;
    return {};
}

std::string Store::pcapPath(const std::string& id) const {
    std::lock_guard lk(mMu);
    return pcapPathLocked(id);
}

std::string Store::pcapName(const std::string& id) const {
    std::lock_guard lk(mMu);
    for (auto& p : mPcaps)
        if (p.id == id) return p.name;
    return {};
}

std::string Store::sessionDir(const std::string& id) const {
    return mDataDir + "/sessions/" + id;
}
std::string Store::sessionPcapPath(const std::string& id) const {
    return sessionDir(id) + "/capture.pcap";
}
std::string Store::sessionSrcMapPath(const std::string& id) const {
    return sessionDir(id) + "/capture.src";
}

std::vector<Store::SessionSource> Store::sessionSources(const std::string& id) const {
    std::lock_guard lk(mMu);
    std::vector<SessionSource> out;
    for (auto& s : mSessions) {
        if (s.id != id) continue;
        for (size_t i = 0; i < s.pcapIds.size(); ++i) {
            std::string name;
            for (auto& p : mPcaps)
                if (p.id == s.pcapIds[i]) { name = p.name; break; }
            std::string alias = i < s.pcapAliases.size() && !s.pcapAliases[i].empty()
                                    ? s.pcapAliases[i]
                                    : (name.empty() ? s.pcapIds[i] : name);
            out.push_back({s.pcapIds[i], name, alias});
        }
        break;
    }
    return out;
}

bool Store::setSessionAlias(const std::string& id, size_t index,
                            const std::string& alias, std::string& err) {
    std::lock_guard lk(mMu);
    for (auto& s : mSessions) {
        if (s.id != id) continue;
        if (index >= s.pcapIds.size()) {
            err = "source index out of range";
            return false;
        }
        if (s.pcapAliases.size() < s.pcapIds.size())
            s.pcapAliases.resize(s.pcapIds.size());
        s.pcapAliases[index] = alias;
        return save(err);
    }
    err = "no such session " + id;
    return false;
}
std::string Store::sessionNotesPath(const std::string& id) const {
    return sessionDir(id) + "/notes.md";
}

std::string Store::addSession(SessionMeta meta, std::string& err) {
    std::lock_guard lk(mMu);
    meta.id = "s" + std::to_string(mNextSession);
    meta.createdAt = nowIso8601();
    if (meta.domain.empty()) meta.domain = "default";

    // Resolve the source captures. pcapIds (>=1) is the combine path; otherwise
    // a single library pcap or a server path (unchanged behaviour).
    auto nameOf = [&](const std::string& pid) {
        for (auto& p : mPcaps)
            if (p.id == pid) return p.name;
        return pid;
    };
    std::vector<std::string> srcPaths, srcNames;
    if (!meta.pcapIds.empty()) {
        for (auto& pid : meta.pcapIds) {
            srcPaths.push_back(pcapPathLocked(pid));
            srcNames.push_back(nameOf(pid));
        }
        if (meta.pcapId.empty()) meta.pcapId = meta.pcapIds.front();
        // Default alias for each source is its capture name; user-editable.
        meta.pcapAliases = srcNames;
    } else if (!meta.pcapId.empty()) {
        srcPaths.push_back(pcapPathLocked(meta.pcapId));
        srcNames.push_back(nameOf(meta.pcapId));
    } else {
        srcPaths.push_back(meta.resolvedPath.empty() ? meta.path
                                                     : meta.resolvedPath);
        srcNames.push_back(meta.name);
    }

    // Session folder with its own capture copy — self-contained (BE-8).
    std::error_code ec;
    std::filesystem::create_directories(sessionDir(meta.id), ec);
    if (ec) {
        err = "cannot create session folder: " + ec.message();
        return "";
    }
    if (srcPaths.size() == 1) {
        std::filesystem::copy_file(
            srcPaths[0], sessionPcapPath(meta.id),
            std::filesystem::copy_options::overwrite_existing, ec);
        if (ec) {
            err = "cannot copy capture into session folder: " + ec.message();
            std::filesystem::remove_all(sessionDir(meta.id), ec);
            return "";
        }
    } else {
        // Merge the sources into one chronological capture.pcap (+ a per-packet
        // source-index sidecar); downstream treats it as a single-file session.
        if (!mergePcaps(srcPaths, srcNames, sessionPcapPath(meta.id),
                        sessionSrcMapPath(meta.id), err)) {
            std::filesystem::remove_all(sessionDir(meta.id), ec);
            return ""; // err set by mergePcaps
        }
    }

    // Seed the investigation notes the user edits in the UI.
    {
        std::ofstream f(sessionNotesPath(meta.id), std::ios::trunc);
        f << "# Investigation: " << meta.name << "\n\n"
          << "- Created: " << meta.createdAt << "\n";
        if (srcNames.size() > 1) {
            f << "- Combined captures (" << srcNames.size()
              << ", merged by capture time):\n";
            for (auto& nm : srcNames) f << "  - `" << nm << "`\n";
        } else {
            f << "- Capture: `" << meta.name << "`"
              << (meta.pcapId.empty() ? " (from server path `" + meta.path + "`)"
                                      : " (upload " + meta.pcapId + ")")
              << "\n";
        }
        f << "\n## Context\n\n_What is being investigated, and why?_\n\n"
          << "## Findings\n\n- \n\n## Open questions\n\n- \n";
    }

    mNextSession++;
    mSessions.push_back(meta);
    save(err); // metadata loss on failure is non-fatal; the session still runs
    err.clear();
    return meta.id;
}

void Store::removeSession(const std::string& id) {
    std::lock_guard lk(mMu);
    std::erase_if(mSessions, [&](const SessionMeta& s) { return s.id == id; });
    std::error_code ec;
    std::filesystem::remove_all(sessionDir(id), ec);
    std::string err;
    save(err);
}

std::string Store::readNotes(const std::string& id) const {
    std::lock_guard lk(mMu);
    std::ifstream f(sessionNotesPath(id), std::ios::binary);
    if (!f) return {};
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

bool Store::writeNotes(const std::string& id, const std::string& markdown,
                       std::string& err) {
    std::lock_guard lk(mMu);
    std::string path = sessionNotesPath(id);
    std::string tmp = path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) {
            err = "cannot write notes";
            return false;
        }
        f.write(markdown.data(), (std::streamsize)markdown.size());
        if (!f) {
            err = "short write (disk full?)";
            return false;
        }
    }
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        err = "cannot replace notes file";
        return false;
    }
    return true;
}

std::vector<Store::SessionMeta> Store::sessions() const {
    std::lock_guard lk(mMu);
    return mSessions;
}

std::string Store::sessionDomain(const std::string& id) const {
    std::lock_guard lk(mMu);
    for (auto& s : mSessions)
        if (s.id == id) return s.domain;
    return {};
}

std::map<std::string, std::string> Store::deviceNames(
    const std::string& domain) const {
    std::lock_guard lk(mMu);
    auto it = mDeviceNames.find(domain);
    return it == mDeviceNames.end() ? std::map<std::string, std::string>{}
                                    : it->second;
}

bool Store::saveDeviceNames(std::string& err) {
    JsonWriter w;
    w.beginObj();
    for (auto& [dom, names] : mDeviceNames) {
        w.key(dom).beginObj();
        for (auto& [mac, name] : names) w.kv(mac, name);
        w.endObj();
    }
    w.endObj();
    std::string path = mDataDir + "/devices.json";
    std::string tmp = path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::trunc);
        if (!f) {
            err = "cannot write " + tmp;
            return false;
        }
        f << w.str();
    }
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        err = "cannot replace " + path;
        return false;
    }
    return true;
}

bool Store::setDeviceName(const std::string& domain, const std::string& mac,
                          const std::string& name, std::string& err) {
    std::lock_guard lk(mMu);
    if (name.empty()) {
        auto it = mDeviceNames.find(domain);
        if (it != mDeviceNames.end()) {
            it->second.erase(mac);
            if (it->second.empty()) mDeviceNames.erase(it);
        }
    } else {
        mDeviceNames[domain][mac] = name;
    }
    return saveDeviceNames(err);
}

} // namespace avb
