/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 */
#include "store.h"

#include <sys/stat.h>

#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <sstream>

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

    // Global device names (survive restarts; independent of sessions).
    {
        std::ifstream f(dataDir + "/devices.json");
        if (f) {
            std::stringstream ss;
            ss << f.rdbuf();
            JsonValue root = JsonValue::parse(ss.str());
            for (auto& [mac, v] : root.obj)
                if (v.type == JsonValue::Type::String && !v.str.empty())
                    mDeviceNames[mac] = v.str;
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
    if (auto* arr = root.get("pcaps"); arr)
        for (auto& p : arr->arr)
            mPcaps.push_back({p.getStr("id"), p.getStr("name"),
                              p.getStr("uploaded_at"),
                              (uint64_t)p.getNum("size")});
    if (auto* arr = root.get("sessions"); arr)
        for (auto& s : arr->arr)
            mSessions.push_back({s.getStr("id"), s.getStr("name"),
                                 s.getStr("pcap_id"), s.getStr("path"),
                                 s.getStr("created_at")});
    return true;
}

bool Store::save(std::string& err) {
    JsonWriter w;
    w.beginObj();
    w.kv("next_pcap", mNextPcap);
    w.kv("next_session", mNextSession);
    w.key("pcaps").beginArr();
    for (auto& p : mPcaps) {
        w.beginObj();
        w.kv("id", p.id);
        w.kv("name", p.name);
        w.kv("uploaded_at", p.uploadedAt);
        w.kv("size", p.size);
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

std::string Store::addPcap(const std::string& name, const std::string& bytes,
                           std::string& err) {
    std::lock_guard lk(mMu);
    std::string id = "p" + std::to_string(mNextPcap);
    std::string path = mDataDir + "/pcaps/" + id + ".pcap";
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
    mPcaps.push_back({id, name, nowIso8601(), bytes.size()});
    if (!save(err)) {
        std::remove(path.c_str());
        mPcaps.pop_back();
        return "";
    }
    return id;
}

std::vector<Store::PcapMeta> Store::pcaps() const {
    std::lock_guard lk(mMu);
    return mPcaps;
}

bool Store::hasPcap(const std::string& id) const {
    std::lock_guard lk(mMu);
    for (auto& p : mPcaps)
        if (p.id == id) return true;
    return false;
}

std::string Store::pcapPath(const std::string& id) const {
    return mDataDir + "/pcaps/" + id + ".pcap";
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
std::string Store::sessionNotesPath(const std::string& id) const {
    return sessionDir(id) + "/notes.md";
}

std::string Store::addSession(SessionMeta meta, std::string& err) {
    std::lock_guard lk(mMu);
    meta.id = "s" + std::to_string(mNextSession);
    meta.createdAt = nowIso8601();

    // Session folder with its own capture copy — self-contained (BE-8).
    std::string src =
        meta.pcapId.empty() ? meta.path : pcapPath(meta.pcapId);
    std::error_code ec;
    std::filesystem::create_directories(sessionDir(meta.id), ec);
    if (ec) {
        err = "cannot create session folder: " + ec.message();
        return "";
    }
    std::filesystem::copy_file(src, sessionPcapPath(meta.id),
                               std::filesystem::copy_options::overwrite_existing,
                               ec);
    if (ec) {
        err = "cannot copy capture into session folder: " + ec.message();
        std::filesystem::remove_all(sessionDir(meta.id), ec);
        return "";
    }

    // Seed the investigation notes the user edits in the UI.
    {
        std::ofstream f(sessionNotesPath(meta.id), std::ios::trunc);
        f << "# Investigation: " << meta.name << "\n\n"
          << "- Created: " << meta.createdAt << "\n"
          << "- Capture: `" << meta.name << "`"
          << (meta.pcapId.empty() ? " (from server path `" + meta.path + "`)"
                                  : " (upload " + meta.pcapId + ")")
          << "\n\n## Context\n\n_What is being investigated, and why?_\n\n"
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

std::map<std::string, std::string> Store::deviceNames() const {
    std::lock_guard lk(mMu);
    return mDeviceNames;
}

bool Store::saveDeviceNames(std::string& err) {
    JsonWriter w;
    w.beginObj();
    for (auto& [mac, name] : mDeviceNames) w.kv(mac, name);
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

bool Store::setDeviceName(const std::string& mac, const std::string& name,
                          std::string& err) {
    std::lock_guard lk(mMu);
    if (name.empty())
        mDeviceNames.erase(mac);
    else
        mDeviceNames[mac] = name;
    return saveDeviceNames(err);
}

} // namespace avb
