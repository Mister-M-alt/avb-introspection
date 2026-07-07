/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 */
#include "auth.h"

#include <sodium.h>

#include <fstream>
#include <iterator>
#include <sstream>

#include "../util/json.h"

namespace avb {

bool Auth::validUsername(const std::string& u) {
    if (u.size() < 3 || u.size() > 32) return false;
    for (char c : u) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
        if (!ok) return false;
    }
    return true;
}

bool Auth::init(const std::string& usersFile, std::string& err) {
    if (sodium_init() < 0) {
        err = "libsodium initialization failed";
        return false;
    }
    mPath = usersFile;

    std::ifstream f(usersFile);
    if (!f) return true; // first run — file created on first register
    std::stringstream ss;
    ss << f.rdbuf();
    std::string perr;
    JsonValue root = JsonValue::parse(ss.str(), &perr);
    if (root.isNull()) {
        err = "cannot parse " + usersFile + ": " + perr;
        return false;
    }
    if (auto* users = root.get("users"); users) {
        for (auto& u : users->arr) {
            std::string name = u.getStr("username");
            std::string hash = u.getStr("hash");
            std::string role = u.getStr("role", "user");
            if (role != "admin") role = "user";
            // Pre-domain users.json entries join the built-in domain (SE-5).
            std::string domain = u.getStr("domain", "default");
            if (domain.empty()) domain = "default";
            if (!name.empty() && !hash.empty()) mUsers[name] = {hash, role, domain};
        }
    }
    return true;
}

bool Auth::save(std::string& err) {
    JsonWriter w;
    w.beginObj().key("users").beginArr();
    for (auto& [name, u] : mUsers) {
        w.beginObj();
        w.kv("username", name);
        w.kv("hash", u.hash);
        w.kv("role", u.role);
        w.kv("domain", u.domain.empty() ? "default" : u.domain);
        w.endObj();
    }
    w.endArr().endObj();

    std::string tmp = mPath + ".tmp";
    {
        std::ofstream f(tmp, std::ios::trunc);
        if (!f) {
            err = "cannot write " + tmp;
            return false;
        }
        f << w.str();
    }
    if (std::rename(tmp.c_str(), mPath.c_str()) != 0) {
        err = "cannot replace " + mPath;
        return false;
    }
    return true;
}

bool Auth::registerUser(const std::string& username,
                        const std::string& password, std::string& err,
                        const std::string& role, const std::string& domain) {
    if (!validUsername(username)) {
        err = "username must be 3-32 chars of [a-zA-Z0-9_.-]";
        return false;
    }
    if (password.size() < 8) {
        err = "password must be at least 8 characters";
        return false;
    }
    std::lock_guard lk(mMu);
    if (mUsers.count(username)) {
        err = "username already exists";
        return false;
    }
    char hash[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(hash, password.c_str(), password.size(),
                          crypto_pwhash_OPSLIMIT_INTERACTIVE,
                          crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        err = "hashing failed (out of memory?)";
        return false;
    }
    mUsers[username] = {hash, role == "admin" ? "admin" : "user",
                        domain.empty() ? "default" : domain};
    return save(err);
}

std::string Auth::roleOf(const std::string& username) const {
    std::lock_guard lk(mMu);
    auto it = mUsers.find(username);
    return it == mUsers.end() ? std::string() : it->second.role;
}

std::string Auth::domainOf(const std::string& username) const {
    std::lock_guard lk(mMu);
    auto it = mUsers.find(username);
    if (it == mUsers.end()) return {};
    return it->second.domain.empty() ? "default" : it->second.domain;
}

Auth::UserInfo Auth::infoOf(const std::string& username) const {
    std::lock_guard lk(mMu);
    auto it = mUsers.find(username);
    if (it == mUsers.end()) return {};
    return {username, it->second.role,
            it->second.domain.empty() ? "default" : it->second.domain};
}

bool Auth::setDomain(const std::string& username, const std::string& domain,
                     std::string& err) {
    std::lock_guard lk(mMu);
    auto it = mUsers.find(username);
    if (it == mUsers.end()) {
        err = "no such user";
        return false;
    }
    it->second.domain = domain.empty() ? "default" : domain;
    return save(err);
}

std::vector<Auth::UserInfo> Auth::users() const {
    std::lock_guard lk(mMu);
    std::vector<UserInfo> out;
    out.reserve(mUsers.size());
    for (auto& [name, u] : mUsers)
        out.push_back({name, u.role, u.domain.empty() ? "default" : u.domain});
    return out;
}

bool Auth::hasAdmin() const {
    std::lock_guard lk(mMu);
    for (auto& [n, u] : mUsers)
        if (u.role == "admin") return true;
    return false;
}

bool Auth::deleteUser(const std::string& username, std::string& err) {
    std::lock_guard lk(mMu);
    auto it = mUsers.find(username);
    if (it == mUsers.end()) {
        err = "no such user";
        return false;
    }
    if (it->second.role == "admin") {
        int admins = 0;
        for (auto& [n, u] : mUsers)
            if (u.role == "admin") ++admins;
        if (admins <= 1) {
            err = "cannot delete the last admin";
            return false;
        }
    }
    mUsers.erase(it);
    for (auto t = mTokens.begin(); t != mTokens.end();)
        t = (t->second == username) ? mTokens.erase(t) : std::next(t);
    return save(err);
}

bool Auth::ensureAdmin(const std::string& username,
                       const std::string& password, std::string& err) {
    {
        std::lock_guard lk(mMu);
        auto it = mUsers.find(username);
        if (it != mUsers.end()) {
            if (it->second.role != "admin") {
                it->second.role = "admin"; // promote the existing account
                return save(err);
            }
            return true;
        }
    }
    return registerUser(username, password, err, "admin");
}

bool Auth::login(const std::string& username, const std::string& password,
                 std::string& token) {
    std::lock_guard lk(mMu);
    auto it = mUsers.find(username);
    if (it == mUsers.end()) return false;
    if (crypto_pwhash_str_verify(it->second.hash.c_str(), password.c_str(),
                                 password.size()) != 0)
        return false;

    unsigned char raw[32];
    randombytes_buf(raw, sizeof raw);
    char hex[65];
    sodium_bin2hex(hex, sizeof hex, raw, sizeof raw);
    token = hex;
    mTokens[token] = username;
    return true;
}

std::string Auth::check(const std::string& token) const {
    if (token.empty()) return {};
    std::lock_guard lk(mMu);
    auto it = mTokens.find(token);
    return it == mTokens.end() ? std::string() : it->second;
}

void Auth::logout(const std::string& token) {
    std::lock_guard lk(mMu);
    mTokens.erase(token);
}

} // namespace avb
