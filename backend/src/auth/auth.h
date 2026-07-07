/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * User accounts (SE-1..SE-3): registration with Argon2id password hashes
 * (libsodium crypto_pwhash_str), opaque random bearer tokens for sessions.
 */
#pragma once

#include <map>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace avb {

class Auth {
public:
    struct UserInfo {
        std::string username, role; // role: "admin" | "user"
        std::string domain;         // tenant domain (SE-5); "default" built-in
    };

    /** Loads users from `usersFile` (created on first save). */
    bool init(const std::string& usersFile, std::string& err);

    bool registerUser(const std::string& username, const std::string& password,
                      std::string& err, const std::string& role = "user",
                      const std::string& domain = "default");
    /** On success fills `token` (64 hex chars). */
    bool login(const std::string& username, const std::string& password,
               std::string& token);
    /** Token -> username; empty when invalid. */
    std::string check(const std::string& token) const;
    void logout(const std::string& token);

    std::string roleOf(const std::string& username) const;
    std::string domainOf(const std::string& username) const;
    /** Username+role+domain in one lock; username empty when unknown. */
    UserInfo infoOf(const std::string& username) const;
    /** Move a user into another domain (domain create / owner assignment). */
    bool setDomain(const std::string& username, const std::string& domain,
                   std::string& err);
    std::vector<UserInfo> users() const;
    /** True once at least one admin account exists. False = fresh deployment
     *  that still needs its first admin (bootstrap). */
    bool hasAdmin() const;
    /** Deletes the user and revokes their tokens. Refuses to remove the
     *  last admin. */
    bool deleteUser(const std::string& username, std::string& err);

    /** Deployment provisioning (SE-1, admin environment): create the user
     *  as admin, or promote it when it already exists. */
    bool ensureAdmin(const std::string& username, const std::string& password,
                     std::string& err);

    static bool validUsername(const std::string& u);

private:
    struct User {
        std::string hash, role, domain;
    };
    bool save(std::string& err);

    std::string mPath;
    mutable std::mutex mMu;
    std::map<std::string, User> mUsers;                    // name -> record
    std::unordered_map<std::string, std::string> mTokens;  // token -> name
};

} // namespace avb
