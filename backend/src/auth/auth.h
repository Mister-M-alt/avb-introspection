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
    };

    /** Loads users from `usersFile` (created on first save). */
    bool init(const std::string& usersFile, std::string& err);

    bool registerUser(const std::string& username, const std::string& password,
                      std::string& err, const std::string& role = "user");
    /** On success fills `token` (64 hex chars). */
    bool login(const std::string& username, const std::string& password,
               std::string& token);
    /** Token -> username; empty when invalid. */
    std::string check(const std::string& token) const;
    void logout(const std::string& token);

    std::string roleOf(const std::string& username) const;
    std::vector<UserInfo> users() const;
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
        std::string hash, role;
    };
    bool save(std::string& err);

    std::string mPath;
    mutable std::mutex mMu;
    std::map<std::string, User> mUsers;                    // name -> record
    std::unordered_map<std::string, std::string> mTokens;  // token -> name
};

} // namespace avb
