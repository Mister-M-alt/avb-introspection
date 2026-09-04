/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * Small IP-address helpers for deployment plumbing: parsing bind addresses
 * and CIDR ranges, and deciding which client address a request really
 * came from when it arrived through a reverse proxy (SE-6: per-IP rate
 * limiting must see the client, not the proxy).
 */
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace avb {

struct IpAddr {
    bool v6 = false;
    std::array<uint8_t, 16> bytes{}; // IPv4 uses bytes[0..3]
    bool operator==(const IpAddr&) const = default;
};

/** Parse an IPv4 or IPv6 literal. An IPv4-mapped IPv6 address
 *  (::ffff:a.b.c.d — what a dual-stack listener reports for IPv4 peers)
 *  normalises to the IPv4 form so ranges match either way. */
bool parseIp(const std::string& text, IpAddr& out);
std::string ipToString(const IpAddr& ip);
bool isLoopback(const IpAddr& ip);

struct IpNet {
    IpAddr addr;
    int prefix = 0;
    bool contains(const IpAddr& ip) const;
};

/** "10.0.0.0/8", "fd00::/8", or a bare address (= /32 or /128). */
bool parseCidr(const std::string& text, IpNet& out);
/** Comma- or whitespace-separated CIDR list. False + err on the first bad
 *  entry; an empty list is valid and yields no networks. */
bool parseCidrList(const std::string& text, std::vector<IpNet>& out,
                   std::string& err);

/** Host part of a peer string as HttpServer formats it:
 *  "a.b.c.d:port" -> "a.b.c.d", "[v6]:port" -> "v6". */
std::string hostOfPeer(const std::string& peer);

/**
 * The client address to attribute a request to. The socket peer is used
 * unless it is loopback or inside one of `trustedProxies`, in which case the
 * proxy's X-Real-IP is honoured, falling back to the last hop appended to
 * X-Forwarded-For (the entry the trusted proxy itself wrote). Header values
 * that do not parse as an IP are ignored, so a bogus header can never
 * become a rate-limit key.
 */
std::string resolveClientIp(const std::string& peer, const std::string& xRealIp,
                            const std::string& xForwardedFor,
                            const std::vector<IpNet>& trustedProxies);

} // namespace avb
