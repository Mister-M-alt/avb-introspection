/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 */
#include "netaddr.h"

#include <arpa/inet.h>

#include <cstring>

namespace avb {

bool parseIp(const std::string& text, IpAddr& out) {
    if (text.empty() || text.size() > 45) return false;
    in_addr a4{};
    if (::inet_pton(AF_INET, text.c_str(), &a4) == 1) {
        out = IpAddr{};
        std::memcpy(out.bytes.data(), &a4, 4);
        return true;
    }
    in6_addr a6{};
    if (::inet_pton(AF_INET6, text.c_str(), &a6) == 1) {
        out = IpAddr{};
        if (IN6_IS_ADDR_V4MAPPED(&a6)) {
            std::memcpy(out.bytes.data(), a6.s6_addr + 12, 4);
            return true;
        }
        out.v6 = true;
        std::memcpy(out.bytes.data(), a6.s6_addr, 16);
        return true;
    }
    return false;
}

std::string ipToString(const IpAddr& ip) {
    char buf[INET6_ADDRSTRLEN] = "?";
    if (ip.v6) {
        in6_addr a6{};
        std::memcpy(a6.s6_addr, ip.bytes.data(), 16);
        ::inet_ntop(AF_INET6, &a6, buf, sizeof buf);
    } else {
        in_addr a4{};
        std::memcpy(&a4, ip.bytes.data(), 4);
        ::inet_ntop(AF_INET, &a4, buf, sizeof buf);
    }
    return buf;
}

bool isLoopback(const IpAddr& ip) {
    if (!ip.v6) return ip.bytes[0] == 127;
    for (int i = 0; i < 15; ++i)
        if (ip.bytes[(size_t)i] != 0) return false;
    return ip.bytes[15] == 1; // ::1
}

bool IpNet::contains(const IpAddr& ip) const {
    if (ip.v6 != addr.v6) return false;
    int bits = prefix;
    for (size_t i = 0; i < (addr.v6 ? 16u : 4u) && bits > 0; ++i, bits -= 8) {
        uint8_t mask = bits >= 8 ? 0xff : (uint8_t)(0xff << (8 - bits));
        if ((ip.bytes[i] & mask) != (addr.bytes[i] & mask)) return false;
    }
    return true;
}

bool parseCidr(const std::string& text, IpNet& out) {
    size_t slash = text.find('/');
    std::string host = text.substr(0, slash);
    IpAddr a;
    if (!parseIp(host, a)) return false;
    int maxBits = a.v6 ? 128 : 32;
    int prefix = maxBits;
    if (slash != std::string::npos) {
        std::string p = text.substr(slash + 1);
        if (p.empty() || p.size() > 3) return false;
        for (char c : p)
            if (c < '0' || c > '9') return false;
        prefix = std::stoi(p);
        if (prefix < 0 || prefix > maxBits) return false;
    }
    out.addr = a;
    out.prefix = prefix;
    return true;
}

bool parseCidrList(const std::string& text, std::vector<IpNet>& out,
                   std::string& err) {
    size_t i = 0;
    while (i < text.size()) {
        while (i < text.size() && (text[i] == ',' || text[i] == ' ' ||
                                   text[i] == '\t' || text[i] == '\n'))
            ++i;
        size_t start = i;
        while (i < text.size() && text[i] != ',' && text[i] != ' ' &&
               text[i] != '\t' && text[i] != '\n')
            ++i;
        if (start == i) continue;
        std::string item = text.substr(start, i - start);
        IpNet net;
        if (!parseCidr(item, net)) {
            err = "bad address or CIDR range \"" + item + "\"";
            return false;
        }
        out.push_back(net);
    }
    return true;
}

std::string hostOfPeer(const std::string& peer) {
    if (!peer.empty() && peer[0] == '[') {
        size_t close = peer.find(']');
        return close == std::string::npos ? peer.substr(1)
                                          : peer.substr(1, close - 1);
    }
    size_t colon = peer.rfind(':');
    // A bare IPv6 literal without a port has several colons; only strip a
    // trailing ":port" from the v4 form.
    if (colon != std::string::npos && peer.find(':') == colon)
        return peer.substr(0, colon);
    return peer;
}

namespace {

std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t");
    if (a == std::string::npos) return {};
    size_t b = s.find_last_not_of(" \t");
    return s.substr(a, b - a + 1);
}

} // namespace

std::string resolveClientIp(const std::string& peer, const std::string& xRealIp,
                            const std::string& xForwardedFor,
                            const std::vector<IpNet>& trustedProxies) {
    std::string host = hostOfPeer(peer);
    IpAddr peerIp;
    if (!parseIp(host, peerIp)) return host;

    bool trusted = isLoopback(peerIp);
    for (auto& net : trustedProxies)
        if (!trusted && net.contains(peerIp)) trusted = true;
    if (!trusted) return ipToString(peerIp);

    IpAddr fwd;
    if (parseIp(trim(xRealIp), fwd)) return ipToString(fwd);
    // Last entry of X-Forwarded-For is the one our trusted proxy appended.
    if (!xForwardedFor.empty()) {
        size_t comma = xForwardedFor.rfind(',');
        std::string last = trim(comma == std::string::npos
                                    ? xForwardedFor
                                    : xForwardedFor.substr(comma + 1));
        if (parseIp(last, fwd)) return ipToString(fwd);
    }
    return ipToString(peerIp);
}

} // namespace avb
