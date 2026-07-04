/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 */
#include "pcap_reader.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <memory>

namespace avb {

namespace {

constexpr uint32_t kMagicUs = 0xa1b2c3d4;
constexpr uint32_t kMagicUsSwap = 0xd4c3b2a1;
constexpr uint32_t kMagicNs = 0xa1b23c4d;
constexpr uint32_t kMagicNsSwap = 0x4d3cb2a1;
constexpr uint32_t kMagicNg = 0x0a0d0d0a;
constexpr uint16_t kLinkEthernet = 1;
// IEEE 802.3br mPackets: preamble + SMD before the frame, e.g. ProfiShark
// taps capturing with preamble for hardware timestamping.
constexpr uint16_t kLinkEthernetMPacket = 274;

bool usableLinkType(uint16_t lt) {
    return lt == kLinkEthernet || lt == kLinkEthernetMPacket;
}

std::string linkTypeName(uint16_t lt) {
    switch (lt) {
    case 0: return "NULL/loopback (0)";
    case 1: return "Ethernet (1)";
    case 101: return "raw IP (101)";
    case 105: return "IEEE 802.11 (105)";
    case 113: return "Linux cooked/SLL (113, the \"any\" pseudo-interface)";
    case 127: return "802.11 Radiotap (127)";
    case 274: return "802.3br mPacket (274)";
    case 276: return "Linux cooked v2/SLL2 (276, the \"any\" pseudo-interface)";
    }
    return "link type " + std::to_string(lt);
}

const char* kEthernetHint =
    "; v1 decodes Ethernet captures only — capture directly on the wired "
    "interface (e.g. tcpdump -i eth0), not on \"any\"";

/**
 * 802.3br mPacket record -> plain Ethernet frame: skip the 0x55 preamble
 * bytes and the SMD. Express frames (SMD-E, 0xD5) are real frames;
 * preemption fragments (SMD-S/C) are left untouched and surface as
 * decode-error events downstream.
 */
void stripMPacketPreamble(PcapPacket& p, const std::vector<uint8_t>& data) {
    const uint8_t* d = data.data() + p.offset;
    uint32_t lim = std::min<uint32_t>(p.caplen, 16);
    for (uint32_t i = 0; i < lim; ++i) {
        if (d[i] == 0xD5) { // SFD/SMD-E: frame starts right after
            p.offset += i + 1;
            p.caplen -= i + 1;
            if (p.origlen > i) p.origlen -= i + 1;
            return;
        }
        if (d[i] != 0x55) return; // not preamble — fragment or garbage
    }
}

class Cursor {
public:
    Cursor(const uint8_t* p, size_t n) : mP(p), mN(n) {}
    bool need(size_t n) const { return mPos + n <= mN; }
    size_t pos() const { return mPos; }
    void seek(size_t p) { mPos = p; }
    bool skip(size_t n) {
        if (!need(n)) return false;
        mPos += n;
        return true;
    }
    bool u16(uint16_t& v, bool swap) {
        if (!need(2)) return false;
        std::memcpy(&v, mP + mPos, 2);
        if (swap) v = (uint16_t)((v >> 8) | (v << 8));
        mPos += 2;
        return true;
    }
    bool u32(uint32_t& v, bool swap) {
        if (!need(4)) return false;
        std::memcpy(&v, mP + mPos, 4);
        if (swap) v = __builtin_bswap32(v);
        mPos += 4;
        return true;
    }

private:
    const uint8_t* mP;
    size_t mN;
    size_t mPos = 0;
};

} // namespace

bool PcapFile::open(const std::string& path, std::string& err) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        err = "cannot open file: " + path;
        return false;
    }
    f.seekg(0, std::ios::end);
    auto size = f.tellg();
    if (size < 4) {
        err = "file too small to be a capture";
        return false;
    }
    f.seekg(0);
    mData.resize((size_t)size);
    f.read(reinterpret_cast<char*>(mData.data()), size);
    if (!f) {
        err = "read failed: " + path;
        return false;
    }

    uint32_t magic;
    std::memcpy(&magic, mData.data(), 4);
    if (magic == kMagicNg) return parseNg(err);
    if (magic == kMagicUs || magic == kMagicUsSwap || magic == kMagicNs ||
        magic == kMagicNsSwap)
        return parseClassic(err);
    err = "not a pcap or pcapng file (bad magic)";
    return false;
}

bool PcapFile::parseClassic(std::string& err) {
    uint32_t magic;
    std::memcpy(&magic, mData.data(), 4);
    bool swap = (magic == kMagicUsSwap || magic == kMagicNsSwap);
    bool nanos = (magic == kMagicNs || magic == kMagicNsSwap);

    Cursor c(mData.data(), mData.size());
    c.seek(4);
    uint16_t verMaj, verMin;
    uint32_t thiszone, sigfigs, snaplen, network;
    if (!c.u16(verMaj, swap) || !c.u16(verMin, swap) || !c.u32(thiszone, swap) ||
        !c.u32(sigfigs, swap) || !c.u32(snaplen, swap) || !c.u32(network, swap)) {
        err = "truncated pcap global header";
        return false;
    }
    uint16_t linktype = (uint16_t)(network & 0xffff);
    if (!usableLinkType(linktype)) {
        err = "capture is " + linkTypeName(linktype) + kEthernetHint;
        return false;
    }

    while (c.need(16)) {
        uint32_t tsSec, tsFrac, caplen, origlen;
        if (!c.u32(tsSec, swap) || !c.u32(tsFrac, swap) || !c.u32(caplen, swap) ||
            !c.u32(origlen, swap))
            break;
        if (!c.need(caplen)) {
            err = "truncated packet record #" + std::to_string(mPackets.size() + 1);
            return false;
        }
        PcapPacket p;
        p.tsNanos = (uint64_t)tsSec * 1000000000ull +
                    (nanos ? tsFrac : (uint64_t)tsFrac * 1000ull);
        p.caplen = caplen;
        p.origlen = origlen;
        p.offset = c.pos();
        c.skip(caplen);
        if (linktype == kLinkEthernetMPacket) stripMPacketPreamble(p, mData);
        mPackets.push_back(p);
    }
    if (mPackets.empty()) {
        err = "pcap contains no packets";
        return false;
    }
    return true;
}

bool PcapFile::parseNg(std::string& err) {
    Cursor c(mData.data(), mData.size());
    bool swap = false;
    // tsresol numerator per interface: ns per tick.
    std::vector<uint64_t> ifaceNsPerTick;
    std::vector<uint16_t> ifaceLink;
    bool sawEthernet = false;

    while (c.need(12)) {
        size_t blockStart = c.pos();
        uint32_t blockType, blockLen;
        if (!c.u32(blockType, swap)) break;

        if (blockType == kMagicNg) { // SHB: byte order comes from the magic
            uint32_t rawLen;
            std::memcpy(&rawLen, mData.data() + c.pos(), 4);
            uint32_t bom;
            std::memcpy(&bom, mData.data() + c.pos() + 4, 4);
            swap = (bom == 0x4d3c2b1a); // byte-swapped 0x1a2b3c4d
            if (!swap && bom != 0x1a2b3c4d) {
                err = "pcapng: bad byte-order magic";
                return false;
            }
            c.seek(blockStart);
            c.skip(4);
            if (!c.u32(blockLen, swap)) break;
            c.seek(blockStart + blockLen);
            ifaceNsPerTick.clear();
            ifaceLink.clear();
            continue;
        }

        if (!c.u32(blockLen, swap) || blockLen < 12 ||
            blockStart + blockLen > mData.size()) {
            err = "pcapng: truncated block";
            return false;
        }

        if (blockType == 1) { // IDB
            uint16_t linktype, rsv;
            uint32_t snaplen;
            if (!c.u16(linktype, swap) || !c.u16(rsv, swap) || !c.u32(snaplen, swap)) {
                err = "pcapng: truncated IDB";
                return false;
            }
            uint64_t nsPerTick = 1000; // default 1e-6 s
            // Walk options for if_tsresol (code 9).
            size_t optEnd = blockStart + blockLen - 4;
            while (c.pos() + 4 <= optEnd) {
                uint16_t code, len;
                if (!c.u16(code, swap) || !c.u16(len, swap)) break;
                if (code == 0) break;
                if (code == 9 && len >= 1) {
                    uint8_t r = mData[c.pos()];
                    uint64_t ticksPerSec = 1;
                    if (r & 0x80) {
                        int p = r & 0x7f;
                        ticksPerSec = (p < 63) ? (1ull << p) : (1ull << 62);
                    } else {
                        for (int i = 0; i < r && i < 18; ++i) ticksPerSec *= 10;
                    }
                    nsPerTick = ticksPerSec ? 1000000000ull / ticksPerSec : 1;
                    if (nsPerTick == 0) nsPerTick = 1;
                }
                c.skip((len + 3u) & ~3u);
            }
            ifaceNsPerTick.push_back(nsPerTick);
            ifaceLink.push_back(linktype);
            if (usableLinkType(linktype)) sawEthernet = true;
        } else if (blockType == 6) { // EPB
            uint32_t ifaceId, tsHi, tsLo, caplen, origlen;
            if (!c.u32(ifaceId, swap) || !c.u32(tsHi, swap) || !c.u32(tsLo, swap) ||
                !c.u32(caplen, swap) || !c.u32(origlen, swap)) {
                err = "pcapng: truncated EPB";
                return false;
            }
            if (ifaceId < ifaceLink.size() && usableLinkType(ifaceLink[ifaceId])) {
                uint64_t nsPerTick = ifaceNsPerTick[ifaceId];
                PcapPacket p;
                p.tsNanos = (((uint64_t)tsHi << 32) | tsLo) * nsPerTick;
                p.caplen = caplen;
                p.origlen = origlen;
                p.offset = c.pos();
                if (p.offset + caplen > mData.size()) {
                    err = "pcapng: truncated packet data";
                    return false;
                }
                if (ifaceLink[ifaceId] == kLinkEthernetMPacket)
                    stripMPacketPreamble(p, mData);
                mPackets.push_back(p);
            }
        } else if (blockType == 3) { // SPB — no timestamp, single interface
            uint32_t origlen;
            if (!c.u32(origlen, swap)) {
                err = "pcapng: truncated SPB";
                return false;
            }
            if (!ifaceLink.empty() && usableLinkType(ifaceLink[0])) {
                PcapPacket p;
                p.tsNanos = mPackets.empty() ? 0 : mPackets.back().tsNanos;
                p.caplen = blockLen - 16;
                p.origlen = origlen;
                p.offset = c.pos();
                if (ifaceLink[0] == kLinkEthernetMPacket)
                    stripMPacketPreamble(p, mData);
                mPackets.push_back(p);
            }
        }
        c.seek(blockStart + blockLen);
    }

    if (!sawEthernet) {
        err = "pcapng: no Ethernet interface in the capture";
        if (ifaceLink.empty()) {
            err += " (no interface description blocks at all)";
        } else {
            err += " (found: ";
            for (size_t i = 0; i < ifaceLink.size(); ++i)
                err += (i ? ", " : "") + linkTypeName(ifaceLink[i]);
            err += ")";
        }
        err += kEthernetHint;
        return false;
    }
    if (mPackets.empty()) {
        err = "pcapng contains no packets";
        return false;
    }
    return true;
}

namespace {

std::string fileLabel(const std::vector<std::string>& names,
                      const std::vector<std::string>& sources, size_t i) {
    if (i < names.size() && !names[i].empty()) return names[i];
    const std::string& p = sources[i];
    auto slash = p.find_last_of('/');
    return slash == std::string::npos ? p : p.substr(slash + 1);
}

} // namespace

bool mergePcaps(const std::vector<std::string>& sources,
                const std::vector<std::string>& names,
                const std::string& outPath, const std::string& srcMapPath,
                std::string& err, PcapMergeResult* out) {
    if (sources.empty()) {
        err = "no source captures to combine";
        return false;
    }

    // Load every source (whole-file, like analysis).
    std::vector<std::unique_ptr<PcapFile>> files;
    files.reserve(sources.size());
    for (size_t i = 0; i < sources.size(); ++i) {
        auto pf = std::make_unique<PcapFile>();
        if (!pf->open(sources[i], err)) {
            err = "'" + fileLabel(names, sources, i) + "': " + err;
            return false;
        }
        files.push_back(std::move(pf));
    }

    // Interleave every packet by absolute capture timestamp. Captures may
    // OVERLAP in time (e.g. two tap points watching the same window) or be
    // disjoint with gaps — either way they land on one chronological timeline;
    // uploads in any order are handled, and ties keep source order.
    struct Ref {
        uint64_t ts;
        uint32_t file, pkt;
    };
    std::vector<Ref> refs;
    for (uint32_t fi = 0; fi < files.size(); ++fi) {
        const auto& pkts = files[fi]->packets();
        for (uint32_t pi = 0; pi < pkts.size(); ++pi)
            refs.push_back({pkts[pi].tsNanos, fi, pi});
    }
    std::stable_sort(refs.begin(), refs.end(),
                     [](const Ref& a, const Ref& b) { return a.ts < b.ts; });

    // Write one classic nanosecond Ethernet pcap (native endianness — the reader
    // detects it via the magic, so no swap is needed on read-back).
    std::ofstream o(outPath, std::ios::binary);
    if (!o) {
        err = "cannot write merged capture: " + outPath;
        return false;
    }
    auto w32 = [&](uint32_t v) { o.write(reinterpret_cast<const char*>(&v), 4); };
    auto w16 = [&](uint16_t v) { o.write(reinterpret_cast<const char*>(&v), 2); };
    w32(kMagicNs);
    w16(2);
    w16(4);          // version 2.4
    w32(0);          // thiszone
    w32(0);          // sigfigs
    w32(262144);     // snaplen
    w32(kLinkEthernet);
    for (const auto& r : refs) {
        const PcapFile& f = *files[r.file];
        const PcapPacket& p = f.packets()[r.pkt];
        w32((uint32_t)(p.tsNanos / 1000000000ull));
        w32((uint32_t)(p.tsNanos % 1000000000ull));
        w32(p.caplen);
        w32(std::max(p.origlen, p.caplen));
        o.write(reinterpret_cast<const char*>(f.packetData(r.pkt)), p.caplen);
    }
    o.flush();
    if (!o) {
        err = "failed writing merged capture: " + outPath;
        return false;
    }

    // Sidecar: source index (uint16 LE) per merged packet, in capture order —
    // lets the inspector attribute each packet to its origin capture.
    if (!srcMapPath.empty()) {
        std::ofstream sm(srcMapPath, std::ios::binary);
        if (!sm) {
            err = "cannot write source map: " + srcMapPath;
            return false;
        }
        for (const auto& r : refs) {
            uint16_t sidx = (uint16_t)r.file;
            sm.write(reinterpret_cast<const char*>(&sidx), 2);
        }
        sm.flush();
        if (!sm) {
            err = "failed writing source map: " + srcMapPath;
            return false;
        }
    }

    if (out) {
        out->firstTsNanos = refs.front().ts;
        out->lastTsNanos = refs.back().ts;
        out->packets = refs.size();
        out->sources = sources.size();
    }
    return true;
}

} // namespace avb
