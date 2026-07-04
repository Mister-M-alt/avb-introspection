/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * pcap (classic, µs and ns variants, both endiannesses) and pcapng
 * (SHB/IDB/EPB/SPB) file readers. Only LINKTYPE_ETHERNET (1) captures are
 * accepted in v1 (BE-5).
 */
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace avb {

struct PcapPacket {
    uint64_t tsNanos = 0;  // absolute capture timestamp, ns since epoch
    uint32_t caplen = 0;   // captured bytes present in file
    uint32_t origlen = 0;  // original wire length
    size_t offset = 0;     // offset of packet data within the file
};

class PcapFile {
public:
    /** Parse the file; returns false and sets err on any format problem. */
    bool open(const std::string& path, std::string& err);

    const std::vector<PcapPacket>& packets() const { return mPackets; }
    const std::vector<uint8_t>& data() const { return mData; }

    /** Packet bytes (view into the loaded file). i is 0-based. */
    const uint8_t* packetData(size_t i) const { return mData.data() + mPackets[i].offset; }

    /** Seconds since the first packet of the capture. */
    double relTs(size_t i) const {
        return mPackets.empty() ? 0.0
                                : (double)(mPackets[i].tsNanos - mPackets.front().tsNanos) / 1e9;
    }
    /** Capture duration in seconds. */
    double duration() const {
        return mPackets.empty() ? 0.0 : relTs(mPackets.size() - 1);
    }

private:
    bool parseClassic(std::string& err);
    bool parseNg(std::string& err);

    std::vector<uint8_t> mData;
    std::vector<PcapPacket> mPackets;
};

struct PcapMergeResult {
    uint64_t firstTsNanos = 0;
    uint64_t lastTsNanos = 0;
    size_t packets = 0;
    size_t sources = 0;
};

/**
 * Combine several Ethernet captures into ONE chronologically-ordered classic
 * (nanosecond) pcap at outPath. Packets from all sources are merged and sorted
 * by absolute capture timestamp, so captures uploaded in any order land on a
 * single timeline — whether their time-windows are disjoint (gaps preserved)
 * or OVERLAP (e.g. two tap points, interleaved packet-by-packet). The only
 * failure (returns false + err) is a source that can't be opened / isn't an
 * Ethernet capture. `names[i]` is a human label for sources[i] used in errors.
 *
 * When srcMapPath is non-empty, also writes a sidecar: one little-endian
 * uint16 per merged packet (in capture order) = the 0-based index into
 * `sources` it came from, so the inspector can show each packet's origin.
 */
bool mergePcaps(const std::vector<std::string>& sources,
                const std::vector<std::string>& names,
                const std::string& outPath, const std::string& srcMapPath,
                std::string& err, PcapMergeResult* out = nullptr);

} // namespace avb
