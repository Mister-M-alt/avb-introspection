/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * Compressed-capture support: detect the compression format by magic bytes
 * and inflate through the matching system decompressor (gzip, xz, zstd,
 * bzip2, lz4, lzip, and .zip archives via unzip — whatever the host has
 * installed). Keeping the codecs external means "any compression format
 * supported on this Linux" without linking N libraries.
 */
#pragma once

#include <string>

namespace avb {

/** Decompressor command for these leading bytes ("" = not compressed). */
std::string compressionTool(const unsigned char* head, size_t len);
inline std::string compressionTool(const std::string& bytes) {
    return compressionTool((const unsigned char*)bytes.data(), bytes.size());
}

/** compressionTool() applied to a file's first bytes ("" also on I/O error). */
std::string compressionToolForFile(const std::string& path);

/** Run `tool -dc < src > dst`. False + err on failure (incl. tool missing). */
bool decompressFile(const std::string& tool, const std::string& src,
                    const std::string& dst, std::string& err);

/** "trace.pcap.gz" -> "trace.pcap" (known compression suffixes only). */
std::string stripCompressionSuffix(const std::string& name);

} // namespace avb
