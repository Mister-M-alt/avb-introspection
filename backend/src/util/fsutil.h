/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * Crash-safe file replacement for the JSON state files (BE-8). Data is
 * written to a sibling temp file, fsync'd, renamed over the target, and the
 * directory entry is fsync'd too — so a reader never sees a torn file and a
 * power loss after the call returns cannot roll the write back.
 */
#pragma once

#include <sys/types.h>

#include <string>

namespace avb {

/** Atomically replace `path` with `data`. `mode` applies to a newly created
 *  file (the umask still applies). False + err on any failure; the target
 *  is left untouched in that case. */
bool writeFileAtomic(const std::string& path, const std::string& data,
                     std::string& err, mode_t mode = 0644);

} // namespace avb
