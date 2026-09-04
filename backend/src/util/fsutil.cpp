/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 */
#include "fsutil.h"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>

namespace avb {

bool writeFileAtomic(const std::string& path, const std::string& data,
                     std::string& err, mode_t mode) {
    std::string tmp = path + ".tmp";
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) {
        err = "cannot write " + tmp + ": " + std::strerror(errno);
        return false;
    }
    size_t off = 0;
    while (off < data.size()) {
        ssize_t n = ::write(fd, data.data() + off, data.size() - off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            err = "short write to " + tmp + " (disk full?)";
            ::close(fd);
            ::unlink(tmp.c_str());
            return false;
        }
        off += (size_t)n;
    }
    if (::fsync(fd) != 0) {
        err = "fsync " + tmp + ": " + std::strerror(errno);
        ::close(fd);
        ::unlink(tmp.c_str());
        return false;
    }
    ::close(fd);
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        err = "cannot replace " + path + ": " + std::strerror(errno);
        ::unlink(tmp.c_str());
        return false;
    }
    // Persist the rename itself: fsync the containing directory.
    size_t slash = path.find_last_of('/');
    std::string dir = slash == std::string::npos ? "." : path.substr(0, slash);
    if (dir.empty()) dir = "/";
    int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd >= 0) {
        ::fsync(dfd); // best effort — some filesystems refuse directory fsync
        ::close(dfd);
    }
    return true;
}

} // namespace avb
