/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 */
#include "decompress.h"

#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstring>

namespace avb {

namespace {

struct Magic {
    const char* bytes;
    size_t len;
    const char* tool;
    const char* ext;
};

// gzip also inflates old .Z (compress) streams.
const Magic kMagics[] = {
    {"\x1f\x8b", 2, "gzip", ".gz"},
    {"\x1f\x9d", 2, "gzip", ".Z"},
    {"\xfd""7zXZ\x00", 6, "xz", ".xz"},
    {"\x28\xb5\x2f\xfd", 4, "zstd", ".zst"},
    {"BZh", 3, "bzip2", ".bz2"},
    {"\x04\x22\x4d\x18", 4, "lz4", ".lz4"},
    {"LZIP", 4, "lzip", ".lz"},
};

} // namespace

std::string compressionTool(const unsigned char* head, size_t len) {
    for (const Magic& m : kMagics)
        if (len >= m.len && std::memcmp(head, m.bytes, m.len) == 0)
            return m.tool;
    return {};
}

std::string compressionToolForFile(const std::string& path) {
    int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) return {};
    unsigned char head[8] = {};
    ssize_t n = ::read(fd, head, sizeof head);
    ::close(fd);
    return n > 0 ? compressionTool(head, (size_t)n) : std::string{};
}

std::string stripCompressionSuffix(const std::string& name) {
    for (const char* ext : {".gz", ".xz", ".zst", ".bz2", ".lz4", ".lz", ".Z",
                            ".zstd", ".bzip2"}) {
        size_t el = std::strlen(ext);
        if (name.size() > el &&
            name.compare(name.size() - el, el, ext) == 0)
            return name.substr(0, name.size() - el);
    }
    return name;
}

bool decompressFile(const std::string& tool, const std::string& src,
                    const std::string& dst, std::string& err) {
    int in = ::open(src.c_str(), O_RDONLY);
    if (in < 0) {
        err = "cannot open " + src;
        return false;
    }
    int out = ::open(dst.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) {
        ::close(in);
        err = "cannot create " + dst;
        return false;
    }
    pid_t pid = ::fork();
    if (pid < 0) {
        ::close(in);
        ::close(out);
        err = "fork failed";
        return false;
    }
    if (pid == 0) { // child: tool -dc < src > dst
        ::dup2(in, 0);
        ::dup2(out, 1);
        ::close(in);
        ::close(out);
        ::execlp(tool.c_str(), tool.c_str(), "-dc", (char*)nullptr);
        _exit(127);
    }
    ::close(in);
    ::close(out);
    int status = 0;
    if (::waitpid(pid, &status, 0) < 0) {
        err = "waitpid failed";
        return false;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        err = WIFEXITED(status) && WEXITSTATUS(status) == 127
                  ? tool + " is not installed on the backend host"
                  : tool + " failed to decompress the capture (corrupt file?)";
        ::unlink(dst.c_str());
        return false;
    }
    return true;
}

} // namespace avb
