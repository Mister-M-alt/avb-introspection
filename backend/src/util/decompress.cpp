/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 */
#include "decompress.h"

#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cctype>
#include <cstring>
#include <fstream>
#include <vector>

namespace avb {

namespace {

struct Magic {
    const char* bytes;
    size_t len;
    const char* tool;
    const char* ext;
};

// Single-stream compressors decode via `<tool> -dc`. Zip is an archive
// container (magic PK\x03\x04) handled specially through `unzip` because it
// needs a seekable file and may hold several entries.
// gzip also inflates old .Z (compress) streams.
const Magic kMagics[] = {
    {"\x1f\x8b", 2, "gzip", ".gz"},
    {"\x1f\x9d", 2, "gzip", ".Z"},
    {"\xfd""7zXZ\x00", 6, "xz", ".xz"},
    {"\x28\xb5\x2f\xfd", 4, "zstd", ".zst"},
    {"BZh", 3, "bzip2", ".bz2"},
    {"\x04\x22\x4d\x18", 4, "lz4", ".lz4"},
    {"LZIP", 4, "lzip", ".lz"},
    {"PK\x03\x04", 4, "unzip", ".zip"},
};

// Run argv with stdin from inPath ("" -> /dev/null) and stdout to outPath
// (created/truncated). False + err on spawn failure, missing binary, or a
// non-zero exit; the (partial) output file is removed on failure.
bool runRedirect(const std::vector<std::string>& argv, const std::string& inPath,
                 const std::string& outPath, std::string& err) {
    const char* in = inPath.empty() ? "/dev/null" : inPath.c_str();
    int infd = ::open(in, O_RDONLY);
    if (infd < 0) {
        err = "cannot open " + std::string(in);
        return false;
    }
    int outfd = ::open(outPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (outfd < 0) {
        ::close(infd);
        err = "cannot create " + outPath;
        return false;
    }
    pid_t pid = ::fork();
    if (pid < 0) {
        ::close(infd);
        ::close(outfd);
        err = "fork failed";
        return false;
    }
    if (pid == 0) { // child
        ::dup2(infd, 0);
        ::dup2(outfd, 1);
        ::close(infd);
        ::close(outfd);
        std::vector<char*> args;
        args.reserve(argv.size() + 1);
        for (auto& a : argv) args.push_back(const_cast<char*>(a.c_str()));
        args.push_back(nullptr);
        ::execvp(args[0], args.data());
        _exit(127);
    }
    ::close(infd);
    ::close(outfd);
    int status = 0;
    if (::waitpid(pid, &status, 0) < 0) {
        err = "waitpid failed";
        return false;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        err = (WIFEXITED(status) && WEXITSTATUS(status) == 127)
                  ? argv[0] + " is not installed on the backend host"
                  : argv[0] + " exited with an error";
        ::unlink(outPath.c_str());
        return false;
    }
    return true;
}

bool endsWithCi(const std::string& s, const std::string& suf) {
    if (s.size() < suf.size()) return false;
    for (size_t i = 0; i < suf.size(); ++i)
        if (std::tolower((unsigned char)s[s.size() - suf.size() + i]) != suf[i])
            return false;
    return true;
}

// Extract one capture from a .zip: list entries, pick the pcap/pcapng one
// (else the first file), and stream it out via `unzip -p`.
bool decompressZip(const std::string& src, const std::string& dst,
                   std::string& err) {
    std::string listPath = dst + ".zilist";
    if (!runRedirect({"unzip", "-Z1", src}, "", listPath, err)) {
        ::unlink(listPath.c_str());
        if (err.find("not installed") == std::string::npos)
            err = "cannot read zip archive (corrupt, encrypted, or not a zip?)";
        return false;
    }
    std::vector<std::string> entries;
    {
        std::ifstream lf(listPath);
        std::string line;
        while (std::getline(lf, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (!line.empty() && line.back() != '/') entries.push_back(line);
        }
    }
    ::unlink(listPath.c_str());
    if (entries.empty()) {
        err = "zip archive contains no files";
        return false;
    }
    // Ignore macOS archive cruft (__MACOSX/…, ._AppleDouble sidecars) — it is
    // never the capture and would fail validation if picked.
    auto isCruft = [](const std::string& e) {
        if (e.rfind("__MACOSX/", 0) == 0) return true;
        size_t slash = e.find_last_of('/');
        std::string base = slash == std::string::npos ? e : e.substr(slash + 1);
        return base.rfind("._", 0) == 0 || base == ".DS_Store";
    };
    std::string entry;
    for (auto& e : entries)   // 1st choice: a capture-typed, non-cruft entry
        if (!isCruft(e) && (endsWithCi(e, ".pcap") || endsWithCi(e, ".pcapng") ||
                            endsWithCi(e, ".cap"))) {
            entry = e;
            break;
        }
    if (entry.empty())        // else: the first non-cruft file
        for (auto& e : entries)
            if (!isCruft(e)) { entry = e; break; }
    if (entry.empty()) entry = entries.front();
    if (!runRedirect({"unzip", "-p", src, entry}, "", dst, err)) {
        if (err.find("not installed") == std::string::npos)
            err = "failed to extract \"" + entry + "\" from the zip archive";
        return false;
    }
    return true;
}

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
                            ".zstd", ".bzip2", ".zip"}) {
        size_t el = std::strlen(ext);
        if (name.size() > el && name.compare(name.size() - el, el, ext) == 0)
            return name.substr(0, name.size() - el);
    }
    return name;
}

bool decompressFile(const std::string& tool, const std::string& src,
                    const std::string& dst, std::string& err) {
    if (tool == "unzip") return decompressZip(src, dst, err);
    bool ok = runRedirect({tool, "-dc"}, src, dst, err);
    if (!ok && err.find("not installed") == std::string::npos)
        err = tool + " failed to decompress the capture (corrupt file?)";
    return ok;
}

} // namespace avb
