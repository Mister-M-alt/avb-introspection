/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 */
#include "model/event.h"
#include "test.h"
#include "util/bytes.h"
#include "util/crypto_util.h"
#include "util/decompress.h"
#include "util/json.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>

using namespace avb;

TEST(sha1_known_vector) {
    // FIPS 180 example: SHA1("abc")
    const uint8_t abc[] = {'a', 'b', 'c'};
    auto d = sha1(std::span<const uint8_t>(abc, 3));
    CHECK_EQ(hexDump(std::span<const uint8_t>(d.data(), d.size())),
             std::string("a9993e364706816aba3e25717850c26c9cd0d89d"));
}

TEST(base64_padding) {
    const uint8_t a[] = {'f', 'o', 'o', 'b', 'a', 'r'};
    CHECK_EQ(base64(std::span<const uint8_t>(a, 6)), std::string("Zm9vYmFy"));
    CHECK_EQ(base64(std::span<const uint8_t>(a, 5)), std::string("Zm9vYmE="));
    CHECK_EQ(base64(std::span<const uint8_t>(a, 4)), std::string("Zm9vYg=="));
}

TEST(ws_accept_key_rfc6455) {
    CHECK_EQ(wsAcceptKey("dGhlIHNhbXBsZSBub25jZQ=="),
             std::string("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
}

TEST(be_reader_bounds) {
    const uint8_t data[] = {0x12, 0x34, 0x56};
    BeReader r({data, 3});
    CHECK_EQ(r.u16(), 0x1234u);
    bool threw = false;
    try {
        r.u32();
    } catch (const ShortFrame&) {
        threw = true;
    }
    CHECK(threw);
    CHECK_EQ(r.remaining(), (size_t)1);
}

TEST(formatting) {
    CHECK_EQ(macStr((uint64_t)0x001b92000001), std::string("00:1b:92:00:00:01"));
    CHECK_EQ(idStr(0x001b92fffe000001ull), std::string("0x001b92fffe000001"));
    const uint8_t padded[] = {'F', 'O', 'H', 0, 0, 0};
    CHECK_EQ(paddedStr({padded, 6}), std::string("FOH"));
}

TEST(json_writer_escaping) {
    JsonWriter w;
    w.beginObj().kv("a", "x\"y\n").kv("b", (int64_t)-3).key("c").beginArr()
        .value((uint64_t)1).value(true).null().endArr().endObj();
    CHECK_EQ(w.str(), std::string("{\"a\":\"x\\\"y\\n\",\"b\":-3,\"c\":[1,true,null]}"));
}

TEST(json_parse_roundtrip) {
    std::string err;
    JsonValue v = JsonValue::parse(
        "{\"user\": \"al\\u00e9x\", \"n\": 42.5, \"list\": [1, {\"k\": false}]}",
        &err);
    CHECK_EQ(err, std::string());
    CHECK_EQ(v.getStr("user"), std::string("al\xc3\xa9x"));
    CHECK_EQ(v.getNum("n"), 42.5);
    CHECK(v.get("list") && v.get("list")->arr.size() == 2);

    JsonValue bad = JsonValue::parse("{\"a\": }", &err);
    CHECK(bad.isNull());
    CHECK(!err.empty());

    JsonValue trailing = JsonValue::parse("{} x", &err);
    CHECK(trailing.isNull());
}

TEST(json_numeric_field_heuristic) {
    Event e;
    e.fields = {{"sequence_id", "7"}, {"status", "SUCCESS"}, {"weird", "007"}};
    JsonWriter w;
    e.toJson(w);
    CHECK(w.str().find("\"sequence_id\":7") != std::string::npos);
    CHECK(w.str().find("\"status\":\"SUCCESS\"") != std::string::npos);
    CHECK(w.str().find("\"weird\":\"007\"") != std::string::npos);
}

TEST(compression_magic_detection) {
    const unsigned char gz[] = {0x1f, 0x8b, 0x08, 0x00};
    const unsigned char xz[] = {0xfd, '7', 'z', 'X', 'Z', 0x00};
    const unsigned char zst[] = {0x28, 0xb5, 0x2f, 0xfd};
    const unsigned char bz[] = {'B', 'Z', 'h', '9'};
    const unsigned char lz4[] = {0x04, 0x22, 0x4d, 0x18};
    const unsigned char zip[] = {'P', 'K', 0x03, 0x04};
    const unsigned char pcap[] = {0xd4, 0xc3, 0xb2, 0xa1};
    const unsigned char pcapng[] = {0x0a, 0x0d, 0x0d, 0x0a};
    CHECK_EQ(compressionTool(gz, sizeof gz), std::string("gzip"));
    CHECK_EQ(compressionTool(xz, sizeof xz), std::string("xz"));
    CHECK_EQ(compressionTool(zst, sizeof zst), std::string("zstd"));
    CHECK_EQ(compressionTool(bz, sizeof bz), std::string("bzip2"));
    CHECK_EQ(compressionTool(lz4, sizeof lz4), std::string("lz4"));
    CHECK_EQ(compressionTool(zip, sizeof zip), std::string("unzip"));
    CHECK_EQ(compressionTool(pcap, sizeof pcap), std::string());
    CHECK_EQ(compressionTool(pcapng, sizeof pcapng), std::string());
    CHECK_EQ(compressionTool(gz, 1), std::string());  // too short to tell

    CHECK_EQ(stripCompressionSuffix("trace.pcap.gz"), std::string("trace.pcap"));
    CHECK_EQ(stripCompressionSuffix("trace.pcapng.zst"), std::string("trace.pcapng"));
    CHECK_EQ(stripCompressionSuffix("trace.pcap.zip"), std::string("trace.pcap"));
    CHECK_EQ(stripCompressionSuffix("trace.pcap"), std::string("trace.pcap"));
}

TEST(decompress_gzip_roundtrip) {
    // gzip is part of the base system everywhere the backend runs.
    std::string dir = "build/test-decomp";
    std::filesystem::create_directories(dir);
    std::string plain = dir + "/x.txt", gz = dir + "/x.txt.gz",
                out = dir + "/x.out";
    {
        std::ofstream f(plain, std::ios::trunc);
        f << "hello capture";
    }
    CHECK_EQ(std::system(("gzip -kf " + plain).c_str()), 0);
    std::string err;
    CHECK(decompressFile("gzip", gz, out, err));
    std::ifstream f(out);
    std::string got((std::istreambuf_iterator<char>(f)),
                    std::istreambuf_iterator<char>());
    CHECK_EQ(got, std::string("hello capture"));
    // A missing tool reports a clear error instead of a silent failure.
    CHECK(!decompressFile("definitely-not-a-real-tool", gz, out, err));
    CHECK(err.find("not installed") != std::string::npos);
}

TEST(decompress_zip_extracts_capture) {
    // A zip holding a pcap (behind a decoy entry) should yield that pcap's
    // bytes — extraction uses `unzip`, part of the base image the backend runs
    // on. Build the archive with python3's zipfile so no `zip` binary is
    // required; skip if the host has neither (the e2e still covers this path).
    std::string dir = "build/test-zip";
    std::filesystem::create_directories(dir);
    std::string zip = dir + "/bundle.zip", out = dir + "/out.bin";
    std::filesystem::remove(zip);
    std::string mk = "python3 - <<'PY'\n"
                     "import zipfile\n"
                     "z = zipfile.ZipFile('" + zip + "', 'w')\n"
                     "z.writestr('readme.txt', 'notes')\n"
                     "z.writestr('trace.pcap', 'PCAP-BYTES-HERE')\n"
                     "z.close()\n"
                     "PY\n";
    if (std::system(mk.c_str()) != 0 || !std::filesystem::exists(zip)) {
        CHECK(true);   // no zip builder available — skip the extraction check
        return;
    }
    std::string err;
    CHECK(decompressFile("unzip", zip, out, err));
    std::ifstream f(out);
    std::string got((std::istreambuf_iterator<char>(f)),
                    std::istreambuf_iterator<char>());
    CHECK_EQ(got, std::string("PCAP-BYTES-HERE"));
}

#include "sec/flowguard.h"
#include "store/store.h"
#include "util/ratelimit.h"

TEST(rate_limiter_burst_then_deny) {
    RateLimiter rl;
    // burst of 5 at 1 token/s: five pass, the sixth is denied with a
    // retry hint under a second.
    double retry = -1;
    for (int i = 0; i < 5; ++i) CHECK(rl.allow("u:a", 1.0, 5.0));
    CHECK(!rl.allow("u:a", 1.0, 5.0, 1.0, &retry));
    CHECK(retry > 0 && retry <= 1.1);
    // Other actors have their own bucket, penalties slow the refill hint.
    CHECK(rl.allow("u:b", 1.0, 5.0));
    for (int i = 0; i < 5; ++i) rl.allow("u:c", 1.0, 5.0);
    double slow = -1;
    CHECK(!rl.allow("u:c", 1.0, 5.0, 4.0, &slow));
    CHECK(slow > 3.0); // 4x penalty divides the refill rate
}

TEST(flowguard_bruteforce_alert_and_penalty) {
    FlowGuard g; // no log path — memory only
    // Normal traffic stays legit and unpenalized.
    g.record("u:ok", "default", "user", "GET", "/api/sessions", 200, 0);
    CHECK_EQ(g.penalty("u:ok"), 1.0);
    // 8 login failures inside the window raise auth-bruteforce + penalty.
    for (int i = 0; i < 8; ++i)
        g.record("ip:10.0.0.9", "(unauthenticated)", "", "POST", "/api/login",
                 401, 0);
    CHECK_EQ(g.penalty("ip:10.0.0.9"), 4.0);
    // A traversal probe is flagged immediately, first strike.
    g.record("u:evil", "default", "user", "GET", "/api/../../etc/passwd", 403,
             0);
    CHECK_EQ(g.penalty("u:evil"), 4.0);
    JsonWriter w;
    g.snapshot(w);
    std::string snap = w.take();
    CHECK(snap.find("auth-bruteforce") != std::string::npos);
    CHECK(snap.find("path-traversal") != std::string::npos);
    CHECK(snap.find("\"suspect\"") != std::string::npos);
}

TEST(store_domain_id_validation) {
    CHECK(Store::validDomainId("acme"));
    CHECK(Store::validDomainId("team-42"));
    CHECK(!Store::validDomainId(""));
    CHECK(!Store::validDomainId("Acme"));       // uppercase
    CHECK(!Store::validDomainId("42team"));     // must start with a letter
    CHECK(!Store::validDomainId("a/b"));        // path separator
    CHECK(!Store::validDomainId("a.b"));        // no dots (path safety)
    CHECK(!Store::validDomainId("default"));    // reserved
    CHECK(!Store::validDomainId("domains"));    // reserved (layout)
    CHECK(!Store::validDomainId(std::string(33, 'a'))); // too long
}

// ---------------------------------------------------------------------------
// util/netaddr.h — bind/CIDR parsing and trusted-proxy client resolution
// ---------------------------------------------------------------------------
#include "util/netaddr.h"

TEST(netaddr_parse_ip_forms) {
    IpAddr a;
    CHECK(parseIp("192.168.1.20", a));
    CHECK(!a.v6);
    CHECK_EQ(ipToString(a), std::string("192.168.1.20"));
    CHECK(parseIp("::1", a));
    CHECK(a.v6);
    CHECK(isLoopback(a));
    // IPv4-mapped IPv6 (what a dual-stack "::" listener reports) folds to v4.
    CHECK(parseIp("::ffff:127.0.0.1", a));
    CHECK(!a.v6);
    CHECK(isLoopback(a));
    CHECK_EQ(ipToString(a), std::string("127.0.0.1"));
    CHECK(!parseIp("", a));
    CHECK(!parseIp("not-an-ip", a));
    CHECK(!parseIp("10.0.0.1:8342", a));
    CHECK(!parseIp("300.1.1.1", a));
}

TEST(netaddr_cidr) {
    IpNet n;
    CHECK(parseCidr("10.0.0.0/8", n));
    IpAddr a;
    parseIp("10.200.3.4", a);
    CHECK(n.contains(a));
    parseIp("11.0.0.1", a);
    CHECK(!n.contains(a));
    CHECK(parseCidr("172.16.0.0/12", n));
    parseIp("172.31.255.1", a);
    CHECK(n.contains(a));
    parseIp("172.32.0.1", a);
    CHECK(!n.contains(a));
    // bare address = host route
    CHECK(parseCidr("10.20.0.5", n));
    CHECK_EQ(n.prefix, 32);
    parseIp("10.20.0.5", a);
    CHECK(n.contains(a));
    parseIp("10.20.0.6", a);
    CHECK(!n.contains(a));
    // v6 range; a v4 address never matches a v6 range
    CHECK(parseCidr("fd00::/8", n));
    parseIp("fd12:3456::1", a);
    CHECK(n.contains(a));
    parseIp("10.0.0.1", a);
    CHECK(!n.contains(a));
    CHECK(!parseCidr("10.0.0.0/33", n));
    CHECK(!parseCidr("10.0.0.0/", n));
    CHECK(!parseCidr("10.0.0.0/x", n));
    CHECK(!parseCidr("::/129", n));

    std::vector<IpNet> list;
    std::string err;
    CHECK(parseCidrList("10.0.0.0/8, 192.168.0.0/16\n fd00::/8", list, err));
    CHECK_EQ(list.size(), (size_t)3);
    CHECK(parseCidrList("", list, err)); // empty list is fine
    list.clear();
    CHECK(!parseCidrList("10.0.0.0/8,oops", list, err));
    CHECK(err.find("oops") != std::string::npos);
}

TEST(netaddr_host_of_peer) {
    CHECK_EQ(hostOfPeer("10.1.2.3:41234"), std::string("10.1.2.3"));
    CHECK_EQ(hostOfPeer("[fd00::1]:41234"), std::string("fd00::1"));
    CHECK_EQ(hostOfPeer("fd00::1"), std::string("fd00::1"));
    CHECK_EQ(hostOfPeer("10.1.2.3"), std::string("10.1.2.3"));
}

TEST(netaddr_resolve_client_ip) {
    std::vector<IpNet> none;
    std::vector<IpNet> nets;
    std::string err;
    parseCidrList("10.89.0.0/16", nets, err);

    // Loopback peer: forwarded headers are honoured, X-Real-IP first.
    CHECK_EQ(resolveClientIp("127.0.0.1:5000", "203.0.113.9", "", none),
             std::string("203.0.113.9"));
    CHECK_EQ(resolveClientIp("[::1]:5000", "", "198.51.100.1, 203.0.113.9", none),
             std::string("203.0.113.9"));
    // Untrusted remote peer: headers ignored (cannot spoof past the limiter).
    CHECK_EQ(resolveClientIp("10.89.0.7:5000", "203.0.113.9", "", none),
             std::string("10.89.0.7"));
    // Same peer inside AVB_TRUSTED_PROXIES: honoured.
    CHECK_EQ(resolveClientIp("10.89.0.7:5000", "203.0.113.9", "", nets),
             std::string("203.0.113.9"));
    CHECK_EQ(resolveClientIp("10.89.0.7:5000", "", "203.0.113.9", nets),
             std::string("203.0.113.9"));
    // Garbage in the header never becomes a rate-limit key.
    CHECK_EQ(resolveClientIp("10.89.0.7:5000", "evil\"key", "also bad", nets),
             std::string("10.89.0.7"));
    // Dual-stack listener reports v4 peers as mapped v6 — still recognised.
    CHECK_EQ(resolveClientIp("[::ffff:10.89.0.7]:5000", "203.0.113.9", "", nets),
             std::string("203.0.113.9"));
    CHECK_EQ(resolveClientIp("[::ffff:127.0.0.1]:5000", "203.0.113.9", "", none),
             std::string("203.0.113.9"));
    // Unparseable peer (should not happen) passes through unchanged.
    CHECK_EQ(resolveClientIp("?", "203.0.113.9", "", nets), std::string("?"));
}

// ---------------------------------------------------------------------------
// util/fsutil.h — atomic, durable file replacement
// ---------------------------------------------------------------------------
#include "util/fsutil.h"

#include <sys/stat.h>

TEST(fsutil_write_file_atomic) {
    std::string dir = "build/test-fsutil";
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    std::string path = dir + "/state.json";
    std::string err;

    CHECK(writeFileAtomic(path, "{\"v\":1}", err, 0600));
    CHECK_EQ(err, std::string());
    {
        std::ifstream f(path);
        std::string s((std::istreambuf_iterator<char>(f)), {});
        CHECK_EQ(s, std::string("{\"v\":1}"));
    }
    struct stat st{};
    CHECK(::stat(path.c_str(), &st) == 0);
    CHECK_EQ((int)(st.st_mode & 0777), 0600);
    CHECK(!std::filesystem::exists(path + ".tmp")); // no staging leftovers

    // Replacement is complete-or-nothing and keeps the earlier mode choice
    // irrelevant: the new file carries the requested mode.
    CHECK(writeFileAtomic(path, "{\"v\":2}", err, 0644));
    {
        std::ifstream f(path);
        std::string s((std::istreambuf_iterator<char>(f)), {});
        CHECK_EQ(s, std::string("{\"v\":2}"));
    }

    // Unwritable directory: error reported, nothing created.
    CHECK(!writeFileAtomic("/proc/avb-no-such/state.json", "x", err));
    CHECK(!err.empty());
    std::filesystem::remove_all(dir);
}
