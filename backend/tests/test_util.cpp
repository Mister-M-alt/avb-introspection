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
