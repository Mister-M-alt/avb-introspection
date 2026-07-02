/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 */
#include "model/event.h"
#include "test.h"
#include "util/bytes.h"
#include "util/crypto_util.h"
#include "util/json.h"

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
